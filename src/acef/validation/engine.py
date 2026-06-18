"""ACEF validation engine — orchestrator for the 4-phase validation pipeline.

Phase 1: Schema validation (manifest -> envelope -> payload)
Phase 2: Integrity verification (hashes -> Merkle -> signatures)
Phase 3: Reference checking (entity refs -> file paths -> duplicates)
Phase 4: Rule evaluation (DSL rules -> provision rollup)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cryptography.x509 import Certificate

from acef.errors import ACEFError, ACEFSchemaError, ValidationDiagnostic
from acef.models.assessment import (
    AssessmentBundle,
    Assessor,
    EvidenceBundleRef,
    RuleResult,
)
from acef.models.records import RecordEnvelope, dict_to_record_envelope
from acef.schemas.registry import schema_version_for_core_version
from acef.templates.registry import compute_template_digest, load_template
from acef.validation.integrity_checker import check_integrity, get_signature_info
from acef.validation.reference_checker import check_references
from acef.validation.rollup import compute_provision_outcome
from acef.validation.rule_engine import evaluate_rules_for_subject
from acef.validation.schema_validator import validate_manifest_schema, validate_record_schemas


def _validate_record_file_path(path_str: str) -> bool:
    """Validate a record_files path for safety before reading.

    Rejects absolute paths, path traversal (..), current-dir (.) segments,
    and backslash separators per spec Section 3.1.1.

    Args:
        path_str: The path from a record_files entry.

    Returns:
        True if the path is safe to use, False otherwise.
    """
    # Delegate to loader._validate_path so this validator catches the
    # same surface as the loader: empty paths, NUL bytes, backslash,
    # absolute, non-NFC, '.'/'..' segments, and empty segments. Returning
    # False (instead of raising) keeps the engine's "skip malformed
    # entries" contract.
    from acef.errors import ACEFFormatError
    from acef.loader import _validate_path as _loader_validate_path

    try:
        _loader_validate_path(path_str)
    except ACEFFormatError:
        return False
    return True


def _content_hashes_is_str_mapping(content_hashes: object) -> bool:
    """Return ``True`` only when ``content_hashes`` is a ``dict`` whose keys AND
    values are all ``str`` (the shape of a well-formed content-hashes.json).

    Used at the bundle-digest site to decide whether ``compute_bundle_digest``
    may run. A non-string value (number / NaN / list / object) is a structural
    error already reported upstream as ACEF-014, and feeding it to
    ``compute_bundle_digest`` would either raise an
    ``rfc8785.CanonicalizationError`` (NaN / out-of-range number) or canonicalize
    a meaningless shape (list value) into a bogus digest. Refusing to compute
    here keeps the digest unset (the authoritative diagnostic stays ACEF-014)
    instead of duplicating it as the generic ACEF-001 backstop.

    A non-string KEY cannot arise from ``json.loads`` (JSON object keys are
    always strings), but is checked too so the predicate is total over any
    in-memory mapping a caller might pass.

    Args:
        content_hashes: The JSON-decoded content-hashes.json value (any type).

    Returns:
        ``True`` iff ``content_hashes`` is ``dict[str, str]``.
    """
    if not isinstance(content_hashes, dict):
        return False
    return all(isinstance(k, str) and isinstance(v, str) for k, v in content_hashes.items())


def validate_bundle(
    bundle_dir: str | Path,
    *,
    profiles: list[str] | None = None,
    evaluation_instant: str | None = None,
    timestamp: str | None = None,
    assessment_id: str | None = None,
    trust_anchors: list[Certificate] | None = None,
) -> AssessmentBundle:
    """Validate an ACEF Evidence Bundle and produce an Assessment Bundle.

    This is the main entry point for validation. Runs all 4 phases:
    1. Schema validation
    2. Integrity verification
    3. Reference checking
    4. Rule evaluation (if profiles specified)

    Args:
        bundle_dir: Path to the bundle directory.
        profiles: List of profile IDs to evaluate (e.g., ['eu-ai-act-2024']).
        evaluation_instant: Override evaluation timestamp (ISO 8601). This is
            the spec §3.7 "Canonical evaluation instant" that pins the
            evaluation RESULTS (results[]/provision_summary[]); it does not
            pin the assessment's creation-identity scalars below.
        timestamp: Override the Assessment Bundle's CREATION ``timestamp``
            (ISO 8601). Default ``None`` preserves the historical behavior:
            the field falls back to ``datetime.now(UTC)`` (wall-clock creation
            time), which is intentionally non-reproducible. Because the entire
            Assessment Bundle — including ``timestamp`` — is canonicalized and
            signed (``sign_assessment``), pinning ``timestamp`` (with
            ``assessment_id``) stabilizes the assessment PAYLOAD: the canonical
            RFC-8785 bytes become byte-identical across runs, so an UNSIGNED
            assessment is byte-reproducible. Byte equality of the SIGNED
            artifact (the exported ``.acef-assessment.json`` INCLUDING its JWS)
            ALSO requires a deterministic signing algorithm — RS256 (PKCS1v15)
            is deterministic; ES256 uses a random ECDSA nonce and is therefore
            NOT byte-reproducible even with both identity scalars pinned (the
            payload bytes match, the signature bytes differ). See audit
            findings assessment-rollup-5 and export-determinism-4; callers
            needing a byte-reproducible signed assessment must use RS256. Note
            this is distinct from ``evaluation_instant``, which the engine
            already pins from ``metadata.timestamp`` for reproducible results.
        assessment_id: Override the Assessment Bundle's ``assessment_id`` URN.
            Default ``None`` mints a fresh random URN per run
            (``urn:acef:asx:<uuid4>``), which — like ``timestamp`` — perturbs
            the signed bytes. Supply an explicit value alongside ``timestamp``
            to stabilize the assessment PAYLOAD; an RS256-signed export of that
            pinned payload is then byte-reproducible, while an ES256-signed
            export is not (random ECDSA nonce). The default random URN is the
            SECOND creation-identity non-determinism source (beyond the one
            named in assessment-rollup-5) that must be pinned before the
            payload — and hence an RS256-signed assessment — is reproducible.
        trust_anchors: Locally configured trust-anchor certificates
            (``cryptography.x509.Certificate``) for x5c chain termination
            during Phase-2 signature verification. Spec §3.1.3 "Signature
            trust model": "If x5c is present, verifiers MUST validate the
            full certificate chain against a locally configured set of
            trust anchors." Default ``None`` preserves the historical
            behavior EXACTLY — absent anchors yield self-attested trust
            per the trust model (chain links and manifest-timestamp
            expiry are still verified; no external root anchoring is
            enforced). When anchors ARE configured and a signature
            carries an x5c header, a chain not terminating at any anchor
            surfaces as an ACEF-012 signature diagnostic.

    Returns:
        An AssessmentBundle with all results.
    """
    bundle_path = Path(bundle_dir)

    # Creation-identity overrides. Each scalar is applied AFTER construction
    # only when the caller supplied a non-None value, so an unset scalar falls
    # through to its default factory (wall-clock ``timestamp`` / random
    # ``assessment_id``), preserving the historical default behavior EXACTLY.
    # When BOTH are supplied (together with a pinned ``evaluation_instant``)
    # the assessment PAYLOAD (canonical RFC-8785 bytes) is byte-reproducible;
    # byte equality of the SIGNED artifact additionally requires a
    # deterministic signing algorithm — RS256 (PKCS1v15), not ES256 (random
    # ECDSA nonce) — see audit finding assessment-rollup-5. Applied via a
    # typed helper (not a ``**dict`` spread)
    # so the per-field types stay statically checkable.
    def _pin_identity(bundle: AssessmentBundle) -> AssessmentBundle:
        if timestamp is not None:
            bundle.timestamp = timestamp
        if assessment_id is not None:
            bundle.assessment_id = assessment_id
        return bundle

    # Load manifest first so we can derive a deterministic evaluation_instant
    # from metadata.timestamp when the caller did not supply one. Spec §3.7
    # forbids using wall-clock time during evaluation — a default of
    # ``datetime.now()`` makes assessment non-reproducible.
    manifest_path = bundle_path / "acef-manifest.json"
    if not manifest_path.exists():
        # No manifest means we cannot derive an instant; fall back to
        # wall-clock for the structural-error stub only. The assessment
        # short-circuits below.
        if evaluation_instant is None:
            evaluation_instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        assessment = _pin_identity(AssessmentBundle(evaluation_instant=evaluation_instant))
        assessment.structural_errors.append(ValidationDiagnostic("ACEF-002", "acef-manifest.json not found").to_dict())
        return assessment

    try:
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        # A malformed manifest must produce a structured diagnostic, not
        # crash the validator before any other phase runs.
        if evaluation_instant is None:
            evaluation_instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        assessment = _pin_identity(AssessmentBundle(evaluation_instant=evaluation_instant))
        assessment.structural_errors.append(
            ValidationDiagnostic(
                "ACEF-050",
                f"acef-manifest.json is not valid JSON: {exc}",
                path="/acef-manifest.json",
            ).to_dict()
        )
        return assessment
    if not isinstance(manifest_data, dict):
        if evaluation_instant is None:
            evaluation_instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        assessment = _pin_identity(AssessmentBundle(evaluation_instant=evaluation_instant))
        assessment.structural_errors.append(
            ValidationDiagnostic(
                "ACEF-002",
                "acef-manifest.json must be a JSON object",
                path="/acef-manifest.json",
            ).to_dict()
        )
        return assessment

    if evaluation_instant is None:
        # Defensively look up metadata: a manifest that survives the
        # top-level dict check above may still have non-dict
        # metadata/versioning sections (those are checked by schema
        # validation in Phase 1 but Phase 0 must not crash on them).
        _metadata = manifest_data.get("metadata")
        manifest_ts = _metadata.get("timestamp") if isinstance(_metadata, dict) else None
        # ``metadata.timestamp`` is untrusted external JSON and may be a
        # non-string (list/dict/int/bool) even when ``metadata`` is a dict.
        # It must NOT flow into ``AssessmentBundle.evaluation_instant`` (a
        # Pydantic ``str`` field) or the rule-engine timestamp parser, both of
        # which would raise on a non-string. Only accept a real string; the
        # Phase-1 manifest schema emits the wrong-type diagnostic, and the
        # wall-clock fallback below keeps Phase 0 non-crashing.
        if isinstance(manifest_ts, str) and manifest_ts:
            evaluation_instant = manifest_ts
        else:
            # Last resort — should be unreachable for spec-valid bundles
            # because metadata.timestamp is required at the schema level.
            evaluation_instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ACEF-001: Check module version compatibility. Use defensive type
    # coercion so a schema-invalid manifest (e.g. "versioning":[]) does
    # not crash before Phase 1 schema validation can emit diagnostics.
    versioning = manifest_data.get("versioning")
    if not isinstance(versioning, dict):
        versioning = {}
    core_version = versioning.get("core_version", "1.0.0")
    if not isinstance(core_version, str):
        # Schema validation in Phase 1 will diagnose the type error; we
        # just need to keep Phase 0 from crashing.
        core_version = "1.0.0"

    # Resolve schema-version token from core_version. This routes Phase 1
    # schema validation to v1/ for 1.0.x bundles and v1.1/ for 1.1.x
    # bundles (with v1.1 → v1 fallback for record types unchanged in
    # the v1.1 minor release). See VAL-VALIDATION-001/002.
    try:
        schema_version = schema_version_for_core_version(core_version)
    except ACEFSchemaError as exc:
        assessment = _pin_identity(AssessmentBundle(evaluation_instant=evaluation_instant))
        assessment.structural_errors.append(
            ValidationDiagnostic(
                exc.code,
                exc.message,
            ).to_dict()
        )
        return assessment

    try:
        core_major = int(core_version.split(".")[0])
        if core_major != 1:
            assessment = _pin_identity(AssessmentBundle(evaluation_instant=evaluation_instant))
            assessment.structural_errors.append(
                ValidationDiagnostic(
                    "ACEF-001",
                    f"Incompatible core_version: {core_version!r} (validator supports 1.x only)",
                ).to_dict()
            )
            return assessment
    except (ValueError, IndexError):
        pass  # Malformed version — schema validation will catch it

    # ---------------------------------------------------------------- #
    # UNTRUSTED-INPUT BOUNDARY (last-resort defensive backstop).
    #
    # Everything below this point is the phase orchestration that walks
    # arbitrary, attacker-controlled on-disk JSON/JSONL. The per-field guards
    # throughout this module (and ``_run_validation_phases``) handle the KNOWN
    # crash sites with PRECISE typed diagnostics — that is the primary
    # mechanism and the common path. This try/except is the LAST RESORT only:
    # if some not-yet-guarded deep path raises an UNEXPECTED exception, we
    # convert it into a FATAL ACEF-001 structural diagnostic (carrying the
    # exception type + message so the failure is SURFACED, never hidden) and
    # return the diagnostics collected so far. This guarantees
    # ``validate_bundle`` NEVER crashes on untrusted input.
    #
    # Scope discipline (so this does NOT hide real bugs on well-formed input):
    #   * We catch ``Exception`` (NOT ``BaseException``) — KeyboardInterrupt /
    #     SystemExit still propagate.
    #   * The wrapper is at the OUTERMOST phase-orchestration level ONLY; it is
    #     not sprinkled around individual statements.
    #   * Well-formed bundles never raise here, so the backstop never fires for
    #     them — the unchanged full test suite proves the happy path is intact.
    #
    # The shared ``assessment`` is created up-front so partial diagnostics
    # gathered before any failure are preserved alongside the fatal one.
    package_id, package_timestamp = _resolve_package_scalars(manifest_data)
    assessment = _pin_identity(
        AssessmentBundle(
            evaluation_instant=evaluation_instant,
            assessor=Assessor(name="acef-validator", version="0.1.0", organization="AI Commons"),
            evidence_bundle_ref=EvidenceBundleRef(package_id=package_id),
        )
    )
    try:
        _run_validation_phases(
            assessment,
            bundle_path,
            manifest_data,
            schema_version=schema_version,
            evaluation_instant=evaluation_instant,
            package_timestamp=package_timestamp,
            profiles=profiles,
            trust_anchors=trust_anchors,
        )
    except Exception as exc:  # noqa: BLE001 — deliberate untrusted-input backstop
        # A not-yet-guarded path raised. Surface it as a FATAL structural
        # error (ACEF-001 = package structurally invalid / cannot complete
        # validation) including the concrete exception type and message, then
        # return everything collected so far. Never swallow silently.
        assessment.structural_errors.append(
            ValidationDiagnostic(
                "ACEF-001",
                "Validation could not be completed: an unexpected "
                f"{type(exc).__name__} was raised while processing this "
                f"(structurally invalid) bundle: {exc}",
            ).to_dict()
        )
    return assessment


def _resolve_package_scalars(manifest_data: dict[str, Any]) -> tuple[str, str]:
    """Extract ``metadata.package_id`` / ``metadata.timestamp`` as guaranteed
    strings from untrusted manifest JSON.

    ``metadata`` may be a non-dict, and even when it is a dict the scalar
    values may be wrong-typed (list / dict / int / bool). ``package_id`` flows
    into the Pydantic ``EvidenceBundleRef`` (str) field and ``timestamp`` flows
    into the rule-engine date parser — both raise on a non-string. Coerce any
    non-string to ``""`` so a malformed scalar never reaches a string sink; the
    Phase-1 manifest schema emits the wrong-type diagnostic.
    """
    _metadata_section = manifest_data.get("metadata")
    if not isinstance(_metadata_section, dict):
        _metadata_section = {}
    package_id = _metadata_section.get("package_id", "")
    if not isinstance(package_id, str):
        package_id = ""
    package_timestamp = _metadata_section.get("timestamp", "")
    if not isinstance(package_timestamp, str):
        package_timestamp = ""
    return package_id, package_timestamp


def _run_validation_phases(
    assessment: AssessmentBundle,
    bundle_path: Path,
    manifest_data: dict[str, Any],
    *,
    schema_version: str,
    evaluation_instant: str,
    package_timestamp: str,
    profiles: list[str] | None,
    trust_anchors: list[Certificate] | None = None,
) -> None:
    """Run validation Phases 1–4, appending diagnostics into ``assessment``.

    This is the inner phase orchestration. It is intentionally invoked inside
    the untrusted-input try/except in :func:`validate_bundle`: per-field guards
    here handle the common malformed cases with precise diagnostics, and the
    caller's backstop catches any not-yet-guarded path so the public entrypoint
    never crashes. ``assessment`` is mutated in place so that partial
    diagnostics survive even if a later phase raises.
    """
    # Load all records from JSONL files. Wrap each parse / model
    # conversion so a single malformed line surfaces as ACEF-050 / ACEF-004
    # rather than crashing the validator before Phase 1 diagnostics are
    # collected.
    from acef.errors import ACEFFormatError as _ACEFFormatErr

    all_records_data: list[dict[str, Any]] = []
    all_records: list[RecordEnvelope] = []
    record_file_type_mismatches: list[ValidationDiagnostic] = []
    early_load_diagnostics: list[ValidationDiagnostic] = []
    _record_files = manifest_data.get("record_files", [])
    if not isinstance(_record_files, list):
        _record_files = []
    for rf in _record_files:
        if not isinstance(rf, dict):
            continue
        rf_path_str = rf.get("path", "")
        if not rf_path_str:
            continue
        # Validate path for safety before constructing a filesystem path.
        # This prevents path traversal attacks via malicious manifest entries
        # (e.g., "../../etc/passwd") that would be read before Phase 3
        # reference checking runs.
        if not _validate_record_file_path(rf_path_str):
            continue
        declared_type = rf.get("record_type", "")
        rf_path = bundle_path / rf_path_str
        if rf_path.exists():
            try:
                with open(rf_path, encoding="utf-8") as _record_file:
                    file_lines = _record_file.readlines()
            except (OSError, UnicodeDecodeError) as exc:
                early_load_diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-050",
                        f"Cannot read record file {rf_path_str}: {exc}",
                        path=f"/{rf_path_str}",
                    )
                )
                continue
            for line_number, line in enumerate(file_lines, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    rec_data = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    early_load_diagnostics.append(
                        ValidationDiagnostic(
                            "ACEF-050",
                            f"Malformed JSONL at {rf_path_str}:{line_number}: {exc}",
                            path=f"/{rf_path_str}",
                        )
                    )
                    continue
                # JSONL lines must be JSON objects — null, arrays, strings,
                # and numbers are well-formed JSON but cannot be records.
                if not isinstance(rec_data, dict):
                    early_load_diagnostics.append(
                        ValidationDiagnostic(
                            "ACEF-050",
                            f"JSONL line at {rf_path_str}:{line_number} is not a JSON object "
                            f"(got {type(rec_data).__name__})",
                            path=f"/{rf_path_str}",
                        )
                    )
                    continue
                # Cross-check: every record's record_type must match
                # the manifest's declared record_type for the file
                # it appears in. A malicious bundle could otherwise
                # place mismatched records in a file labeled with a
                # benign type to bypass downstream type-based
                # filtering (structural review finding).
                actual_type = rec_data.get("record_type", "")
                if declared_type and actual_type and actual_type != declared_type:
                    record_file_type_mismatches.append(
                        ValidationDiagnostic(
                            "ACEF-025",
                            f"Record type mismatch in {rf_path_str}:{line_number}: "
                            f"file declares {declared_type!r} but record has "
                            f"{actual_type!r}",
                            path=f"/{rf_path_str}",
                        )
                    )
                all_records_data.append(rec_data)
                try:
                    all_records.append(dict_to_record_envelope(rec_data))
                except _ACEFFormatErr as exc:
                    early_load_diagnostics.append(
                        ValidationDiagnostic(
                            "ACEF-004",
                            f"Cannot construct RecordEnvelope from {rf_path_str}:{line_number}: {exc}",
                            path=f"/{rf_path_str}",
                        )
                    )
                except Exception as exc:
                    # Catch raw Pydantic ValidationError or any other
                    # construction failure that escapes the
                    # ACEFFormatError wrapper. The validator must continue
                    # collecting diagnostics, not crash on a single bad
                    # line.
                    early_load_diagnostics.append(
                        ValidationDiagnostic(
                            "ACEF-004",
                            f"Cannot construct RecordEnvelope from {rf_path_str}:{line_number}: {exc}",
                            path=f"/{rf_path_str}",
                        )
                    )

    # ``assessment`` (with its EvidenceBundleRef.package_id) and the
    # ``package_timestamp`` scalar are resolved by the caller via
    # ``_resolve_package_scalars`` and passed in — they are guaranteed strings,
    # so no wrong-typed metadata scalar reaches a Pydantic/timestamp sink here.
    #
    # Diagnostics are flushed into ``assessment.structural_errors`` INCREMENTALLY
    # as each phase completes (not buffered in a local until the end). This is
    # load-bearing: if a LATER phase (e.g. ``check_references`` or a v1.1 rule
    # family) raises, the caller's untrusted-input backstop must still return
    # every diagnostic collected UP TO the failure point — not drop them. Each
    # diagnostic reaches ``assessment.structural_errors`` exactly once, so the
    # success path produces no duplicates.
    def _flush(diagnostics: list[ValidationDiagnostic]) -> None:
        for diag in diagnostics:
            assessment.structural_errors.append(diag.to_dict())

    # Phase 1: Schema validation — route to v1/ or v1.1/ schemas based on
    # the bundle's declared core_version (resolved above into
    # ``schema_version``). v1.1 falls back to v1 for record types unchanged
    # in the minor release; v1 has no fallback so v1.1-only record types
    # in a v1.0-declared bundle correctly emit ACEF-003.
    schema_diagnostics = validate_manifest_schema(manifest_data, schema_version)
    schema_diagnostics.extend(validate_record_schemas(all_records_data, schema_version))
    _flush(schema_diagnostics)

    # Surface record-file type-mismatch and early-load diagnostics gathered
    # during JSONL parse.
    _flush(record_file_type_mismatches)
    _flush(early_load_diagnostics)

    # Phase 2: Integrity verification. ``trust_anchors`` (None by default —
    # self-attested trust per spec §3.1.3) flows from validate_bundle into
    # the signature checks so x5c chains can be anchored to locally
    # configured roots (VAL-FIX-LOADER-005).
    integrity_diagnostics = check_integrity(bundle_path, trust_anchors=trust_anchors)
    _flush(integrity_diagnostics)

    # Phase 3: Reference checking
    reference_diagnostics = check_references(manifest_data, all_records_data, bundle_path)
    _flush(reference_diagnostics)

    # Phase 3b: Cross-record validation (v1.1 only)
    # Gated on schema_version so v1.0 bundles are byte-equivalent to pre-v0.4
    # validator behavior (VAL-REGRESSION-001).  Reads verified-signature
    # count from get_signature_info for the causation_chain check, under the
    # SAME trust_anchors configuration as the Phase-2 integrity check — a
    # signature Phase 2 rejected (ACEF-012, unanchored x5c) must not vouch
    # for causation chains here (cross-phase consistency).
    if schema_version == "v1.1":
        # Importing the bundled_freddy submodule auto-registers the
        # ``x-freddy/voice-rubric-emission`` lint pattern (WS3.10 /
        # VAL-VALIDATION-012). Done at first v1.1 dispatch so v1.0
        # validation paths remain byte-equivalent to pre-v0.4 behavior.
        import acef.validation.namespace_lints.bundled_freddy  # noqa: F401
        from acef.validation.cross_record import run_cross_record_validation
        from acef.validation.incident_rules import run_incident_rules
        from acef.validation.namespace_lints import run_namespace_lints
        from acef.validation.v1_1_rules import run_v1_1_rules

        _xr_sig_count, _ = get_signature_info(bundle_path, trust_anchors=trust_anchors)
        cross_record_diagnostics = run_cross_record_validation(
            manifest_data,
            all_records_data,
            signature_count=_xr_sig_count,
        )
        _flush(cross_record_diagnostics)

        # Phase 3c: v1.1 rule families (banned claim-language lint,
        # state-class taxonomy enforcement, mode-gated forbidden record
        # types). Per VAL-VALIDATION-008/009/010. The banned-language
        # lint operates on an Assessment Bundle if one is provided
        # sibling-to-bundle (golden-bundle convention:
        # ``<bundle_dir>.acef-assessment.json``) or in-bundle
        # (``<bundle_dir>/acef-assessment.json``); record-scoped rules
        # always run.
        _assessment_data: dict[str, Any] | None = None
        for _ab_candidate in (
            bundle_path.parent / f"{bundle_path.name}.acef-assessment.json",
            bundle_path / "acef-assessment.json",
        ):
            if _ab_candidate.is_file():
                try:
                    _parsed = json.loads(_ab_candidate.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                    _parsed = None
                if isinstance(_parsed, dict):
                    _assessment_data = _parsed
                    break
        v1_1_rule_diagnostics = run_v1_1_rules(
            manifest_data,
            all_records_data,
            assessment_bundle=_assessment_data,
        )
        _flush(v1_1_rule_diagnostics)

        # Phase 3c-bis: RFC-0002 offline incident rules (ACEF-081..088). Runs
        # ONLY on the v1.1 path (this block is gated on schema_version ==
        # "v1.1"), so a v1.0 bundle never sees them — incident validation is
        # byte-equivalent-absent for v1.0 (VAL-VLD-001). The version-gated
        # offline rules cover: version-gating, the Art.73 shortest-clock check +
        # ACEF-084 (existential dual-source + regulatory_timeline framework-match,
        # the ART73-DELEGATED list; VAL-CLOCK-001), the §5.11 publishability gate
        # (VAL-PUB-001 / ACEF-086), the offline public_incident_id id-trust check
        # (ACEF-083, NO attribution — a forged self-consistent card passes
        # offline by design; attribution is F-M3-DOMAIN-CONTROL's OPTIONAL online
        # verifier, a separate module), and ACEF-081/082/085/087/088.
        # Thread the caller-requested ``profiles`` (validate_bundle argument / CLI
        # ``--profile``) into the incident rules so the profile-conditional Art.73
        # (ACEF-084) and mandatory-crosswalk (ACEF-081) checks evaluate against the
        # UNION of requested + manifest-declared profile ids. Without this, a bundle
        # validated against ``eu-ai-act-art73-2026`` by argument — but not
        # self-declaring it in ``manifest.profiles`` — would bypass the delegated
        # ACEF-084 checks (the generic template DSL cannot express them).
        # Thread the bundle's ``metadata.timestamp`` (``package_timestamp``,
        # resolved by the caller) into the incident rules so the ACEF-083 JWS
        # self-consistency sub-check (§5.3(ii) / VAL-FIX-INCVAL-001) can anchor x5c
        # certificate-validity to the manifest timestamp, NOT wall-clock (spec
        # §3.1.3 reproducible verification). The signature material itself (the
        # per-record ``attestation`` JWS block) already travels in
        # ``all_records_data``; only the timestamp anchor needs threading, so this
        # does not refactor the integrity phase.
        incident_rule_diagnostics = run_incident_rules(
            manifest_data,
            all_records_data,
            requested_profiles=profiles,
            # An empty string (MISSING/malformed metadata.timestamp, coerced by
            # _resolve_package_scalars) maps to None — the signing layer's
            # skip-if-not-provided semantics — instead of failing every x5c
            # attestation on a timestamp parse error (a SPURIOUS ACEF-083).
            # Mirrors the sibling rule_engine.py record_attested path.
            manifest_timestamp=package_timestamp or None,
        )
        _flush(incident_rule_diagnostics)

        # Phase 3d: Vendor-namespace lint hooks (WS3.10 /
        # F-M1-NAMESPACE-LINT-HOOK). Registered patterns under
        # ``x-<vendor>/*`` namespaces emit Core error codes (notably
        # ACEF-077 for x-freddy/voice-rubric-emission). Unregistered
        # namespaces are a silent no-op (VAL-VALIDATION-013); the
        # bundled_freddy submodule imported above auto-registers the
        # default x-freddy pattern. Per VAL-VALIDATION-LINT-INVOCATION-001
        # this runs BEFORE structural_errors is finalized so the lint
        # blocks otherwise-success acceptance.
        namespace_lint_diagnostics = run_namespace_lints(
            manifest_data,
            all_records_data,
        )
        _flush(namespace_lint_diagnostics)

    # All pre-profile structural diagnostics have already been flushed into
    # ``assessment.structural_errors`` incrementally (above) so they survive a
    # late-phase crash via the caller's backstop. No final buffer flush remains.

    # Phase 4: Rule evaluation (only if profiles specified)
    # Note: spec S3.6 says "Validators MUST report ALL errors encountered within
    # each validation phase" — so we continue even if earlier phases had fatal errors,
    # to give complete diagnostic output.
    if profiles:
        _evaluate_profiles(
            assessment,
            manifest_data,
            all_records,
            profiles,
            evaluation_instant=evaluation_instant,
            package_timestamp=package_timestamp,
            bundle_dir=bundle_path,
            trust_anchors=trust_anchors,
        )

    # Compute bundle digest for evidence_bundle_ref
    content_hashes_path = bundle_path / "hashes" / "content-hashes.json"
    if content_hashes_path.exists():
        import rfc8785

        from acef.integrity import ACEFCanonicalizationError, compute_bundle_digest

        try:
            content_hashes = json.loads(content_hashes_path.read_text(encoding="utf-8"))
            # Only a well-formed dict[str, str] is a computable bundle digest.
            #
            # ``compute_bundle_digest`` RFC-8785-canonicalizes the JSON-decoded
            # content-hashes.json. ``json.loads`` accepts tokens that RFC 8785
            # REJECTS (a bare/NaN/Infinity number, an out-of-range integer) and
            # shapes (a list value) that canonicalize to a digest unrelated to a
            # real content-hashes mapping. A non-string value is ALWAYS a
            # structural error already reported upstream as ACEF-014 by the
            # integrity checker (and a list value would otherwise yield a
            # meaningless digest). So we treat anything that is not dict[str, str]
            # as having an uncomputable digest: leave ``content_hash`` unset
            # (``EvidenceBundleRef.content_hash`` defaults to "") and skip the
            # computation rather than duplicate the structural diagnostic as an
            # ACEF-001 backstop or emit a digest over malformed input.
            if _content_hashes_is_str_mapping(content_hashes):
                assessment.evidence_bundle_ref.content_hash = compute_bundle_digest(content_hashes)
        except (
            rfc8785.CanonicalizationError,
            UnicodeEncodeError,
            ACEFCanonicalizationError,
            json.JSONDecodeError,
            UnicodeDecodeError,
            OSError,
        ):
            # Belt-and-suspenders catch for ANY canonicalization fault that
            # survives the dict[str, str] pre-check above. ``compute_bundle_digest``
            # RFC-8785-canonicalizes the SAME content-hashes.json that the Phase-2
            # integrity check already flagged. A surrogate / non-NFC key (a valid
            # ``str`` value that PASSES the dict[str, str] check, yet is NFC-equal
            # and not UTF-8-encodable) makes ``rfc8785.dumps`` raise
            # ``UnicodeEncodeError``; the hash domain's own canonicalization faults
            # surface as ``ACEFCanonicalizationError``; and any other RFC 8785
            # domain violation surfaces as the BASE
            # ``rfc8785.CanonicalizationError`` (e.g. ``FloatDomainError`` /
            # ``IntegerDomainError`` for numeric values that slipped past the
            # str-value guard). The read-side ``json``/``Unicode``/``OS`` errors
            # are kept for completeness. All are caught so the digest is simply
            # left unset; the authoritative structural diagnostic (ACEF-014 /
            # ACEF-051) was already emitted upstream by the integrity checker, and
            # this site must NOT let the fault escape into validate_bundle()'s
            # generic ACEF-001 untrusted-input backstop.
            pass

    # ``assessment`` was mutated in place; the caller (validate_bundle) owns it
    # and returns it (wrapped by the untrusted-input backstop).
    return


def _collect_results(
    assessment: AssessmentBundle,
    results: list[RuleResult],
    profile_id: str,
    records: list[RecordEnvelope],
    *,
    subject_scope: list[str] | None = None,
) -> None:
    """Collect rule results and compute provision summaries.

    Provision IDs are iterated in sorted order so that the produced
    ``assessment.provision_summary`` list is deterministic across runs
    regardless of Python's hash randomization. Without sorting,
    ``set`` iteration would order entries by PYTHONHASHSEED-salted hashes,
    producing byte-different Assessment Bundles for the same input —
    violating the spec §3.7 reproducibility contract.
    """
    assessment.results.extend(results)
    seen_provisions: set[str] = set()
    for r in results:
        seen_provisions.add(r.provision_id)
    for prov_id in sorted(seen_provisions):
        prov_results = [r for r in results if r.provision_id == prov_id]
        summary = compute_provision_outcome(
            prov_id,
            profile_id,
            prov_results,
            records,
            subject_scope=subject_scope or [],
        )
        assessment.provision_summary.append(summary)

        # ACEF-053: emit info diagnostic if any rule result for this
        # provision came from a vendor-namespaced (x-*) rule_id or
        # operator. Per spec §3.5 + §3.7 such rules MUST NOT affect
        # provision_outcome, so the rollup excludes them; surface their
        # presence so producers know their extension rules ran but did
        # not influence the assessment.
        x_rules = [r for r in prov_results if r.rule_id.startswith("x-")]
        if x_rules:
            assessment.structural_errors.append(
                ValidationDiagnostic(
                    "ACEF-053",
                    f"Provision {prov_id} has {len(x_rules)} vendor-extension "
                    f"rule(s) (x-*) whose outcomes were excluded from rollup "
                    f"per spec §3.7. Rule IDs: "
                    f"{', '.join(r.rule_id for r in x_rules)}",
                ).to_dict()
            )

        # ACEF-042: emit info diagnostic when a provision rolls up to
        # GAP_ACKNOWLEDGED so consumers can see at-a-glance which
        # provisions are passing only because an evidence_gap record
        # acknowledges the missing evidence (spec §3.7 step 4).
        from acef.models.enums import ProvisionOutcome

        if summary.provision_outcome == ProvisionOutcome.GAP_ACKNOWLEDGED:
            assessment.structural_errors.append(
                ValidationDiagnostic(
                    "ACEF-042",
                    f"evidence_gap acknowledged for provision {prov_id} in profile {profile_id}",
                ).to_dict()
            )

        # ACEF-041: emit warning diagnostic when an evidence_freshness
        # rule (severity=warning) failed for this provision. Spec §3.6
        # ACEF-041 is the canonical code for stale evidence.
        from acef.models.enums import RuleOutcome, RuleSeverity

        for r in prov_results:
            if (
                r.outcome == RuleOutcome.FAILED
                and r.rule_severity == RuleSeverity.WARNING
                and "freshness" in (r.rule_id or "").lower()
            ):
                assessment.structural_errors.append(
                    ValidationDiagnostic(
                        "ACEF-041",
                        f"Evidence freshness exceeded for rule {r.rule_id}: {r.message or ''}",
                    ).to_dict()
                )

        # ACEF-040 ("Required evidence type missing") is NOT emitted as a separate
        # structural diagnostic here, by design (audit finding F38). Unlike its
        # siblings — ACEF-041 (freshness, WARNING) and ACEF-042 (gap, INFO), which
        # surface NON-GATING conditions — ACEF-040 is the GATING condition: a
        # missing required evidence type is realized as a FAILED fail-severity
        # required-evidence rule (the auto-generated ``{provision}-{type}-exists``
        # rule, rule_engine.py) which rolls the provision up to NOT_SATISFIED
        # (rollup step 1). Emitting an additional ERROR structural diagnostic would
        # (a) duplicate the NOT_SATISFIED verdict and (b) wrongly escalate a
        # voluntary/advisory provision's missing evidence to a blocking ERROR — a
        # voluntary filing legitimately rolls up NOT_SATISFIED without ERROR
        # diagnostics. The spec §3.6 + USER_GUIDE document this realization.


def _parse_iso_instant(value: str) -> datetime | None:
    """Parse an ISO 8601 timestamp or date into a UTC datetime.

    Accepts both ``"YYYY-MM-DDTHH:MM:SSZ"`` (Zulu) and
    ``"YYYY-MM-DDTHH:MM:SS+00:00"`` forms, and bare ``"YYYY-MM-DD"`` dates
    (which become midnight UTC of that day). Returns ``None`` on parse
    failure so callers can decide how to react.

    Note: lexicographic comparison of mixed-format ISO strings is unsafe
    (``"2026-01-01T00:00:00Z" > "2026-01-01"``), so date / instant
    comparisons MUST go through this helper before comparing.
    """
    if not value:
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _is_before(a: str, b: str) -> bool:
    """Return True iff timestamp ``a`` is strictly before ``b``.

    Parses both via :func:`_parse_iso_instant`. If either side fails to
    parse, falls back to lexicographic comparison (preserves the legacy
    behavior so producers with malformed dates still get a deterministic
    answer rather than a crash).
    """
    pa = _parse_iso_instant(a)
    pb = _parse_iso_instant(b)
    if pa is None or pb is None:
        return a < b
    return pa < pb


def _evaluate_profiles(
    assessment: AssessmentBundle,
    manifest_data: dict[str, Any],
    records: list[RecordEnvelope],
    profile_ids: list[str],
    *,
    evaluation_instant: str,
    package_timestamp: str,
    bundle_dir: Path,
    trust_anchors: list[Certificate] | None = None,
) -> None:
    """Evaluate template rules for all specified profiles.

    ``trust_anchors`` is the SAME trust configuration the Phase-2
    integrity check ran under; the verified-signature count feeding
    ``bundle_signed`` rules must agree with Phase 2's verdict (an
    unanchored x5c signature rejected there with ACEF-012 must not
    satisfy ``bundle_signed`` here). Default ``None`` preserves the
    historical self-attested behavior exactly.
    """
    # ``subjects`` is untrusted external JSON; coerce a non-list to an empty
    # list so the per-subject loop below cannot crash on iteration.
    subjects = manifest_data.get("subjects")
    if not isinstance(subjects, list):
        subjects = []
    sig_count, sig_algs = get_signature_info(bundle_dir, trust_anchors=trust_anchors)

    for profile_id in profile_ids:
        try:
            template = load_template(profile_id)
        except ACEFError:
            assessment.structural_errors.append(
                ValidationDiagnostic(
                    "ACEF-030",
                    f"Template not found: {profile_id!r}",
                ).to_dict()
            )
            continue

        # ACEF-031: Manifest declares a template_version for this profile
        # that disagrees with the template loaded from the registry.
        # ACEF-033: Module compatibility — spec §6.2 requires Core and
        # Profiles within the same major version.
        # ``profiles`` and its entries are untrusted external JSON; coerce a
        # non-list section to empty and skip non-dict declarations so the
        # ``_decl.get(...)`` lookup below cannot crash.
        _profiles_decls = manifest_data.get("profiles")
        if not isinstance(_profiles_decls, list):
            _profiles_decls = []
        manifest_profile_decl: dict[str, Any] | None = None
        for _decl in _profiles_decls:
            if not isinstance(_decl, dict):
                continue
            if _decl.get("profile_id") == profile_id:
                manifest_profile_decl = _decl
                break

        declared_template_version = manifest_profile_decl.get("template_version") if manifest_profile_decl else None
        if declared_template_version and declared_template_version != template.version:
            assessment.structural_errors.append(
                ValidationDiagnostic(
                    "ACEF-031",
                    f"Template version mismatch for {profile_id!r}: manifest "
                    f"declares {declared_template_version!r} but registry has "
                    f"{template.version!r}",
                ).to_dict()
            )

        # Core/Profiles compatibility: both must share major version per §6.2.
        try:
            _versioning = manifest_data.get("versioning")
            if not isinstance(_versioning, dict):
                _versioning = {}
            _core_v = _versioning.get("core_version", "")
            _profiles_v = _versioning.get("profiles_version", "")
            if _core_v and _profiles_v:
                core_major_v = int(_core_v.split(".")[0])
                profiles_major_v = int(_profiles_v.split(".")[0])
                if core_major_v != profiles_major_v:
                    assessment.structural_errors.append(
                        ValidationDiagnostic(
                            "ACEF-033",
                            f"Incompatible module versions: core_version={_core_v!r} "
                            f"profiles_version={_profiles_v!r} (major versions must match per §6.2)",
                        ).to_dict()
                    )
        except (ValueError, IndexError):
            pass

        # ACEF-044: Check for duplicate rule_ids within the template
        seen_rule_ids: set[str] = set()
        for provision in template.provisions:
            for rule in provision.evaluation:
                if rule.rule_id in seen_rule_ids:
                    assessment.structural_errors.append(
                        ValidationDiagnostic(
                            "ACEF-044",
                            f"Duplicate rule_id in template {profile_id}: {rule.rule_id!r}",
                        ).to_dict()
                    )
                seen_rule_ids.add(rule.rule_id)

        # Record template digest
        try:
            digest = compute_template_digest(profile_id)
            assessment.template_digests[f"{profile_id}:{template.version}"] = digest
        except Exception:
            pass

        assessment.profiles_evaluated.append(f"{profile_id}:{template.version}")

        # Determine applicable provisions from the manifest's profile
        # declaration. Reuse the coerced ``_profiles_decls`` list (non-list
        # already normalized to empty) and skip non-dict entries so a
        # malformed manifest cannot crash this lookup.
        applicable_provisions = None
        for prof in _profiles_decls:
            if not isinstance(prof, dict):
                continue
            if prof.get("profile_id") == profile_id:
                _ap = prof.get("applicable_provisions", [])
                applicable_provisions = _ap if isinstance(_ap, list) else []
                break

        # Filter template provisions to those declared applicable
        provisions_to_evaluate = template.provisions
        if applicable_provisions:
            provisions_to_evaluate = [
                p
                for p in template.provisions
                if p.provision_id in applicable_provisions
                or any(
                    ap.startswith(p.provision_id + ".") or ap.startswith(p.provision_id + "-")
                    for ap in applicable_provisions
                )
            ]

        # ACEF-032: Emit info diagnostic AND mark provisions not-yet-effective.
        # Per spec §3.6 the rules for these provisions MUST produce a
        # ``skipped`` outcome rather than being evaluated normally — a
        # provision that is not yet legally in force cannot fail.
        not_yet_effective: set[str] = set()
        for prov in provisions_to_evaluate:
            if prov.effective_date and evaluation_instant:
                if _is_before(evaluation_instant, prov.effective_date):
                    not_yet_effective.add(prov.provision_id)
                    assessment.structural_errors.append(
                        ValidationDiagnostic(
                            "ACEF-032",
                            f"Provision {prov.provision_id} not yet effective "
                            f"(effective: {prov.effective_date}, "
                            f"evaluation: {evaluation_instant})",
                        ).to_dict()
                    )

        # Synthesize SKIPPED results for not-yet-effective provisions so the
        # roll-up algorithm reports ``skipped`` for them (spec §3.7 step 3).
        #
        # The synthesis MUST mirror the package/per-subject split used for
        # effective provisions (assessment-rollup-2): a not-yet-effective
        # PER-SUBJECT provision in a multi-subject bundle must produce one SKIPPED
        # summary PER SUBJECT, each carrying that subject's ``subject_scope`` —
        # NOT a single package-scoped summary with empty ``subject_scope`` (which
        # violates the §3.7 MUST that per-subject ``provision_summary`` entries
        # identify their subject(s)). Package-scoped not-yet-effective provisions
        # still produce one summary with empty ``subject_scope``.
        if not_yet_effective:
            from acef.models.assessment import RuleResult
            from acef.models.enums import RuleOutcome, RuleSeverity

            def _synthesize_skipped(prov: Any, scope: list[str]) -> list[RuleResult]:
                """One SKIPPED RuleResult per rule for a not-yet-effective provision."""
                return [
                    RuleResult(
                        rule_id=rule.rule_id,
                        provision_id=prov.provision_id,
                        profile_id=profile_id,
                        rule_severity=RuleSeverity(rule.severity),
                        outcome=RuleOutcome.SKIPPED,
                        message=(
                            f"Provision not yet effective "
                            f"(effective_date={prov.effective_date}, "
                            f"evaluation_instant={evaluation_instant})"
                        ),
                        evidence_refs=[],
                        subject_scope=list(scope),
                    )
                    for rule in prov.evaluation
                ]

            nye_provisions = [p for p in provisions_to_evaluate if p.provision_id in not_yet_effective]
            nye_package = [p for p in nye_provisions if p.evaluation_scope == "package"]
            nye_per_subject = [p for p in nye_provisions if p.evaluation_scope != "package"]

            # Package-scoped not-yet-effective: one summary, empty subject_scope.
            for prov in nye_package:
                skipped_results = _synthesize_skipped(prov, [])
                if skipped_results:
                    _collect_results(assessment, skipped_results, profile_id, records)

            # Per-subject not-yet-effective: one summary PER applicable subject,
            # each scoped to that subject (mirrors the effective per-subject
            # split, honoring ``applicable_to`` so a non-applicable subject yields
            # no summary — consistent with effective evaluation). With no subjects
            # declared, evaluate at package level (empty scope), matching the
            # ``elif per_subject`` effective fallback.
            if nye_per_subject:
                concrete_subjects = [s for s in subjects if isinstance(s, dict)]
                if concrete_subjects:
                    for subject in concrete_subjects:
                        subject_id = subject.get("subject_id", "")
                        risk_class = subject.get("risk_classification", "")
                        for prov in nye_per_subject:
                            if prov.applicable_to and risk_class and risk_class not in prov.applicable_to:
                                continue
                            skipped_results = _synthesize_skipped(prov, [subject_id])
                            if skipped_results:
                                _collect_results(
                                    assessment,
                                    skipped_results,
                                    profile_id,
                                    records,
                                    subject_scope=[subject_id],
                                )
                else:
                    for prov in nye_per_subject:
                        skipped_results = _synthesize_skipped(prov, [])
                        if skipped_results:
                            _collect_results(assessment, skipped_results, profile_id, records)

        # Exclude not-yet-effective provisions from further evaluation.
        provisions_to_evaluate = [p for p in provisions_to_evaluate if p.provision_id not in not_yet_effective]

        # Split provisions into package-scoped and per-subject (default)
        package_scoped = [p for p in provisions_to_evaluate if p.evaluation_scope == "package"]
        per_subject = [p for p in provisions_to_evaluate if p.evaluation_scope != "package"]

        # Evaluate package-scoped provisions ONCE (no subject filter)
        if package_scoped:
            pkg_results = evaluate_rules_for_subject(
                package_scoped,
                records,
                profile_id=profile_id,
                evaluation_instant=evaluation_instant,
                package_timestamp=package_timestamp,
                signature_count=sig_count,
                signature_algorithms=sig_algs,
            )
            _collect_results(assessment, pkg_results, profile_id, records)

        # Evaluate per-subject provisions. Entries in ``subjects`` are
        # untrusted external JSON; skip any non-dict subject so the
        # ``subject.get(...)`` lookups cannot crash. ``modalities`` may also be
        # a non-list, so coerce it for the downstream scope filter.
        if subjects and per_subject:
            for subject in subjects:
                if not isinstance(subject, dict):
                    continue
                subject_id = subject.get("subject_id", "")
                risk_class = subject.get("risk_classification", "")
                modalities = subject.get("modalities", [])
                if not isinstance(modalities, list):
                    modalities = []

                results = evaluate_rules_for_subject(
                    per_subject,
                    records,
                    subject_id=subject_id,
                    subject_risk_classification=risk_class,
                    subject_modalities=modalities,
                    profile_id=profile_id,
                    evaluation_instant=evaluation_instant,
                    package_timestamp=package_timestamp,
                    signature_count=sig_count,
                    signature_algorithms=sig_algs,
                )
                _collect_results(
                    assessment,
                    results,
                    profile_id,
                    records,
                    subject_scope=[subject_id],
                )
        elif per_subject:
            # No subjects — evaluate at package level
            results = evaluate_rules_for_subject(
                per_subject,
                records,
                profile_id=profile_id,
                evaluation_instant=evaluation_instant,
                package_timestamp=package_timestamp,
                signature_count=sig_count,
                signature_algorithms=sig_algs,
            )
            _collect_results(assessment, results, profile_id, records)
