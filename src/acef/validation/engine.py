"""ACEF validation engine — orchestrator for the 4-phase validation pipeline.

Phase 1: Schema validation (manifest -> envelope -> payload)
Phase 2: Integrity verification (hashes -> Merkle -> signatures)
Phase 3: Reference checking (entity refs -> file paths -> duplicates)
Phase 4: Rule evaluation (DSL rules -> provision rollup)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from acef.errors import ACEFError, ValidationDiagnostic
from acef.models.assessment import (
    AssessmentBundle,
    Assessor,
    EvidenceBundleRef,
    RuleResult,
)
from acef.models.records import RecordEnvelope, dict_to_record_envelope
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


def validate_bundle(
    bundle_dir: str | Path,
    *,
    profiles: list[str] | None = None,
    evaluation_instant: str | None = None,
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
        evaluation_instant: Override evaluation timestamp (ISO 8601).

    Returns:
        An AssessmentBundle with all results.
    """
    bundle_path = Path(bundle_dir)

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
            evaluation_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        assessment = AssessmentBundle(evaluation_instant=evaluation_instant)
        assessment.structural_errors.append(
            ValidationDiagnostic("ACEF-002", "acef-manifest.json not found").to_dict()
        )
        return assessment

    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))

    if evaluation_instant is None:
        manifest_ts = manifest_data.get("metadata", {}).get("timestamp")
        if manifest_ts:
            evaluation_instant = manifest_ts
        else:
            # Last resort — should be unreachable for spec-valid bundles
            # because metadata.timestamp is required at the schema level.
            evaluation_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ACEF-001: Check module version compatibility
    versioning = manifest_data.get("versioning", {})
    core_version = versioning.get("core_version", "1.0.0")
    try:
        core_major = int(core_version.split(".")[0])
        if core_major != 1:
            assessment = AssessmentBundle(evaluation_instant=evaluation_instant)
            assessment.structural_errors.append(
                ValidationDiagnostic(
                    "ACEF-001",
                    f"Incompatible core_version: {core_version!r} (validator supports 1.x only)",
                ).to_dict()
            )
            return assessment
    except (ValueError, IndexError):
        pass  # Malformed version — schema validation will catch it

    # Load all records from JSONL files
    all_records_data: list[dict[str, Any]] = []
    all_records: list[RecordEnvelope] = []
    record_file_type_mismatches: list[ValidationDiagnostic] = []
    for rf in manifest_data.get("record_files", []):
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
            with open(rf_path, "r", encoding="utf-8") as f:
                for line_number, line in enumerate(f, start=1):
                    line = line.strip()
                    if line:
                        rec_data = json.loads(line)
                        # Cross-check: every record's record_type must match
                        # the manifest's declared record_type for the file
                        # it appears in. A malicious bundle could otherwise
                        # place mismatched records in a file labeled with a
                        # benign type to bypass downstream type-based
                        # filtering (structural review P2 finding).
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
                        all_records.append(dict_to_record_envelope(rec_data))

    # Initialize assessment
    package_id = manifest_data.get("metadata", {}).get("package_id", "")
    package_timestamp = manifest_data.get("metadata", {}).get("timestamp", "")

    assessment = AssessmentBundle(
        evaluation_instant=evaluation_instant,
        assessor=Assessor(name="acef-validator", version="0.1.0", organization="AI Commons"),
        evidence_bundle_ref=EvidenceBundleRef(package_id=package_id),
    )

    all_diagnostics: list[ValidationDiagnostic] = []

    # Phase 1: Schema validation
    schema_diagnostics = validate_manifest_schema(manifest_data)
    schema_diagnostics.extend(validate_record_schemas(all_records_data))
    all_diagnostics.extend(schema_diagnostics)

    # Surface record-file type-mismatch diagnostics gathered during load.
    all_diagnostics.extend(record_file_type_mismatches)

    # Phase 2: Integrity verification
    integrity_diagnostics = check_integrity(bundle_path)
    all_diagnostics.extend(integrity_diagnostics)

    # Phase 3: Reference checking
    reference_diagnostics = check_references(manifest_data, all_records_data, bundle_path)
    all_diagnostics.extend(reference_diagnostics)

    # Record all structural errors
    for diag in all_diagnostics:
        assessment.structural_errors.append(diag.to_dict())

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
        )

    # Compute bundle digest for evidence_bundle_ref
    content_hashes_path = bundle_path / "hashes" / "content-hashes.json"
    if content_hashes_path.exists():
        from acef.integrity import compute_bundle_digest

        content_hashes = json.loads(content_hashes_path.read_text(encoding="utf-8"))
        assessment.evidence_bundle_ref.content_hash = compute_bundle_digest(content_hashes)

    return assessment


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
            prov_id, profile_id, prov_results, records,
            subject_scope=subject_scope or [],
        )
        assessment.provision_summary.append(summary)


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
        parsed = parsed.replace(tzinfo=timezone.utc)
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
) -> None:
    """Evaluate template rules for all specified profiles."""
    subjects = manifest_data.get("subjects", [])
    sig_count, sig_algs = get_signature_info(bundle_dir)

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
        manifest_profile_decl: dict[str, Any] | None = None
        for _decl in manifest_data.get("profiles", []):
            if _decl.get("profile_id") == profile_id:
                manifest_profile_decl = _decl
                break

        declared_template_version = (
            manifest_profile_decl.get("template_version") if manifest_profile_decl else None
        )
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
            _versioning = manifest_data.get("versioning", {})
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

        # Determine applicable provisions from the manifest's profile declaration
        applicable_provisions = None
        for prof in manifest_data.get("profiles", []):
            if prof.get("profile_id") == profile_id:
                applicable_provisions = prof.get("applicable_provisions", [])
                break

        # Filter template provisions to those declared applicable
        provisions_to_evaluate = template.provisions
        if applicable_provisions:
            provisions_to_evaluate = [
                p for p in template.provisions
                if p.provision_id in applicable_provisions
                or any(
                    ap.startswith(p.provision_id + ".")
                    or ap.startswith(p.provision_id + "-")
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
        if not_yet_effective:
            from acef.models.assessment import RuleResult
            from acef.models.enums import RuleOutcome, RuleSeverity

            for prov in provisions_to_evaluate:
                if prov.provision_id not in not_yet_effective:
                    continue
                skipped_results: list[RuleResult] = []
                for rule in prov.evaluation:
                    skipped_results.append(
                        RuleResult(
                            rule_id=rule.rule_id,
                            provision_id=prov.provision_id,
                            profile_id=profile_id,
                            rule_severity=rule.severity,
                            outcome=RuleOutcome.SKIPPED,
                            message=(
                                f"Provision not yet effective "
                                f"(effective_date={prov.effective_date}, "
                                f"evaluation_instant={evaluation_instant})"
                            ),
                            evidence_refs=[],
                            subject_scope=[],
                        )
                    )
                if skipped_results:
                    _collect_results(assessment, skipped_results, profile_id, records)

        # Exclude not-yet-effective provisions from further evaluation.
        provisions_to_evaluate = [
            p for p in provisions_to_evaluate
            if p.provision_id not in not_yet_effective
        ]

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

        # Evaluate per-subject provisions
        if subjects and per_subject:
            for subject in subjects:
                subject_id = subject.get("subject_id", "")
                risk_class = subject.get("risk_classification", "")
                modalities = subject.get("modalities", [])

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
                    assessment, results, profile_id, records,
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
