"""Cross-record validation phase for ACEF v1.1 bundles.

Runs as a post-schema, post-integrity validation step. Only invoked when the
manifest's resolved schema version is v1.1 — v1.0 bundles MUST NOT see any
of these checks fire (regression-safety per VAL-REGRESSION-001).

Implements the following assertions from contract.md:

- VAL-VALIDATION-003: tenant uniformity (ACEF-075)
- VAL-VALIDATION-004: cross-tenant entity reference (ACEF-020)
- VAL-VALIDATION-005: causation_chain unsigned URN (ACEF-073)
- VAL-VALIDATION-006: redaction_attestation_ref unresolvable (ACEF-078)
- VAL-VALIDATION-007: non-public record without redaction_policy_version (ACEF-074)
- VAL-VALIDATION-EXTERNAL-URN-001/002: external URN resolution via
  manifest.namespaces['x-external'].bundleReferences (ACEF-073)
- VAL-VALIDATION-VERSION-COMPAT-002: subscriber mode missing required records
  (ACEF-080)
- VAL-VALIDATION-LOAD-AUTHORITY-MATRIX-001: disposition authority matrix
  (ACEF-080)

Each function returns a list of ValidationDiagnostic. The engine merges
them into the AssessmentBundle.structural_errors list.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from acef.errors import ValidationDiagnostic
from acef.validation.authority_matrix import AUTHORITY_CLASSES
from acef.validation.authority_matrix import lookup as _matrix_lookup

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _records_iter(
    records: list[dict[str, Any]],
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield (idx, record_dict) for records that are dicts.

    Defensive iteration — malformed entries (non-dict, missing fields) are
    silently skipped here; the schema-validation phase has already emitted
    diagnostics for them.
    """
    for idx, r in enumerate(records):
        if isinstance(r, dict):
            yield idx, r


def _record_id_of(rec: dict[str, Any]) -> str:
    rid = rec.get("record_id", "")
    return rid if isinstance(rid, str) else ""


def _record_type_of(rec: dict[str, Any]) -> str:
    rt = rec.get("record_type", "")
    return rt if isinstance(rt, str) else ""


def _tenant_of(rec: dict[str, Any]) -> str | None:
    """Return the tenant_label of a record, or None if unset / non-string."""
    t = rec.get("tenant_label")
    if isinstance(t, str) and t:
        return t
    return None


def _entity_refs_of(rec: dict[str, Any]) -> list[str]:
    """Collect every URN appearing in entity_refs.{subject,component,dataset,actor}_refs."""
    er = rec.get("entity_refs")
    if not isinstance(er, dict):
        return []
    out: list[str] = []
    for key in ("subject_refs", "component_refs", "dataset_refs", "actor_refs"):
        v = er.get(key)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str) and item:
                    out.append(item)
    return out


# ---------------------------------------------------------------------------
# VAL-VALIDATION-003: tenant uniformity
# ---------------------------------------------------------------------------


def enforce_tenant_uniformity(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-075 if multiple distinct tenant_labels coexist when
    analysis_mode is set.

    Per contract VAL-VALIDATION-003: a v1.1 bundle with `analysis_mode` set
    AND two or more distinct non-null tenant_label values across records
    fails with ACEF-075. Records without tenant_label are ignored for the
    uniformity check (they are valid neighbors of any single tenant).
    """
    analysis_mode = manifest.get("analysis_mode") if isinstance(manifest, dict) else None
    if not analysis_mode:
        return []

    seen: dict[str, str] = {}  # tenant_label -> first record_id with that label
    for _idx, rec in _records_iter(records):
        t = _tenant_of(rec)
        if t is None:
            continue
        if t not in seen:
            seen[t] = _record_id_of(rec)

    if len(seen) <= 1:
        return []

    labels_sorted = sorted(seen.keys())
    return [
        ValidationDiagnostic(
            "ACEF-075",
            (
                "Bundle declares analysis_mode="
                f"{analysis_mode!r} but records carry multiple distinct "
                f"tenant_label values: {labels_sorted!r}. Per the ACEF-075 "
                "error-taxonomy row (spec §3.6), a single bundle MUST NOT "
                "carry two distinct tenant_label values."
            ),
        )
    ]


# ---------------------------------------------------------------------------
# VAL-VALIDATION-004: cross-tenant entity reference (entity inheritance)
# ---------------------------------------------------------------------------


def build_entity_tenant_map(
    records: list[dict[str, Any]],
) -> dict[str, str]:
    """Build URN → tenant_label map by inheritance from declaring record.

    Each entity URN inherits the tenant_label of the *first* record whose
    entity_refs list it appears in. Records WITHOUT a tenant_label do not
    contribute to the map (entities they reference remain unmapped); this
    matches the contract VAL-VALIDATION-004 semantics — only tenant-tagged
    records can claim ownership.

    Iteration order is the input order, which the engine produces by
    manifest record_files ordering (deterministic per §3.1.1).
    """
    mapping: dict[str, str] = {}
    for _idx, rec in _records_iter(records):
        t = _tenant_of(rec)
        if t is None:
            continue
        for urn in _entity_refs_of(rec):
            if urn not in mapping:
                mapping[urn] = t
    return mapping


def enforce_cross_tenant_refs(
    records: list[dict[str, Any]],
    entity_tenant_map: dict[str, str],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-020 for every record→entity reference that crosses tenants.

    A record with tenant_label T1 referencing an entity URN whose inherited
    tenant_label is T2 (T1 != T2) violates VAL-VALIDATION-004.
    Records without tenant_label are not checked (the cross-tenant invariant
    presumes both sides are tenant-tagged).
    """
    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        rec_tenant = _tenant_of(rec)
        if rec_tenant is None:
            continue
        rec_id = _record_id_of(rec)
        for urn in _entity_refs_of(rec):
            owner_tenant = entity_tenant_map.get(urn)
            if owner_tenant is None:
                continue
            if owner_tenant != rec_tenant:
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-020",
                        (
                            f"Cross-tenant entity reference: record "
                            f"{rec_id!r} (tenant_label={rec_tenant!r}) "
                            f"references entity {urn!r} owned by tenant "
                            f"{owner_tenant!r}. Per the ACEF-020 reference-"
                            "integrity rule (spec §3.6 error taxonomy — "
                            "entity_refs reference-integrity; cross-tenant "
                            "entity-reference model), entity references MUST "
                            "NOT cross tenant_label boundaries."
                        ),
                    )
                )
    return diags


# ---------------------------------------------------------------------------
# VAL-VALIDATION-005 / EXTERNAL-URN-001 / EXTERNAL-URN-002: causation_chain
# ---------------------------------------------------------------------------


def _declared_external_urns(manifest: dict[str, Any]) -> set[str]:
    """Collect URNs declared in manifest.namespaces['x-external'].bundleReferences.

    The convention (this operation's): an external bundle reference is an
    object with at least a `urn` field naming an in-bundle-or-out-of-bundle
    record. Optionally it may carry a `bundle_id` or `content_hash` field
    for downstream resolution; we only need the URN strings for the
    causation_chain rejection check.

    Defensive parsing: any malformed structure is treated as "no
    references" (returns an empty set). The schema validator catches
    structural errors separately.
    """
    out: set[str] = set()
    namespaces = manifest.get("namespaces")
    if not isinstance(namespaces, dict):
        return out
    x_external = namespaces.get("x-external")
    if not isinstance(x_external, dict):
        return out
    refs = x_external.get("bundleReferences")
    if not isinstance(refs, list):
        return out
    for ref in refs:
        if isinstance(ref, dict):
            urn = ref.get("urn")
            if isinstance(urn, str) and urn:
                out.add(urn)
        elif isinstance(ref, str) and ref:
            # Allow a plain-string shorthand: bundleReferences: ["urn:...", ...]
            out.add(ref)
    return out


def enforce_causation_chain_signed(
    records: list[dict[str, Any]],
    in_bundle_record_urns: set[str],
    signature_count: int,
    manifest: dict[str, Any],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-073 for each unresolvable causation_chain URN.

    A causation_chain URN is *resolved* when one of these holds:

    1. It refers to a record present IN this bundle, AND this bundle has at
       least one cryptographically verified signature (signature_count > 0).
       (Spec §6.5 — causation chains across unsigned bundles cannot be
       trusted.)
    2. It refers to an external bundle, AND its URN is declared in
       `manifest.namespaces['x-external'].bundleReferences`. (External
       trust is asserted by the producer; further verification is out of
       scope for this validator pass.)

    Otherwise ACEF-073 fires.

    Args:
        records: All record dicts in the bundle.
        in_bundle_record_urns: Set of record_id URNs that exist in this
            bundle (precomputed by the engine).
        signature_count: Count of cryptographically VERIFIED signatures on
            this bundle (from integrity_checker.get_signature_info).
        manifest: Manifest dict — read for external bundle references.
    """
    declared_external = _declared_external_urns(manifest)
    diags: list[ValidationDiagnostic] = []

    for _idx, rec in _records_iter(records):
        chain = rec.get("causation_chain")
        if not isinstance(chain, list) or not chain:
            continue
        rec_id = _record_id_of(rec)
        for urn in chain:
            if not isinstance(urn, str) or not urn:
                # Malformed chain entry — schema layer already flagged it
                continue
            in_bundle = urn in in_bundle_record_urns
            in_declared = urn in declared_external
            if in_bundle and signature_count > 0:
                continue  # case (1): resolved
            if in_declared:
                continue  # case (2): resolved
            # Failed: emit a single ACEF-073 diagnostic naming the chain
            # entry and why resolution failed
            if in_bundle and signature_count == 0:
                reason = (
                    "resolves to an in-bundle record, but the bundle is "
                    "unsigned (zero verified JWS signatures); causation "
                    "chains require a signed owning bundle"
                )
            else:
                reason = (
                    "neither resolves to an in-bundle record nor is "
                    "declared in manifest.namespaces['x-external']"
                    ".bundleReferences"
                )
            diags.append(
                ValidationDiagnostic(
                    "ACEF-073",
                    (f"causation_chain URN {urn!r} on record {rec_id!r} {reason}."),
                )
            )
    return diags


# ---------------------------------------------------------------------------
# VAL-VALIDATION-006 / 007: redaction policy + attestation
# ---------------------------------------------------------------------------


def enforce_redaction_policy_version(
    records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-074 for non-public records missing redaction_policy_version.

    A record is "non-public" when confidentiality is set to any value other
    than 'public' (or is absent — which defaults to public, so absent is
    OK). Per VAL-VALIDATION-007 the policy version is required at the
    validator level (not at the schema level — schemas treat the field as
    optional).
    """
    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        conf = rec.get("confidentiality")
        if not isinstance(conf, str) or conf == "public":
            continue
        version = rec.get("redaction_policy_version")
        if isinstance(version, str) and version:
            continue
        rec_id = _record_id_of(rec)
        diags.append(
            ValidationDiagnostic(
                "ACEF-074",
                (
                    f"Record {rec_id!r} has confidentiality={conf!r} "
                    "(non-public) but no redaction_policy_version. Per "
                    "spec §6.3, non-public records MUST declare the "
                    "redaction policy semver under which they were "
                    "produced."
                ),
            )
        )
    return diags


def enforce_redaction_attestation_ref(
    records: list[dict[str, Any]],
    in_bundle_record_urns: set[str],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-078 when redaction_attestation_ref points to an unknown URN.

    Per VAL-VALIDATION-006: when a record sets `redaction_attestation_ref`
    and the URN does not resolve to a record in this bundle, fail with
    ACEF-078 (NOT ACEF-022 — the codex policy carved out ACEF-078 for this
    specific case so general dangling-entity-ref errors don't subsume it).

    Records without a `redaction_attestation_ref` are not checked here —
    the *conditional-required* enforcement (i.e., must be set on non-public
    records) is a separate question we don't yet enforce because the brief
    is silent on whether the attestation ref is mandatory or merely
    strongly recommended. This function only checks resolvability when the
    field is present.
    """
    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        ref = rec.get("redaction_attestation_ref")
        if not isinstance(ref, str) or not ref:
            continue
        if ref in in_bundle_record_urns:
            continue
        rec_id = _record_id_of(rec)
        diags.append(
            ValidationDiagnostic(
                "ACEF-078",
                (
                    f"Record {rec_id!r} has redaction_attestation_ref="
                    f"{ref!r} but no record with that URN exists in the "
                    "bundle. Per spec §6.3, the attestation reference "
                    "MUST resolve to an in-bundle record."
                ),
            )
        )
    return diags


# ---------------------------------------------------------------------------
# VAL-VALIDATION-VERSION-COMPAT-002: mode-gated required records
# ---------------------------------------------------------------------------

# Subscriber mode requires at least one of each of these record types.
# Public-artifact / canary / unattributed_artifact do not require additional
# record types beyond standard v1.0 envelope content; F-M1-VALIDATOR-RULES
# handles the *forbidden*-type side of mode-gating (VAL-VALIDATION-010).
_SUBSCRIBER_REQUIRED_TYPES: tuple[str, ...] = (
    "authorized_test_scope",
    "harness_attestation",
)


def enforce_mode_gates(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-080 when analysis_mode requires record types that are absent.

    Per VAL-VALIDATION-VERSION-COMPAT-002 and the ACEF-080 error-taxonomy
    row (spec §3.6: "Bundle declares analysis_mode but lacks required
    envelope/manifest fields for that mode"): a bundle declaring
    `analysis_mode: "subscriber"` MUST contain at least one
    `authorized_test_scope` AND at least one `harness_attestation` record.
    Missing either emits ACEF-080.

    NOTE (audit cross-record-authority-2): the ACEF-080 *code* is normative
    (spec §3.6), but the per-mode required-record-type TABLE itself has no
    normative home in the ACEF spec or RFC-0002 — it derives from the ACEF
    mode-gate model defined by the acef-v0.4-freddy-adoption operation. The
    diagnostic therefore cites the code's real home, not a fabricated §.
    """
    if not isinstance(manifest, dict):
        return []
    mode = manifest.get("analysis_mode")
    if mode != "subscriber":
        return []

    present_types: set[str] = set()
    for _idx, rec in _records_iter(records):
        rt = _record_type_of(rec)
        if rt:
            present_types.add(rt)

    missing = [rt for rt in _SUBSCRIBER_REQUIRED_TYPES if rt not in present_types]
    if not missing:
        return []

    return [
        ValidationDiagnostic(
            "ACEF-080",
            (
                "Bundle declares analysis_mode='subscriber' but is missing "
                f"required mode-gated record types: {missing!r}. Per the "
                "ACEF-080 mode-gate rule (spec §3.6 error taxonomy), "
                "subscriber-mode bundles MUST carry at least one "
                "authorized_test_scope AND at least one harness_attestation "
                "(per-mode table: ACEF mode-gate model)."
            ),
        )
    ]


# ---------------------------------------------------------------------------
# VAL-VALIDATION-LOAD-AUTHORITY-MATRIX-001: disposition authority matrix
# ---------------------------------------------------------------------------


def _actor_role_map(manifest: dict[str, Any]) -> dict[str, str]:
    """Return actor_id URN → role string from manifest.entities.actors."""
    out: dict[str, str] = {}
    entities = manifest.get("entities") if isinstance(manifest, dict) else None
    if not isinstance(entities, dict):
        return out
    actors = entities.get("actors")
    if not isinstance(actors, list):
        return out
    for actor in actors:
        if not isinstance(actor, dict):
            continue
        actor_id = actor.get("actor_id")
        role = actor.get("role")
        if isinstance(actor_id, str) and isinstance(role, str):
            out[actor_id] = role
    return out


def _is_disposition_record(rec: dict[str, Any]) -> bool:
    """True iff record is a risk_treatment with treatment_subtype=external_disposition."""
    if _record_type_of(rec) != "risk_treatment":
        return False
    payload = rec.get("payload")
    if not isinstance(payload, dict):
        return False
    return payload.get("treatment_subtype") == "external_disposition"


def enforce_disposition_authority(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-080 for disposition records that violate the authority matrix.

    For each `disposition_record` (risk_treatment with
    treatment_subtype=external_disposition) whose
    `payload.authority_check.authority_granted: true`, look up the
    associated actor's role and the authority_class, and consult the
    matrix. A denied cell fires ACEF-080.

    Normative basis (audit cross-record-authority-2): the ACEF-080 *code*
    is normative (spec §3.6 error taxonomy: "mode-gated rule violation").
    The disposition-authority MATRIX itself — the 5x4 (authority_class x
    actor_role) grid — has NO normative home in the ACEF spec or RFC-0002;
    it derives from the ACEF authority model defined by the
    acef-v0.4-freddy-adoption operation. Diagnostics therefore cite "the
    ACEF authority model", not a fabricated spec section.

    The authority_class is read from `payload.authority_check.authority_class`.
    The check FAILS CLOSED (audit finding cross-record-authority-5): when
    `authority_granted: true` is claimed but authority_class is missing, not
    a non-empty string, or not one of the five recognized authority classes,
    ACEF-080 is emitted — mirroring the matrix's own defensive-deny default.
    A silent skip is legitimate ONLY when no authority is claimed (no
    `authority_granted: true`).

    The actor URN is read from `payload.authority_check.actor_ref` (the
    disposition's explicitly claimed authorizing actor — single-actor
    semantics). If actor_ref is absent, EVERY `entity_refs.actor_refs` URN
    is evaluated (audit finding cross-record-authority-6): ANY denied or
    undeclared actor emits ACEF-080, so ordering a permitted actor first
    cannot hide a denied one. A granted disposition naming no resolvable
    actor at all is itself an authority-model violation (ACEF-080).
    """
    actor_role = _actor_role_map(manifest)
    diags: list[ValidationDiagnostic] = []

    for _idx, rec in _records_iter(records):
        if not _is_disposition_record(rec):
            continue
        payload = rec.get("payload", {})
        auth = payload.get("authority_check") if isinstance(payload, dict) else None
        if not isinstance(auth, dict):
            continue
        if auth.get("authority_granted") is not True:
            # No granted claim = nothing to check; only the *granted=true*
            # case can violate the matrix.
            continue

        rec_id = _record_id_of(rec)

        ac = auth.get("authority_class")
        if not isinstance(ac, str) or not ac:
            # Fail closed: a granted disposition with no usable
            # authority_class discriminator would otherwise escape the
            # matrix entirely (the V3 oneOf payload schema is deferred, so
            # nothing else validates the authority_check shape).
            diags.append(
                ValidationDiagnostic(
                    "ACEF-080",
                    (
                        f"disposition_record {rec_id!r} claims "
                        "authority_granted: true but "
                        "authority_check.authority_class is missing or not "
                        "a non-empty string. Per the ACEF authority model "
                        "(ACEF-080, spec §3.6), a granted disposition MUST "
                        "declare a recognized authority_class; fail closed "
                        "(deny)."
                    ),
                )
            )
            continue
        if ac not in AUTHORITY_CLASSES:
            # Fail closed with a PRECISE diagnostic: the matrix's own
            # lookup would deny an unrecognized class anyway, but the
            # caller deserves to know the class itself is unknown rather
            # than a (class × role) cell being denied.
            diags.append(
                ValidationDiagnostic(
                    "ACEF-080",
                    (
                        f"disposition_record {rec_id!r} claims "
                        "authority_granted: true with unrecognized "
                        f"authority_class={ac!r}. Recognized authority-model "
                        f"classes: {list(AUTHORITY_CLASSES)!r}. Fail closed "
                        "(deny)."
                    ),
                )
            )
            continue

        # Resolve the actor set to evaluate. An explicit
        # authority_check.actor_ref is the producer's explicit claim →
        # single-actor semantics. Otherwise EVERY entity_refs.actor_refs
        # URN is evaluated; ANY denied actor fails the record.
        actor_ref = auth.get("actor_ref")
        if isinstance(actor_ref, str) and actor_ref:
            candidate_refs = [actor_ref]
        else:
            candidate_refs = []
            er = rec.get("entity_refs", {})
            if isinstance(er, dict):
                actors = er.get("actor_refs")
                if isinstance(actors, list):
                    # Deduplicate while preserving order; non-string
                    # entries are the schema phase's concern.
                    candidate_refs = list(dict.fromkeys(a for a in actors if isinstance(a, str) and a))

        if not candidate_refs:
            # Fail closed: a granted disposition with no resolvable
            # authorizing actor is itself an authority-model violation.
            diags.append(
                ValidationDiagnostic(
                    "ACEF-080",
                    (
                        f"disposition_record {rec_id!r} grants authority_class="
                        f"{ac!r} but names no authorizing actor (no "
                        "authority_check.actor_ref and no "
                        "entity_refs.actor_refs). Per the ACEF authority "
                        "model (ACEF-080), authority grants require a mapped "
                        "actor with an explicit role; fail closed (deny)."
                    ),
                )
            )
            continue

        for candidate in candidate_refs:
            role = actor_role.get(candidate)
            if role is None:
                # Unknown actor — emit ACEF-080 (the matrix lookup defaults
                # to denied for unknown actor types; a granted disposition
                # referencing an undeclared actor is itself an authority-
                # model violation).
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-080",
                        (
                            f"disposition_record {rec_id!r} grants "
                            f"authority_class={ac!r} but the authorizing "
                            f"actor ({candidate!r}) is not declared in "
                            "manifest.entities.actors. Per the ACEF authority "
                            "model (ACEF-080), authority grants require a "
                            "mapped actor with an explicit role."
                        ),
                    )
                )
                continue

            if _matrix_lookup(ac, role):
                continue  # cell is granted — OK for this actor

            diags.append(
                ValidationDiagnostic(
                    "ACEF-080",
                    (
                        f"disposition_record {rec_id!r} grants authority_class="
                        f"{ac!r} to actor {candidate!r} (role={role!r}), but the "
                        "ACEF authority matrix denies that "
                        "(authority_class × actor_role) pair (ACEF-080, spec "
                        "§3.6 error taxonomy; matrix per ACEF authority "
                        "model). Reject."
                    ),
                )
            )
    return diags


# ---------------------------------------------------------------------------
# VAL-LOAD-001 / 002 / 005: harness_attestation verifier_class
# ---------------------------------------------------------------------------

# Mirror of acef.load_rejections._BANNED_VERIFIER_CLASSES. Kept duplicated
# (not imported) to avoid a circular dependency loader→validation. If this
# set drifts in one module, the agreement contract VAL-LOAD-005 breaks; the
# integration test test_load_validate_agree.py asserts they stay aligned.
_BANNED_VERIFIER_CLASSES: tuple[str, ...] = ("persona", "llm")


def enforce_harness_verifier_class(
    records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-070 for harness_attestation records with banned verifier_class.

    VAL-LOAD-005 mirror of the loader's VAL-LOAD-001/002 rejection: when
    :func:`acef.validation.engine.validate_bundle` is run on the same
    bundle that the loader would reject, this function emits a diagnostic
    carrying the same ACEF-070 code so callers see consistent semantics
    regardless of which entry point they used.

    Per brief §3.6: persona and LLM verifiers lack the determinism required
    to attest state transitions. The :class:`HarnessVerifier` Pydantic
    enum already excludes them at parse time, but validate_bundle inspects
    the raw record dicts (it does NOT depend on payload Pydantic models)
    so we surface a diagnostic explicitly.
    """
    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) != "harness_attestation":
            continue
        payload = rec.get("payload")
        if not isinstance(payload, dict):
            continue
        verifier = payload.get("verifier")
        if not isinstance(verifier, dict):
            continue
        vc = verifier.get("verifier_class")
        if not isinstance(vc, str) or vc not in _BANNED_VERIFIER_CLASSES:
            continue
        rec_id = _record_id_of(rec)
        diags.append(
            ValidationDiagnostic(
                "ACEF-070",
                (
                    f"harness_attestation {rec_id!r} uses banned "
                    f"verifier_class={vc!r}: persona and LLM verifiers lack "
                    "the determinism required to attest state transitions "
                    "per brief §3.6."
                ),
            )
        )
    return diags


# ---------------------------------------------------------------------------
# VAL-LOAD-003 / 005: disposition_record internal_state_unchanged
# ---------------------------------------------------------------------------


def enforce_disposition_internal_state(
    records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-076 for disposition records with internal_state_unchanged=false.

    VAL-LOAD-005 mirror of the loader's VAL-LOAD-003 rejection. Per brief
    §V3: external dispositions are advisory and MUST NOT mutate internal
    evidence state; :samp:`internal_state_unchanged: false` is the
    forbidden condition.

    ACEF-076's registry text reads "state_class record lacks fake-green
    test reference" but the same code is reused here per ops plan WS3.4:
    both conditions are "discipline failures around state mutation" and
    sharing a code keeps the error taxonomy compact. The diagnostic
    message disambiguates by naming the specific violation.
    """
    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        if not _is_disposition_record(rec):
            continue
        payload = rec.get("payload", {})
        if not isinstance(payload, dict):
            continue
        # Only the explicit boolean False fires; absent / true / non-boolean
        # are not violations at this layer (schema validation handles
        # type-shape requirements separately).
        if payload.get("internal_state_unchanged") is not False:
            continue
        rec_id = _record_id_of(rec)
        diags.append(
            ValidationDiagnostic(
                "ACEF-076",
                (
                    f"disposition_record {rec_id!r} sets "
                    "internal_state_unchanged=false: external dispositions "
                    "are advisory per brief §V3 and MUST NOT mutate "
                    "internal evidence state."
                ),
            )
        )
    return diags


# ---------------------------------------------------------------------------
# ACEF-070: harness_attestation evidence binding (empty refs / unresolvable URN)
#
# Brief §3.6: empty bound_evidence_refs OR a ref that cannot be resolved to
# an in-bundle record (or an externally-declared bundle reference) emits
# ACEF-070 at validation time. The SDK builder Package.attest() rejects
# empty refs at build time (VAL-SDK-005); this validator covers the
# post-hoc / hand-authored / loaded-and-mutated cases that bypass the SDK.
# ---------------------------------------------------------------------------


def enforce_harness_evidence_binding(
    records: list[dict[str, Any]],
    in_bundle_record_urns: set[str],
    manifest: dict[str, Any],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-070 for harness_attestation records with broken evidence binding.

    Two failure modes both emit ACEF-070 per brief §3.6:

    1. ``payload.bound_evidence_refs`` is missing OR an empty list — a
       state-class attestation that does not cite any evidence has no
       binding, so any claim is structurally unverifiable.
    2. A ref URN in ``bound_evidence_refs`` resolves to neither an
       in-bundle record nor an externally-declared bundle reference (via
       ``manifest.namespaces['x-external'].bundleReferences``).

    Records of any type OTHER than ``harness_attestation`` are skipped —
    ACEF-070 is reserved for harness attestation per VAL-SDK-EDGE-001.
    """
    declared_external = _declared_external_urns(manifest)
    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) != "harness_attestation":
            continue
        payload = rec.get("payload")
        if not isinstance(payload, dict):
            continue
        rec_id = _record_id_of(rec)
        refs = payload.get("bound_evidence_refs")
        # Empty / missing list — fire once per record.
        if not isinstance(refs, list) or len(refs) == 0:
            diags.append(
                ValidationDiagnostic(
                    "ACEF-070",
                    (
                        f"harness_attestation {rec_id!r} has empty or missing "
                        "bound_evidence_refs: state-class attestations require "
                        "at least one URN binding the transition to evidence "
                        "(brief §3.6)."
                    ),
                )
            )
            continue
        # Resolve each ref.
        for urn in refs:
            if not isinstance(urn, str) or not urn:
                continue  # schema layer flagged malformed entries
            if urn in in_bundle_record_urns:
                continue
            if urn in declared_external:
                continue
            diags.append(
                ValidationDiagnostic(
                    "ACEF-070",
                    (
                        f"harness_attestation {rec_id!r} cites "
                        f"bound_evidence_ref {urn!r} that resolves to "
                        "neither an in-bundle record nor an externally-"
                        "declared bundle reference (brief §3.6)."
                    ),
                )
            )
    return diags


# ---------------------------------------------------------------------------
# ACEF-071 / ACEF-072: delivery_verdict verified-delivery integrity
#
# Brief §3.4: when delivery_state='verified_delivered', the triple
# requirement read_back + read_back.digest_match=true +
# harness_attestation_ref MUST hold. Missing the read-back emits ACEF-071;
# a read_back present whose read_back_digest does NOT byte-equal the
# write_attempt.request_digest emits ACEF-072 (independent of
# delivery_state: a self-inconsistent read-back is always a finding).
# ---------------------------------------------------------------------------


def enforce_delivery_verdict_integrity(
    records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-071 / ACEF-072 for delivery_verdict integrity failures.

    Per brief §3.4 and VAL-ERROR-001 / VAL-CONFORMANCE-002:

    - ACEF-071 fires when ``delivery_state == 'verified_delivered'`` and
      any of ``read_back`` / ``read_back.digest_match == true`` /
      ``harness_attestation_ref`` is missing. The bundle is claiming
      verified delivery without the cryptographic read-back that proves
      the destination object byte-equals the write payload.

    - ACEF-072 fires whenever a ``read_back`` block is present and its
      ``read_back_digest`` is NOT byte-equal to
      ``write_attempt.request_digest``. The schema layer's allOf
      requires ``digest_match=true`` for verified_delivered but does
      not assert digest equality; this validator closes that gap.
    """
    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        if _record_type_of(rec) != "delivery_verdict":
            continue
        payload = rec.get("payload")
        if not isinstance(payload, dict):
            continue
        rec_id = _record_id_of(rec)
        state = payload.get("delivery_state")
        read_back = payload.get("read_back")
        write_attempt = payload.get("write_attempt")
        harness_ref = payload.get("harness_attestation_ref")

        # ACEF-072: read-back digest mismatch (independent of state).
        if isinstance(read_back, dict) and isinstance(write_attempt, dict):
            req_digest = write_attempt.get("request_digest")
            rb_digest = read_back.get("read_back_digest")
            if (
                isinstance(req_digest, str)
                and isinstance(rb_digest, str)
                and req_digest
                and rb_digest
                and req_digest != rb_digest
            ):
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-072",
                        (
                            f"delivery_verdict {rec_id!r} read_back.read_back_digest "
                            f"{rb_digest!r} does not byte-equal "
                            f"write_attempt.request_digest {req_digest!r} "
                            "(brief §3.4): a self-inconsistent read-back "
                            "cannot witness verified delivery."
                        ),
                    )
                )

        # ACEF-071: verified_delivered without the required triple.
        if state == "verified_delivered":
            problems: list[str] = []
            if not isinstance(read_back, dict):
                problems.append("read_back is missing")
            elif read_back.get("digest_match") is not True:
                problems.append(f"read_back.digest_match must be exactly true (got {read_back.get('digest_match')!r})")
            if not (isinstance(harness_ref, str) and harness_ref):
                problems.append("harness_attestation_ref is missing or empty")
            if problems:
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-071",
                        (
                            f"delivery_verdict {rec_id!r} declares "
                            "delivery_state='verified_delivered' but is missing "
                            f"the required read-back triple: {problems!r} "
                            "(brief §3.4)."
                        ),
                    )
                )
    return diags


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def run_cross_record_validation(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    signature_count: int,
) -> list[ValidationDiagnostic]:
    """Run all v1.1 cross-record checks and return diagnostics.

    Called by the engine ONLY when `schema_version == "v1.1"`. v1.0 bundles
    do not pass through this function (regression-safety).

    Args:
        manifest: Parsed acef-manifest.json content.
        records: All record dicts loaded from the bundle's JSONL files,
            in deterministic order.
        signature_count: Verified-signature count from
            integrity_checker.get_signature_info (used by the
            causation_chain check).
    """
    diags: list[ValidationDiagnostic] = []

    # Build URN set once — used by both causation_chain and
    # redaction_attestation_ref resolution.
    in_bundle_urns: set[str] = set()
    for _idx, rec in _records_iter(records):
        rid = _record_id_of(rec)
        if rid:
            in_bundle_urns.add(rid)

    # 1. Tenant uniformity
    diags.extend(enforce_tenant_uniformity(manifest, records))

    # 2. Cross-tenant entity references (entity inheritance)
    entity_tenant_map = build_entity_tenant_map(records)
    diags.extend(enforce_cross_tenant_refs(records, entity_tenant_map))

    # 3. causation_chain URN resolution
    diags.extend(
        enforce_causation_chain_signed(
            records,
            in_bundle_urns,
            signature_count,
            manifest,
        )
    )

    # 4. Redaction policy version (conditional-required)
    diags.extend(enforce_redaction_policy_version(records))

    # 5. Redaction attestation ref (URN resolvability)
    diags.extend(enforce_redaction_attestation_ref(records, in_bundle_urns))

    # 6. Mode-gated required record types
    diags.extend(enforce_mode_gates(manifest, records))

    # 7. Disposition authority matrix (also handles VAL-LOAD-005 mirror of
    #    VAL-LOAD-004 — same ACEF-080 code path emits a diagnostic for the
    #    same input the loader rejects with LoadRejection).
    diags.extend(enforce_disposition_authority(manifest, records))

    # 8. VAL-LOAD-005 mirror of VAL-LOAD-001/002: harness verifier_class
    #    persona/llm. Emits ACEF-070 — same code the loader uses for
    #    LoadRejection.
    diags.extend(enforce_harness_verifier_class(records))

    # 9. VAL-LOAD-005 mirror of VAL-LOAD-003: disposition_record with
    #    internal_state_unchanged=false. Emits ACEF-076 — same code the
    #    loader uses for LoadRejection.
    diags.extend(enforce_disposition_internal_state(records))

    # 10. Brief §3.6 harness_attestation evidence binding — emits ACEF-070
    #     for empty bound_evidence_refs OR unresolvable ref URN.
    diags.extend(enforce_harness_evidence_binding(records, in_bundle_urns, manifest))

    # 11. Brief §3.4 delivery_verdict integrity — emits ACEF-071 for
    #     verified_delivered without the read-back triple, and ACEF-072
    #     for a read_back whose digest does not match the write digest.
    diags.extend(enforce_delivery_verdict_integrity(records))

    return diags
