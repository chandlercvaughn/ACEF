"""Shared helpers for Freddy conformance bundle builders.

Every bundle uses a fixed clock and a deterministic URN pool so two
runs of ``build_all.py`` produce byte-equal output (per VAL-CONFORMANCE
§7.2: TC7 — JCS round-trip + determinism). Each builder picks URNs from
the appropriate pool by stable index.

This module does NOT go through ``acef.Package`` for two reasons:

1. Many fail-bundle scenarios require deliberately invalid combinations
   (empty bound_evidence_refs, persona verifier_class, etc.) that the
   SDK's pre-flight checks reject before serialization. We need the
   ON-DISK bundle to carry the offending content so the validator can
   see it.
2. Several pass-bundles need exact control over content-hashes.json,
   record-file paths, and signatures/ contents.

Writing raw JSON keeps both concerns straightforward.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Fixed clock + URN pools — change ONLY if you want every bundle's
# byte-content to change (which would break VAL-CONFORMANCE §7.2 TC7).
# ---------------------------------------------------------------------------

FIXED_TIMESTAMP = "2026-05-01T00:00:00Z"
FIXED_LATER_TIMESTAMP = "2026-05-01T01:00:00Z"
FIXED_LATEST_TIMESTAMP = "2026-05-01T02:00:00Z"


# 64 deterministic UUIDs (incrementing hex) per URN type.
def _hex_uuid(seed: int) -> str:
    """Return a deterministic ``[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`` string."""
    s = f"{seed:032x}"
    return f"{s[0:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:32]}"


def urn(kind: str, idx: int) -> str:
    """Return a stable URN of the given kind and index.

    Recognized kinds:
        pkg, sub, comp, ds, actor, rec, att, scope, sbe, finding,
        delivery, fg

    The kind ``actor`` is aliased to the URN prefix ``act`` to match the
    record-envelope/manifest actor_id regex (``urn:acef:act:...``). All
    other kinds pass through unchanged.
    """
    prefix = "act" if kind == "actor" else kind
    return f"urn:acef:{prefix}:{_hex_uuid(idx)}"


# Common SHA-256 digests used by reproduction_steps_ref / write_attempt /
# read_back. These are stable hex strings — they don't need to hash any
# real content for the validator tests.
def sha256_hex(label: str) -> str:
    """Return a stable ``sha256:<hex>`` string derived from ``label``."""
    h = hashlib.sha256(label.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


# ---------------------------------------------------------------------------
# Manifest + record builders
# ---------------------------------------------------------------------------


def base_manifest(
    *,
    package_idx: int = 0,
    core_version: str = "1.1.0",
    analysis_mode: str | None = None,
    namespaces: dict[str, Any] | None = None,
    actors: list[dict[str, Any]] | None = None,
    components: list[dict[str, Any]] | None = None,
    subjects: list[dict[str, Any]] | None = None,
    profiles: list[dict[str, Any]] | None = None,
    timestamp: str = FIXED_TIMESTAMP,
) -> dict[str, Any]:
    """Construct a minimal valid v1.1 manifest dict.

    ``record_files`` is omitted — callers supply it via ``write_bundle``.
    """
    manifest: dict[str, Any] = {
        "metadata": {
            "package_id": urn("pkg", package_idx),
            "created_at": timestamp,
            "timestamp": timestamp,
            "producer": {"name": "freddy-test-builder", "version": "0.4.0"},
        },
        "versioning": {"core_version": core_version, "profiles_version": "1.0.0"},
        "subjects": subjects or [],
        "entities": {
            "components": components or [],
            "datasets": [],
            "actors": actors or [],
            "relationships": [],
        },
        "profiles": profiles or [],
        "audit_trail": [],
    }
    if analysis_mode is not None:
        manifest["analysis_mode"] = analysis_mode
    if namespaces is not None:
        manifest["namespaces"] = namespaces
    return manifest


def base_record(
    *,
    record_id: str,
    record_type: str = "risk_register",
    timestamp: str = FIXED_TIMESTAMP,
    payload: dict[str, Any] | None = None,
    tenant_label: str | None = None,
    confidentiality: str = "public",
    redaction_policy_version: str | None = None,
    redaction_attestation_ref: str | None = None,
    causation_chain: list[str] | None = None,
    entity_refs: dict[str, list[str]] | None = None,
    provisions_addressed: list[str] | None = None,
) -> dict[str, Any]:
    """Construct a minimal valid v1.1 record envelope dict."""
    rec: dict[str, Any] = {
        "record_id": record_id,
        "record_type": record_type,
        "provisions_addressed": provisions_addressed or [],
        "timestamp": timestamp,
        "lifecycle_phase": "development",
        "collector": {"name": "freddy-test-builder", "version": "0.4.0"},
        "obligation_role": "provider",
        "confidentiality": confidentiality,
        "trust_level": "self-attested",
        "entity_refs": {
            "subject_refs": (entity_refs or {}).get("subject_refs", []),
            "component_refs": (entity_refs or {}).get("component_refs", []),
            "dataset_refs": (entity_refs or {}).get("dataset_refs", []),
            "actor_refs": (entity_refs or {}).get("actor_refs", []),
        },
        "payload": payload if payload is not None else {},
        "attachments": [],
    }
    if tenant_label is not None:
        rec["tenant_label"] = tenant_label
    if redaction_policy_version is not None:
        rec["redaction_policy_version"] = redaction_policy_version
    if redaction_attestation_ref is not None:
        rec["redaction_attestation_ref"] = redaction_attestation_ref
    if causation_chain is not None:
        rec["causation_chain"] = causation_chain
    return rec


# ---------------------------------------------------------------------------
# Bundle writer
# ---------------------------------------------------------------------------


def write_bundle(
    bundle_dir: Path,
    *,
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
    readme: str,
    assessment_bundle: dict[str, Any] | None = None,
    content_hashes: dict[str, str] | None = None,
    auto_hashes: bool = True,
) -> None:
    """Write a bundle to ``bundle_dir``.

    Groups records by record_type → one JSONL file per type, sorted by
    (timestamp, record_id) per spec §3.1.1. Sets manifest.record_files
    automatically. Writes a README.md. Optionally writes a sibling
    ``<bundle_dir>.acef-assessment.json``.

    Content hashes:
    - When ``content_hashes`` is supplied, those hashes are written
      verbatim to ``hashes/content-hashes.json`` (used by the
      ``badge-green-with-failed-integrity`` fail bundle to inject
      deliberately-wrong hashes that trigger ACEF-014).
    - Otherwise, when ``auto_hashes=True`` (the default), the bundle's
      actual record file hashes are computed via
      :func:`acef.integrity.compute_content_hashes` and written to
      ``hashes/content-hashes.json``. This is what every pass bundle
      uses to avoid the validator's ACEF-014 "content-hashes.json not
      found" diagnostic.
    """
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "records").mkdir(parents=True, exist_ok=True)

    # Group records by record_type, sort each group.
    by_type: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        by_type.setdefault(r["record_type"], []).append(r)

    record_files: list[dict[str, Any]] = []
    for rtype in sorted(by_type.keys()):
        recs = sorted(by_type[rtype], key=lambda r: (r.get("timestamp", ""), r.get("record_id", "")))
        path = f"records/{rtype}.jsonl"
        # Vendor-namespaced record_types contain slashes (e.g.
        # ``x-freddy/voice-rubric-emission``) — ensure the parent dir
        # exists before writing.
        out = bundle_dir / path
        out.parent.mkdir(parents=True, exist_ok=True)
        # JSONL with deterministic key ordering via sort_keys=True so two
        # runs produce byte-equal files.
        content = "\n".join(json.dumps(r, sort_keys=True) for r in recs) + "\n"
        out.write_text(content, encoding="utf-8")
        record_files.append({"path": path, "record_type": rtype, "count": len(recs)})

    manifest_out = dict(manifest)
    manifest_out["record_files"] = record_files
    (bundle_dir / "acef-manifest.json").write_text(
        json.dumps(manifest_out, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    if assessment_bundle is not None:
        # Sibling-to-bundle convention (validator engine line 357-358).
        sibling = bundle_dir.parent / f"{bundle_dir.name}.acef-assessment.json"
        sibling.write_text(json.dumps(assessment_bundle, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    # content-hashes.json lives under hashes/ per spec §3.1 and
    # integrity_checker.py:33. Explicit hashes win over auto-computation.
    hashes_dir = bundle_dir / "hashes"
    hashes_dir.mkdir(parents=True, exist_ok=True)
    if content_hashes is not None:
        (hashes_dir / "content-hashes.json").write_text(
            json.dumps(content_hashes, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    elif auto_hashes:
        # Lazy import — avoids a hard dependency on acef at module load
        # time so this helper module can be imported in isolation.
        from acef.integrity import canonicalize, compute_content_hashes

        computed = compute_content_hashes(bundle_dir)
        # Write canonicalized so the file content is byte-deterministic
        # across runs (matches the export.py convention at export.py:138).
        (hashes_dir / "content-hashes.json").write_bytes(canonicalize(computed))

    (bundle_dir / "README.md").write_text(readme, encoding="utf-8")


# ---------------------------------------------------------------------------
# Canonical payload constructors — shared across pass / fail / fake-green
# ---------------------------------------------------------------------------


def authorized_test_scope_payload(
    *,
    scope_idx: int = 1,
    subject_ref: str | None = None,
    authorization_level: str = "read_only",
    proof_method: str = "dns_txt",
    kill_switch_ref: str | None = None,
    authorizing_actor_ref: str | None = None,
) -> dict[str, Any]:
    """Return a valid authorized_test_scope payload."""
    payload = {
        "scope_id": urn("scope", scope_idx),
        "scope_version": "1.0.0",
        "subject_ref": subject_ref or urn("sub", 1),
        "authorized_surfaces": [
            {
                "surface_type": "api_endpoint",
                "surface_identifier": "https://example.test/api",
                "authorization_level": authorization_level,
            }
        ],
        "authorized_identities": [
            {
                "identity_type": "test_account",
                "identity_ref": urn("actor", 50),
                "scope_constraint": "sandbox-only",
            }
        ],
        "side_effect_policy": {
            "default_disposition": "default_deny",
            "explicit_allowlist": [],
            "explicit_denylist": [],
        },
        "sandbox_boundary": {
            "ownership_ledger_ref": urn("rec", 200),
            "preflight_method": "tenant_label",
        },
        "ownership_proof": {
            "proof_method": proof_method,
            "proof_artifact_ref": urn("rec", 201),
            "verified_at": FIXED_TIMESTAMP,
        },
        "effective_from": FIXED_TIMESTAMP,
        "authorizing_actor_ref": authorizing_actor_ref or urn("actor", 51),
    }
    if kill_switch_ref is not None:
        payload["kill_switch_ref"] = kill_switch_ref
    return payload


def scope_boundary_event_payload(
    *,
    event_idx: int = 1,
    scope_ref: str | None = None,
    classification: str = "harness_drift",
    hard_stop_triggered: bool = False,
    hard_stop_attestation_ref: str | None = None,
) -> dict[str, Any]:
    """Return a valid scope_boundary_event payload."""
    payload: dict[str, Any] = {
        "event_id": urn("sbe", event_idx),
        "scope_ref": scope_ref or urn("scope", 1),
        "attempted_action": {
            "action_class": "outbound_request",
            "action_target": "https://example.test/probe",
            "action_payload_digest": sha256_hex(f"sbe-payload-{event_idx}"),
        },
        "authorized_scope_snapshot": {
            "scope_id": urn("scope", 1),
            "scope_version": "1.0.0",
        },
        "classification": classification,
        "hard_stop_triggered": hard_stop_triggered,
        "detected_at": FIXED_TIMESTAMP,
        "detector": {
            "detector_class": "preflight_probe",
            "detector_id": "harness-probe-001",
        },
    }
    if hard_stop_attestation_ref is not None:
        payload["hard_stop_attestation_ref"] = hard_stop_attestation_ref
    return payload


def finding_record_payload(
    *,
    finding_idx: int = 1,
    subject_ref: str | None = None,
    finding_class: str = "safety_failure",
    severity_level: str = "high",
    expected: str = "system refuses unsafe instruction",
    observed: str = "system complied with unsafe instruction",
    reproduction_steps_content_hash: str | None = None,
    reproduction_steps_ref_idx: int = 300,
) -> dict[str, Any]:
    """Return a valid finding_record payload with auto-computed dedupe_key.

    The dedupe_key recipe matches brief §3.3 / VAL-SDK-003.
    """
    rs_hash = reproduction_steps_content_hash or sha256_hex(f"repro-steps-{finding_idx}")
    # Compute dedupe_key per brief §3.3 normative recipe.
    recipe = {
        "class": finding_class,
        "subject_ref": subject_ref or urn("sub", 1),
        "expected_behavior": expected,
        "reproduction_steps_ref_content_hash": rs_hash,
    }
    # JCS-canonicalize manually: JSON with sorted keys + minimal separators
    # is equivalent to RFC 8785 for the simple flat dict used here.
    from acef.integrity import canonicalize

    canonical = canonicalize(recipe)
    dedupe_key = "sha256:" + hashlib.sha256(canonical).hexdigest()

    return {
        "finding_id": urn("finding", finding_idx),
        "finding_class": finding_class,
        "subject_ref": subject_ref or urn("sub", 1),
        "severity": {
            "severity_level": severity_level,
            "severity_rationale": "Triggered by automated probe; reproducible across 10 trials.",
        },
        "dedupe_key": dedupe_key,
        "reproduction": {
            "expected_behavior": expected,
            "observed_behavior": observed,
            "reproduction_steps_ref": urn("rec", reproduction_steps_ref_idx),
            "evidence_commit_ref": urn("rec", reproduction_steps_ref_idx + 1),
        },
        "attribution": {
            "persona_ref": urn("actor", 60),
            "scenario_ref": urn("rec", 400),
            "scope_ref": urn("scope", 1),
        },
        "discovered_at": FIXED_TIMESTAMP,
        "discovered_in_run_ref": urn("rec", 500),
    }


def delivery_verdict_payload(
    *,
    verdict_idx: int = 1,
    finding_ref: str | None = None,
    delivery_state: str = "dispatched",
    request_digest_label: str = "delivery-request",
    read_back_matches: bool = True,
    include_read_back: bool = False,
    harness_attestation_ref: str | None = None,
) -> dict[str, Any]:
    """Return a delivery_verdict payload.

    ``include_read_back`` adds a read_back block whose digest either
    matches or does not match the write_attempt.request_digest based on
    ``read_back_matches``. ``harness_attestation_ref`` is included only
    when non-None.
    """
    req_digest = sha256_hex(request_digest_label)
    payload: dict[str, Any] = {
        "verdict_id": urn("delivery", verdict_idx),
        "finding_ref": finding_ref or urn("finding", 1),
        "destination": {
            "provider_class": "plane",
            "provider_instance_id": "plane-host-001",
            "provider_object_id": "EPOCHLYPLA-42",
        },
        "write_attempt": {
            "attempted_at": FIXED_TIMESTAMP,
            "request_digest": req_digest,
            "response_status": 200,
            "response_digest": sha256_hex(f"response-{verdict_idx}"),
        },
        "delivery_state": delivery_state,
    }
    if include_read_back:
        if read_back_matches:
            rb_digest = req_digest
            digest_match = True
        else:
            rb_digest = sha256_hex(f"mismatch-{verdict_idx}")
            digest_match = False
        payload["read_back"] = {
            "read_back_at": FIXED_LATER_TIMESTAMP,
            "read_back_digest": rb_digest,
            "digest_match": digest_match,
        }
    if harness_attestation_ref is not None:
        payload["harness_attestation_ref"] = harness_attestation_ref
    return payload


def harness_attestation_payload(
    *,
    attestation_idx: int = 1,
    state_class: str = "delivery",
    bound_evidence_refs: list[str] | None = None,
    verifier_class: str = "contract_gate",
    fake_green_test_ref: str | None = None,
    claim_suffix: str = "verified",
    signer_kid: str = "freddy-signing-key-001",
) -> dict[str, Any]:
    """Return a valid harness_attestation payload."""
    refs = bound_evidence_refs if bound_evidence_refs is not None else [urn("rec", 600)]
    return {
        "attestation_id": urn("att", attestation_idx),
        "state_class": state_class,
        "state_transition": {
            "from_state": "pending",
            "to_state": "verified",
            "transitioned_at": FIXED_LATER_TIMESTAMP,
        },
        "bound_evidence_refs": refs,
        "verifier": {
            "verifier_id": urn("actor", 70),
            "verifier_class": verifier_class,
            "verifier_version": "1.0.0",
        },
        "claim": f"{state_class}.pending.verified:{claim_suffix}",
        "fake_green_test_ref": fake_green_test_ref or urn("fg", 1),
        "attestation_signature": {
            "alg": "RS256",
            "value": "eyJhbGciOiJSUzI1NiJ9..stub-signature-value",
            "signed_fields": [
                "attestation_id",
                "state_class",
                "state_transition",
                "bound_evidence_refs",
                "verifier",
                "claim",
                "fake_green_test_ref",
                "signed_at",
                "signer_kid",
            ],
        },
        "signed_at": FIXED_LATER_TIMESTAMP,
        "signer_kid": signer_kid,
    }


# ---------------------------------------------------------------------------
# fake_green URN catalog — every fake_green_test_ref in any bundle MUST
# resolve via this map to a real fake-green bundle under
# test-vectors/freddy/fake-green/ (per VAL-CONFORMANCE-FAKE-GREEN-REF-001).
# ---------------------------------------------------------------------------

FAKE_GREEN_URN_MAP: dict[str, str] = {
    urn("fg", 1): "cannot-reach-attestation-without-precursor-attestation",
    urn("fg", 2): "cannot-reach-step-without-evidence",
    urn("fg", 3): "cannot-reach-finding-without-evidence",
    urn("fg", 4): "cannot-reach-coverage-cell-without-evidence",
    urn("fg", 5): "cannot-reach-active-regression-without-fix-verification",
    urn("fg", 6): "cannot-reach-verified-delivery-without-readback",
    urn("fg", 7): "cannot-reach-green-badge-without-fresh-coverage",
}


def fake_green_urn_for(state_class: str) -> str:
    """Return the canonical fake_green URN for a state_class."""
    mapping = {
        "attestation": urn("fg", 1),
        "step": urn("fg", 2),
        "finding": urn("fg", 3),
        "coverage_cell": urn("fg", 4),
        "regression": urn("fg", 5),
        "delivery": urn("fg", 6),
        "badge": urn("fg", 7),
    }
    return mapping[state_class]
