"""VAL-VALIDATION-VERSION-COMPAT-002: subscriber mode missing required records → ACEF-080.

A v1.1 bundle declaring `analysis_mode: "subscriber"` MUST include at
least one `authorized_test_scope` AND one `harness_attestation` record.
Missing either emits ACEF-080.
"""

from __future__ import annotations

from pathlib import Path

from acef.validation.engine import validate_bundle
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
    write_bundle,
)


def _harness_attestation_payload() -> dict:
    """A payload that the v1.1 schema accepts (per
    tests/unit/test_validator_version_selection.py:95-113).
    """
    return {
        "attestation_id": "urn:acef:att:33333333-3333-3333-3333-333333333333",
        "state_class": "attestation",
        "state_transition": "active",
        "bound_evidence_refs": ["urn:acef:rec:99999999-9999-9999-9999-999999999999"],
        "verifier": {
            "verifier_id": "urn:acef:act:44444444-4444-4444-4444-444444444444",
            "verifier_class": "deterministic",
        },
        "claim": "test attestation",
        "fake_green_test_ref": "urn:acef:fg:55555555-5555-5555-5555-555555555555",
        "signed_at": "2026-01-01T00:00:00Z",
        "signer_kid": "test-key-1",
    }


def test_subscriber_mode_missing_both_required_types_emits_acef_080(
    tmp_path: Path,
) -> None:
    """analysis_mode=subscriber + no authorized_test_scope AND no
    harness_attestation → ACEF-080.
    """
    bundle = tmp_path / "subscriber-missing-both"
    write_bundle(
        bundle,
        manifest=base_manifest(analysis_mode="subscriber"),
        records=[
            base_record(
                record_id="urn:acef:rec:55550000-0000-0000-0000-000000000001",
                record_type="risk_register",
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-080" in found, f"Expected ACEF-080 for subscriber-mode missing required records; got: {found!r}"

    messages = [d["message"] for d in assessment.structural_errors if d.get("code") == "ACEF-080"]
    joined = " ".join(messages)
    # Both required types should be named in the diagnostic.
    assert "authorized_test_scope" in joined, joined
    assert "harness_attestation" in joined, joined


def test_subscriber_mode_missing_harness_only_emits_acef_080(tmp_path: Path) -> None:
    """authorized_test_scope present but harness_attestation absent → ACEF-080."""
    bundle = tmp_path / "subscriber-missing-harness"
    # Use separate record files because the JSONL writer expects one
    # record_type per file (see helpers note about ACEF-025).
    manifest = base_manifest(analysis_mode="subscriber")
    manifest["record_files"] = [
        {
            "path": "records/authorized_test_scope.jsonl",
            "record_type": "authorized_test_scope",
            "count": 1,
        },
    ]
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "records").mkdir(parents=True, exist_ok=True)
    (bundle / "records" / "authorized_test_scope.jsonl").write_text(
        '{"record_id": "urn:acef:rec:66660000-0000-0000-0000-000000000001",'
        '"record_type": "authorized_test_scope","provisions_addressed": [],'
        '"timestamp": "2026-01-01T00:00:00Z","lifecycle_phase": "development",'
        '"collector": {"name": "t", "version": "1"},'
        '"obligation_role": "provider","confidentiality": "public",'
        '"trust_level": "self-attested","entity_refs": {"subject_refs": [],'
        '"component_refs": [],"dataset_refs": [],"actor_refs": []},'
        '"payload": {},"attachments": []}\n',
        encoding="utf-8",
    )
    import json

    (bundle / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-080" in found, f"Expected ACEF-080 for subscriber missing harness_attestation; got: {found!r}"

    messages = [d["message"] for d in assessment.structural_errors if d.get("code") == "ACEF-080"]
    joined = " ".join(messages)
    assert "harness_attestation" in joined, f"Diagnostic should name the missing type; got: {messages!r}"


def test_subscriber_mode_with_both_required_types_no_acef_080_for_mode_gates(
    tmp_path: Path,
) -> None:
    """When both required record types are present, the mode-gate check
    does not fire ACEF-080. (Other ACEF-080 sources — like authority-
    matrix violations — may still fire from unrelated content; this test
    builds a bundle with no disposition records, so no other source applies.)
    """
    import json

    bundle = tmp_path / "subscriber-both-present"

    manifest = base_manifest(analysis_mode="subscriber")
    manifest["record_files"] = [
        {
            "path": "records/authorized_test_scope.jsonl",
            "record_type": "authorized_test_scope",
            "count": 1,
        },
        {
            "path": "records/harness_attestation.jsonl",
            "record_type": "harness_attestation",
            "count": 1,
        },
    ]
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "records").mkdir(parents=True, exist_ok=True)

    ats_rec = base_record(
        record_id="urn:acef:rec:77770000-0000-0000-0000-000000000001",
        record_type="authorized_test_scope",
        payload={},
    )
    har_rec = base_record(
        record_id="urn:acef:rec:77770000-0000-0000-0000-000000000002",
        record_type="harness_attestation",
        payload=_harness_attestation_payload(),
    )
    (bundle / "records" / "authorized_test_scope.jsonl").write_text(json.dumps(ats_rec) + "\n", encoding="utf-8")
    (bundle / "records" / "harness_attestation.jsonl").write_text(json.dumps(har_rec) + "\n", encoding="utf-8")
    (bundle / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)

    # The mode-gates check should NOT contribute an ACEF-080. There may
    # be other ACEF-080 sources (none in this bundle), so we assert the
    # diagnostic message does not mention "missing required mode-gated".
    mode_gate_messages = [
        d["message"]
        for d in assessment.structural_errors
        if d.get("code") == "ACEF-080" and "missing required mode-gated" in d.get("message", "")
    ]
    assert not mode_gate_messages, (
        f"Mode-gate ACEF-080 fired even though both required types present; "
        f"got: {mode_gate_messages!r}; all codes: {found!r}"
    )


def test_no_analysis_mode_no_mode_gates_check(tmp_path: Path) -> None:
    """Without analysis_mode set, no mode-gate ACEF-080 even with no
    authorized_test_scope or harness_attestation records.
    """
    bundle = tmp_path / "no-mode"
    write_bundle(
        bundle,
        manifest=base_manifest(analysis_mode=None),
        records=[
            base_record(
                record_id="urn:acef:rec:88880000-0000-0000-0000-000000000001",
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    mode_gate_messages = [
        d["message"]
        for d in assessment.structural_errors
        if d.get("code") == "ACEF-080" and "missing required mode-gated" in d.get("message", "")
    ]
    assert not mode_gate_messages, f"Mode-gate ACEF-080 fired without analysis_mode set; got: {mode_gate_messages!r}"
