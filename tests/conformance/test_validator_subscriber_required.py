"""VAL-VALIDATION-011: mode-gated required record types enforced.

A bundle with ``analysis_mode: "subscriber"`` lacking ``authorized_test_scope``
OR ``harness_attestation`` emits ACEF-080. "Lacking either" means missing
EITHER type is a violation (not "lacking both").

This rule was implemented as part of F-M1-VALIDATOR-CROSS-RECORD in
:func:`acef.validation.cross_record.enforce_mode_gates`. This test file
adds the EITHER-direction coverage explicitly: subscriber-with-both should
not fire; subscriber-without-scope-only and subscriber-without-attestation-
only should each fire ACEF-080 with the missing type named in the message.

The existing :file:`tests/conformance/test_cross_record_mode_gates.py`
covers the missing-both and present-both cases; this file fills the
single-missing gaps.
"""

from __future__ import annotations

import json
from pathlib import Path

from acef.validation.engine import validate_bundle
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
)


def _harness_attestation_payload() -> dict:
    """Minimal harness_attestation payload accepted by the v1.1 schema."""
    return {
        "attestation_id": "urn:acef:att:33333333-3333-3333-3333-333333333333",
        "state_class": "attestation",
        "state_transition": "active",
        "bound_evidence_refs": [
            "urn:acef:rec:99999999-9999-9999-9999-999999999999",
        ],
        "verifier": {
            "verifier_id": "urn:acef:act:44444444-4444-4444-4444-444444444444",
            "verifier_class": "deterministic",
        },
        "claim": "test attestation",
        "fake_green_test_ref": "urn:acef:fg:55555555-5555-5555-5555-555555555555",
        "signed_at": "2026-01-01T00:00:00Z",
        "signer_kid": "test-key-1",
    }


def _mode_gates_missing_messages(structural_errors: list[dict]) -> list[str]:
    """Filter to ACEF-080 messages produced by cross_record.enforce_mode_gates.

    Those messages contain the substring "missing required mode-gated"
    (per cross_record.py:432) so we can isolate them from this file's
    forbidden-type rule emissions.
    """
    return [
        d["message"]
        for d in structural_errors
        if d.get("code") == "ACEF-080" and "missing required mode-gated" in d.get("message", "")
    ]


def test_subscriber_with_both_required_types_no_acef_080(tmp_path: Path) -> None:
    """authorized_test_scope AND harness_attestation present — no
    mode-gate ACEF-080 from the required-records rule.
    """
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
    missing = _mode_gates_missing_messages(assessment.structural_errors)
    assert not missing, (
        f"Mode-gate required-records ACEF-080 fired even though both "
        f"required types present; got: {missing!r}; all codes: "
        f"{codes(assessment.structural_errors)!r}"
    )


def test_subscriber_missing_only_authorized_test_scope_emits_acef_080(
    tmp_path: Path,
) -> None:
    """harness_attestation present, authorized_test_scope absent → ACEF-080
    naming the missing type.
    """
    bundle = tmp_path / "subscriber-missing-scope-only"

    manifest = base_manifest(analysis_mode="subscriber")
    manifest["record_files"] = [
        {
            "path": "records/harness_attestation.jsonl",
            "record_type": "harness_attestation",
            "count": 1,
        }
    ]
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "records").mkdir(parents=True, exist_ok=True)

    har_rec = base_record(
        record_id="urn:acef:rec:88880000-0000-0000-0000-000000000001",
        record_type="harness_attestation",
        payload=_harness_attestation_payload(),
    )
    (bundle / "records" / "harness_attestation.jsonl").write_text(json.dumps(har_rec) + "\n", encoding="utf-8")
    (bundle / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-080" in found, f"Expected ACEF-080 for missing authorized_test_scope; got: {found!r}"

    missing = _mode_gates_missing_messages(assessment.structural_errors)
    joined = " ".join(missing)
    assert "authorized_test_scope" in joined, f"Diagnostic should name the missing type; got: {missing!r}"
    # And NOT name harness_attestation as missing (it IS present).
    # The diagnostic message format from cross_record.py:432-440 says
    # "missing required mode-gated record types: [...]" — the list
    # shouldn't contain harness_attestation.
    assert "harness_attestation" not in joined.replace(
        "harness_attestation",
        "",
        1,  # allow one mention of "must carry ... harness_attestation"
    ).replace("authorized_test_scope AND at least one harness_attestation", ""), (
        f"Diagnostic should not list harness_attestation as missing when it IS present; got: {missing!r}"
    )


def test_subscriber_missing_only_harness_attestation_emits_acef_080(
    tmp_path: Path,
) -> None:
    """authorized_test_scope present, harness_attestation absent → ACEF-080
    naming the missing type.
    """
    bundle = tmp_path / "subscriber-missing-harness-only"

    manifest = base_manifest(analysis_mode="subscriber")
    manifest["record_files"] = [
        {
            "path": "records/authorized_test_scope.jsonl",
            "record_type": "authorized_test_scope",
            "count": 1,
        }
    ]
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "records").mkdir(parents=True, exist_ok=True)

    ats_rec = base_record(
        record_id="urn:acef:rec:99990000-0000-0000-0000-000000000001",
        record_type="authorized_test_scope",
        payload={},
    )
    (bundle / "records" / "authorized_test_scope.jsonl").write_text(json.dumps(ats_rec) + "\n", encoding="utf-8")
    (bundle / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-080" in found, f"Expected ACEF-080 for missing harness_attestation; got: {found!r}"

    missing = _mode_gates_missing_messages(assessment.structural_errors)
    joined = " ".join(missing)
    assert "harness_attestation" in joined, f"Diagnostic should name the missing type; got: {missing!r}"


def test_subscriber_missing_both_emits_acef_080_naming_both(
    tmp_path: Path,
) -> None:
    """Missing-both case: ACEF-080 diagnostic names both required types.

    Covers the same logic as the existing
    test_cross_record_mode_gates.test_subscriber_mode_missing_both...
    but lives here for full single/double coverage in one place.
    """
    bundle = tmp_path / "subscriber-missing-both"

    manifest = base_manifest(analysis_mode="subscriber")
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "records").mkdir(parents=True, exist_ok=True)
    rec = base_record(
        record_id="urn:acef:rec:aaaa0000-0000-0000-0000-000000000001",
        record_type="risk_register",
    )
    manifest["record_files"] = [
        {
            "path": "records/all.jsonl",
            "record_type": "risk_register",
            "count": 1,
        }
    ]
    (bundle / "records" / "all.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
    (bundle / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-080" in found, found

    missing = _mode_gates_missing_messages(assessment.structural_errors)
    joined = " ".join(missing)
    assert "authorized_test_scope" in joined
    assert "harness_attestation" in joined


def test_non_subscriber_modes_no_required_types_check(tmp_path: Path) -> None:
    """public_artifact / canary / unattributed_artifact bundles do NOT
    require authorized_test_scope or harness_attestation.

    A bundle in public_artifact mode without these types should not emit
    the mode-gate required-records ACEF-080.
    """
    bundle = tmp_path / "public-artifact-no-required"

    manifest = base_manifest(analysis_mode="public_artifact")
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "records").mkdir(parents=True, exist_ok=True)
    rec = base_record(
        record_id="urn:acef:rec:bbbb0000-0000-0000-0000-000000000001",
        record_type="risk_register",
    )
    manifest["record_files"] = [
        {
            "path": "records/all.jsonl",
            "record_type": "risk_register",
            "count": 1,
        }
    ]
    (bundle / "records" / "all.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
    (bundle / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assessment = validate_bundle(bundle)
    missing = _mode_gates_missing_messages(assessment.structural_errors)
    assert not missing, f"public_artifact mode should not require subscriber records; got: {missing!r}"
