"""VAL-VALIDATION-009: state_class outside taxonomy emits ACEF-076.

A ``harness_attestation`` (or any other record with a ``payload.state_class``
field) whose ``state_class`` is not in the seven-entry v1.1 taxonomy
(``step, finding, coverage_cell, regression, delivery, badge, attestation``)
emits ACEF-076. The same code fires when the state_class is known and the
taxonomy entry's ``fake_green_test_required`` is true but the record lacks
``payload.fake_green_test_ref`` — per the ACEF-076 description
("state_class record lacks fake-green test reference") and brief §3.6.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acef.validation.engine import validate_bundle
from acef.validation.v1_1_rules import (
    enforce_state_class_taxonomy,
    load_state_class_taxonomy,
)
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
)

# The seven hard-coded taxonomy entries per
# acef-conventions/v1.1/state-class-taxonomy.json.
TAXONOMY_IDS = (
    "step",
    "finding",
    "coverage_cell",
    "regression",
    "delivery",
    "badge",
    "attestation",
)


def _harness_attestation_payload(
    *,
    state_class: str,
    include_fake_green_ref: bool = True,
) -> dict:
    """Minimal harness_attestation payload accepted by v1.1 schema."""
    p: dict = {
        "attestation_id": "urn:acef:att:33333333-3333-3333-3333-333333333333",
        "state_class": state_class,
        "state_transition": "active",
        "bound_evidence_refs": [
            "urn:acef:rec:99999999-9999-9999-9999-999999999999",
        ],
        "verifier": {
            "verifier_id": "urn:acef:act:44444444-4444-4444-4444-444444444444",
            "verifier_class": "deterministic",
        },
        "claim": "test attestation",
        "signed_at": "2026-01-01T00:00:00Z",
        "signer_kid": "test-key-1",
    }
    if include_fake_green_ref:
        p["fake_green_test_ref"] = "urn:acef:fg:55555555-5555-5555-5555-555555555555"
    return p


# ---------------------------------------------------------------------------
# Function-level tests (direct lint of records list)
# ---------------------------------------------------------------------------


def test_taxonomy_loads_seven_entries() -> None:
    """The v1.1 taxonomy loader returns exactly the seven hard-coded IDs."""
    tax = load_state_class_taxonomy()
    assert set(tax.keys()) == set(TAXONOMY_IDS), f"Expected seven taxonomy entries; got: {sorted(tax.keys())!r}"


@pytest.mark.parametrize("state_class", list(TAXONOMY_IDS))
def test_each_taxonomy_id_with_fake_green_ref_no_diagnostic(
    state_class: str,
) -> None:
    """Each of the seven taxonomy IDs with a fake_green_test_ref present
    produces no ACEF-076.
    """
    rec = base_record(
        record_id=f"urn:acef:rec:11110000-0000-0000-0000-{state_class[:8]:>08}".replace(" ", "0"),
        record_type="harness_attestation",
        payload=_harness_attestation_payload(state_class=state_class),
    )
    diags = enforce_state_class_taxonomy([rec])
    found_codes = [d.code for d in diags]
    assert "ACEF-076" not in found_codes, (
        f"Valid state_class {state_class!r} with fake_green_test_ref should not emit ACEF-076; got: {found_codes!r}"
    )


def test_unknown_state_class_emits_acef_076() -> None:
    """A made-up state_class outside the seven entries emits ACEF-076."""
    rec = base_record(
        record_id="urn:acef:rec:22220000-0000-0000-0000-000000000001",
        record_type="harness_attestation",
        payload=_harness_attestation_payload(state_class="made_up_class"),
    )
    diags = enforce_state_class_taxonomy([rec])
    found_codes = [d.code for d in diags]
    assert "ACEF-076" in found_codes, found_codes
    assert any("made_up_class" in d.message for d in diags), (
        f"Diagnostic should name the rejected state_class; messages: {[d.message for d in diags]!r}"
    )


@pytest.mark.parametrize("state_class", list(TAXONOMY_IDS))
def test_known_state_class_missing_fake_green_ref_emits_acef_076(
    state_class: str,
) -> None:
    """Every taxonomy entry sets fake_green_test_required: true, so
    omitting the ref triggers ACEF-076 for each.
    """
    rec = base_record(
        record_id=f"urn:acef:rec:33330000-0000-0000-0000-{state_class[:8]:>08}".replace(" ", "0"),
        record_type="harness_attestation",
        payload=_harness_attestation_payload(state_class=state_class, include_fake_green_ref=False),
    )
    diags = enforce_state_class_taxonomy([rec])
    found_codes = [d.code for d in diags]
    assert "ACEF-076" in found_codes, (
        f"state_class={state_class!r} without fake_green_test_ref should emit ACEF-076; got: {found_codes!r}"
    )


def test_record_without_state_class_field_no_diagnostic() -> None:
    """Records lacking a state_class field are ignored (the field is
    conditional, not absolute-required for non-attestation records).
    """
    rec = base_record(
        record_id="urn:acef:rec:44440000-0000-0000-0000-000000000001",
        record_type="risk_register",
        payload={"some": "data"},
    )
    diags = enforce_state_class_taxonomy([rec])
    assert [d.code for d in diags] == []


def test_empty_string_state_class_ignored() -> None:
    """A record whose state_class is an empty string is ignored (treated
    as 'not set').
    """
    rec = base_record(
        record_id="urn:acef:rec:55550000-0000-0000-0000-000000000001",
        record_type="harness_attestation",
        payload={"state_class": "", "fake_green_test_ref": "urn:x"},
    )
    diags = enforce_state_class_taxonomy([rec])
    assert "ACEF-076" not in [d.code for d in diags]


def test_state_class_at_envelope_level_also_checked() -> None:
    """A record carrying state_class at the envelope level (forward-compat)
    is checked the same as payload-level.
    """
    rec = base_record(
        record_id="urn:acef:rec:66660000-0000-0000-0000-000000000001",
        record_type="harness_attestation",
        payload={"fake_green_test_ref": "urn:x"},
    )
    rec["state_class"] = "bogus_envelope_class"
    diags = enforce_state_class_taxonomy([rec])
    assert "ACEF-076" in [d.code for d in diags]


# ---------------------------------------------------------------------------
# Engine-level tests
# ---------------------------------------------------------------------------


def _write_bundle_with_harness(
    bundle_dir: Path,
    *,
    harness_payload: dict,
) -> None:
    """Write a minimal v1.1 bundle with one harness_attestation record."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "records").mkdir(parents=True, exist_ok=True)

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

    ats_rec = base_record(
        record_id="urn:acef:rec:77770000-0000-0000-0000-000000000001",
        record_type="authorized_test_scope",
        payload={},
    )
    har_rec = base_record(
        record_id="urn:acef:rec:77770000-0000-0000-0000-000000000002",
        record_type="harness_attestation",
        payload=harness_payload,
    )

    (bundle_dir / "records" / "authorized_test_scope.jsonl").write_text(json.dumps(ats_rec) + "\n", encoding="utf-8")
    (bundle_dir / "records" / "harness_attestation.jsonl").write_text(json.dumps(har_rec) + "\n", encoding="utf-8")
    (bundle_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_engine_unknown_state_class_emits_acef_076(tmp_path: Path) -> None:
    """End-to-end: a v1.1 bundle with an unknown state_class triggers
    ACEF-076 via the engine.
    """
    bundle = tmp_path / "unknown-state-class"
    _write_bundle_with_harness(
        bundle,
        harness_payload=_harness_attestation_payload(state_class="hallucinated"),
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-076" in found, f"Expected ACEF-076 for unknown state_class; got: {found!r}"


def test_engine_known_state_class_with_fake_green_ref_no_acef_076(
    tmp_path: Path,
) -> None:
    """End-to-end: a valid state_class with fake_green_test_ref emits no
    ACEF-076 from this validator family. (Other code paths may emit
    ACEF-076 if a fake-green-required record violates other rules; this
    test isolates the taxonomy-check rule by passing a clean payload.)
    """
    bundle = tmp_path / "valid-state-class"
    _write_bundle_with_harness(
        bundle,
        harness_payload=_harness_attestation_payload(state_class="attestation"),
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-076" not in found, (
        f"Valid state_class with fake_green_test_ref should not emit ACEF-076; got: {found!r}"
    )


def test_engine_v1_0_bundle_with_bogus_state_class_no_acef_076(
    tmp_path: Path,
) -> None:
    """Regression: a v1.0-declared bundle does not trigger the v1.1
    taxonomy check (gated on schema_version == 'v1.1').

    A v1.0 bundle declaring harness_attestation will already emit ACEF-003
    (unknown record_type) because the v1.0 schema registry doesn't know
    that type — but it MUST NOT emit ACEF-076 from the v1.1 taxonomy
    enforcer.
    """
    bundle = tmp_path / "v1-0-state-class"
    manifest = base_manifest(core_version="1.0.0")
    manifest["record_files"] = [
        {
            "path": "records/all.jsonl",
            "record_type": "risk_register",
            "count": 1,
        }
    ]
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "records").mkdir(parents=True, exist_ok=True)
    rec = base_record(
        record_id="urn:acef:rec:88880000-0000-0000-0000-000000000001",
        record_type="risk_register",
        payload={"state_class": "completely_bogus"},
    )
    (bundle / "records" / "all.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
    (bundle / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-076" not in found, f"v1.0 bundle should not trigger v1.1 ACEF-076; got: {found!r}"
