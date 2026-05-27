"""Conformance tests for VAL-VARIANT-003 — parent-schema oneOf enforcement.

VAL-VARIANT-003 mandate (per contract.md, area VARIANT):
    When a parent record-type schema in v1.1/ has been extended with a oneOf
    block keyed on the discriminator field, a record whose payload sets the
    discriminator value must satisfy the matching oneOf branch.

This feature (F-M1-VARIANTS) satisfies the "at least 2 of 5" threshold by
extending:
    1. transparency_disclosure.schema.json (v1.1 overlay) — V4 badge_state
       variant on /payload/variant = "verification_badge" (brief §4.4)
    2. evidence_gap.schema.json (v1.1 overlay) — V5 evidence_freshness_window
       variant on /payload/gap_subtype = "freshness_window" (brief §4.5)

For each enforced variant, this test file exercises:
    POSITIVE — a payload setting the discriminator AND providing every
               variant-required field validates clean.
    NEGATIVE — a payload setting the discriminator but OMITTING one variant-
               required field fails validation with a meaningful error
               (the conditional branch does not match).
    DISJOINT — a payload that does NOT set the discriminator continues to
               validate clean (the conditional does not over-constrain
               unrelated records).
"""

from __future__ import annotations

import pytest

from acef.schemas.registry import validate_record_payload

# ---------------------------------------------------------------------------
# Variant 1: transparency_disclosure / V4 badge_state
# Discriminator: /payload/variant == "verification_badge"
# Required-on-branch (brief §4.4): badge_id, subject_ref, page_state,
#   integrity_state, evidence_chain_root_ref, freshness_state_ref.
# Conditional: provisional_reason required when page_state="provisional";
#   public_artifact_link required when page_state in {green, provisional}.
# ---------------------------------------------------------------------------


def _verification_badge_positive_payload() -> dict:
    return {
        "disclosure_type": "transparency_report",
        "variant": "verification_badge",
        "badge_id": "urn:acef:badge:11111111-1111-1111-1111-111111111111",
        "subject_ref": "urn:acef:subject:22222222-2222-2222-2222-222222222222",
        "page_state": "green",
        "integrity_state": "verified",
        "evidence_chain_root_ref": "urn:acef:rec:33333333-3333-3333-3333-333333333333",
        "freshness_state_ref": "urn:acef:rec:44444444-4444-4444-4444-444444444444",
        "public_artifact_link": "https://acef.ai/public/badge/11111111",
    }


def test_verification_badge_positive_validates_clean() -> None:
    errors = validate_record_payload(
        _verification_badge_positive_payload(),
        "transparency_disclosure",
        "v1.1",
    )
    assert errors == [], (
        f"Positive verification_badge payload should validate clean; got {[e.message for e in errors]!r}"
    )


@pytest.mark.parametrize(
    "missing_field",
    [
        "badge_id",
        "subject_ref",
        "page_state",
        "integrity_state",
        "evidence_chain_root_ref",
        "freshness_state_ref",
    ],
)
def test_verification_badge_missing_branch_required_field_fails(
    missing_field: str,
) -> None:
    """A verification_badge payload that omits a branch-required field
    (per brief §4.4) must fail the conditional branch."""
    payload = _verification_badge_positive_payload()
    del payload[missing_field]
    errors = validate_record_payload(payload, "transparency_disclosure", "v1.1")
    assert errors, f"Negative payload missing {missing_field!r} should fail the conditional branch; got zero errors"


def test_verification_badge_provisional_without_reason_fails() -> None:
    """Brief §4.4: provisional_reason is REQUIRED when page_state='provisional'."""
    payload = _verification_badge_positive_payload()
    payload["page_state"] = "provisional"
    # public_artifact_link already set; provisional_reason intentionally absent.
    errors = validate_record_payload(payload, "transparency_disclosure", "v1.1")
    assert errors, (
        "page_state='provisional' without provisional_reason should fail (brief §4.4 TC-FRD-V4-N2); got zero errors"
    )


def test_verification_badge_provisional_with_reason_validates() -> None:
    """Positive: provisional state with reason + public_artifact_link validates."""
    payload = _verification_badge_positive_payload()
    payload["page_state"] = "provisional"
    payload["provisional_reason"] = "partial_coverage"
    errors = validate_record_payload(payload, "transparency_disclosure", "v1.1")
    assert errors == [], (
        f"Positive provisional verification_badge should validate clean; got {[e.message for e in errors]!r}"
    )


def test_verification_badge_green_without_public_artifact_link_fails() -> None:
    """Brief §4.4: public_artifact_link REQUIRED when page_state is green or provisional."""
    payload = _verification_badge_positive_payload()
    # page_state already 'green' in positive baseline.
    del payload["public_artifact_link"]
    errors = validate_record_payload(payload, "transparency_disclosure", "v1.1")
    assert errors, "page_state='green' without public_artifact_link should fail (brief §4.4); got zero errors"


def test_verification_badge_red_without_public_artifact_link_validates() -> None:
    """Brief §4.4: public_artifact_link only required for green/provisional.
    A 'red' page_state may legitimately omit public_artifact_link."""
    payload = _verification_badge_positive_payload()
    payload["page_state"] = "red"
    del payload["public_artifact_link"]
    errors = validate_record_payload(payload, "transparency_disclosure", "v1.1")
    assert errors == [], (
        f"page_state='red' without public_artifact_link should validate clean; got {[e.message for e in errors]!r}"
    )


def test_transparency_disclosure_without_verification_badge_variant_still_valid() -> None:
    """The conditional MUST NOT over-constrain records that don't set the
    discriminator — a plain transparency_report continues to validate
    without verification_badge fields."""
    payload = {
        "disclosure_type": "transparency_report",
        "title": "Quarterly Transparency Report",
    }
    errors = validate_record_payload(payload, "transparency_disclosure", "v1.1")
    assert errors == [], (
        "Plain transparency_disclosure without /payload/variant should "
        f"validate clean; got {[e.message for e in errors]!r}"
    )


# ---------------------------------------------------------------------------
# Variant 2: evidence_gap / V5 evidence_freshness_window
# Discriminator: /payload/gap_subtype == "freshness_window" (brief §4.5)
# Required-on-branch: window_start, window_end, refresh_due_at,
#                     current_freshness_state.
# ---------------------------------------------------------------------------


def _freshness_window_positive_payload() -> dict:
    return {
        "missing_record_type": "evaluation_report",
        "reason": "scheduled",
        "gap_subtype": "freshness_window",
        "window_start": "2026-05-01T00:00:00Z",
        "window_end": "2026-06-01T00:00:00Z",
        "refresh_due_at": "2026-06-15T00:00:00Z",
        "current_freshness_state": "fresh",
    }


def test_freshness_window_positive_validates_clean() -> None:
    errors = validate_record_payload(
        _freshness_window_positive_payload(),
        "evidence_gap",
        "v1.1",
    )
    assert errors == [], (
        f"Positive evidence_freshness_window payload should validate clean; got {[e.message for e in errors]!r}"
    )


@pytest.mark.parametrize(
    "missing_field",
    ["window_start", "window_end", "refresh_due_at", "current_freshness_state"],
)
def test_freshness_window_missing_branch_required_field_fails(
    missing_field: str,
) -> None:
    """An evidence_freshness_window payload that omits a branch-required
    field must fail the conditional branch."""
    payload = _freshness_window_positive_payload()
    del payload[missing_field]
    errors = validate_record_payload(payload, "evidence_gap", "v1.1")
    assert errors, f"Negative payload missing {missing_field!r} should fail the conditional branch; got zero errors"


def test_evidence_gap_without_gap_subtype_still_valid() -> None:
    """The conditional MUST NOT over-constrain records that don't set the
    discriminator — a plain evidence_gap with just missing_record_type +
    reason continues to validate."""
    payload = {
        "missing_record_type": "robustness_assessment",
        "reason": "lifecycle_phase_not_reached",
    }
    errors = validate_record_payload(payload, "evidence_gap", "v1.1")
    assert errors == [], (
        f"Plain evidence_gap without /payload/gap_subtype should validate clean; got {[e.message for e in errors]!r}"
    )


# ---------------------------------------------------------------------------
# Resolve check: cross-validation that the variant registry's declared
# discriminator field/value for the two enforced variants matches what the
# schemas actually enforce. Guards against future drift between registry
# and parent schema.
# ---------------------------------------------------------------------------


def test_v1_1_enforced_variants_align_with_registry() -> None:
    """The schemas extended by this feature must accept payloads whose
    discriminator value matches the value declared in the v1.1 registry."""
    from acef.schemas.registry import resolve_variant

    # V4 badge_state → /payload/variant = "verification_badge"
    vb = resolve_variant("badge_state", "v1.1")
    assert vb is not None
    assert vb["record_type"] == "transparency_disclosure"
    assert vb["discriminator_field"] == "/payload/variant"
    assert vb["discriminator_value"] == "verification_badge"

    # V5 evidence_freshness_window → /payload/gap_subtype = "freshness_window"
    ef = resolve_variant("evidence_freshness_window", "v1.1")
    assert ef is not None
    assert ef["record_type"] == "evidence_gap"
    assert ef["discriminator_field"] == "/payload/gap_subtype"
    assert ef["discriminator_value"] == "freshness_window"
