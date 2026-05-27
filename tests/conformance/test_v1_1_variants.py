"""Conformance tests for VAL-VARIANT-004 — parent-schema oneOf enforcement.

VAL-VARIANT-004 mandate (per contract.md, area VARIANT):
    When a parent record-type schema in v1.1/ has been extended with a oneOf
    block keyed on the discriminator field, a record whose payload sets the
    discriminator value must satisfy the matching oneOf branch.

This feature (F-M1-VARIANTS) satisfies the "at least 2 of 5" threshold by
extending:
    1. transparency_disclosure.schema.json (v1.1 overlay) — verification_badge
       variant on /payload/disclosure_subtype
    2. evidence_gap.schema.json (v1.1 overlay) — evidence_freshness_window
       variant on /payload/gap_class

For each enforced variant, this test file exercises:
    POSITIVE — a payload setting the discriminator AND providing every
               variant-required field validates clean.
    NEGATIVE — a payload setting the discriminator but OMITTING one variant-
               required field fails validation with a meaningful error
               (the oneOf branch does not match).
    DISJOINT — a payload that does NOT set the discriminator continues to
               validate clean (the oneOf does not over-constrain unrelated
               records).
"""

from __future__ import annotations

import pytest

from acef.schemas.registry import validate_record_payload

# ---------------------------------------------------------------------------
# Variant 1: transparency_disclosure / verification_badge
# Discriminator: /payload/disclosure_subtype == "verification_badge"
# Required-on-branch: badge_id, claim, expires_at, signing_kid
# ---------------------------------------------------------------------------


def _verification_badge_positive_payload() -> dict:
    return {
        "disclosure_type": "transparency_report",
        "disclosure_subtype": "verification_badge",
        "badge_id": "urn:acef:badge:11111111-1111-1111-1111-111111111111",
        "claim": "Bundle X has been independently verified.",
        "expires_at": "2027-05-27T00:00:00Z",
        "signing_kid": "verifier-key-2026-05",
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
    ["badge_id", "claim", "expires_at", "signing_kid"],
)
def test_verification_badge_missing_branch_required_field_fails(
    missing_field: str,
) -> None:
    """A verification_badge payload that omits a branch-required field
    must fail the oneOf branch."""
    payload = _verification_badge_positive_payload()
    del payload[missing_field]
    errors = validate_record_payload(payload, "transparency_disclosure", "v1.1")
    assert errors, f"Negative payload missing {missing_field!r} should fail oneOf branch; got zero errors"


def test_transparency_disclosure_without_subtype_still_valid() -> None:
    """The oneOf MUST NOT over-constrain records that don't set the
    discriminator — the publication_evidence variant or a plain
    transparency_report continues to validate without verification_badge
    fields."""
    payload = {
        "disclosure_type": "transparency_report",
        "title": "Quarterly Transparency Report",
    }
    errors = validate_record_payload(payload, "transparency_disclosure", "v1.1")
    assert errors == [], (
        "Plain transparency_disclosure without disclosure_subtype should "
        f"validate clean; got {[e.message for e in errors]!r}"
    )


# ---------------------------------------------------------------------------
# Variant 2: evidence_gap / evidence_freshness_window
# Discriminator: /payload/gap_class == "evidence_freshness_window"
# Required-on-branch: window_start, window_end, refresh_due_at,
#                     current_freshness_state
# ---------------------------------------------------------------------------


def _freshness_window_positive_payload() -> dict:
    return {
        "missing_record_type": "evaluation_report",
        "reason": "scheduled",
        "gap_class": "evidence_freshness_window",
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
    field must fail the oneOf branch."""
    payload = _freshness_window_positive_payload()
    del payload[missing_field]
    errors = validate_record_payload(payload, "evidence_gap", "v1.1")
    assert errors, f"Negative payload missing {missing_field!r} should fail oneOf branch; got zero errors"


def test_regression_definition_branch_requires_its_fields() -> None:
    """The regression_definition branch on evidence_gap requires
    regression_id, surface_class, baseline_evidence_ref. A payload that sets
    /payload/gap_class = 'regression_definition' but omits these fails."""
    # Positive
    positive = {
        "missing_record_type": "evaluation_report",
        "reason": "in_progress",
        "gap_class": "regression_definition",
        "regression_id": "urn:acef:reg:22222222-2222-2222-2222-222222222222",
        "surface_class": "voice_rubric",
        "baseline_evidence_ref": "urn:acef:rec:33333333-3333-3333-3333-333333333333",
    }
    errors = validate_record_payload(positive, "evidence_gap", "v1.1")
    assert errors == [], (
        f"Positive regression_definition payload should validate clean; got {[e.message for e in errors]!r}"
    )

    # Negative — omit baseline_evidence_ref
    negative = dict(positive)
    del negative["baseline_evidence_ref"]
    errors = validate_record_payload(negative, "evidence_gap", "v1.1")
    assert errors, (
        "Negative regression_definition payload missing baseline_evidence_ref should fail oneOf branch; got zero errors"
    )


def test_evidence_gap_without_gap_class_still_valid() -> None:
    """The oneOf MUST NOT over-constrain records that don't set the
    discriminator — a plain evidence_gap with just missing_record_type +
    reason continues to validate."""
    payload = {
        "missing_record_type": "robustness_assessment",
        "reason": "lifecycle_phase_not_reached",
    }
    errors = validate_record_payload(payload, "evidence_gap", "v1.1")
    assert errors == [], (
        f"Plain evidence_gap without gap_class should validate clean; got {[e.message for e in errors]!r}"
    )


# ---------------------------------------------------------------------------
# Resolve check: VAL-VARIANT-004 requires that the variant registry
# successfully points to schemas whose discriminator field matches what
# the registry declares. This is a sanity cross-check between registry +
# enforcing schema.
# ---------------------------------------------------------------------------


def test_v1_1_enforced_variants_align_with_registry() -> None:
    """The schemas extended by this feature must accept payloads whose
    discriminator value matches the value declared in the v1.1 registry.
    This guards against future drift between registry and parent schema."""
    from acef.schemas.registry import resolve_variant

    # verification_badge → /payload/disclosure_subtype = "verification_badge"
    vb = resolve_variant("verification_badge", "v1.1")
    assert vb is not None
    assert vb["discriminator_field"] == "/payload/disclosure_subtype"
    assert vb["discriminator_value"] == "verification_badge"

    # evidence_freshness_window → /payload/gap_class = "evidence_freshness_window"
    ef = resolve_variant("evidence_freshness_window", "v1.1")
    assert ef is not None
    assert ef["discriminator_field"] == "/payload/gap_class"
    assert ef["discriminator_value"] == "evidence_freshness_window"
