"""Redaction validation rules.

Covers:
- VAL-VALIDATION-006: redaction_attestation_ref points at unresolvable URN
  → ACEF-078 (NOT ACEF-022 — codex policy).
- VAL-VALIDATION-007: confidentiality != public and no
  redaction_policy_version → ACEF-074.
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

# VAL-VALIDATION-007


def test_non_public_record_missing_redaction_policy_version_emits_acef_074(
    tmp_path: Path,
) -> None:
    """A v1.1 record with confidentiality='redacted' and no
    redaction_policy_version emits ACEF-074.
    """
    bundle = tmp_path / "missing-policy-version"
    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:d0000000-0000-0000-0000-000000000001",
                confidentiality="redacted",
                redaction_policy_version=None,
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-074" in found, (
        f"Expected ACEF-074 for non-public record missing redaction_policy_version; got: {found!r}"
    )


def test_public_record_without_policy_version_clean(tmp_path: Path) -> None:
    """confidentiality='public' makes redaction_policy_version irrelevant
    → no ACEF-074.
    """
    bundle = tmp_path / "public-no-policy"
    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:e0000000-0000-0000-0000-000000000001",
                confidentiality="public",
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    assert "ACEF-074" not in codes(assessment.structural_errors)


def test_non_public_record_with_policy_version_clean(tmp_path: Path) -> None:
    """When the field is populated, no ACEF-074."""
    bundle = tmp_path / "non-public-with-policy"
    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:f0000000-0000-0000-0000-000000000001",
                confidentiality="redacted",
                redaction_policy_version="1.0.0",
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    assert "ACEF-074" not in codes(assessment.structural_errors)


# VAL-VALIDATION-006


def test_unresolvable_redaction_attestation_ref_emits_acef_078_not_022(
    tmp_path: Path,
) -> None:
    """redaction_attestation_ref pointing at a URN that is not an in-bundle
    record fires ACEF-078, and MUST NOT also fire ACEF-022 for the same
    diagnostic (codex policy: ACEF-022 is general dangling-entity-ref;
    ACEF-078 is the specific redaction-attestation case).
    """
    bundle = tmp_path / "bad-attestation-ref"
    nonexistent_urn = "urn:acef:rec:deadbeef-0000-0000-0000-000000000000"
    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:11110000-0000-0000-0000-000000000001",
                confidentiality="redacted",
                redaction_policy_version="1.0.0",
                redaction_attestation_ref=nonexistent_urn,
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-078" in found, f"Expected ACEF-078 for unresolvable redaction_attestation_ref; got: {found!r}"

    # No ACEF-022 about this URN — the redaction-attestation-ref case is
    # carved out and routed exclusively through ACEF-078. (Other ACEF-022
    # diagnostics about unrelated URNs would be fine, but our bundle has
    # no other URN refs, so we assert ACEF-022 is absent.)
    assert "ACEF-022" not in found, (
        f"ACEF-022 must NOT fire for redaction_attestation_ref cases (use ACEF-078); got codes: {found!r}"
    )

    # Diagnostic should name the unresolvable URN.
    messages = [d["message"] for d in assessment.structural_errors if d.get("code") == "ACEF-078"]
    assert any(nonexistent_urn in m for m in messages), (
        f"Expected diagnostic naming {nonexistent_urn!r}; got: {messages!r}"
    )


def test_resolvable_redaction_attestation_ref_clean(tmp_path: Path) -> None:
    """When the URN resolves to an in-bundle record, no ACEF-078."""
    bundle = tmp_path / "good-attestation-ref"
    attestation_id = "urn:acef:rec:11110000-0000-0000-0000-000000000002"
    target_id = "urn:acef:rec:11110000-0000-0000-0000-000000000003"

    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id=attestation_id,
                record_type="event_log",
                confidentiality="public",
                payload={"event_type": "redaction"},
            ),
            base_record(
                record_id=target_id,
                confidentiality="redacted",
                redaction_policy_version="1.0.0",
                redaction_attestation_ref=attestation_id,
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    assert "ACEF-078" not in codes(assessment.structural_errors)


def test_no_redaction_attestation_ref_clean(tmp_path: Path) -> None:
    """When the field is absent entirely, no ACEF-078."""
    bundle = tmp_path / "no-attestation-ref"
    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:11110000-0000-0000-0000-000000000004",
                confidentiality="public",
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    assert "ACEF-078" not in codes(assessment.structural_errors)
