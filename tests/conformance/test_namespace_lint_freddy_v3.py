"""VAL-VALIDATION-012: namespace_lints recognizes
``x-freddy/voice-rubric-emission`` and emits ACEF-077.

A v1.1 bundle containing a record whose record_type is
``x-freddy/voice-rubric-emission`` with a non-empty
``claim_lexicon_scan_result.tokens_found`` array AND
``rejection_state: "accepted"`` (or, alternatively, missing
``harness_attestation_ref``) must emit ACEF-077.

The bundled freddy lint is auto-registered when the submodule
``acef.validation.namespace_lints.bundled_freddy`` is imported. The engine
imports it as part of the v1.1 wiring; tests also import it explicitly to
make the registration guarantee load-order-independent.
"""

from __future__ import annotations

from pathlib import Path

# Explicit import to guarantee registration even if test-collection order
# does not exercise the engine's import first.
import acef.validation.namespace_lints.bundled_freddy  # noqa: F401
from acef.validation.engine import validate_bundle
from acef.validation.namespace_lints import list_registered_namespaces
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
    write_bundle,
)

FREDDY_NS = "x-freddy/voice-rubric-emission"


def test_freddy_voice_rubric_emission_namespace_is_registered() -> None:
    """Bundled freddy lint registers the namespace on import."""
    assert FREDDY_NS in list_registered_namespaces()


def _voice_rubric_payload(
    *,
    tokens_found: list[str],
    rejection_state: str = "accepted",
    include_harness_attestation_ref: bool = False,
) -> dict:
    """Construct a minimal voice-rubric-emission payload per brief §5.2."""
    payload: dict = {
        "emission_id": "urn:freddy:emi:00000000-0000-0000-0000-000000000001",
        "rubric_id": "urn:freddy:rub:00000000-0000-0000-0000-000000000001",
        "rubric_version": "1.0.0",
        "redaction_attestation_ref": ("urn:acef:rec:99000000-0000-0000-0000-000000000099"),
        "styled_prose_digest": ("sha256:0000000000000000000000000000000000000000000000000000000000000001"),
        "claim_lexicon_scan_result": {
            "tokens_found": tokens_found,
            "scan_timestamp": "2026-01-01T00:00:00Z",
            "scanner_version": "1.0.0",
        },
        "rejection_state": rejection_state,
    }
    if include_harness_attestation_ref:
        payload["harness_attestation_ref"] = "urn:acef:rec:88000000-0000-0000-0000-000000000088"
    return payload


def test_banned_token_with_accepted_state_emits_acef_077(tmp_path: Path) -> None:
    """tokens_found non-empty AND rejection_state=accepted AND no
    harness_attestation_ref → ACEF-077 (per brief §5.2 / VAL-VALIDATION-012).
    """
    bundle_dir = tmp_path / "freddy-banned-token"
    write_bundle(
        bundle_dir,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:22000000-0000-0000-0000-000000000001",
                record_type=FREDDY_NS,
                payload=_voice_rubric_payload(
                    tokens_found=["compliant"],
                    rejection_state="accepted",
                    include_harness_attestation_ref=False,
                ),
            ),
        ],
    )

    assessment = validate_bundle(bundle_dir)
    found = codes(assessment.structural_errors)
    assert "ACEF-077" in found, (
        f"Voice-rubric record with banned token + accepted state must fire ACEF-077; got: {found!r}"
    )


def test_clean_voice_rubric_record_does_not_fire_acef_077(tmp_path: Path) -> None:
    """tokens_found EMPTY and rejection_state accepted → no ACEF-077."""
    bundle_dir = tmp_path / "freddy-clean"
    write_bundle(
        bundle_dir,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:22000000-0000-0000-0000-000000000002",
                record_type=FREDDY_NS,
                payload=_voice_rubric_payload(
                    tokens_found=[],
                    rejection_state="accepted",
                ),
            ),
        ],
    )

    assessment = validate_bundle(bundle_dir)
    found = codes(assessment.structural_errors)
    assert "ACEF-077" not in found, f"Clean voice-rubric record must NOT fire ACEF-077; got: {found!r}"


def test_banned_token_with_paired_harness_attestation_does_not_fire(
    tmp_path: Path,
) -> None:
    """tokens_found non-empty BUT harness_attestation_ref is present in
    payload → no ACEF-077 (the brief's "paired harness_attestation" carve-out).
    """
    bundle_dir = tmp_path / "freddy-paired-attestation"
    write_bundle(
        bundle_dir,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:22000000-0000-0000-0000-000000000003",
                record_type=FREDDY_NS,
                payload=_voice_rubric_payload(
                    tokens_found=["compliant"],
                    rejection_state="accepted",
                    include_harness_attestation_ref=True,
                ),
            ),
        ],
    )

    assessment = validate_bundle(bundle_dir)
    found = codes(assessment.structural_errors)
    assert "ACEF-077" not in found, (
        f"Voice-rubric with paired harness_attestation_ref must NOT fire ACEF-077; got: {found!r}"
    )


def test_banned_token_with_rejected_state_does_not_fire(tmp_path: Path) -> None:
    """tokens_found non-empty BUT rejection_state=rejected_invalid_voice_rubric_emission
    → no ACEF-077 (the producer properly rejected the record).
    """
    bundle_dir = tmp_path / "freddy-rejected"
    write_bundle(
        bundle_dir,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:22000000-0000-0000-0000-000000000004",
                record_type=FREDDY_NS,
                payload=_voice_rubric_payload(
                    tokens_found=["compliant"],
                    rejection_state="rejected_invalid_voice_rubric_emission",
                ),
            ),
        ],
    )

    assessment = validate_bundle(bundle_dir)
    found = codes(assessment.structural_errors)
    assert "ACEF-077" not in found, (
        f"Voice-rubric with rejection_state=rejected... must NOT fire ACEF-077; got: {found!r}"
    )
