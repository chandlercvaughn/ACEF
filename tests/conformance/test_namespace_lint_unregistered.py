"""VAL-VALIDATION-013: graceful no-op for unregistered vendor namespaces.

A bundle containing ``x-unregistered-vendor/voice-rubric-emission`` content
that WOULD trigger ACEF-077 if the namespace were registered does NOT emit
ACEF-077, because the lint registry's dispatch only invokes patterns for
registered namespaces. Other error codes are permitted (e.g., schema
mismatch for unknown record_type) but the lint hook itself MUST be silent.
"""

from __future__ import annotations

from pathlib import Path

# Ensure bundled freddy module is imported so its registration runs — we
# WANT x-freddy/voice-rubric-emission registered but NOT
# x-unregistered-vendor/voice-rubric-emission, to verify the dispatch is
# scoped by namespace string equality.
import acef.validation.namespace_lints.bundled_freddy  # noqa: F401
from acef.validation.engine import validate_bundle
from acef.validation.namespace_lints import list_registered_namespaces
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
    write_bundle,
)

UNREGISTERED_NS = "x-unregistered-vendor/voice-rubric-emission"


def test_unregistered_namespace_is_not_registered() -> None:
    """Pre-condition: the namespace under test must NOT be in the registry."""
    assert UNREGISTERED_NS not in list_registered_namespaces()


def test_unregistered_namespace_with_tripwire_payload_emits_no_acef_077(
    tmp_path: Path,
) -> None:
    """A record under an unregistered vendor namespace, carrying the SAME
    payload shape that WOULD trigger ACEF-077 in the registered
    ``x-freddy/voice-rubric-emission`` namespace, MUST NOT emit ACEF-077.

    VAL-VALIDATION-013 — graceful no-op for unregistered namespaces.
    """
    bundle_dir = tmp_path / "unregistered-vendor"
    write_bundle(
        bundle_dir,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:33000000-0000-0000-0000-000000000001",
                record_type=UNREGISTERED_NS,
                payload={
                    "emission_id": "urn:vendor:emi:000",
                    "rubric_id": "urn:vendor:rub:000",
                    "rubric_version": "1.0.0",
                    "claim_lexicon_scan_result": {
                        "tokens_found": ["compliant"],
                        "scan_timestamp": "2026-01-01T00:00:00Z",
                        "scanner_version": "1.0.0",
                    },
                    "rejection_state": "accepted",
                    # NO harness_attestation_ref — would trigger ACEF-077
                    # under the x-freddy/voice-rubric-emission lint.
                },
            ),
        ],
    )

    assessment = validate_bundle(bundle_dir)
    found = codes(assessment.structural_errors)
    assert "ACEF-077" not in found, f"Unregistered vendor namespace must NOT fire ACEF-077; got: {found!r}"
