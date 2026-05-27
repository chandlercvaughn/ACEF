"""VAL-VALIDATION-LINT-INVOCATION-001: lint hooks fire BEFORE the validator
returns a clean result. A bundle that would otherwise have zero diagnostics
returns at least one when its registered namespace lint fires.
"""

from __future__ import annotations

from pathlib import Path

import acef.validation.namespace_lints.bundled_freddy  # noqa: F401
from acef.validation.engine import validate_bundle
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
    write_bundle,
)

FREDDY_NS = "x-freddy/voice-rubric-emission"


def test_clean_v1_1_bundle_returns_no_lint_diagnostics(tmp_path: Path) -> None:
    """Baseline: a v1.1 bundle with no voice-rubric-emission record returns
    no ACEF-077 diagnostic. This anchors the comparison below.
    """
    bundle_dir = tmp_path / "clean-baseline"
    write_bundle(
        bundle_dir,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:44000000-0000-0000-0000-000000000001",
            ),
        ],
    )
    assessment = validate_bundle(bundle_dir)
    found = codes(assessment.structural_errors)
    assert "ACEF-077" not in found


def test_registered_namespace_lint_blocks_acceptance(tmp_path: Path) -> None:
    """A bundle is otherwise clean-shape but contains a record that fires
    the bundled freddy lint. The validator MUST report at least one
    ACEF-077 diagnostic, i.e., the lint blocks otherwise-success acceptance.
    """
    bundle_dir = tmp_path / "blocked-by-lint"
    write_bundle(
        bundle_dir,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:44000000-0000-0000-0000-000000000002",
                record_type=FREDDY_NS,
                payload={
                    "emission_id": "urn:freddy:emi:fff",
                    "rubric_id": "urn:freddy:rub:fff",
                    "rubric_version": "1.0.0",
                    "redaction_attestation_ref": ("urn:acef:rec:99000000-0000-0000-0000-000000000099"),
                    "styled_prose_digest": ("sha256:0000000000000000000000000000000000000000000000000000000000000002"),
                    "claim_lexicon_scan_result": {
                        "tokens_found": ["certified"],
                        "scan_timestamp": "2026-01-01T00:00:00Z",
                        "scanner_version": "1.0.0",
                    },
                    "rejection_state": "accepted",
                },
            ),
        ],
    )
    assessment = validate_bundle(bundle_dir)
    found = codes(assessment.structural_errors)
    # Lint MUST have fired — at least one ACEF-077 diagnostic present.
    assert "ACEF-077" in found, f"Lint must block acceptance: ACEF-077 expected in structural_errors; got: {found!r}"
    # And the result is not clean — there is at least one diagnostic in total.
    assert len(assessment.structural_errors) >= 1
