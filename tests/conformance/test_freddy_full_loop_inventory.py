"""VAL-CONFORMANCE-004 — subscriber-mode-full-loop bundle inventory.

The canonical full-loop bundle MUST contain:
  - at least one record of each of the 5 NEW Core record types (the
    6th, coverage_cell, lives in the sibling Assessment Bundle):
        authorized_test_scope, scope_boundary_event, finding_record,
        delivery_verdict, harness_attestation
  - at least one coverage_cell entry in the sibling Assessment Bundle
  - at least one record per new variant discriminator value (5 from
    F-M1-VARIANTS):
        human_oversight_action / oversight_subtype=kill_switch
        risk_treatment / treatment_subtype=regression_definition
        risk_treatment / treatment_subtype=external_disposition
        transparency_disclosure / variant=verification_badge
        evidence_gap / gap_subtype=freshness_window
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
BUNDLE_DIR = REPO_ROOT / "test-vectors" / "freddy" / "pass" / "subscriber-mode-full-loop.acef"
ASSESSMENT_PATH = BUNDLE_DIR.parent / f"{BUNDLE_DIR.name}.acef-assessment.json"


def _iter_records() -> list[dict]:
    records_dir = BUNDLE_DIR / "records"
    out: list[dict] = []
    for jsonl in sorted(records_dir.rglob("*.jsonl")):
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            out.append(json.loads(line))
    return out


REQUIRED_RECORD_TYPES = (
    "authorized_test_scope",
    "scope_boundary_event",
    "finding_record",
    "delivery_verdict",
    "harness_attestation",
)

# (record_type, discriminator_jsonpath_key, discriminator_value)
REQUIRED_VARIANTS = (
    ("human_oversight_action", "oversight_subtype", "kill_switch"),
    ("risk_treatment", "treatment_subtype", "regression_definition"),
    ("risk_treatment", "treatment_subtype", "external_disposition"),
    ("transparency_disclosure", "variant", "verification_badge"),
    ("evidence_gap", "gap_subtype", "freshness_window"),
)


@pytest.mark.plumbing
@pytest.mark.conformance
def test_bundle_exists() -> None:
    assert BUNDLE_DIR.exists() and BUNDLE_DIR.is_dir(), f"Canonical full-loop bundle not found at {BUNDLE_DIR}"


@pytest.mark.plumbing
@pytest.mark.conformance
@pytest.mark.parametrize("record_type", REQUIRED_RECORD_TYPES)
def test_full_loop_has_record_type(record_type: str) -> None:
    """At least one record of the given Core v1.1 record_type."""
    records = _iter_records()
    matches = [r for r in records if r.get("record_type") == record_type]
    assert matches, (
        f"VAL-CONFORMANCE-004: subscriber-mode-full-loop.acef MUST contain "
        f">=1 record of record_type={record_type!r}; found {len(matches)}."
    )


@pytest.mark.plumbing
@pytest.mark.conformance
@pytest.mark.parametrize(
    "record_type,disc_key,disc_value",
    REQUIRED_VARIANTS,
    ids=lambda v: v if not isinstance(v, str) else v.replace("/", "_"),
)
def test_full_loop_has_variant(record_type: str, disc_key: str, disc_value: str) -> None:
    """At least one record of the given (parent record_type, discriminator value)."""
    records = _iter_records()
    matches = [
        r
        for r in records
        if r.get("record_type") == record_type
        and isinstance(r.get("payload"), dict)
        and r["payload"].get(disc_key) == disc_value
    ]
    assert matches, (
        f"VAL-CONFORMANCE-004: subscriber-mode-full-loop.acef MUST contain "
        f">=1 record where record_type={record_type!r} and payload.{disc_key}={disc_value!r}; "
        f"found {len(matches)}."
    )


@pytest.mark.plumbing
@pytest.mark.conformance
def test_full_loop_has_coverage_cell_in_assessment() -> None:
    """At least one coverage_cell in the sibling Assessment Bundle."""
    assert ASSESSMENT_PATH.exists(), f"Sibling assessment bundle missing at {ASSESSMENT_PATH}"
    data = json.loads(ASSESSMENT_PATH.read_text(encoding="utf-8"))
    cells = data.get("coverage_cells")
    assert isinstance(cells, list) and len(cells) >= 1, (
        f"VAL-CONFORMANCE-004: sibling assessment bundle MUST contain >=1 coverage_cell entry; got: {cells!r}"
    )
