"""VAL-VALIDATION-003: tenant uniformity → ACEF-075.

A v1.1 bundle with `analysis_mode` set and two distinct tenant_label values
across records MUST emit ACEF-075. The same bundle without `analysis_mode`
MUST NOT emit ACEF-075. v1.0 bundles MUST NEVER trigger this check.
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


def test_tenant_uniformity_violation_emits_acef_075(tmp_path: Path) -> None:
    """Two distinct tenant_labels + analysis_mode set → ACEF-075 fires."""
    bundle = tmp_path / "two-tenants"
    write_bundle(
        bundle,
        manifest=base_manifest(analysis_mode="subscriber"),
        records=[
            base_record(
                record_id="urn:acef:rec:10000000-0000-0000-0000-000000000001",
                tenant_label="urn:acef:tenant:alpha",
            ),
            base_record(
                record_id="urn:acef:rec:10000000-0000-0000-0000-000000000002",
                tenant_label="urn:acef:tenant:beta",
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-075" in found, f"Expected ACEF-075 (tenant uniformity violation), got codes: {found!r}"


def test_single_tenant_no_acef_075(tmp_path: Path) -> None:
    """Same tenant_label on all records + analysis_mode → no ACEF-075."""
    bundle = tmp_path / "one-tenant"
    write_bundle(
        bundle,
        manifest=base_manifest(analysis_mode="subscriber"),
        records=[
            base_record(
                record_id="urn:acef:rec:20000000-0000-0000-0000-000000000001",
                tenant_label="urn:acef:tenant:alpha",
            ),
            base_record(
                record_id="urn:acef:rec:20000000-0000-0000-0000-000000000002",
                tenant_label="urn:acef:tenant:alpha",
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    assert "ACEF-075" not in codes(assessment.structural_errors)


def test_no_analysis_mode_no_acef_075_even_with_two_tenants(tmp_path: Path) -> None:
    """Without analysis_mode set, tenant uniformity is not enforced."""
    bundle = tmp_path / "no-mode"
    write_bundle(
        bundle,
        manifest=base_manifest(analysis_mode=None),
        records=[
            base_record(
                record_id="urn:acef:rec:30000000-0000-0000-0000-000000000001",
                tenant_label="urn:acef:tenant:alpha",
            ),
            base_record(
                record_id="urn:acef:rec:30000000-0000-0000-0000-000000000002",
                tenant_label="urn:acef:tenant:beta",
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    assert "ACEF-075" not in codes(assessment.structural_errors)


def test_records_without_tenant_label_are_ignored_for_uniformity(tmp_path: Path) -> None:
    """Records without tenant_label do not count as a distinct tenant."""
    bundle = tmp_path / "mixed-presence"
    write_bundle(
        bundle,
        manifest=base_manifest(analysis_mode="subscriber"),
        records=[
            base_record(
                record_id="urn:acef:rec:40000000-0000-0000-0000-000000000001",
                tenant_label="urn:acef:tenant:alpha",
            ),
            base_record(
                record_id="urn:acef:rec:40000000-0000-0000-0000-000000000002",
                tenant_label=None,
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    assert "ACEF-075" not in codes(assessment.structural_errors)
