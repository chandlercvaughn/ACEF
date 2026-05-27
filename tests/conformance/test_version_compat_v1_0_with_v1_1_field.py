"""VAL-VALIDATION-VERSION-COMPAT-001: v1.0 bundle with stray v1.1 field.

A bundle declaring `core_version: 1.0.0` but containing a v1.1-only
manifest field (`analysis_mode`) MUST NOT emit FATAL or ERROR. The
validator's v1.1 cross-record phase is gated on schema_version == "v1.1",
so the stray field is silently ignored on the v1.0 path (the Pydantic
manifest model has `extra="allow"`).

Also includes a control test: the same field on a v1.1 bundle DOES exercise
the cross-record phase (i.e., the gate works in both directions).
"""

from __future__ import annotations

from pathlib import Path

from acef.errors import ERROR_REGISTRY
from acef.validation.engine import validate_bundle
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
    write_bundle,
)


def _severities(diagnostics: list) -> list[str]:
    """Map each diagnostic to its severity string via the ERROR_REGISTRY."""
    out: list[str] = []
    for d in diagnostics:
        code = d.get("code") if isinstance(d, dict) else None
        if code in ERROR_REGISTRY:
            sev, _cat, _desc = ERROR_REGISTRY[code]
            out.append(sev.value)
    return out


def test_v1_0_bundle_with_stray_analysis_mode_no_fatal_or_error(
    tmp_path: Path,
) -> None:
    """v1.0 bundle + stray analysis_mode → no FATAL/ERROR from cross-record.

    Other diagnostics (integrity, schema mismatch from the v1.0 schema not
    knowing analysis_mode) may exist; we assert that the cross-record-
    phase-specific codes (ACEF-073, ACEF-074, ACEF-075, ACEF-078, ACEF-080)
    do NOT fire because v1.0 must skip Phase 3b entirely.
    """
    bundle = tmp_path / "v1-0-stray"

    manifest = base_manifest(core_version="1.0.0")
    # Inject the stray v1.1 field directly. Pydantic's extra="allow" lets
    # this round-trip; the v1.0 JSON Schema may reject it — that's a
    # separate question (schema-validation phase).
    manifest["analysis_mode"] = "subscriber"

    # Two records with different tenant_labels — would trip ACEF-075 if
    # cross-record fired. They MUST NOT trip it on the v1.0 path.
    write_bundle(
        bundle,
        manifest=manifest,
        records=[
            base_record(
                record_id="urn:acef:rec:22220000-0000-0000-0000-000000000001",
                tenant_label="urn:acef:tenant:alpha",
            ),
            base_record(
                record_id="urn:acef:rec:22220000-0000-0000-0000-000000000002",
                tenant_label="urn:acef:tenant:beta",
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)

    # All v1.1 cross-record codes must be absent.
    for cr_code in ("ACEF-073", "ACEF-074", "ACEF-075", "ACEF-078", "ACEF-080"):
        assert cr_code not in found, (
            f"v1.0 bundle must not trip {cr_code} (cross-record phase gated on v1.1). Got codes: {found!r}"
        )


def test_v1_1_bundle_with_analysis_mode_triggers_cross_record(
    tmp_path: Path,
) -> None:
    """Control: the same fields on a v1.1 bundle DO trip cross-record
    (ACEF-075 fires for tenant_label divergence).
    """
    bundle = tmp_path / "v1-1-control"
    write_bundle(
        bundle,
        manifest=base_manifest(core_version="1.1.0", analysis_mode="subscriber"),
        records=[
            base_record(
                record_id="urn:acef:rec:33330000-0000-0000-0000-000000000001",
                tenant_label="urn:acef:tenant:alpha",
            ),
            base_record(
                record_id="urn:acef:rec:33330000-0000-0000-0000-000000000002",
                tenant_label="urn:acef:tenant:beta",
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    assert "ACEF-075" in codes(assessment.structural_errors), (
        "v1.1 control bundle should still trigger ACEF-075 for tenant "
        "divergence — confirms the v1.0 result above is not a false negative."
    )


def test_v1_0_bundle_with_stray_field_no_severity_escalation(
    tmp_path: Path,
) -> None:
    """A v1.0 bundle with a stray v1.1 field MAY produce diagnostics
    (schema mismatch, integrity), but none of them should be from the
    cross-record phase. As a stronger assertion, no cross-record-phase
    code should appear; severities of any non-cross-record diagnostics
    are out of scope here.

    This is the explicit lenient-round-trip behavior promised by
    VAL-VALIDATION-VERSION-COMPAT-001.
    """
    bundle = tmp_path / "v1-0-no-escalation"

    manifest = base_manifest(core_version="1.0.0")
    manifest["analysis_mode"] = "public_artifact"

    write_bundle(
        bundle,
        manifest=manifest,
        records=[
            base_record(
                record_id="urn:acef:rec:44440000-0000-0000-0000-000000000001",
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    for cr_code in ("ACEF-073", "ACEF-074", "ACEF-075", "ACEF-078", "ACEF-080"):
        assert cr_code not in found, f"v1.0 + stray v1.1 field must not emit {cr_code}; got: {found!r}"
