"""Version-gate behavior for ``Package.record()`` on v1.1-only record types.

Covers audit findings (operation acef-audit-remediation):

- records-payloads-2 (VAL-FIX-RECORDS-002): generic ``record()`` of a v1.1-only
  record type MUST bump ``core_version`` to 1.1.0 (matching the typed incident
  builders) so the SDK never authors a manifest its own validator rejects.
- records-payloads-3 (VAL-FIX-RECORDS-003): ``coverage_cell`` is an
  Assessment-Bundle inventory concept with no ``coverage_cell.schema.json`` —
  ``record()`` MUST reject it up front rather than emit a self-rejecting record.
- records-payloads-6 (VAL-FIX-RECORDS-006): ``_ensure_v1_1`` MUST gate on the
  parsed numeric (major, minor) tuple, not a lexicographic string comparison.
"""

from __future__ import annotations

import pytest

from acef.errors import ACEFSchemaError
from acef.models.enums import RECORD_TYPES
from acef.package import Package
from acef.schemas.registry import schema_version_for_core_version
from acef.validation.schema_validator import validate_record_schemas


def _v1_1_only_record_types() -> set[str]:
    """v1.1-only types that DO have a v1.1 schema file (excludes coverage_cell).

    ``coverage_cell`` is in ``RECORD_TYPES`` but has no schema in v1 OR v1.1,
    so it is handled by its own reject-up-front guard (records-payloads-3),
    not the version-bump path.
    """
    from acef.schemas.registry import list_record_type_schemas

    v1 = set(list_record_type_schemas("v1"))
    v1_1 = set(list_record_type_schemas("v1.1"))
    return (RECORD_TYPES - v1) & v1_1


# ---------------------------------------------------------------------------
# records-payloads-2 — record() bumps core_version for v1.1-only types
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("record_type", sorted(_v1_1_only_record_types()))
def test_record_v1_1_only_type_bumps_core_version(record_type: str) -> None:
    """A default (1.0.0) Package.record() of a v1.1-only type bumps to 1.1.0."""
    package = Package()
    assert package.build_manifest().versioning.core_version == "1.0.0"

    package.record(record_type=record_type, payload={"placeholder": "value"})

    assert package.build_manifest().versioning.core_version == "1.1.0"


def test_record_incident_card_resolves_v1_1_schema_set() -> None:
    """record('incident_card') on a default Package no longer self-rejects.

    RED before the fix: core_version stays 1.0.0, the validator resolves the
    v1 allowlist (which excludes incident_card) and emits ACEF-003. After the
    fix the manifest declares 1.1.0, resolves the v1.1 allowlist, and the
    record_type is recognized.
    """
    package = Package()
    record = package.record(record_type="incident_card", payload={"placeholder": "value"})

    manifest = package.build_manifest()
    schema_version = schema_version_for_core_version(manifest.versioning.core_version)
    assert schema_version == "v1.1"

    diagnostics = validate_record_schemas([record.to_jsonl_dict()], schema_version)
    unknown_type = [d for d in diagnostics if d.code == "ACEF-003" and "Unknown record_type" in d.message]
    assert unknown_type == [], (
        "record('incident_card') on a default package must not produce a "
        f"self-rejecting bundle, got: {[d.message for d in diagnostics]}"
    )


def test_record_v1_0_type_does_not_bump_core_version() -> None:
    """A v1.0 record type leaves core_version at 1.0.0 (no spurious bump)."""
    package = Package()
    package.record(record_type="risk_register", payload={"placeholder": "value"})
    assert package.build_manifest().versioning.core_version == "1.0.0"


def test_record_v1_1_type_preserves_already_declared_v1_1() -> None:
    """A package already at 1.1.x is left untouched (no downgrade/clobber)."""
    package = Package()
    package.set_analysis_mode("public_artifact")  # bumps to 1.1.0
    assert package.build_manifest().versioning.core_version == "1.1.0"
    package.record(record_type="incident_card", payload={"placeholder": "value"})
    assert package.build_manifest().versioning.core_version == "1.1.0"


# ---------------------------------------------------------------------------
# records-payloads-3 — coverage_cell rejected up front
# ---------------------------------------------------------------------------


def test_record_coverage_cell_rejected_up_front() -> None:
    """record('coverage_cell') is rejected at record() with a clear message.

    RED before the fix: coverage_cell is accepted (it is in RECORD_TYPES) then
    later rejected ACEF-003 by the validator (no coverage_cell.schema.json).
    After the fix it is rejected at the builder with an assessment-bundle hint.
    """
    package = Package()
    with pytest.raises(ACEFSchemaError) as exc_info:
        package.record(record_type="coverage_cell", payload={"placeholder": "value"})

    assert exc_info.value.code == "ACEF-003"
    message = str(exc_info.value)
    assert "coverage_cell" in message
    assert "assessment" in message.lower()


def test_record_coverage_cell_rejection_does_not_bump_core_version() -> None:
    """A rejected coverage_cell must not mutate package version state."""
    package = Package()
    with pytest.raises(ACEFSchemaError):
        package.record(record_type="coverage_cell", payload={"placeholder": "value"})
    assert package.build_manifest().versioning.core_version == "1.0.0"


# ---------------------------------------------------------------------------
# records-payloads-6 — _ensure_v1_1 numeric semver gate
# ---------------------------------------------------------------------------


def test_ensure_v1_1_numeric_gate_does_not_bump_future_minor() -> None:
    """A future minor (e.g. 1.10.0) is >= (1,1) numerically and must NOT bump.

    Lexicographic '1.10' >= '1.1' is True here only by luck; the real risk is a
    value where lexicographic and numeric ordering diverge. '1.10.0' is already
    a v1.1+ bundle and must be left as-is (not clobbered down to '1.1.0').
    """
    package = Package()
    package._versioning.core_version = "1.10.0"
    package._ensure_v1_1()
    assert package.build_manifest().versioning.core_version == "1.10.0"


def test_ensure_v1_1_numeric_gate_bumps_v1_0() -> None:
    """A 1.0.x bundle is below (1,1) and is bumped to 1.1.0."""
    package = Package()
    package._versioning.core_version = "1.0.0"
    package._ensure_v1_1()
    assert package.build_manifest().versioning.core_version == "1.1.0"


def test_ensure_v1_1_numeric_gate_leaves_1_2() -> None:
    """A 1.2.x bundle is above (1,1) and is left as-is."""
    package = Package()
    package._versioning.core_version = "1.2.0"
    package._ensure_v1_1()
    assert package.build_manifest().versioning.core_version == "1.2.0"


def test_ensure_v1_1_numeric_gate_non_numeric_minor_bumps() -> None:
    """A non-numeric/odd value (e.g. '1.1abc') is treated as below the gate.

    Lexicographic '1.1abc' >= '1.1' is True (would NOT bump), but '1.1abc' is
    not a valid v1.1 declaration; the numeric gate cannot parse the minor and
    falls through to the bump, repairing the version to the canonical '1.1.0'.
    """
    package = Package()
    package._versioning.core_version = "1.1abc"
    package._ensure_v1_1()
    assert package.build_manifest().versioning.core_version == "1.1.0"
