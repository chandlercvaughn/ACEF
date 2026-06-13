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
from acef.models.enums import RECORD_TYPES, Confidentiality
from acef.package import Package
from acef.redaction import RedactionPolicy
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
    """A major-1 non-numeric/odd value (e.g. '1.1abc') is below the gate.

    The minor '1abc' is unparseable, so '1.1abc' is NOT a valid v1.1
    declaration; the numeric gate falls through to the bump, repairing the
    version to the canonical '1.1.0'. (Major stays 1, so no unsupported-major
    concern here.)
    """
    package = Package()
    package._versioning.core_version = "1.1abc"
    package._ensure_v1_1()
    assert package.build_manifest().versioning.core_version == "1.1.0"


# ---------------------------------------------------------------------------
# roborev finding 1 — _ensure_v1_1 MUST NOT rewrite an UNSUPPORTED-MAJOR version
# (e.g. '2.x', '2.abc') to '1.1.0'. Previously the malformed minor masked the
# major, the gate saw None, and silently clobbered an unsupported core 2.x
# bundle down to a self-inconsistent '1.1.0'. The parse now preserves the major
# so the gate leaves a non-1 major untouched (the validator surfaces ACEF-001).
# ---------------------------------------------------------------------------


def test_ensure_v1_1_does_not_rewrite_unsupported_major_malformed_minor() -> None:
    """'2.x' (unsupported major, malformed minor) MUST NOT become '1.1.0'."""
    package = Package()
    package._versioning.core_version = "2.x"
    package._ensure_v1_1()
    assert package.build_manifest().versioning.core_version == "2.x"


def test_ensure_v1_1_does_not_rewrite_unsupported_major_alpha_minor() -> None:
    """'2.abc' (unsupported major) MUST NOT be clobbered to '1.1.0'."""
    package = Package()
    package._versioning.core_version = "2.abc"
    package._ensure_v1_1()
    assert package.build_manifest().versioning.core_version == "2.abc"


def test_ensure_v1_1_does_not_rewrite_unsupported_major_valid_minor() -> None:
    """'2.0' (unsupported major, valid minor) MUST NOT be clobbered."""
    package = Package()
    package._versioning.core_version = "2.0"
    package._ensure_v1_1()
    assert package.build_manifest().versioning.core_version == "2.0"


# ---------------------------------------------------------------------------
# redaction-5 (VAL-FIX-REDACT-005) regression — the X1/X2 auto-population gate
# in Package.record() must NOT crash on the new (major, None) parse result. The
# gate compares ``parsed_core >= (1, 1)``; a ``(1, None)`` minor (malformed,
# e.g. '1.1abc') would TypeError on ``None >= 1``. The gate must treat a
# malformed/unsupported-major version as NOT v1.1+ (suppress auto-population)
# rather than raising.
# ---------------------------------------------------------------------------


def _non_public_record_on(core_version: str) -> Package:
    package = Package(
        producer={"name": "t", "version": "1.0"},
        redaction_policy=RedactionPolicy(version="1.0.0"),
    )
    package._versioning.core_version = core_version
    package.add_subject("ai_system", name="System")
    package.record(
        "risk_register",
        payload={"secret": "S"},
        confidentiality=Confidentiality.HASH_COMMITTED,
    )
    return package


def test_redaction_gate_major1_malformed_minor_does_not_crash() -> None:
    """'1.1abc' (major 1, malformed minor) does NOT raise in the X1/X2 gate.

    The gate compares the parsed result to ``(1, 1)``; a ``(1, None)`` minor
    must be treated as NOT-v1.1+ (auto-population suppressed) rather than
    raising ``TypeError: '>=' not supported between 'NoneType' and 'int'``.
    """
    package = _non_public_record_on("1.1abc")
    # Auto-population suppressed -> no X1 set by the gate (malformed minor is
    # not a valid v1.1 declaration). The record still exists.
    rec = next(r for r in package._records if r.record_type == "risk_register")
    assert rec.redaction_policy_version is None


def test_redaction_gate_unsupported_major_malformed_minor_does_not_crash() -> None:
    """'2.x' (unsupported major) does NOT raise in the X1/X2 gate."""
    package = _non_public_record_on("2.x")
    rec = next(r for r in package._records if r.record_type == "risk_register")
    assert rec.redaction_policy_version is None


def test_redaction_gate_v1_1_still_auto_populates() -> None:
    """A genuine 1.1.0 bundle still auto-populates X1 (gate unchanged)."""
    package = _non_public_record_on("1.1.0")
    rec = next(r for r in package._records if r.record_type == "risk_register")
    assert rec.redaction_policy_version == "1.0.0"
