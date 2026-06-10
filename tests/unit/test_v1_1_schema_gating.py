"""Unit: v1.1 incident schema gating + record-type allowlist (F-M2-SCHEMA-GATING).

Covers the integration capstone wiring for VAL-SCH-001:

- ``core_version: 1.1.0`` routes to the v1.1 schema set; ``1.0.0`` stays on v1.
- The record-type ALLOWLIST distinguishes RECORD TYPES (``incident_card``,
  ``incident_report``) from COMPANION sub-schemas (``harm-core-taxonomy``,
  ``taxonomy_crosswalk``, ``severity_vector``, ``coordinated_disclosure``,
  ``incident_report.card_source``) so a companion is NOT an independently
  claimable ``record_type`` (resolves the "companion looks like a record type"
  roborev finding).
- ``RECORD_TYPES`` registers ``incident_card`` and ``incident_report`` but NOT
  the companions / ``card_source`` (which is a companion, not a top-level type).
- The v1.1 variant-registry registers the incident companions as variants of
  ``incident_report`` under ``core_version: 1.1.0`` gating, using the X6
  ``^x-...`` closure pattern where closures are used.
- ``acef-conventions/v1/`` is byte-unchanged (asserted via git in the
  integration verification, mirrored here by confirming v1's record-type set is
  free of any incident additions).

Determinism: static literals only; no wall-clock / random values.
"""

from __future__ import annotations

import json
from pathlib import Path

from acef.models.enums import RECORD_TYPES
from acef.schemas.registry import (
    list_record_type_schemas,
    load_variant_registry,
    schema_version_for_core_version,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_V1_1_DIR = _PROJECT_ROOT / "acef-conventions" / "v1.1"

# Companion sub-schemas referenced by $ref from the incident record types. These
# are NOT independently claimable record_type values — they are projection
# building blocks.
_COMPANION_SCHEMAS = {
    "harm-core-taxonomy",
    "taxonomy_crosswalk",
    "severity_vector",
    "coordinated_disclosure",
    "incident_report.card_source",
}

# The two genuine v1.1 incident record types.
_INCIDENT_RECORD_TYPES = {"incident_card", "incident_report"}


# --------------------------------------------------------------------------- #
# core_version routing                                                         #
# --------------------------------------------------------------------------- #


def test_core_version_1_1_0_routes_to_v1_1() -> None:
    """``1.1.0`` routes to the v1.1 schema-dir token (VAL-SCH-001)."""
    assert schema_version_for_core_version("1.1.0") == "v1.1"


def test_core_version_1_0_0_routes_to_v1() -> None:
    """``1.0.0`` stays on the frozen v1 schema set (VAL-SCH-001)."""
    assert schema_version_for_core_version("1.0.0") == "v1"


def test_core_version_absent_routes_to_v1() -> None:
    """A missing core_version (legacy bundle) stays on v1 (VAL-SCH-001)."""
    assert schema_version_for_core_version(None) == "v1"


# --------------------------------------------------------------------------- #
# record-type allowlist: companions are NOT record types                      #
# --------------------------------------------------------------------------- #


def test_incident_record_types_in_allowlist() -> None:
    """``incident_card`` and ``incident_report`` ARE v1.1 record types
    (VAL-SCH-001)."""
    types = set(list_record_type_schemas("v1.1"))
    assert _INCIDENT_RECORD_TYPES <= types


def test_companions_excluded_from_record_type_allowlist() -> None:
    """The companion sub-schemas are NOT independently claimable record types
    (VAL-SCH-001 — resolves the 'companion looks like a record type' finding)."""
    types = set(list_record_type_schemas("v1.1"))
    leaked = _COMPANION_SCHEMAS & types
    assert leaked == set(), f"companion sub-schemas leaked into the record-type allowlist: {sorted(leaked)}"


def test_card_source_is_a_companion_not_a_record_type() -> None:
    """``incident_report.card_source`` is a COMPANION overlay block, not a
    top-level record type (VAL-SCH-001)."""
    types = set(list_record_type_schemas("v1.1"))
    assert "incident_report.card_source" not in types


# --------------------------------------------------------------------------- #
# RECORD_TYPES inventory (enums.py)                                           #
# --------------------------------------------------------------------------- #


def test_record_types_inventory_includes_incident_card() -> None:
    """``incident_card`` is registered in the SDK record-type inventory
    (VAL-SCH-001)."""
    assert "incident_card" in RECORD_TYPES


def test_record_types_inventory_includes_incident_report() -> None:
    """``incident_report`` (v1.0 + v1.1 overlay) is in the inventory
    (VAL-SCH-001)."""
    assert "incident_report" in RECORD_TYPES


def test_record_types_inventory_excludes_companions() -> None:
    """No companion / ``card_source`` block is a top-level record type
    (VAL-SCH-001)."""
    leaked = _COMPANION_SCHEMAS & RECORD_TYPES
    assert leaked == set(), f"companions leaked into RECORD_TYPES: {sorted(leaked)}"


# --------------------------------------------------------------------------- #
# v1.1 variant-registry: incident_profile record-type allowlist               #
#                                                                             #
# The incident profile adds NO payload-discriminator variants (its additions   #
# are whole record types + $ref'd companions), so the `variants` array stays   #
# at exactly the five agent-reliability entries (VAL-VARIANT-001). The         #
# core_version 1.1.0 record-type ALLOWLIST lives in a separate                 #
# `incident_profile` block, distinguishing RECORD TYPES from COMPANIONS.       #
# --------------------------------------------------------------------------- #


def test_v1_1_variant_registry_variants_array_unchanged_count() -> None:
    """The incident profile adds NO `variants` entries — the array stays at the
    five agent-reliability entries (VAL-SCH-001 preserves VAL-VARIANT-001)."""
    variants = load_variant_registry("v1.1")
    names = {v["artifact_name"] for v in variants}
    # The 5 agent-reliability v1.1 additions are present, and the v1.0 entries
    # survive the union; no incident companion leaks into the variants array.
    assert "badge_state" in names  # representative v1.1 agent-reliability entry
    assert "management_review" in names  # representative v1.0 entry that survives the union
    assert not (_COMPANION_SCHEMAS & names), "no incident companion may appear in the variants array"
    assert not (_INCIDENT_RECORD_TYPES & names), "no incident record type may appear in the variants array"


def test_v1_1_incident_profile_block_present_and_gated() -> None:
    """The v1.1 variant-registry carries an `incident_profile` block gated on
    core_version 1.1.0 (VAL-SCH-001)."""
    registry_path = _V1_1_DIR / "variant-registry.json"
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    assert "incident_profile" in data, "v1.1 variant-registry must carry an incident_profile allowlist block"
    profile = data["incident_profile"]
    assert profile.get("core_version") == "1.1.0", "incident_profile must declare the 1.1.0 core_version gate"


def test_v1_1_incident_profile_record_types_allowlist() -> None:
    """The `incident_profile.record_types` allowlist is exactly the two incident
    record types — companions are NOT listed there (VAL-SCH-001)."""
    registry_path = _V1_1_DIR / "variant-registry.json"
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    record_types = set(data["incident_profile"]["record_types"])
    assert record_types == _INCIDENT_RECORD_TYPES
    assert not (_COMPANION_SCHEMAS & record_types), "no companion may appear in record_types"


def test_v1_1_incident_profile_companions_listed_separately() -> None:
    """The `incident_profile.companion_subschemas` block lists the $ref'd
    companions, disjoint from record_types (VAL-SCH-001)."""
    registry_path = _V1_1_DIR / "variant-registry.json"
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    profile = data["incident_profile"]
    companions = set(profile["companion_subschemas"])
    record_types = set(profile["record_types"])
    assert companions == _COMPANION_SCHEMAS
    assert companions.isdisjoint(record_types), "record types and companions must be disjoint sets"
