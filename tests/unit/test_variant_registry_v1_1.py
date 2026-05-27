"""Tests for v1.1 variant-registry additions (F-M1-VARIANTS).

Covers:
- VAL-VARIANT-001: v1.1 variant-registry.json has EXACTLY 5 new artifact
  names matching brief §4.1-§4.5.
- VAL-VARIANT-002: ``resolve_variant(name, "v1.1")`` returns the union of
  v1.0 and v1.1 registries — all 12 v1.0 entries continue to resolve, all
  5 new entries resolve.
- VAL-VARIANT-004: v1.0 variants resolve byte-identical to the R0 snapshot
  at ``tests/conformance/fixtures/v1.0-variants.json`` (12 entries).

These are PROJECT CLAUDE.md TDD-mandated tests: written RED before the
v1.1/variant-registry.json file exists, then implemented to GREEN.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acef.schemas.registry import (
    load_variant_registry,
    resolve_variant,
)

# Project root — registry files live under this tree.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_V1_1_REGISTRY_PATH = _PROJECT_ROOT / "acef-conventions" / "v1.1" / "variant-registry.json"
_V1_REGISTRY_PATH = _PROJECT_ROOT / "acef-conventions" / "v1" / "variant-registry.json"
_R0_SNAPSHOT_PATH = _PROJECT_ROOT / "tests" / "conformance" / "fixtures" / "v1.0-variants.json"

# The 5 new artifact names this feature adds, per brief §4.1-§4.5 (lines
# 70-74 of planning/freddy-on-acef-requirements-v0.1.md). The dispatch's
# fix-feature instructions reaffirm these as the normative mapping.
_NEW_V1_1_VARIANTS = {
    # V1: brief §4.1
    "human_oversight_kill_switch": {
        "record_type": "human_oversight_action",
        "discriminator_field": "/payload/oversight_subtype",
        "discriminator_value": "kill_switch",
    },
    # V2: brief §4.2
    "regression_definition": {
        "record_type": "risk_treatment",
        "discriminator_field": "/payload/treatment_subtype",
        "discriminator_value": "regression_definition",
    },
    # V3: brief §4.3 — note artifact_name is `disposition_record`;
    # `external_disposition` is the discriminator value.
    "disposition_record": {
        "record_type": "risk_treatment",
        "discriminator_field": "/payload/treatment_subtype",
        "discriminator_value": "external_disposition",
    },
    # V4: brief §4.4 — note artifact_name is `badge_state`;
    # `verification_badge` is the discriminator value on /payload/variant.
    "badge_state": {
        "record_type": "transparency_disclosure",
        "discriminator_field": "/payload/variant",
        "discriminator_value": "verification_badge",
    },
    # V5: brief §4.5
    "evidence_freshness_window": {
        "record_type": "evidence_gap",
        "discriminator_field": "/payload/gap_subtype",
        "discriminator_value": "freshness_window",
    },
}


# ---------- VAL-VARIANT-001 ----------


def test_v1_1_variant_registry_file_exists() -> None:
    """The v1.1 variant-registry.json file must exist at the expected path."""
    assert _V1_1_REGISTRY_PATH.exists(), f"Missing variant registry file: {_V1_1_REGISTRY_PATH}"


def test_v1_1_variant_registry_parses_as_json() -> None:
    """The v1.1 registry file must be valid JSON with a 'variants' array."""
    with open(_V1_1_REGISTRY_PATH, encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, dict)
    assert "variants" in data
    assert isinstance(data["variants"], list)


def test_v1_1_variant_registry_has_exactly_five_new_entries() -> None:
    """VAL-VARIANT-001: registry contains EXACTLY 5 new entries."""
    with open(_V1_1_REGISTRY_PATH, encoding="utf-8") as f:
        data = json.load(f)
    names = sorted(e["artifact_name"] for e in data["variants"])
    assert names == sorted(_NEW_V1_1_VARIANTS.keys()), (
        f"v1.1 registry should contain EXACTLY the 5 new variant artifact_names; "
        f"got {names!r}, expected {sorted(_NEW_V1_1_VARIANTS.keys())!r}"
    )


@pytest.mark.parametrize(
    "artifact_name,expected",
    list(_NEW_V1_1_VARIANTS.items()),
)
def test_v1_1_each_new_entry_has_correct_triple(artifact_name: str, expected: dict) -> None:
    """VAL-VARIANT-001: each new entry has the expected record_type,
    discriminator_field, and discriminator_value per brief §4.1-§4.5."""
    with open(_V1_1_REGISTRY_PATH, encoding="utf-8") as f:
        data = json.load(f)
    matches = [e for e in data["variants"] if e["artifact_name"] == artifact_name]
    assert len(matches) == 1, f"Expected exactly one entry for {artifact_name!r}; got {len(matches)}"
    entry = matches[0]
    for field in ("record_type", "discriminator_field", "discriminator_value"):
        assert entry[field] == expected[field], (
            f"{artifact_name}.{field}: expected {expected[field]!r}, got {entry[field]!r}"
        )


# ---------- VAL-VARIANT-002 ----------


def test_load_variant_registry_v1_returns_twelve_entries() -> None:
    """v1.0 registry remains 12 entries (unchanged baseline)."""
    entries = load_variant_registry("v1")
    assert len(entries) == 12, f"v1 registry size should be 12; got {len(entries)}"


def test_load_variant_registry_v1_1_returns_seventeen_entries() -> None:
    """VAL-VARIANT-002: v1.1 registry is the UNION of v1.0 (12) + v1.1 new (5) = 17 entries."""
    entries = load_variant_registry("v1.1")
    names = {e["artifact_name"] for e in entries}
    # v1.0 names
    v1_names = {e["artifact_name"] for e in load_variant_registry("v1")}
    assert v1_names.issubset(names), f"v1.1 union must include all v1.0 names. Missing: {v1_names - names}"
    # 5 new names must be present
    new_names = set(_NEW_V1_1_VARIANTS.keys())
    assert new_names.issubset(names), f"v1.1 union must include the 5 new names. Missing: {new_names - names}"
    # Exact count: union of disjoint sets
    assert len(entries) == 17, f"v1.1 union should have exactly 17 entries (12 v1.0 + 5 new); got {len(entries)}"


@pytest.mark.parametrize(
    "artifact_name,expected",
    list(_NEW_V1_1_VARIANTS.items()),
)
def test_resolve_variant_v1_1_new_entries(artifact_name: str, expected: dict) -> None:
    """VAL-VARIANT-002: ``resolve_variant(name, 'v1.1')`` returns the
    expected triple for each new variant."""
    entry = resolve_variant(artifact_name, "v1.1")
    assert entry is not None, f"resolve_variant({artifact_name!r}, 'v1.1') returned None"
    for field in ("record_type", "discriminator_field", "discriminator_value"):
        assert entry[field] == expected[field], (
            f"{artifact_name}.{field}: expected {expected[field]!r}, got {entry[field]!r}"
        )


def test_resolve_variant_v1_does_not_resolve_new_entries() -> None:
    """Version-gate guarantee: new v1.1 variants MUST NOT resolve under
    ``resolve_variant(name, 'v1')`` — they are v1.1-only additions."""
    for artifact_name in _NEW_V1_1_VARIANTS.keys():
        entry = resolve_variant(artifact_name, "v1")
        assert entry is None, (
            f"resolve_variant({artifact_name!r}, 'v1') should return None (v1.1-only variant); got {entry!r}"
        )


# ---------- VAL-VARIANT-004 ----------


def test_r0_snapshot_fixture_exists_and_has_twelve_entries() -> None:
    """R0 snapshot at tests/conformance/fixtures/v1.0-variants.json must
    exist with the captured baseline (12 entries — the brief's "13" is a
    documentation miscount)."""
    assert _R0_SNAPSHOT_PATH.exists(), f"Missing R0 snapshot: {_R0_SNAPSHOT_PATH}"
    with open(_R0_SNAPSHOT_PATH, encoding="utf-8") as f:
        snapshot = json.load(f)
    assert len(snapshot) == 12, f"R0 snapshot should have 12 entries; got {len(snapshot)}"


def test_r0_snapshot_each_entry_resolves_identically_under_v1() -> None:
    """VAL-VARIANT-004: every R0 fixture entry resolves via
    ``resolve_variant(name, 'v1')`` to a byte-identical triple
    (record_type, discriminator_field, discriminator_value).
    """
    with open(_R0_SNAPSHOT_PATH, encoding="utf-8") as f:
        snapshot = json.load(f)

    mismatches: list[str] = []
    for fixture_entry in snapshot:
        name = fixture_entry["artifact_name"]
        resolved = resolve_variant(name, "v1")
        if resolved is None:
            mismatches.append(f"{name}: resolve_variant returned None")
            continue
        for field in ("record_type", "discriminator_field", "discriminator_value"):
            if resolved.get(field) != fixture_entry[field]:
                mismatches.append(
                    f"{name}.{field}: snapshot={fixture_entry[field]!r}, resolved={resolved.get(field)!r}"
                )
    assert not mismatches, "R0 snapshot drift detected (this would break VAL-VARIANT-004):\n" + "\n".join(mismatches)


def test_r0_snapshot_each_entry_also_resolves_identically_under_v1_1() -> None:
    """The v1.1 union must NOT mutate any v1.0 entry — every snapshot
    entry must resolve via ``resolve_variant(name, 'v1.1')`` to the same
    triple captured in the R0 snapshot."""
    with open(_R0_SNAPSHOT_PATH, encoding="utf-8") as f:
        snapshot = json.load(f)

    mismatches: list[str] = []
    for fixture_entry in snapshot:
        name = fixture_entry["artifact_name"]
        resolved = resolve_variant(name, "v1.1")
        if resolved is None:
            mismatches.append(f"{name}: resolve_variant returned None under v1.1")
            continue
        for field in ("record_type", "discriminator_field", "discriminator_value"):
            if resolved.get(field) != fixture_entry[field]:
                mismatches.append(
                    f"{name}.{field}: snapshot={fixture_entry[field]!r}, v1.1-resolved={resolved.get(field)!r}"
                )
    assert not mismatches, "v1.1 union mutates a v1.0 variant tuple (forbidden by VAL-VARIANT-004):\n" + "\n".join(
        mismatches
    )
