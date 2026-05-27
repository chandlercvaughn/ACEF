"""Tests for v1.1 -> v1 schema fallback (F-M1-VALIDATOR-VERSION-SELECTION).

Covers VAL-VALIDATION-001 partial: when the validator selects schema
version "v1.1", record types unchanged in v1.1 (e.g. risk_register) must
still resolve via fallback to acef-conventions/v1/.

Contract:
- load_schema(<unchanged-type>, "v1.1") falls back to v1/.
- load_schema(<v1.1-only type>, "v1.1") loads from v1.1/.
- load_schema(<v1.1-only type>, "v1") raises ACEFSchemaError (no fallback
  the other direction; v1.0 bundles must not silently inherit v1.1
  record-type schemas).
- load_schema(<unchanged-type>, "v1") still works (existing behavior).
- list_record_type_schemas("v1") does NOT contain the 6 new types.
- list_record_type_schemas("v1.1") contains the 16 v1.0 + 5 v1.1 record
  schemas (coverage_cell is a field group in assessment-bundle, not a
  standalone schema, so it's NOT in this list).
"""

from __future__ import annotations

import pytest

from acef.errors import ACEFSchemaError
from acef.schemas.registry import list_record_type_schemas, load_schema

# Six "v1.1-only" record-type names per the brief / VAL-VALIDATION-002.
# coverage_cell is excluded from the standalone-schema list per VAL-SCHEMA-006
# (it lives inside assessment-bundle.schema.json).
V1_1_ONLY_STANDALONE = {
    "authorized_test_scope",
    "scope_boundary_event",
    "finding_record",
    "delivery_verdict",
    "harness_attestation",
}

V1_1_ONLY_INCLUDING_COVERAGE_CELL = V1_1_ONLY_STANDALONE | {"coverage_cell"}


def test_v1_1_falls_back_to_v1_for_unchanged_record_type() -> None:
    # risk_register is a v1.0 record type; v1.1 does not redefine it.
    schema = load_schema("risk_register", "v1.1")
    assert isinstance(schema, dict)
    # Sanity: this is the risk_register schema, not something else.
    assert "risk" in (schema.get("$id", "") + schema.get("title", "")).lower()


def test_v1_1_only_record_type_loads_from_v1_1() -> None:
    schema = load_schema("authorized_test_scope", "v1.1")
    assert isinstance(schema, dict)
    assert "authorized_test_scope" in (schema.get("$id", "") + schema.get("title", "").lower())


def test_v1_does_not_fall_back_to_v1_1() -> None:
    # v1 bundles must NOT silently inherit v1.1 record types.
    with pytest.raises(ACEFSchemaError) as exc:
        load_schema("authorized_test_scope", "v1")
    assert exc.value.code == "ACEF-003"


def test_v1_loads_unchanged_record_type() -> None:
    # Existing behavior preserved.
    schema = load_schema("risk_register", "v1")
    assert isinstance(schema, dict)


def test_list_v1_excludes_new_record_types() -> None:
    types = set(list_record_type_schemas("v1"))
    for new_type in V1_1_ONLY_INCLUDING_COVERAGE_CELL:
        assert new_type not in types, f"v1 schema list must not contain {new_type!r}"


def test_list_v1_1_is_superset_of_v1_plus_new_types() -> None:
    v1_types = set(list_record_type_schemas("v1"))
    v1_1_types = set(list_record_type_schemas("v1.1"))
    # v1.1 must include every v1 record-type schema.
    missing = v1_types - v1_1_types
    assert not missing, f"v1.1 list missing v1.0 record types: {missing!r}"
    # v1.1 must include the 5 new standalone record-type schemas.
    missing_new = V1_1_ONLY_STANDALONE - v1_1_types
    assert not missing_new, f"v1.1 list missing new record types: {missing_new!r}"


def test_list_v1_1_excludes_coverage_cell() -> None:
    # coverage_cell is a field group inside assessment-bundle, not a
    # standalone record schema, per VAL-SCHEMA-006.
    v1_1_types = set(list_record_type_schemas("v1.1"))
    assert "coverage_cell" not in v1_1_types
