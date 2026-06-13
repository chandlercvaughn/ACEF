"""Model <-> schema parity guard for the v1.1 agent-reliability payload models.

Covers audit findings (operation acef-audit-remediation):

- records-payloads-4 (VAL-FIX-RECORDS-004): the agent-reliability payload models
  had no direct model/schema-parity regression guard. This parametrized test
  loads each model's matching ``acef-conventions/v1.1/<type>.schema.json`` and
  asserts the model's required (non-default) field set equals the schema's
  ``required`` array — so a schema ``required`` change or a model field rename is
  caught.
- records-payloads-5 (VAL-FIX-RECORDS-005): ``CoverageCellPayload`` was an
  orphaned model (defined + exported, never constructed; no
  ``coverage_cell.schema.json`` — coverage_cell is inline in the assessment
  bundle schema). It is removed; this module asserts it is no longer exported,
  so the orphan cannot silently return.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import BaseModel

import acef.models.agent_reliability as agent_reliability
from acef.models.agent_reliability import (
    AuthorizedTestScopePayload,
    DeliveryVerdictPayload,
    FindingRecordPayload,
    HarnessAttestationPayload,
    ScopeBoundaryEventPayload,
)

_SCHEMA_DIR = Path(__file__).resolve().parents[2] / "acef-conventions" / "v1.1"

# Each agent-reliability record-type payload model that has a backing
# ``<type>.schema.json`` under acef-conventions/v1.1/. coverage_cell is
# deliberately absent: it has no standalone schema file (it is defined inline
# in assessment-bundle.schema.json), and its model is removed (records-5).
_MODEL_BY_RECORD_TYPE: dict[str, type[BaseModel]] = {
    "authorized_test_scope": AuthorizedTestScopePayload,
    "scope_boundary_event": ScopeBoundaryEventPayload,
    "finding_record": FindingRecordPayload,
    "delivery_verdict": DeliveryVerdictPayload,
    "harness_attestation": HarnessAttestationPayload,
}


def _schema_required(record_type: str) -> set[str]:
    schema = json.loads((_SCHEMA_DIR / f"{record_type}.schema.json").read_text(encoding="utf-8"))
    return set(schema.get("required", []))


def _model_required(model: type[BaseModel]) -> set[str]:
    """Fields the model treats as required (no default => caller MUST supply)."""
    return {name for name, field in model.model_fields.items() if field.is_required()}


@pytest.mark.parametrize("record_type", sorted(_MODEL_BY_RECORD_TYPE))
def test_model_required_fields_equal_schema_required(record_type: str) -> None:
    """The model's required fields equal the schema's ``required`` array."""
    model = _MODEL_BY_RECORD_TYPE[record_type]
    schema_required = _schema_required(record_type)
    model_required = _model_required(model)

    assert model_required == schema_required, (
        f"{model.__name__} required-field drift vs {record_type}.schema.json: "
        f"schema-only={sorted(schema_required - model_required)}, "
        f"model-only={sorted(model_required - schema_required)}"
    )


@pytest.mark.parametrize("record_type", sorted(_MODEL_BY_RECORD_TYPE))
def test_model_optional_fields_are_in_schema_properties(record_type: str) -> None:
    """Every model field name is a declared schema property (no stray fields)."""
    schema = json.loads((_SCHEMA_DIR / f"{record_type}.schema.json").read_text(encoding="utf-8"))
    schema_properties = set(schema.get("properties", {}))
    model = _MODEL_BY_RECORD_TYPE[record_type]
    model_fields = set(model.model_fields)

    stray = model_fields - schema_properties
    assert stray == set(), (
        f"{model.__name__} declares fields absent from {record_type}.schema.json properties: {sorted(stray)}"
    )


def test_coverage_cell_payload_is_removed() -> None:
    """The orphaned CoverageCellPayload model is gone (records-payloads-5).

    It had no standalone schema (coverage_cell is inline in the assessment
    bundle schema), no construction site in src/, and gave a false impression
    of type-checked coverage-cell construction. It must not be re-exported.
    """
    assert not hasattr(agent_reliability, "CoverageCellPayload")
    assert "CoverageCellPayload" not in agent_reliability.__all__
