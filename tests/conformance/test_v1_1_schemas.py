"""Conformance test for v1.1 record-type JSON Schemas.

Verifies VAL-SCHEMA-001..006 from the acef-v0.4-freddy-adoption contract:

- VAL-SCHEMA-001: authorized_test_scope.schema.json exists and is valid JSON Schema 2020-12.
- VAL-SCHEMA-002: scope_boundary_event.schema.json valid + allOf hard_stop pairing rejects
  bundle with hard_stop_triggered=true but no hard_stop_attestation_ref.
- VAL-SCHEMA-003: finding_record.schema.json valid + normative dedupe_key recipe documented.
- VAL-SCHEMA-004: delivery_verdict.schema.json valid + verified_delivered triple-requirement
  (read_back + digest_match + harness_attestation_ref).
- VAL-SCHEMA-005: harness_attestation.schema.json valid; verifier_class excludes persona/llm.
- VAL-SCHEMA-006: assessment-bundle.schema.json valid; defines coverage_cell as optional
  field group (no standalone coverage_cell.schema.json file in v1.1/).

These tests intentionally exercise the JSON Schema Draft202012Validator.check_schema()
contract path, plus targeted positive/negative fixture validation for the allOf
conditionals, which are the per-schema acceptance criteria in contract.md §SCHEMA.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[2]
V1_1_DIR = REPO_ROOT / "acef-conventions" / "v1.1"

RECORD_SCHEMAS = [
    "authorized_test_scope",
    "scope_boundary_event",
    "finding_record",
    "delivery_verdict",
    "harness_attestation",
    "assessment-bundle",
]


def _load(name: str) -> dict:
    path = V1_1_DIR / f"{name}.schema.json"
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.mark.parametrize("name", RECORD_SCHEMAS)
def test_schema_is_valid_2020_12(name: str) -> None:
    """VAL-SCHEMA-001..006: each schema parses and passes Draft202012Validator.check_schema()."""
    schema = _load(name)
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"].startswith("https://acef.ai/schemas/v1.1/")


def test_scope_boundary_event_hard_stop_pairing() -> None:
    """VAL-SCHEMA-002: hard_stop_triggered=true without attestation_ref MUST fail validation."""
    schema = _load("scope_boundary_event")
    validator = Draft202012Validator(schema)
    negative = {
        "event_id": "urn:acef:sbe:00000000-0000-0000-0000-000000000001",
        "scope_ref": "urn:acef:scope:00000000-0000-0000-0000-000000000002",
        "attempted_action": {
            "action_class": "tool_call",
            "action_target": "x://example",
            "action_payload_digest": "sha256:" + "a" * 64,
        },
        "authorized_scope_snapshot": {"scope_id": "x", "scope_version": "1.0.0"},
        "classification": "intentional_bypass_attempt",
        "hard_stop_triggered": True,
        "detected_at": "2026-01-01T00:00:00Z",
        "detector": {"detector_class": "preflight_probe", "detector_id": "pf-1"},
    }
    errors = list(validator.iter_errors(negative))
    assert errors, "hard_stop_triggered=true without hard_stop_attestation_ref must fail validation"


def test_finding_record_dedupe_key_recipe_documented() -> None:
    """VAL-SCHEMA-003: dedupe_key recipe (JCS-canonicalized SHA-256) documented in schema."""
    schema = _load("finding_record")
    dedupe_field = schema["properties"]["dedupe_key"]
    description = dedupe_field.get("description", "")
    assert "RFC 8785" in description or "JCS" in description, (
        "dedupe_key description must reference RFC 8785 / JCS canonicalization"
    )
    assert "sha256" in description.lower(), "dedupe_key must specify sha256 hash"
    for field in [
        "expected_behavior",
        "reproduction_steps_ref_content_hash",
        "subject_ref",
    ]:
        assert field in description, f"dedupe_key recipe must enumerate field '{field}'"


def test_delivery_verdict_verified_delivered_triple_requirement() -> None:
    """VAL-SCHEMA-004: verified_delivered requires read_back + digest_match=true + harness_attestation_ref."""
    schema = _load("delivery_verdict")
    validator = Draft202012Validator(schema)
    negative = {
        "verdict_id": "urn:acef:delivery:00000000-0000-0000-0000-000000000001",
        "finding_ref": "urn:acef:finding:00000000-0000-0000-0000-000000000002",
        "destination": {
            "provider_class": "plane",
            "provider_instance_id": "plane-1",
            "provider_object_id": "ticket-1",
        },
        "write_attempt": {
            "attempted_at": "2026-01-01T00:00:00Z",
            "request_digest": "sha256:" + "a" * 64,
            "response_status": 200,
            "response_digest": "sha256:" + "b" * 64,
        },
        "delivery_state": "verified_delivered",
    }
    errors = list(validator.iter_errors(negative))
    assert errors, "verified_delivered missing read_back/digest_match/harness_attestation_ref must fail"


def test_harness_attestation_verifier_class_excludes_persona_and_llm() -> None:
    """VAL-SCHEMA-005: verifier.verifier_class enum forbids 'persona' and 'llm'."""
    schema = _load("harness_attestation")
    verifier_class_enum = schema["properties"]["verifier"]["properties"]["verifier_class"]["enum"]
    assert "persona" not in verifier_class_enum
    assert "llm" not in verifier_class_enum
    assert "contract_gate" in verifier_class_enum


def test_assessment_bundle_v1_1_has_coverage_cell() -> None:
    """VAL-SCHEMA-006: assessment-bundle.schema.json v1.1 defines coverage_cell as optional field group."""
    schema = _load("assessment-bundle")
    # coverage_cell or coverage_cells must be in properties
    props = schema.get("properties", {})
    assert "coverage_cell" in props or "coverage_cells" in props, (
        "v1.1 assessment-bundle must define coverage_cell or coverage_cells"
    )
    # Must NOT be in top-level required (optional)
    required = schema.get("required", [])
    assert "coverage_cell" not in required
    assert "coverage_cells" not in required


def test_no_standalone_coverage_cell_schema_file() -> None:
    """VAL-SCHEMA-006: coverage_cell MUST NOT exist as a standalone record schema in v1.1/."""
    standalone = V1_1_DIR / "coverage_cell.schema.json"
    assert not standalone.exists(), "coverage_cell must be defined inside assessment-bundle, not as standalone record"
