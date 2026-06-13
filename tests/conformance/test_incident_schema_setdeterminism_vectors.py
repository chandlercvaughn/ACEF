"""Conformance driver for the F-M8-INCIDENT-SCHEMA set-determinism vectors.

Validates the four record-level ``incident_card`` payload vectors under
``test-vectors/incident-schema-setdeterminism/`` against the SHIPPED
``acef-conventions/v1.1/incident_card.schema.json`` through the PRODUCTION
``acef.schemas.registry.build_schema_registry('v1.1')`` resolver — the same
resolution backbone the validator uses.

These vectors prove the two set-determinism fixes:

- VAL-FIX-INCSCHEMA-002 — public ``taxonomy_crosswalk.eu_ai_act.serious_incident_triggers``
  carries ``uniqueItems: true`` (matching the source-backed twin), so a card with
  ``["3.49.a","3.49.a"]`` is rejected while ``["3.49.a","3.49.b"]`` validates.
- VAL-FIX-INCSCHEMA-003 — ``harm_distribution_basis`` carries ``uniqueItems: true``,
  so ``["race","race"]`` is rejected while ``["race","sex"]`` validates.

RED-first: before the schema edits the two ``fail-*`` vectors VALIDATED (the
documented determinism hole); after the edits they are rejected with a
``uniqueItems`` violation. The ``pass-*`` vectors validate in both states.

Deterministic: vectors are static JSON literals on disk; the registry build is a
byte-stable filesystem sweep (no wall-clock, no random, no network).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_VECTOR_DIR = _PROJECT_ROOT / "test-vectors" / "incident-schema-setdeterminism"
_INCIDENT_CARD_PATH = _PROJECT_ROOT / "acef-conventions" / "v1.1" / "incident_card.schema.json"

_SRC = _PROJECT_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from acef.schemas.registry import build_schema_registry  # noqa: E402


@pytest.fixture(scope="module")
def card_validator() -> Draft202012Validator:
    schema = json.loads(_INCIDENT_CARD_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=build_schema_registry("v1.1"))


def _load_vector(name: str) -> dict[str, Any]:
    return json.loads((_VECTOR_DIR / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "vector_name",
    [
        "fail-dup-serious-incident-triggers.json",
        "fail-dup-harm-distribution-basis.json",
    ],
)
def test_fail_vectors_rejected_on_uniqueitems(card_validator: Draft202012Validator, vector_name: str) -> None:
    """Each ``fail-*`` set-determinism vector is rejected with a ``uniqueItems`` error.

    Pre-fix these cards validated (no ``uniqueItems`` on the set-typed arrays);
    post-fix the only diagnostic is the duplicate-element rejection.
    """
    card = _load_vector(vector_name)
    errors = list(card_validator.iter_errors(card))
    assert errors, f"{vector_name} must be rejected post-fix, but it validated"
    assert any(e.validator == "uniqueItems" for e in errors), (
        f"{vector_name} must fail on uniqueItems; got validators {[e.validator for e in errors]}"
    )


@pytest.mark.parametrize(
    "vector_name",
    [
        "pass-unique-serious-incident-triggers.json",
        "pass-unique-harm-distribution-basis.json",
    ],
)
def test_pass_vectors_validate(card_validator: Draft202012Validator, vector_name: str) -> None:
    """Each ``pass-*`` set-determinism vector validates (no over-rejection)."""
    card = _load_vector(vector_name)
    errors = list(card_validator.iter_errors(card))
    assert not errors, f"{vector_name} must validate post-fix; got: {[e.message for e in errors]}"
