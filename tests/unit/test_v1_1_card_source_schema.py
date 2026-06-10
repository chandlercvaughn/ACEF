"""Regression tests for the v1.1 ``card_source`` projection-source overlay.

Covers the schema authored under F-M2-SCHEMA-SOURCE:

- ``acef-conventions/v1.1/card_source.schema.json``

Assertion exercised:

- VAL-SRC-001: the closed ``card_source`` overlay validates a CONFORMING
  confidential/embargoed Art.73 projection source (a RESERVED, self-asserted
  ``public_incident_id``; a valid ``harm_core``; a ``publishability_map``; and
  the structured ``eu_ai_act_facts`` carrying ``edition`` + a trigger array +
  ``widespread`` + ``death_involved``) BEFORE any public ``incident_card``
  exists, and REJECTS: an empty ``{}`` source (all requireds missing); a source
  missing ``eu_ai_act_facts`` (the VAL-SRC-001 addition to the Appendix B
  required set); an ``eu_ai_act_facts`` missing ``death_involved``; an
  out-of-enum serious-incident trigger (``3.49.e``); and an
  ``id_grade: registry-canonical`` (the v1.2-only grade rejected on the v1.1
  surface).

The ``card_source`` schema ``$ref``s companion v1.1 schemas:

- ``incident_card.schema.json#/properties/harm_core`` (the single canonical
  closed ``harm_core`` shape, shared so the card and its source never diverge),
- ``harm-core-taxonomy.json#/$defs/harm_class`` (reached transitively through
  the card's ``harm_core``),
- ``coordinated_disclosure.schema.json`` and ``severity_vector.schema.json``
  (the optional projection-input blocks).

All companions are real v1.1 files (authored by CARD / SEV-CROSS), registered by
``$id`` in a local ``referencing.Registry`` so every ``$ref`` resolves against
the ``card_source`` ``$id`` base. Production resolver wiring
(``scripts/validate_schemas.py`` + record-type registration) is
F-M2-SCHEMA-GATING's; these local-registry tests are the SOURCE-scope coverage.

Determinism: fixtures are static literals; no wall-clock or random values.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_V1_1_DIR = _PROJECT_ROOT / "acef-conventions" / "v1.1"
_CARD_SOURCE_PATH = _V1_1_DIR / "card_source.schema.json"
_INCIDENT_CARD_PATH = _V1_1_DIR / "incident_card.schema.json"
_HARM_CORE_TAXONOMY_PATH = _V1_1_DIR / "harm-core-taxonomy.json"
_COORDINATED_DISCLOSURE_PATH = _V1_1_DIR / "coordinated_disclosure.schema.json"
_SEVERITY_VECTOR_PATH = _V1_1_DIR / "severity_vector.schema.json"

# The exact relative $ref strings card_source uses to reach its companions. Pins
# the contract so a rename of a companion file or its sub-pointer can never
# silently pass (the production resolver wired by F-M2-SCHEMA-GATING MUST wire
# the same graph).
_HARM_CORE_REF = "incident_card.schema.json#/properties/harm_core"
_COORDINATED_DISCLOSURE_REF = "coordinated_disclosure.schema.json"
_SEVERITY_VECTOR_REF = "severity_vector.schema.json"

# A valid Crockford-base32 suffix carrying >=128 bits (exactly 26 chars, the
# minimum the pattern permits). Alphabet excludes I, L, O, U.
_VALID_SUFFIX = "0123456789ABCDEFGHJKMNPQRS"
assert len(_VALID_SUFFIX) == 26  # noqa: S101 — fixture invariant, not a runtime check

_VALID_PUBLIC_INCIDENT_ID = f"AIIC-OPENAI-2026-{_VALID_SUFFIX}"

# A structurally valid harm_core subtree (the closed shape shared with
# incident_card via the $ref). harm_class is a normative ACEF class NAME from the
# closed RFC §5.2 vocabulary resolved through harm-core-taxonomy.json.
_VALID_HARM_CORE: dict[str, Any] = {
    "realization": "harm_event",
    "causality": {
        "entity": "ai",
        "intent": "unintentional",
        "timing": "post_deployment",
    },
    "harm_class": "physical_health",
}

# A valid full-Group-I severity vector (HT/HG/RV/SC/BR in fixed order), bandable.
_VALID_SEVERITY_VECTOR = "ACEF-SEV:1.0/HT:P/HG:H/RV:I/SC:U/BR:I"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def card_source_schema() -> dict[str, Any]:
    return _load(_CARD_SOURCE_PATH)


@pytest.fixture(scope="module")
def card_source_validator(card_source_schema: dict[str, Any]) -> Draft202012Validator:
    """Validator for card_source with the companion-schema registry.

    Registers the real v1.1 companions — incident_card (the ``harm_core`` ``$ref``
    target), harm-core-taxonomy (reached transitively through the card's
    ``harm_core``), coordinated_disclosure and severity_vector — by ``$id`` so the
    relative ``incident_card.schema.json#/properties/harm_core``,
    ``coordinated_disclosure.schema.json`` and ``severity_vector.schema.json``
    ``$ref``s all resolve against the card_source ``$id`` base.
    """
    resources = [
        Resource.from_contents(card_source_schema),
        Resource.from_contents(_load(_INCIDENT_CARD_PATH)),
        Resource.from_contents(_load(_HARM_CORE_TAXONOMY_PATH)),
        Resource.from_contents(_load(_COORDINATED_DISCLOSURE_PATH)),
        Resource.from_contents(_load(_SEVERITY_VECTOR_PATH)),
    ]
    registry = Registry().with_resources([(r.id(), r) for r in resources])
    return Draft202012Validator(card_source_schema, registry=registry)


def _valid_card_source() -> dict[str, Any]:
    """A CONFORMING confidential/embargoed Art.73 projection source.

    Carries exactly the six required members: a RESERVED, self-asserted
    ``public_incident_id``; ``id_grade: self-asserted``; ``id_state: RESERVED``
    (the embargo-safe state with no public card); a valid ``harm_core``; a
    ``publishability_map``; and the structured ``eu_ai_act_facts``. This is the
    §5.7 confidential path: it validates BEFORE any public ``incident_card``
    exists.
    """
    return {
        "public_incident_id": _VALID_PUBLIC_INCIDENT_ID,
        "id_grade": "self-asserted",
        "id_state": "RESERVED",
        "harm_core": copy.deepcopy(_VALID_HARM_CORE),
        "publishability_map": {
            "/root_cause_analysis": "omitted",
            "/harm_distribution_basis": "regulator-only",
            "/description": "hash-committed",
        },
        "eu_ai_act_facts": {
            "edition": "reg-2024-1689",
            "serious_incident_triggers": ["3.49.a"],
            "widespread": False,
            "death_involved": True,
        },
    }


# --------------------------------------------------------------------------- #
# card_source.schema.json                                                     #
# --------------------------------------------------------------------------- #


def test_card_source_check_schema(card_source_schema: dict[str, Any]) -> None:
    """The card_source schema is itself a valid Draft 2020-12 schema (VAL-SRC-001)."""
    Draft202012Validator.check_schema(card_source_schema)


def test_card_source_id_and_closure(card_source_schema: dict[str, Any]) -> None:
    """The overlay declares the documented ``$id``, is closed, and pins the
    VAL-SRC-001 required set including ``eu_ai_act_facts`` (VAL-SRC-001)."""
    assert card_source_schema["$id"] == "https://acef.ai/schemas/v1.1/card_source.schema.json"
    assert card_source_schema["additionalProperties"] is False
    assert set(card_source_schema["required"]) == {
        "public_incident_id",
        "id_grade",
        "id_state",
        "harm_core",
        "publishability_map",
        "eu_ai_act_facts",
    }
    assert set(card_source_schema["properties"]["eu_ai_act_facts"]["required"]) == {
        "edition",
        "serious_incident_triggers",
        "widespread",
        "death_involved",
    }


def test_card_source_companion_refs_pinned(card_source_schema: dict[str, Any]) -> None:
    """The overlay reaches its companions via exactly the documented ``$ref``
    strings (VAL-SRC-001).

    Pins the production dependency that F-M2-SCHEMA-GATING's resolver MUST wire:
    ``harm_core`` reuses the incident_card closed shape, and the optional
    projection-input blocks delegate to their companion grammars. Asserting the
    exact strings makes a companion rename loud rather than silent.
    """
    props = card_source_schema["properties"]
    assert props["harm_core"]["$ref"] == _HARM_CORE_REF
    assert props["coordinated_disclosure"]["$ref"] == _COORDINATED_DISCLOSURE_REF
    assert props["severity_vector"]["$ref"] == _SEVERITY_VECTOR_REF


def test_card_source_confidential_art73_validates(
    card_source_validator: Draft202012Validator,
) -> None:
    """A CONFORMING confidential/embargoed Art.73 projection source validates
    BEFORE any public card exists (VAL-SRC-001)."""
    errors = list(card_source_validator.iter_errors(_valid_card_source()))
    assert errors == [], [e.message for e in errors]


def test_card_source_validates_with_optional_companions(
    card_source_validator: Draft202012Validator,
) -> None:
    """The optional ``coordinated_disclosure``, ``severity_vector`` and
    ``disputed`` projection inputs validate THROUGH their ``$ref``s
    (VAL-SRC-001).

    Proves the card_source ``coordinated_disclosure.schema.json`` and
    ``severity_vector.schema.json`` ``$ref``s resolve against the registry and
    admit §5.6/§5.4-conforming blocks alongside the required core.
    """
    source = _valid_card_source()
    source["id_state"] = "PUBLISHED"
    source["disputed"] = True
    source["coordinated_disclosure"] = {
        "status": "coordinated",
        "embargo_until": "2026-12-01T00:00:00Z",
    }
    source["severity_vector"] = _VALID_SEVERITY_VECTOR
    errors = list(card_source_validator.iter_errors(source))
    assert errors == [], [e.message for e in errors]


def test_card_source_rejects_empty_object(
    card_source_validator: Draft202012Validator,
) -> None:
    """An EMPTY ``{}`` card_source is rejected — all six requireds (including
    ``eu_ai_act_facts``) are missing (VAL-SRC-001).

    This is the core VAL-SRC-001 guarantee: an empty/absent projection source
    cannot masquerade as a valid confidential Art.73 report.
    """
    errors = list(card_source_validator.iter_errors({}))
    assert errors != []
    # jsonschema reports a single `required`-keyword error for the closed object,
    # whose validator_value is the LIST of required property names. Assert the
    # empty object is invalid and that eu_ai_act_facts is among the requireds the
    # schema enforces (proving VAL-SRC-001's addition is structurally present).
    required_errors = [e for e in errors if e.validator == "required"]
    assert required_errors  # at least one required-keyword failure fired
    enforced_required = {name for e in required_errors for name in e.validator_value}
    assert "eu_ai_act_facts" in enforced_required
    assert "eu_ai_act_facts" in card_source_validator.schema["required"]


def test_card_source_rejects_severity_vector_through_ref(
    card_source_validator: Draft202012Validator,
) -> None:
    """An HG-less/unbandable ``severity_vector`` is rejected THROUGH the
    companion ``$ref`` (VAL-SRC-001).

    Proves the card_source ``severity_vector.schema.json`` ``$ref`` enforces the
    full mandatory Group-I grammar (not merely resolves), so card_source rejects
    the same unbandable vectors incident_card does.
    """
    source = _valid_card_source()
    source["severity_vector"] = "ACEF-SEV:1.0/HT:S"  # HG-less, unbandable
    assert not card_source_validator.is_valid(source)


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        pytest.param(
            lambda s: s.pop("eu_ai_act_facts"),
            "missing eu_ai_act_facts rejected (VAL-SRC-001 addition to the required set)",
            id="missing-eu_ai_act_facts",
        ),
        pytest.param(
            lambda s: s["eu_ai_act_facts"].pop("death_involved"),
            "eu_ai_act_facts missing death_involved rejected",
            id="eu_facts-missing-death_involved",
        ),
        pytest.param(
            lambda s: s["eu_ai_act_facts"].pop("edition"),
            "eu_ai_act_facts missing edition rejected",
            id="eu_facts-missing-edition",
        ),
        pytest.param(
            lambda s: s["eu_ai_act_facts"].pop("widespread"),
            "eu_ai_act_facts missing widespread rejected",
            id="eu_facts-missing-widespread",
        ),
        pytest.param(
            lambda s: s["eu_ai_act_facts"].pop("serious_incident_triggers"),
            "eu_ai_act_facts missing serious_incident_triggers rejected",
            id="eu_facts-missing-triggers",
        ),
        pytest.param(
            lambda s: s["eu_ai_act_facts"]["serious_incident_triggers"].append("3.49.e"),
            "out-of-enum serious-incident trigger 3.49.e rejected",
            id="eu_facts-trigger-out-of-enum",
        ),
        pytest.param(
            lambda s: s["eu_ai_act_facts"].__setitem__("edition", "reg-9999-0000"),
            "wrong edition pin rejected (const reg-2024-1689)",
            id="eu_facts-wrong-edition",
        ),
        pytest.param(
            lambda s: s["eu_ai_act_facts"].__setitem__("unknown_fact", True),
            "extra key inside eu_ai_act_facts rejected (closed object)",
            id="eu_facts-extra-key",
        ),
        pytest.param(
            lambda s: s.__setitem__("id_grade", "registry-canonical"),
            "id_grade registry-canonical (v1.2-only) rejected on the v1.1 surface",
            id="id_grade-registry-canonical",
        ),
        pytest.param(
            lambda s: s.__setitem__("id_grade", "bogus-grade"),
            "unknown id_grade rejected",
            id="id_grade-unknown",
        ),
        pytest.param(
            lambda s: s.pop("id_grade"),
            "missing id_grade rejected (grade travels with the id, §5.3)",
            id="missing-id_grade",
        ),
        pytest.param(
            lambda s: s.pop("id_state"),
            "missing id_state rejected",
            id="missing-id_state",
        ),
        pytest.param(
            lambda s: s.__setitem__("id_state", "DISPUTED"),
            "DISPUTED is not a primary id_state (it is the boolean disputed overlay)",
            id="id_state-disputed-not-a-state",
        ),
        pytest.param(
            lambda s: s.pop("public_incident_id"),
            "missing public_incident_id rejected",
            id="missing-public_incident_id",
        ),
        pytest.param(
            lambda s: s.__setitem__("public_incident_id", f"AIIC-OPENAI-2026-{_VALID_SUFFIX[:-1]}"),
            "suffix shorter than 26 Crockford chars rejected (<128 bits)",
            id="suffix-too-short",
        ),
        pytest.param(
            lambda s: s.__setitem__("public_incident_id", f"AIIC-OPENAI.COM-2026-{_VALID_SUFFIX}"),
            "dotted-domain assigner fails the pattern",
            id="assigner-dotted-domain",
        ),
        pytest.param(
            lambda s: s.pop("harm_core"),
            "missing harm_core rejected",
            id="missing-harm_core",
        ),
        pytest.param(
            lambda s: s["harm_core"].__setitem__("harm_class", "3.49.a"),
            "EU trigger code as harm_class rejected through the harm_core $ref",
            id="harm_class-eu-trigger-code",
        ),
        pytest.param(
            lambda s: s.pop("publishability_map"),
            "missing publishability_map rejected",
            id="missing-publishability_map",
        ),
        pytest.param(
            lambda s: s["publishability_map"].__setitem__("/x", "leaked"),
            "out-of-enum publishability disposition rejected",
            id="publishability-disposition-out-of-enum",
        ),
        pytest.param(
            lambda s: s["publishability_map"].__setitem__("not-a-pointer", "public"),
            "non-JSON-Pointer publishability key rejected (propertyNames)",
            id="publishability-key-not-a-pointer",
        ),
        pytest.param(
            lambda s: s.__setitem__("unknown_top_level_key", "x"),
            "extra non-x- top-level key rejected by additionalProperties",
            id="extra-unknown-top-level-key",
        ),
    ],
)
def test_card_source_rejects(
    card_source_validator: Draft202012Validator,
    mutator: Any,
    reason: str,
) -> None:
    """The closed card_source overlay rejects the enumerated malformations
    (VAL-SRC-001)."""
    source = _valid_card_source()
    mutator(source)
    assert not card_source_validator.is_valid(source), reason


@pytest.mark.parametrize(
    ("key", "value"),
    [
        pytest.param("x-freddy/voice-rubric-emission", {}, id="x-slash-qualified"),
        pytest.param("x-freddy", {}, id="x-bare"),
        pytest.param("x-vendor-foo/bar", {"a": 1}, id="x-multi-segment"),
    ],
)
def test_card_source_accepts_x_namespace(
    card_source_validator: Draft202012Validator,
    key: str,
    value: Any,
) -> None:
    """The X6 vendor-extension namespace is accepted on card_source
    (VAL-SRC-001)."""
    source = _valid_card_source()
    source[key] = value
    errors = list(card_source_validator.iter_errors(source))
    assert errors == [], [e.message for e in errors]


@pytest.mark.parametrize(
    ("key", "value", "reason"),
    [
        pytest.param("x-freddy/", {}, "bare trailing slash rejected", id="x-trailing-slash"),
        pytest.param("x-Vendor", {}, "uppercase x- segment rejected", id="x-uppercase"),
        pytest.param("x-vendor", "not-an-object", "x-* value must be an object", id="x-non-object"),
    ],
)
def test_card_source_rejects_malformed_x_namespace(
    card_source_validator: Draft202012Validator,
    key: str,
    value: Any,
    reason: str,
) -> None:
    """Malformed ``x-*`` keys/values are rejected on card_source (VAL-SRC-001)."""
    source = _valid_card_source()
    source[key] = value
    assert not card_source_validator.is_valid(source), reason
