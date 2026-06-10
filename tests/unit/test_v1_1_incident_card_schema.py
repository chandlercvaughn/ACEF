"""Regression tests for the v1.1 incident_card + coordinated_disclosure schemas.

Covers the two schemas authored under F-M2-SCHEMA-CARD:

- ``acef-conventions/v1.1/incident_card.schema.json``
- ``acef-conventions/v1.1/coordinated_disclosure.schema.json``

Assertions exercised:

- VAL-CARD-001: the closed incident_card payload schema validates a minimal
  conforming public-projection card and rejects unknown top-level keys that are
  neither ``x-*``-namespaced nor a ``*_commitment`` field; the ``x-*`` vendor
  namespace accepts both the bare ``x-<vendor>`` form and the slash-qualified
  ``x-<vendor>/<segment>(/<segment>)*`` form while rejecting a bare trailing
  slash, uppercase segments, and non-object values; the single canonical
  coordinated_disclosure shape enforces the §5.6 ``status: public`` conditional
  (``reporter_role`` required, ``embargo_until`` forbidden).
- VAL-IDSCH-001: ``public_incident_id`` enforces the
  ``AIIC-{assigner}-{year}-{suffix}`` grammar with a >=26 Crockford-base32
  suffix (>=128 bits), a 2-8 uppercase-alphanumeric (dot-free) assigner, and a
  ``id_grade`` pinned to ``self-asserted`` on the v1.1 surface
  (``registry-canonical`` and any unknown grade are rejected).

The incident_card schema ``$ref``s a companion ``harm-core-taxonomy.json``
(authored by F-M2-SCHEMA-SEV-CROSS, not yet present). To keep these tests GREEN
today without that file, a minimal stub for the missing ``$id`` is registered in
a local ``referencing.Registry`` alongside the two real v1.1 schemas. No card
fixture exercises the ``taxonomy_crosswalk`` member subschemas, so the only
external dependency is the ``harm_class`` enum stub.

Determinism: fixtures are static literals; no wall-clock or random values.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_V1_1_DIR = _PROJECT_ROOT / "acef-conventions" / "v1.1"
_INCIDENT_CARD_PATH = _V1_1_DIR / "incident_card.schema.json"
_COORDINATED_DISCLOSURE_PATH = _V1_1_DIR / "coordinated_disclosure.schema.json"

# A valid Crockford-base32 suffix carrying >=128 bits (exactly 26 chars, the
# minimum the pattern permits). Alphabet excludes I, L, O, U.
_VALID_SUFFIX = "0123456789ABCDEFGHJKMNPQRS"
assert len(_VALID_SUFFIX) == 26  # noqa: S101 — fixture invariant, not a runtime check

_VALID_PUBLIC_INCIDENT_ID = f"AIIC-OPENAI-2026-{_VALID_SUFFIX}"

# A structurally valid harm_core subtree. harm_class is keyed to Art.3(49)(a-d)
# via the harm-core-taxonomy companion schema; "3.49.a" matches the stub enum.
_VALID_HARM_CORE: dict[str, Any] = {
    "realization": "harm_event",
    "causality": {
        "entity": "ai",
        "intent": "unintentional",
        "timing": "post_deployment",
    },
    "harm_class": "3.49.a",
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _harm_core_taxonomy_stub() -> dict[str, Any]:
    """Minimal stub for the not-yet-authored harm-core-taxonomy.json.

    Supplies the single ``$defs/harm_class`` definition the incident_card
    schema ``$ref``s, so these tests run GREEN before F-M2-SCHEMA-SEV-CROSS
    lands the real companion file.
    """
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://acef.ai/schemas/v1.1/harm-core-taxonomy.json",
        "$defs": {
            "harm_class": {
                "type": "string",
                "enum": ["3.49.a", "3.49.b", "3.49.c", "3.49.d"],
            }
        },
    }


@pytest.fixture(scope="module")
def incident_card_schema() -> dict[str, Any]:
    return _load(_INCIDENT_CARD_PATH)


@pytest.fixture(scope="module")
def coordinated_disclosure_schema() -> dict[str, Any]:
    return _load(_COORDINATED_DISCLOSURE_PATH)


@pytest.fixture(scope="module")
def incident_card_validator(
    incident_card_schema: dict[str, Any],
    coordinated_disclosure_schema: dict[str, Any],
) -> Draft202012Validator:
    """Validator for incident_card with the companion-schema registry.

    Registers the two real v1.1 schemas plus a minimal harm-core-taxonomy stub
    so the relative ``harm-core-taxonomy.json#/$defs/harm_class`` ``$ref``
    resolves against the card's ``$id`` base.
    """
    resources = [
        Resource.from_contents(incident_card_schema),
        Resource.from_contents(coordinated_disclosure_schema),
        Resource.from_contents(_harm_core_taxonomy_stub()),
    ]
    registry = Registry().with_resources([(r.id(), r) for r in resources])
    return Draft202012Validator(incident_card_schema, registry=registry)


@pytest.fixture(scope="module")
def coordinated_disclosure_validator(
    coordinated_disclosure_schema: dict[str, Any],
) -> Draft202012Validator:
    """Validator for coordinated_disclosure (no external ``$ref``s)."""
    return Draft202012Validator(coordinated_disclosure_schema)


def _valid_card() -> dict[str, Any]:
    return {
        "public_incident_id": _VALID_PUBLIC_INCIDENT_ID,
        "id_grade": "self-asserted",
        "harm_core": dict(_VALID_HARM_CORE),
    }


# --------------------------------------------------------------------------- #
# incident_card.schema.json                                                   #
# --------------------------------------------------------------------------- #


def test_incident_card_check_schema(incident_card_schema: dict[str, Any]) -> None:
    """The incident_card schema is itself a valid Draft 2020-12 schema."""
    Draft202012Validator.check_schema(incident_card_schema)


def test_incident_card_minimal_conforming_validates(
    incident_card_validator: Draft202012Validator,
) -> None:
    """A minimal conforming public-projection card validates (VAL-CARD-001)."""
    errors = list(incident_card_validator.iter_errors(_valid_card()))
    assert errors == [], [e.message for e in errors]


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        pytest.param(
            lambda c: c.__setitem__("id_grade", "registry-canonical"),
            "id_grade registry-canonical (v1.2-only) rejected on v1.1 surface",
            id="id_grade-registry-canonical",
        ),
        pytest.param(
            lambda c: c.__setitem__("id_grade", "bogus-grade"),
            "unknown id_grade rejected",
            id="id_grade-unknown",
        ),
        pytest.param(
            lambda c: c.__setitem__("public_incident_id", f"AIIC-OPENAI-2026-{_VALID_SUFFIX[:-1]}"),
            "suffix shorter than 26 Crockford chars rejected",
            id="suffix-too-short",
        ),
        pytest.param(
            lambda c: c.__setitem__("public_incident_id", f"AIIC-OPENAI.COM-2026-{_VALID_SUFFIX}"),
            "dotted-domain assigner fails the pattern",
            id="assigner-dotted-domain",
        ),
        pytest.param(
            lambda c: c.__setitem__("unknown_top_level_key", "x"),
            "extra non-x-, non-_commitment key rejected by additionalProperties",
            id="extra-unknown-key",
        ),
        pytest.param(
            lambda c: c.pop("public_incident_id"),
            "missing required public_incident_id rejected",
            id="missing-public-incident-id",
        ),
    ],
)
def test_incident_card_rejects(
    incident_card_validator: Draft202012Validator,
    mutator: Any,
    reason: str,
) -> None:
    """The closed card rejects the enumerated malformations (VAL-CARD-001 /
    VAL-IDSCH-001)."""
    card = _valid_card()
    mutator(card)
    assert not incident_card_validator.is_valid(card), reason


@pytest.mark.parametrize(
    ("key", "value"),
    [
        pytest.param("x-freddy/voice-rubric-emission", {}, id="x-slash-qualified"),
        pytest.param("x-freddy", {}, id="x-bare"),
        pytest.param("x-vendor-foo/bar", {"a": 1}, id="x-multi-segment"),
        pytest.param("description_commitment", "sha256:" + "a" * 64, id="commitment-field"),
    ],
)
def test_incident_card_accepts_extension_keys(
    incident_card_validator: Draft202012Validator,
    key: str,
    value: Any,
) -> None:
    """The x-* vendor namespace and *_commitment patternProperties are accepted
    (VAL-CARD-001)."""
    card = _valid_card()
    card[key] = value
    errors = list(incident_card_validator.iter_errors(card))
    assert errors == [], [e.message for e in errors]


@pytest.mark.parametrize(
    ("key", "value", "reason"),
    [
        pytest.param("x-freddy/", {}, "bare trailing slash rejected", id="x-trailing-slash"),
        pytest.param("x-Vendor", {}, "uppercase x- segment rejected", id="x-uppercase"),
        pytest.param("x-vendor", "not-an-object", "x-* value must be an object", id="x-non-object"),
    ],
)
def test_incident_card_rejects_malformed_extension_keys(
    incident_card_validator: Draft202012Validator,
    key: str,
    value: Any,
    reason: str,
) -> None:
    """Malformed x-* keys/values are rejected (VAL-CARD-001)."""
    card = _valid_card()
    card[key] = value
    assert not incident_card_validator.is_valid(card), reason


# --------------------------------------------------------------------------- #
# coordinated_disclosure.schema.json                                          #
# --------------------------------------------------------------------------- #


def test_coordinated_disclosure_check_schema(
    coordinated_disclosure_schema: dict[str, Any],
) -> None:
    """The coordinated_disclosure schema is itself a valid Draft 2020-12 schema."""
    Draft202012Validator.check_schema(coordinated_disclosure_schema)


def test_coordinated_disclosure_public_validates(
    coordinated_disclosure_validator: Draft202012Validator,
) -> None:
    """A valid status: public block (with reporter_role, no embargo) validates
    (VAL-CARD-001)."""
    block = {"status": "public", "reporter_role": "external_researcher"}
    errors = list(coordinated_disclosure_validator.iter_errors(block))
    assert errors == [], [e.message for e in errors]


def test_coordinated_disclosure_non_public_validates(
    coordinated_disclosure_validator: Draft202012Validator,
) -> None:
    """A valid non-public block validates; embargo_until is permitted off the
    public state (VAL-CARD-001)."""
    block = {"status": "coordinated", "embargo_until": "2026-01-01T00:00:00Z"}
    errors = list(coordinated_disclosure_validator.iter_errors(block))
    assert errors == [], [e.message for e in errors]


def test_coordinated_disclosure_accepts_x_namespace(
    coordinated_disclosure_validator: Draft202012Validator,
) -> None:
    """The slash-qualified x-* vendor namespace is accepted (VAL-CARD-001)."""
    block = {"status": "coordinated", "x-freddy/voice-rubric-emission": {}}
    errors = list(coordinated_disclosure_validator.iter_errors(block))
    assert errors == [], [e.message for e in errors]


@pytest.mark.parametrize(
    ("block", "reason"),
    [
        pytest.param(
            {"status": "public"},
            "status: public requires reporter_role (§5.6 if/then)",
            id="public-missing-reporter-role",
        ),
        pytest.param(
            {
                "status": "public",
                "reporter_role": "regulator",
                "embargo_until": "2026-01-01T00:00:00Z",
            },
            "embargo_until forbidden on status: public (§5.6 if/then not)",
            id="public-with-embargo",
        ),
        pytest.param(
            {"status": "leaked"},
            "out-of-enum status rejected",
            id="status-out-of-enum",
        ),
        pytest.param(
            {"status": "coordinated", "weird_key": 1},
            "extra non-x- key rejected by additionalProperties",
            id="extra-unknown-key",
        ),
        pytest.param(
            {"status": "coordinated", "x-freddy/": {}},
            "bare trailing slash x-* key rejected",
            id="x-trailing-slash",
        ),
    ],
)
def test_coordinated_disclosure_rejects(
    coordinated_disclosure_validator: Draft202012Validator,
    block: dict[str, Any],
    reason: str,
) -> None:
    """The closed disclosure block rejects the enumerated malformations
    (VAL-CARD-001)."""
    assert not coordinated_disclosure_validator.is_valid(block), reason
