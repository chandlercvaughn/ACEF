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
(authored by F-M2-SCHEMA-SEV-CROSS). Until that file lands, an UNMISTAKABLE
``HARM_CORE_TAXONOMY_STUB`` constant supplies the single ``$defs/harm_class``
definition the card ``$ref``s, registered in a local ``referencing.Registry``
alongside the two real v1.1 schemas. The registry is SELF-DE-STUBBING: if the
real ``acef-conventions/v1.1/harm-core-taxonomy.json`` exists on disk it is
loaded and used instead, so these tests automatically upgrade from stub to the
real companion the moment SEV-CROSS ships it — no false green about
resolvability. No card fixture exercises the ``taxonomy_crosswalk`` member
subschemas, so the only external dependency is the ``harm_class`` enum.

The card-level ``coordinated_disclosure`` ``$ref`` is exercised THROUGH the
incident_card schema (not only against the standalone block): cards carrying a
``coordinated_disclosure`` object validate/reject per the §5.6 ``status: public``
conditional, proving the card→coordinated_disclosure ``$ref`` resolves and
enforces against the registry.

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
_HARM_CORE_TAXONOMY_PATH = _V1_1_DIR / "harm-core-taxonomy.json"
_SEVERITY_VECTOR_PATH = _V1_1_DIR / "severity_vector.schema.json"

# Card-level severity_vector fixtures (§5.4). The card now $ref's the companion
# severity_vector.schema.json (companions are "referenced, not inlined"), whose
# top-level is a string validator enforcing the FULL mandatory Group-I grammar
# (HT/HG/RV/SC/BR in fixed order). A full-Group-I vector validates; an HG-less /
# unbandable vector and an out-of-order vector are rejected THROUGH the card $ref.
_VALID_SEVERITY_VECTOR = "ACEF-SEV:1.0/HT:R/HG:H/RV:I/SC:C/BR:P"
# HG-less: only HT is present, so the vector is unbandable (band() keys on HG) and
# the old weak `^ACEF-SEV:1\.0/` prefix would have WRONGLY accepted it.
_HG_LESS_SEVERITY_VECTOR = "ACEF-SEV:1.0/HT:S"
# Out-of-order: HG precedes HT, violating the fixed group/within-group order.
_OUT_OF_ORDER_SEVERITY_VECTOR = "ACEF-SEV:1.0/HG:H/HT:R/RV:I/SC:C/BR:P"

# The exact relative $ref string the incident_card schema uses to reach the
# harm_class enum in the harm-core-taxonomy companion. GATING's production
# resolver MUST wire this companion $id; this constant pins the contract so a
# rename of the companion's $defs path can never silently pass.
_HARM_CLASS_REF = "harm-core-taxonomy.json#/$defs/harm_class"

# The normative ACEF card-level harm_class vocabulary, fixed verbatim by RFC-0002
# §5.2 ("The code list is normative in this RFC (enumerated here): physical_health
# (3(49)(a)), critical_infrastructure (3(49)(b)), fundamental_rights (3(49)(c)),
# property_or_environment (3(49)(d)), and the AI-specific intangible classes
# discrimination, misinformation_integrity, privacy_data, security_compromise,
# economic, societal_systemic, other"). These are the closed set of ACEF class
# NAMES. The EU Art.3(49) "3.49.*" TRIGGER codes are NOT harm_class values — they
# live under taxonomy_crosswalk.eu_ai_act.serious_incident_triggers[] — so a
# "3.49.a" in harm_core.harm_class MUST be rejected (pinned below).
_NORMATIVE_HARM_CLASS_ENUM: list[str] = [
    "physical_health",
    "critical_infrastructure",
    "fundamental_rights",
    "property_or_environment",
    "discrimination",
    "misinformation_integrity",
    "privacy_data",
    "security_compromise",
    "economic",
    "societal_systemic",
    "other",
]

# INTERIM STUB — replace with the real acef-conventions/v1.1/harm-core-taxonomy.json
# once F-M2-SCHEMA-SEV-CROSS lands it (de-stub tracked). Supplies ONLY the single
# $defs/harm_class definition the incident_card schema $ref's, so these tests run
# GREEN before the real companion exists. Its enum is EXACTLY the normative ACEF
# class-name set from RFC §5.2 above, matching the shape the real
# harm-core-taxonomy.json#/$defs/harm_class will have (an enum of these 11
# strings), so the self-de-stub auto-upgrade below stays seamless once SEV-CROSS
# ships the real file. The validator fixture is self-de-stubbing: it loads the
# real file in preference to this constant the moment SEV-CROSS ships it, so no
# test asserts false confidence in resolvability.
HARM_CORE_TAXONOMY_STUB: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://acef.ai/schemas/v1.1/harm-core-taxonomy.json",
    "$defs": {
        "harm_class": {
            "type": "string",
            "enum": list(_NORMATIVE_HARM_CLASS_ENUM),
        }
    },
}

# A valid Crockford-base32 suffix carrying >=128 bits (exactly 26 chars, the
# minimum the pattern permits). Alphabet excludes I, L, O, U.
_VALID_SUFFIX = "0123456789ABCDEFGHJKMNPQRS"
assert len(_VALID_SUFFIX) == 26  # noqa: S101 — fixture invariant, not a runtime check

_VALID_PUBLIC_INCIDENT_ID = f"AIIC-OPENAI-2026-{_VALID_SUFFIX}"

# A structurally valid harm_core subtree. harm_class is a normative ACEF class
# NAME from the closed RFC §5.2 vocabulary (here "physical_health", the 3(49)(a)
# class), resolved via the harm-core-taxonomy companion $defs/harm_class enum. The
# EU Art.3(49) "3.49.*" codes are crosswalk TRIGGER values (under
# taxonomy_crosswalk.eu_ai_act.serious_incident_triggers[]), NOT harm_class — that
# boundary is pinned by test_incident_card_rejects_eu_trigger_code_as_harm_class.
_VALID_HARM_CORE: dict[str, Any] = {
    "realization": "harm_event",
    "causality": {
        "entity": "ai",
        "intent": "unintentional",
        "timing": "post_deployment",
    },
    "harm_class": "physical_health",
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_harm_core_taxonomy() -> dict[str, Any]:
    """Return the harm-core-taxonomy resource, real if present else the stub.

    SELF-DE-STUBBING: prefers the real ``acef-conventions/v1.1/harm-core-taxonomy.json``
    (authored by F-M2-SCHEMA-SEV-CROSS) the moment it exists on disk, otherwise
    falls back to ``HARM_CORE_TAXONOMY_STUB``. This keeps the suite GREEN today
    while automatically exercising the real companion schema once SEV-CROSS ships
    it — no test asserts false confidence in a non-existent file's resolvability.
    """
    if _HARM_CORE_TAXONOMY_PATH.exists():
        return _load(_HARM_CORE_TAXONOMY_PATH)
    return dict(HARM_CORE_TAXONOMY_STUB)


@pytest.fixture(scope="module")
def incident_card_schema() -> dict[str, Any]:
    return _load(_INCIDENT_CARD_PATH)


@pytest.fixture(scope="module")
def coordinated_disclosure_schema() -> dict[str, Any]:
    return _load(_COORDINATED_DISCLOSURE_PATH)


@pytest.fixture(scope="module")
def severity_vector_schema() -> dict[str, Any]:
    return _load(_SEVERITY_VECTOR_PATH)


@pytest.fixture(scope="module")
def incident_card_validator(
    incident_card_schema: dict[str, Any],
    coordinated_disclosure_schema: dict[str, Any],
    severity_vector_schema: dict[str, Any],
) -> Draft202012Validator:
    """Validator for incident_card with the companion-schema registry.

    Registers the real v1.1 schemas — coordinated_disclosure and
    severity_vector — plus the harm-core-taxonomy resource (real file if
    present, else ``HARM_CORE_TAXONOMY_STUB``) so the relative
    ``harm-core-taxonomy.json#/$defs/harm_class``,
    ``coordinated_disclosure.schema.json`` and ``severity_vector.schema.json``
    ``$ref``s all resolve against the card's ``$id`` base. The
    ``severity_vector.schema.json`` resource is what lets the card's
    ``severity_vector`` ``$ref`` (which delegates to the full companion grammar,
    rejecting HG-less/unbandable vectors) resolve in-test.
    """
    resources = [
        Resource.from_contents(incident_card_schema),
        Resource.from_contents(coordinated_disclosure_schema),
        Resource.from_contents(severity_vector_schema),
        Resource.from_contents(_resolve_harm_core_taxonomy()),
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


def test_incident_card_references_harm_core_taxonomy_companion(
    incident_card_schema: dict[str, Any],
) -> None:
    """The card's ``harm_core.harm_class`` ``$ref`` is exactly the documented
    companion pointer (VAL-CARD-001).

    Pins the production dependency that F-M2-SCHEMA-GATING's resolver MUST wire:
    the card reaches the harm_class enum via the relative
    ``harm-core-taxonomy.json#/$defs/harm_class`` ``$ref``, resolved against the
    card's ``$id`` base. A rename of the companion file or its ``$defs`` path
    would break the real registry; asserting the exact string here makes that
    break loud rather than silent.
    """
    harm_class_ref = incident_card_schema["properties"]["harm_core"]["properties"]["harm_class"]["$ref"]
    assert harm_class_ref == _HARM_CLASS_REF


def test_harm_core_taxonomy_companion_resolution_auto_upgrades() -> None:
    """The harm-core-taxonomy resource is the real file if present, else the stub
    (VAL-CARD-001).

    This documents — and self-de-stubs — the F-M2-SCHEMA-SEV-CROSS dependency:
    while ``acef-conventions/v1.1/harm-core-taxonomy.json`` is absent the stub is
    used; once SEV-CROSS ships the real file this test (and the card validator)
    automatically exercise it, with the contract that whichever resource is in
    play declares the companion ``$id`` and supplies a ``$defs/harm_class`` enum
    covering the normative ACEF class names (RFC §5.2) the card fixtures use.
    """
    taxonomy = _resolve_harm_core_taxonomy()
    assert taxonomy["$id"] == "https://acef.ai/schemas/v1.1/harm-core-taxonomy.json"
    harm_class = taxonomy["$defs"]["harm_class"]
    assert harm_class["type"] == "string"
    # The normative ACEF class name used by every card fixture MUST be admissible
    # by whichever resource (stub today, real companion once SEV-CROSS lands) is in
    # play, so the card validator's harm_class $ref keeps resolving and passing.
    assert _VALID_HARM_CORE["harm_class"] in harm_class["enum"]
    # And the closed vocabulary is exactly the RFC §5.2 class-name set — neither
    # stub nor real companion may admit the EU Art.3(49) "3.49.*" TRIGGER codes,
    # which are crosswalk values, not harm_class names.
    assert set(harm_class["enum"]) == set(_NORMATIVE_HARM_CLASS_ENUM)
    if _HARM_CORE_TAXONOMY_PATH.exists():
        # SEV-CROSS has shipped the real companion: this assertion proves the
        # test upgraded off the stub and is now exercising the production schema.
        assert taxonomy == _load(_HARM_CORE_TAXONOMY_PATH)
    else:
        assert taxonomy == HARM_CORE_TAXONOMY_STUB


def test_incident_card_minimal_conforming_validates(
    incident_card_validator: Draft202012Validator,
) -> None:
    """A minimal conforming public-projection card validates (VAL-CARD-001)."""
    errors = list(incident_card_validator.iter_errors(_valid_card()))
    assert errors == [], [e.message for e in errors]


@pytest.mark.parametrize(
    "trigger_code",
    ["3.49.a", "3.49.b", "3.49.c", "3.49.d"],
)
def test_incident_card_rejects_eu_trigger_code_as_harm_class(
    incident_card_validator: Draft202012Validator,
    trigger_code: str,
) -> None:
    """An EU Art.3(49) TRIGGER code in ``harm_core.harm_class`` is REJECTED
    (VAL-CARD-001).

    Pins the §5.2 vocabulary boundary: the card-level ``harm_class`` enum is the
    closed set of ACEF class NAMES (``physical_health``, ``fundamental_rights``,
    …). The ``3.49.*`` codes are EU AI Act CROSSWALK triggers
    (``taxonomy_crosswalk.eu_ai_act.serious_incident_triggers[]``), NOT
    ``harm_class`` values, so a ``harm_class`` of ``"3.49.a"`` resolved through
    the ``harm-core-taxonomy.json#/$defs/harm_class`` enum MUST fail. This guards
    against re-introducing the conflation roborev flagged: trigger codes are not
    harm classes.
    """
    card = _valid_card()
    card["harm_core"]["harm_class"] = trigger_code
    assert not incident_card_validator.is_valid(card), (
        f"EU trigger code {trigger_code!r} must not validate as a harm_class name"
    )


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
        pytest.param(
            lambda c: c.pop("id_grade"),
            "missing required id_grade rejected (§5.3 line 140: a card carrying a "
            "public_incident_id but omitting id_grade MUST be rejected; the grade is not defaultable)",
            id="missing-id_grade",
        ),
        # Trailing-newline format bypass: the patterns anchored with `$` matched BEFORE
        # a final \n, admitting a hash-corrupting value. The (?![\s\S]) end anchor rejects it.
        pytest.param(
            lambda c: c.__setitem__("incident_dedupe_key", "sha256:" + "a" * 64 + "\n"),
            "trailing-newline incident_dedupe_key rejected",
            id="dedupe-key-trailing-newline",
        ),
        pytest.param(
            lambda c: c.__setitem__("incident_dedupe_key_hmac", "hmac-sha256:" + "b" * 64 + "\n"),
            "trailing-newline incident_dedupe_key_hmac rejected",
            id="dedupe-hmac-trailing-newline",
        ),
        pytest.param(
            lambda c: c.__setitem__("description_commitment", "sha256:" + "a" * 64 + "\n"),
            "trailing-newline *_commitment rejected",
            id="commitment-trailing-newline",
        ),
        # Trailing-newline *_commitment KEY bypass (roborev Medium on e1ec70e): the
        # patternProperties key `^[a-z0-9_]+_commitment$` matched `description_commitment\n`
        # (the `$` matches before a final \n), so additionalProperties:false ACCEPTED the
        # malformed key while check_publishability ignores it (key.endswith('_commitment')
        # is False) — a hash-committed projection that slips the §5.11 commitment-linkage
        # gate. The (?![\s\S]) key anchor rejects the newline-bearing key.
        pytest.param(
            lambda c: c.__setitem__("description_commitment\n", "sha256:" + "a" * 64),
            "trailing-newline *_commitment KEY rejected by additionalProperties",
            id="commitment-key-trailing-newline",
        ),
        # Trailing-newline public_incident_id bypass: the id pattern `^AIIC-…$` matched
        # `AIIC-…\n` (the same $-before-\n weakness), admitting a newline-corrupted,
        # cross-reference-breaking id. The (?![\s\S]) end anchor rejects it.
        pytest.param(
            lambda c: c.__setitem__("public_incident_id", f"AIIC-OPENAI-2026-{_VALID_SUFFIX}\n"),
            "trailing-newline public_incident_id rejected",
            id="public-incident-id-trailing-newline",
        ),
        # Trailing-newline x-* namespace KEY bypass: the patternProperties key
        # `^x-[a-z0-9-]+(/[a-z0-9-]+)*$` matched `"x-vendor\n"` (the $-before-\n weakness),
        # so additionalProperties:false accepted a newline-corrupted vendor namespace key.
        # The (?![\s\S]) key anchor rejects it.
        pytest.param(
            lambda c: c.__setitem__("x-vendor\n", {}),
            "trailing-newline x-* namespace KEY rejected by additionalProperties",
            id="x-namespace-key-trailing-newline",
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
# card -> coordinated_disclosure $ref integration                             #
#                                                                             #
# Exercise the card's coordinated_disclosure $ref THROUGH the incident_card    #
# schema (not only the standalone block), proving the $ref resolves against    #
# the registry and the §5.6 status: public conditional is enforced from the    #
# card surface.                                                                #
# --------------------------------------------------------------------------- #


def test_incident_card_with_valid_coordinated_disclosure_validates(
    incident_card_validator: Draft202012Validator,
) -> None:
    """A card whose coordinated_disclosure is a valid status: public block (with
    reporter_role, no embargo) validates THROUGH the card $ref (VAL-CARD-001).

    Proves the card-level ``coordinated_disclosure.schema.json`` ``$ref``
    resolves against the registry and admits a §5.6-conforming public block.
    """
    card = _valid_card()
    card["coordinated_disclosure"] = {
        "status": "public",
        "reporter_role": "external_researcher",
    }
    errors = list(incident_card_validator.iter_errors(card))
    assert errors == [], [e.message for e in errors]


@pytest.mark.parametrize(
    ("disclosure", "reason"),
    [
        pytest.param(
            {"status": "public"},
            "status: public missing reporter_role rejected through card $ref (§5.6 if/then)",
            id="card-disclosure-public-missing-reporter-role",
        ),
        pytest.param(
            {
                "status": "public",
                "reporter_role": "regulator",
                "embargo_until": "2026-01-01T00:00:00Z",
            },
            "embargo_until forbidden on status: public rejected through card $ref (§5.6 if/then not)",
            id="card-disclosure-public-with-embargo",
        ),
    ],
)
def test_incident_card_with_invalid_coordinated_disclosure_rejects(
    incident_card_validator: Draft202012Validator,
    disclosure: dict[str, Any],
    reason: str,
) -> None:
    """A card carrying an invalid coordinated_disclosure block is rejected
    THROUGH the card ``$ref`` (VAL-CARD-001).

    The card embeds a coordinated_disclosure that violates the §5.6
    ``status: public`` conditional; the card-level ``$ref`` to
    ``coordinated_disclosure.schema.json`` MUST propagate that failure so the
    whole card is invalid (proving the ``$ref`` actually enforces, not merely
    resolves).
    """
    card = _valid_card()
    card["coordinated_disclosure"] = disclosure
    assert not incident_card_validator.is_valid(card), reason


# --------------------------------------------------------------------------- #
# card -> severity_vector $ref integration                                     #
#                                                                             #
# The card's severity_vector now $ref's the companion severity_vector.schema   #
# .json (companions are "referenced, not inlined", RFC §5.4), whose top-level   #
# is a string validator enforcing the FULL mandatory Group-I grammar. Exercise  #
# that the card now REJECTS HG-less/unbandable and out-of-order vectors the old #
# weak `^ACEF-SEV:1\.0/` prefix wrongly admitted, and still ACCEPTS a full      #
# Group-I vector — all THROUGH the card $ref against the registry.             #
# --------------------------------------------------------------------------- #


def test_incident_card_with_valid_severity_vector_validates(
    incident_card_validator: Draft202012Validator,
) -> None:
    """A card with a full-Group-I ``severity_vector`` validates THROUGH the card
    ``$ref`` (VAL-CARD-001).

    Proves the card-level ``severity_vector.schema.json`` ``$ref`` resolves
    against the registry and admits a §5.4-conforming bandable vector
    (HT/HG/RV/SC/BR all present, in fixed order).
    """
    card = _valid_card()
    card["severity_vector"] = _VALID_SEVERITY_VECTOR
    errors = list(incident_card_validator.iter_errors(card))
    assert errors == [], [e.message for e in errors]


@pytest.mark.parametrize(
    ("vector", "reason"),
    [
        pytest.param(
            _HG_LESS_SEVERITY_VECTOR,
            "HG-less/unbandable vector rejected through card $ref (band() keys on HG; §5.4)",
            id="card-severity-vector-hg-less-unbandable",
        ),
        pytest.param(
            _OUT_OF_ORDER_SEVERITY_VECTOR,
            "out-of-order Group-I vector rejected through card $ref (fixed-order grammar; §5.4)",
            id="card-severity-vector-out-of-order",
        ),
        pytest.param(
            "ACEF-SEV:1.0/",
            "bare prefix with no Group-I metrics rejected through card $ref (§5.4)",
            id="card-severity-vector-bare-prefix",
        ),
    ],
)
def test_incident_card_with_invalid_severity_vector_rejects(
    incident_card_validator: Draft202012Validator,
    vector: str,
    reason: str,
) -> None:
    """A card carrying an unbandable or malformed ``severity_vector`` is rejected
    THROUGH the card ``$ref`` (VAL-CARD-001).

    The previous inline ``{"type": "string", "pattern": "^ACEF-SEV:1\\.0/"}``
    accepted any string with the prefix — including the HG-less
    ``ACEF-SEV:1.0/HT:S`` and a bare ``ACEF-SEV:1.0/``. Delegating to
    ``severity_vector.schema.json`` (whose top-level enforces the full mandatory
    Group-I sequence) means the card now propagates that failure: an unbandable
    or out-of-order vector makes the whole card invalid, proving the card
    enforces the full grammar via the ``$ref`` (not merely resolves it).
    """
    card = _valid_card()
    card["severity_vector"] = vector
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
