"""Regression tests for the v1.1 severity_vector + harm-core-taxonomy + taxonomy_crosswalk schemas.

Covers the three companion schemas authored under F-M2-SCHEMA-SEV-CROSS:

- ``acef-conventions/v1.1/severity_vector.schema.json``
- ``acef-conventions/v1.1/harm-core-taxonomy.json``
- ``acef-conventions/v1.1/taxonomy_crosswalk.schema.json``

Assertions exercised:

- VAL-SEV-001: ``severity_vector.schema.json`` encodes the ACEF-SEV:1.0 metric
  grammar from RFC-0002 §5.4 — a representative §5.4 example vector validates,
  the fixed group/metric order is enforced, the FULL mandatory Group-I sequence
  (``HT``/``HG``/``RV``/``SC``/``BR``) is required so every conforming vector is
  bandable (a vector missing ``HG`` — or any other mandatory Group-I metric — is
  unbandable per the §5.4 band() table and is rejected), out-of-table values and
  a malformed ``RP`` trials count are rejected — AND the schema embeds the
  normative ``band()`` table (the §5.4 HG/BR/RV → severity rows) with the coarse
  ``severity`` enum as the band() projection target.
- VAL-CROSS-001: ``harm-core-taxonomy.json`` carries ``$defs`` for the closed
  ACEF ``harm_class`` (exactly the 11 RFC §5.2 codes, keyed to Art.3(49)(a-d)),
  ``realization``, ``causality``, ``tangibility``, plus the concrete one-directional
  core→scheme derivation rows; and ``taxonomy_crosswalk.schema.json`` defines
  closed (``additionalProperties: false``) per-member subschemas — each with a
  REQUIRED ``edition``/``taxonomy_version`` pin — for ``oecd``, ``eu_ai_act``,
  ``cset``, ``nist_ai_600_1``, ``mit_causal``, ``mit_domain``, ``aiid``, ``stix``,
  closed with the X6 ``x-*`` slash-qualified pattern.

Integration (proves the CARD test's self-de-stub auto-upgrade): the
``incident_card.schema.json`` ``harm_core.harm_class`` ``$ref`` is resolved here
against the REAL ``harm-core-taxonomy.json`` companion (registered by ``$id`` in a
local ``referencing.Registry`` alongside ``taxonomy_crosswalk`` and
``coordinated_disclosure``), so an out-of-enum ``harm_class`` and an EU
``3.49.*`` trigger code (a crosswalk value, NOT a harm_class name) are both
rejected through the card.

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
_SEVERITY_VECTOR_PATH = _V1_1_DIR / "severity_vector.schema.json"
_HARM_CORE_TAXONOMY_PATH = _V1_1_DIR / "harm-core-taxonomy.json"
_TAXONOMY_CROSSWALK_PATH = _V1_1_DIR / "taxonomy_crosswalk.schema.json"
_INCIDENT_CARD_PATH = _V1_1_DIR / "incident_card.schema.json"
_COORDINATED_DISCLOSURE_PATH = _V1_1_DIR / "coordinated_disclosure.schema.json"

# The normative ACEF card-level harm_class vocabulary, fixed verbatim by RFC-0002
# §5.2 (the closed code list keyed to EU Art.3(49)(a-d) plus the AI-specific
# intangible classes). harm-core-taxonomy.json#/$defs/harm_class MUST equal this
# exactly so the CARD test's self-de-stub auto-upgrade stays seamless. The EU
# Art.3(49) "3.49.*" TRIGGER codes are NOT harm_class names — they are crosswalk
# values under taxonomy_crosswalk.eu_ai_act.serious_incident_triggers[].
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

# The verified NIST AI 600-1 (July-2024 FINAL) category names (RFC §5.5),
# distinct from the April-2024 draft names. The taxonomy_crosswalk
# nist_ai_600_1.categories[] enum MUST equal this set — it is the one external
# scheme value-set already transcribed/verified and therefore closed in v1.1.
_NIST_AI_600_1_CATEGORIES: list[str] = [
    "CBRN Information or Capabilities",
    "Confabulation",
    "Dangerous, Violent, or Hateful Content",
    "Data Privacy",
    "Environmental Impacts",
    "Harmful Bias or Homogenization",
    "Human-AI Configuration",
    "Information Integrity",
    "Information Security",
    "Intellectual Property",
    "Obscene, Degrading, and/or Abusive Content",
    "Value Chain and Component Integration",
]

# The eight closed scheme members of taxonomy_crosswalk (RFC §5.5 / Appendix E Q15).
_CROSSWALK_MEMBERS: list[str] = [
    "oecd",
    "eu_ai_act",
    "cset",
    "nist_ai_600_1",
    "mit_causal",
    "mit_domain",
    "aiid",
    "stix",
]

# The representative ACEF-SEV:1.0 vector from RFC §5.4 (the worked example).
_SEV_EXAMPLE = "ACEF-SEV:1.0/HT:R/HG:H/RV:I/SC:C/BR:P/RZ:E/RP:0.62@200/XF:Y/AU:A/EX:H/KC:H/SF:N/VL:F/DB:Y"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def severity_vector_schema() -> dict[str, Any]:
    return _load(_SEVERITY_VECTOR_PATH)


@pytest.fixture(scope="module")
def harm_core_taxonomy() -> dict[str, Any]:
    return _load(_HARM_CORE_TAXONOMY_PATH)


@pytest.fixture(scope="module")
def taxonomy_crosswalk_schema() -> dict[str, Any]:
    return _load(_TAXONOMY_CROSSWALK_PATH)


@pytest.fixture(scope="module")
def severity_vector_validator(
    severity_vector_schema: dict[str, Any],
) -> Draft202012Validator:
    """Validator for the severity_vector wire-format string schema."""
    return Draft202012Validator(severity_vector_schema)


@pytest.fixture(scope="module")
def taxonomy_crosswalk_validator(
    taxonomy_crosswalk_schema: dict[str, Any],
) -> Draft202012Validator:
    """Validator for the taxonomy_crosswalk object schema."""
    return Draft202012Validator(taxonomy_crosswalk_schema)


@pytest.fixture(scope="module")
def card_validator() -> Draft202012Validator:
    """incident_card validator wired to the REAL companion schemas by ``$id``.

    Registers the real ``harm-core-taxonomy.json``, ``taxonomy_crosswalk.schema.json``,
    ``severity_vector.schema.json``, and ``coordinated_disclosure.schema.json``
    alongside the card so the card's ``harm-core-taxonomy.json#/$defs/harm_class``
    and ``taxonomy_crosswalk.schema.json`` ``$ref``s resolve against the
    production companions authored here — this is the integration the CARD test's
    self-de-stub anticipates.
    """
    card = _load(_INCIDENT_CARD_PATH)
    resources = [
        Resource.from_contents(card),
        Resource.from_contents(_load(_HARM_CORE_TAXONOMY_PATH)),
        Resource.from_contents(_load(_TAXONOMY_CROSSWALK_PATH)),
        Resource.from_contents(_load(_SEVERITY_VECTOR_PATH)),
        Resource.from_contents(_load(_COORDINATED_DISCLOSURE_PATH)),
    ]
    registry = Registry().with_resources([(r.id(), r) for r in resources])
    return Draft202012Validator(card, registry=registry)


def _valid_card() -> dict[str, Any]:
    return {
        "public_incident_id": "AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
        "id_grade": "self-asserted",
        "harm_core": {
            "realization": "harm_event",
            "causality": {
                "entity": "ai",
                "intent": "unintentional",
                "timing": "post_deployment",
            },
            "harm_class": "physical_health",
        },
    }


# --------------------------------------------------------------------------- #
# severity_vector.schema.json                                                 #
# --------------------------------------------------------------------------- #


def test_severity_vector_check_schema(severity_vector_schema: dict[str, Any]) -> None:
    """The severity_vector schema is itself a valid Draft 2020-12 schema."""
    Draft202012Validator.check_schema(severity_vector_schema)


def test_severity_vector_id_and_type(severity_vector_schema: dict[str, Any]) -> None:
    """The severity_vector schema declares the v1.1 ``$id`` and a string type."""
    assert severity_vector_schema["$id"] == "https://acef.ai/schemas/v1.1/severity_vector.schema.json"
    assert severity_vector_schema["type"] == "string"
    assert severity_vector_schema["pattern"].startswith("^ACEF-SEV:1\\.0/")


def test_severity_vector_accepts_section_5_4_example(
    severity_vector_validator: Draft202012Validator,
) -> None:
    """The representative §5.4 example vector validates (VAL-SEV-001)."""
    errors = list(severity_vector_validator.iter_errors(_SEV_EXAMPLE))
    assert errors == [], [e.message for e in errors]


@pytest.mark.parametrize(
    "vector",
    [
        # Bare full Group-I sequence (no optional T/E/S metrics) — the minimal
        # bandable vector.
        pytest.param("ACEF-SEV:1.0/HT:P/HG:N/RV:A/SC:U/BR:I", id="bare-full-group-I"),
        pytest.param("ACEF-SEV:1.0/HT:K/HG:H/RV:I/SC:C/BR:P", id="full-group-I"),
        # Full Group I + an optional Group-T RP at the boundary rate/trials.
        pytest.param(
            "ACEF-SEV:1.0/HT:R/HG:L/RV:U/SC:U/BR:G/RP:1.0@1",
            id="RP-boundary-rate-1-trials-1",
        ),
        pytest.param(_SEV_EXAMPLE, id="section-5-4-example"),
    ],
)
def test_severity_vector_accepts_well_formed(
    severity_vector_validator: Draft202012Validator,
    vector: str,
) -> None:
    """Well-formed ACEF-SEV:1.0 vectors validate (VAL-SEV-001).

    Every accepted vector carries the FULL mandatory Group-I sequence
    (HT/HG/RV/SC/BR) so it is bandable; optional Group T/E/S metrics may follow.
    """
    errors = list(severity_vector_validator.iter_errors(vector))
    assert errors == [], [e.message for e in errors]


@pytest.mark.parametrize(
    ("vector", "reason"),
    [
        # --- mandatory Group-I completeness (the roborev fix) ----------------
        pytest.param(
            "ACEF-SEV:1.0/HT:S",
            "HT-only vector has no HG and is therefore UNBANDABLE — the §5.4 "
            "band() table keys every row on Group-I metrics",
            id="HT-only-unbandable",
        ),
        pytest.param(
            "ACEF-SEV:1.0/HT:P/RV:A/SC:U/BR:I",
            "missing mandatory Group-I HG (the primary band() input)",
            id="missing-HG",
        ),
        pytest.param(
            "ACEF-SEV:1.0/HT:P/HG:N/SC:U/BR:I",
            "missing mandatory Group-I RV",
            id="missing-RV",
        ),
        pytest.param(
            "ACEF-SEV:1.0/HT:P/HG:N/RV:A/BR:I",
            "missing mandatory Group-I SC",
            id="missing-SC",
        ),
        pytest.param(
            "ACEF-SEV:1.0/HT:P/HG:N/RV:A/SC:U",
            "missing mandatory Group-I BR",
            id="missing-BR",
        ),
        pytest.param(
            "ACEF-SEV:1.0/HG:H",
            "missing mandatory Group-I HT (and the rest of Group I)",
            id="missing-HT",
        ),
        # --- metric ORDER enforcement ----------------------------------------
        pytest.param(
            "ACEF-SEV:1.0/HG:H/HT:P/RV:A/SC:U/BR:I",
            "HG before HT — Group-I metrics out of fixed within-group order",
            id="within-group-I-out-of-order",
        ),
        pytest.param(
            "ACEF-SEV:1.0/HT:P/HG:N/RV:A/RZ:E/SC:U/BR:I",
            "Group-T RZ interleaved before Group I is complete — group order I then T then E then S is violated",
            id="group-T-before-completing-group-I",
        ),
        # --- closed value tables ---------------------------------------------
        pytest.param(
            "ACEF-SEV:1.0/HT:Z/HG:N/RV:A/SC:U/BR:I",
            "HT value outside the closed table",
            id="bad-HT-value",
        ),
        pytest.param(
            "ACEF-SEV:1.0/HT:P/HG:X/RV:A/SC:U/BR:I",
            "HG value outside the closed table",
            id="bad-HG-value",
        ),
        # --- RP wire-form constraints (full Group I present so the ONLY defect
        #     is the RP token) -------------------------------------------------
        pytest.param(
            "ACEF-SEV:1.0/HT:P/HG:N/RV:A/SC:U/BR:I/RP:0.5@0",
            "RP trials count N must be >= 1",
            id="RP-zero-trials",
        ),
        pytest.param(
            "ACEF-SEV:1.0/HT:P/HG:N/RV:A/SC:U/BR:I/RP:1.5@5",
            "RP rate must be in [0,1]",
            id="RP-rate-over-1",
        ),
        # --- prefix / version ------------------------------------------------
        pytest.param("CVSS:4.0/AV:N", "wrong vector prefix", id="wrong-prefix"),
        pytest.param(
            "ACEF-SEV:2.0/HT:P/HG:N/RV:A/SC:U/BR:I",
            "wrong version token",
            id="wrong-version",
        ),
    ],
)
def test_severity_vector_rejects_malformed(
    severity_vector_validator: Draft202012Validator,
    vector: str,
    reason: str,
) -> None:
    """Malformed ACEF-SEV:1.0 vectors are rejected (VAL-SEV-001).

    Covers the mandatory full Group-I sequence (HT/HG/RV/SC/BR) — a vector
    missing any Group-I metric is unbandable and rejected — plus within-group
    and cross-group order enforcement, the closed value tables, and the RP
    wire-form constraints.
    """
    assert not severity_vector_validator.is_valid(vector), reason


def test_severity_vector_embeds_normative_band_table(
    severity_vector_schema: dict[str, Any],
) -> None:
    """The schema embeds the §5.4 ``band()`` table verbatim and the coarse
    ``severity`` enum as the band() projection target (VAL-SEV-001).

    The §5.4 table is normative ("the table here governs and the schema file MUST
    match it"): five rows evaluated top-to-bottom, first match wins, keyed on the
    Group-I metrics HG/BR/RV, producing the coarse severity enum.
    """
    band = severity_vector_schema["$defs"]["band_table"]
    assert band["inputs"] == ["HG", "BR", "RV"]
    assert band["evaluation"] == "first-match-top-to-bottom"
    rows = band["rows"]
    assert [r["severity"] for r in rows] == [
        "critical",
        "major",
        "major",
        "minor",
        "informational",
    ]
    assert rows[0]["condition"] == "HG:H AND (BR:P OR RV:I)"
    assert rows[-1]["condition"] == "HG:N"
    # The coarse severity enum is the band() projection target.
    assert severity_vector_schema["$defs"]["severity"]["enum"] == [
        "critical",
        "major",
        "minor",
        "informational",
    ]


def test_severity_vector_publishes_full_metric_value_tables(
    severity_vector_schema: dict[str, Any],
) -> None:
    """The schema publishes the full §5.4 metric value tables in group order
    I, T, E, S, with the ENTIRE Group-I sequence (HT/HG/RV/SC/BR) flagged
    mandatory and Groups T/E/S optional (VAL-SEV-001)."""
    groups = severity_vector_schema["$defs"]["metric_value_tables"]["groups"]
    assert list(groups.keys()) == ["I", "T", "E", "S"]
    # Group I is mandatory and runs HT, HG, RV, SC, BR in fixed order.
    assert groups["I"]["optional"] is False
    assert groups["I"]["order"] == ["HT", "HG", "RV", "SC", "BR"]
    # §5.4 declares "Group I — Intrinsic Harm (mandatory)" without exempting any
    # member, so every Group-I metric is mandatory (the roborev fix: an HG-less
    # vector is unbandable).
    for metric in ("HT", "HG", "RV", "SC", "BR"):
        assert groups["I"]["metrics"][metric]["mandatory"] is True, metric
    # Groups T/E/S are optional (their metrics default to Not-Defined X).
    for grp in ("T", "E", "S"):
        assert groups[grp]["optional"] is True, grp
    # HT value table is the closed §5.4 set keyed to Art.3(49).
    assert set(groups["I"]["metrics"]["HT"]["values"].keys()) == {"P", "R", "K", "E", "S"}


# --------------------------------------------------------------------------- #
# harm-core-taxonomy.json                                                      #
# --------------------------------------------------------------------------- #


def test_harm_core_taxonomy_check_schema(harm_core_taxonomy: dict[str, Any]) -> None:
    """The harm-core-taxonomy resource is a valid Draft 2020-12 schema."""
    Draft202012Validator.check_schema(harm_core_taxonomy)


def test_harm_core_taxonomy_id(harm_core_taxonomy: dict[str, Any]) -> None:
    """The companion declares the v1.1 ``$id`` the card ``$ref``s against."""
    assert harm_core_taxonomy["$id"] == "https://acef.ai/schemas/v1.1/harm-core-taxonomy.json"


def test_harm_class_enum_is_exactly_the_eleven_normative_codes(
    harm_core_taxonomy: dict[str, Any],
) -> None:
    """``$defs/harm_class`` is exactly the 11 normative RFC §5.2 codes
    (VAL-CROSS-001).

    This is the contract the CARD test's self-de-stub relies on: the real
    companion's ``harm_class`` enum MUST equal the normative class-name set so
    the card validator auto-upgrades off the stub seamlessly.
    """
    harm_class = harm_core_taxonomy["$defs"]["harm_class"]
    assert harm_class["type"] == "string"
    assert harm_class["enum"] == _NORMATIVE_HARM_CLASS_ENUM
    assert set(harm_class["enum"]) == set(_NORMATIVE_HARM_CLASS_ENUM)
    # The EU Art.3(49) "3.49.*" TRIGGER codes are NOT harm_class names.
    for trigger in ("3.49.a", "3.49.b", "3.49.c", "3.49.d"):
        assert trigger not in harm_class["enum"]


def test_harm_core_taxonomy_defs_closed_enums(
    harm_core_taxonomy: dict[str, Any],
) -> None:
    """``realization``, ``causality``, ``tangibility`` are closed §5.2 enums
    (VAL-CROSS-001)."""
    defs = harm_core_taxonomy["$defs"]
    assert defs["realization"]["enum"] == ["harm_event", "harm_issue", "near_miss"]
    assert defs["tangibility"]["enum"] == ["tangible", "intangible"]
    causality = defs["causality"]
    assert causality["additionalProperties"] is False
    assert causality["required"] == ["entity", "intent", "timing"]
    assert causality["properties"]["entity"]["enum"] == ["human", "ai", "other"]


def test_harm_core_taxonomy_derivation_rows_cover_every_harm_class(
    harm_core_taxonomy: dict[str, Any],
) -> None:
    """The concrete core→scheme derivation rows cover every harm_class and project
    into the closed crosswalk scheme members (VAL-CROSS-001; the ACEF-085
    dependency).

    RFC §5.2 requires each ``harm_class`` to carry a one-directional derivation
    table to the scheme members (``harm_class`` → {nist_ai_600_1, cset, mit_domain,
    oecd}); the concrete ACEF-side rows are materialized here.
    """
    rows = harm_core_taxonomy["derivation_rows"]["rows"]
    covered = {r["harm_class"] for r in rows}
    assert covered == set(_NORMATIVE_HARM_CLASS_ENUM)
    for row in rows:
        for scheme in ("nist_ai_600_1", "cset", "mit_domain", "oecd"):
            assert scheme in row, f"{row['harm_class']} missing {scheme} projection"
            assert "members" in row[scheme]
            assert "external_value_set_status" in row[scheme]
    # The four EU Art.3(49) trigger letters key to their ACEF harm_class names.
    trigger_rows = harm_core_taxonomy["art3_49_trigger_keying"]["rows"]
    keyed = {r["art3_49_trigger"]: r["harm_class"] for r in trigger_rows}
    assert keyed == {
        "3.49.a": "physical_health",
        "3.49.b": "critical_infrastructure",
        "3.49.c": "fundamental_rights",
        "3.49.d": "property_or_environment",
    }


# --------------------------------------------------------------------------- #
# taxonomy_crosswalk.schema.json                                              #
# --------------------------------------------------------------------------- #


def test_taxonomy_crosswalk_check_schema(
    taxonomy_crosswalk_schema: dict[str, Any],
) -> None:
    """The taxonomy_crosswalk schema is itself a valid Draft 2020-12 schema."""
    Draft202012Validator.check_schema(taxonomy_crosswalk_schema)


def test_taxonomy_crosswalk_is_closed_with_x_namespace(
    taxonomy_crosswalk_schema: dict[str, Any],
) -> None:
    """The crosswalk object is closed and defines all eight members plus the X6
    slash-qualified ``x-*`` namespace (VAL-CROSS-001)."""
    assert taxonomy_crosswalk_schema["additionalProperties"] is False
    assert set(taxonomy_crosswalk_schema["properties"].keys()) == set(_CROSSWALK_MEMBERS)
    assert "^x-[a-z0-9-]+(/[a-z0-9-]+)*$" in taxonomy_crosswalk_schema["patternProperties"]


def test_taxonomy_crosswalk_members_are_closed_and_edition_pinned(
    taxonomy_crosswalk_schema: dict[str, Any],
) -> None:
    """Every member subschema is closed (``additionalProperties: false``) and
    carries a REQUIRED version-pin — ``edition`` for all except ``mit_domain``,
    which uses ``taxonomy_version`` (VAL-CROSS-001)."""
    props = taxonomy_crosswalk_schema["properties"]
    for member in _CROSSWALK_MEMBERS:
        sub = props[member]
        assert sub["additionalProperties"] is False, f"{member} not closed"
        pin = "taxonomy_version" if member == "mit_domain" else "edition"
        assert sub["required"] == [pin], f"{member} pin must be {pin}"
        assert pin in sub["properties"]


@pytest.mark.parametrize(
    "member",
    [
        pytest.param(
            {"nist_ai_600_1": {"edition": "2024-07-final", "categories": ["Data Privacy"]}},
            id="nist-edition-and-closed-category",
        ),
        pytest.param(
            {
                "eu_ai_act": {
                    "edition": "reg-2024-1689",
                    "serious_incident_triggers": ["3.49.a", "3.49.b"],
                    "widespread": False,
                    "death_involved": True,
                }
            },
            id="eu-act-trigger-array",
        ),
        pytest.param(
            {"mit_domain": {"taxonomy_version": "2025-04", "domain": "Privacy & Security"}},
            id="mit-domain-taxonomy-version-pin",
        ),
        pytest.param(
            {"aiid": {"edition": "aiid", "incident_id": 42, "report_ids": [1, 2, 3]}},
            id="aiid-integer-incident-id",
        ),
        pytest.param({"x-acme/note": {"k": "v"}}, id="x-slash-qualified-extension"),
    ],
)
def test_taxonomy_crosswalk_accepts_valid_members(
    taxonomy_crosswalk_validator: Draft202012Validator,
    member: dict[str, Any],
) -> None:
    """Edition-pinned, closed, well-typed members (and ``x-*`` extensions)
    validate (VAL-CROSS-001)."""
    errors = list(taxonomy_crosswalk_validator.iter_errors(member))
    assert errors == [], [e.message for e in errors]


@pytest.mark.parametrize(
    ("member", "reason"),
    [
        pytest.param(
            {"cset": {"harm_type": "physical"}},
            "member missing its required edition pin",
            id="missing-edition-pin",
        ),
        pytest.param(
            {"mit_domain": {"domain": "Privacy & Security"}},
            "mit_domain missing its required taxonomy_version pin",
            id="missing-taxonomy-version-pin",
        ),
        pytest.param(
            {"cset": {"edition": "csetv1", "bogus_key": 1}},
            "extra non-x- key inside a closed member",
            id="extra-key-in-member",
        ),
        pytest.param(
            {"unknown_member": {}},
            "unknown top-level member rejected by additionalProperties: false",
            id="unknown-member",
        ),
        pytest.param(
            {"nist_ai_600_1": {"edition": "2024-07-final", "categories": ["Bogus Category"]}},
            "category outside the verified NIST final enum",
            id="bad-nist-category",
        ),
        pytest.param(
            {"eu_ai_act": {"edition": "reg-2024-1689", "serious_incident_triggers": ["3.49.z"]}},
            "trigger outside the closed 3.49.a-d set",
            id="bad-eu-trigger",
        ),
        pytest.param(
            {"aiid": {"edition": "aiid", "incident_id": "not-an-int"}},
            "aiid.incident_id must be an integer",
            id="aiid-non-integer-id",
        ),
        pytest.param(
            {"x-Vendor": {}},
            "uppercase x- segment rejected",
            id="x-uppercase",
        ),
    ],
)
def test_taxonomy_crosswalk_rejects_malformed_members(
    taxonomy_crosswalk_validator: Draft202012Validator,
    member: dict[str, Any],
    reason: str,
) -> None:
    """The closed, version-pinned crosswalk rejects the enumerated malformations
    (VAL-CROSS-001)."""
    assert not taxonomy_crosswalk_validator.is_valid(member), reason


def test_taxonomy_crosswalk_nist_categories_match_verified_final_enum(
    taxonomy_crosswalk_schema: dict[str, Any],
) -> None:
    """``nist_ai_600_1.categories`` is the verified July-2024 final enum
    (VAL-CROSS-001)."""
    cats = taxonomy_crosswalk_schema["properties"]["nist_ai_600_1"]["properties"]["categories"]["items"]["enum"]
    assert cats == _NIST_AI_600_1_CATEGORIES


# --------------------------------------------------------------------------- #
# Integration: card harm_class $ref resolves against the REAL companion        #
# (proves the CARD test's self-de-stub auto-upgrade)                           #
# --------------------------------------------------------------------------- #


def test_card_validates_with_real_harm_core_taxonomy_companion(
    card_validator: Draft202012Validator,
) -> None:
    """A minimal card validates with the REAL harm-core-taxonomy companion wired
    in (VAL-CROSS-001).

    Proves the production ``harm-core-taxonomy.json#/$defs/harm_class`` ``$ref``
    resolves and admits the normative ACEF class name — the same path the CARD
    test exercises once it auto-upgrades off its stub.
    """
    errors = list(card_validator.iter_errors(_valid_card()))
    assert errors == [], [e.message for e in errors]


def test_card_rejects_out_of_enum_harm_class_through_real_companion(
    card_validator: Draft202012Validator,
) -> None:
    """An out-of-enum ``harm_class`` is rejected through the real companion
    ``$ref`` (VAL-CROSS-001)."""
    card = _valid_card()
    card["harm_core"]["harm_class"] = "made_up_class"
    assert not card_validator.is_valid(card)


@pytest.mark.parametrize("trigger_code", ["3.49.a", "3.49.b", "3.49.c", "3.49.d"])
def test_card_rejects_eu_trigger_code_as_harm_class_through_real_companion(
    card_validator: Draft202012Validator,
    trigger_code: str,
) -> None:
    """An EU Art.3(49) TRIGGER code in ``harm_core.harm_class`` is rejected
    through the real companion (VAL-CROSS-001).

    The ``3.49.*`` codes are crosswalk values
    (``taxonomy_crosswalk.eu_ai_act.serious_incident_triggers[]``), NOT
    ``harm_class`` names — the real ``$defs/harm_class`` enum must reject them.
    """
    card = _valid_card()
    card["harm_core"]["harm_class"] = trigger_code
    assert not card_validator.is_valid(card)
