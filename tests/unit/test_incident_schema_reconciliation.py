"""F-M8-INCIDENT-SCHEMA — set-determinism + Appendix B reconciliation regressions.

RED-first tests for the three F-M8-INCIDENT-SCHEMA assertions plus the carried
INCVAL-005 RFC-note reconciliation. Each test FAILS against the pre-fix tree and
PASSES after the surgical edits:

- VAL-FIX-INCSCHEMA-002 (determinism): the public-card path
  ``taxonomy_crosswalk.eu_ai_act.serious_incident_triggers`` MUST carry
  ``uniqueItems: true`` (matching the source-backed twin
  ``card_source.eu_ai_act_facts.serious_incident_triggers``). §5.5 treats the
  triggers as a SET and §5.7 reads them from the public card for the ACEF-084
  shortest-applicable clock, so a public card carrying ``["3.49.a","3.49.a"]``
  (a sorted-set-with-duplicate) is self-contradictory and MUST be rejected.

- VAL-FIX-INCSCHEMA-003 (determinism): ``harm_distribution_basis`` is a
  closed-enum, §5.10 order-insensitive (sorted-before-hash) array; it MUST carry
  ``uniqueItems: true`` so ``["race","race"]`` (a sorted protected-attribute axis
  with a duplicate) is rejected, aligning with the protected-attribute-axis set
  intent and the trigger-set precedent.

- VAL-FIX-INCSCHEMA-001 (spec-conformance): the Appendix B normative ``card_source``
  excerpt in the RFC declares exactly FIVE required members; the shipped
  ``incident_report.card_source.schema.json`` makes ``eu_ai_act_facts`` a SIXTH
  required member (so a confidential Art.73 report validates before any public
  card exists, §5.7). The Appendix B excerpt MUST be reconciled to the shipped
  six-member required set, otherwise two conformant implementations built from
  Appendix B vs from the schema disagree on whether a ``card_source`` lacking
  ``eu_ai_act_facts`` is valid.

- INCVAL-005 carry (RFC doc note, schema-validator drift): the public ``eu_ai_act``
  subschema makes ``widespread``/``death_involved`` OPTIONAL (only ``edition`` is
  required), but the validator (``incident_rules._art73_facts_complete``) requires
  a PUBLIC Art.73 card's ``taxonomy_crosswalk.eu_ai_act`` to carry
  ``serious_incident_triggers`` + ``widespread`` + ``death_involved`` (no silent
  default — a missing boolean would wrongly accept a 15-day clock). A per-record
  JSON Schema cannot express the manifest-profile-conditional requirement, so the
  drift is closed at the only correct layer: a normative RFC note documenting that
  the VALIDATOR enforces this Art.73 profile-conditional requirement. This test
  asserts that reconciliation sentence is present in the RFC body.

Determinism: every fixture is a static literal; no wall-clock or random values.
The card validator is built from the PRODUCTION
``acef.schemas.registry.build_schema_registry('v1.1')`` so the relative incident
``$ref`` graph resolves exactly as it does in the shipped validator.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_V1_1_DIR = _PROJECT_ROOT / "acef-conventions" / "v1.1"
_INCIDENT_CARD_PATH = _V1_1_DIR / "incident_card.schema.json"
_TAXONOMY_CROSSWALK_PATH = _V1_1_DIR / "taxonomy_crosswalk.schema.json"
_CARD_SOURCE_PATH = _V1_1_DIR / "incident_report.card_source.schema.json"
_RFC_PATH = _PROJECT_ROOT / "planning" / "ACEF-RFC-0002-ai-incident-reporting-profile.md"

# Ensure the in-repo ``src/`` layout is importable for the production registry.
_SRC = _PROJECT_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from acef.schemas.registry import build_schema_registry  # noqa: E402

# A valid Crockford-base32 suffix carrying >=128 bits (exactly 26 chars, the
# minimum the pattern permits). Alphabet excludes I, L, O, U.
_VALID_SUFFIX = "0123456789ABCDEFGHJKMNPQRS"
_VALID_PUBLIC_INCIDENT_ID = f"AIIC-OPENAI-2026-{_VALID_SUFFIX}"

# A structurally valid harm_core subtree (harm_class is a normative ACEF class
# NAME, resolved via the harm-core-taxonomy companion $defs/harm_class enum).
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


@pytest.fixture(scope="module")
def card_validator() -> Draft202012Validator:
    """Production-path incident_card validator with the v1.1 companion registry.

    Uses ``build_schema_registry('v1.1')`` so the card's relative ``$ref``s
    (harm-core-taxonomy, taxonomy_crosswalk, severity_vector,
    coordinated_disclosure) resolve against each schema's ``$id`` base exactly as
    in the shipped validator — no network fetch, no stub.
    """
    schema = _load(_INCIDENT_CARD_PATH)
    registry = build_schema_registry("v1.1")
    return Draft202012Validator(schema, registry=registry)


def _card_with_triggers(triggers: list[str]) -> dict[str, Any]:
    """A minimal valid public incident_card carrying eu_ai_act crosswalk triggers."""
    return {
        "public_incident_id": _VALID_PUBLIC_INCIDENT_ID,
        "id_grade": "self-asserted",
        "harm_core": dict(_VALID_HARM_CORE),
        "taxonomy_crosswalk": {
            "eu_ai_act": {
                "edition": "reg-2024-1689",
                "serious_incident_triggers": list(triggers),
                "widespread": False,
                "death_involved": True,
            }
        },
    }


def _card_with_basis(basis: list[str]) -> dict[str, Any]:
    """A minimal valid public incident_card carrying harm_distribution_basis."""
    return {
        "public_incident_id": _VALID_PUBLIC_INCIDENT_ID,
        "id_grade": "self-asserted",
        "harm_core": dict(_VALID_HARM_CORE),
        "harm_distribution_basis": list(basis),
    }


# ---------------------------------------------------------------------------
# VAL-FIX-INCSCHEMA-002 — public serious_incident_triggers set determinism
# ---------------------------------------------------------------------------


def test_public_card_rejects_duplicate_serious_incident_triggers(
    card_validator: Draft202012Validator,
) -> None:
    """VAL-FIX-INCSCHEMA-002 (RED→GREEN).

    A public card carrying duplicate triggers ``["3.49.a","3.49.a"]`` is a
    sorted-set-with-duplicate. Pre-fix the public ``eu_ai_act.serious_incident_triggers``
    array constrains items by enum only (no ``uniqueItems``), so this VALIDATES
    today (the documented defect). After adding ``uniqueItems: true`` it MUST be
    rejected with a ``uniqueItems`` violation, matching the source-backed twin.
    """
    card = _card_with_triggers(["3.49.a", "3.49.a"])
    errors = list(card_validator.iter_errors(card))
    assert errors, (
        "RED defect: a public card with duplicate serious_incident_triggers "
        "['3.49.a','3.49.a'] validates with no error — uniqueItems missing on "
        "taxonomy_crosswalk.eu_ai_act.serious_incident_triggers"
    )
    assert any(e.validator == "uniqueItems" for e in errors), (
        f"expected a uniqueItems violation, got: {[e.validator for e in errors]}"
    )


def test_public_card_accepts_unique_serious_incident_triggers(
    card_validator: Draft202012Validator,
) -> None:
    """VAL-FIX-INCSCHEMA-002: unique triggers still validate (no over-rejection)."""
    card = _card_with_triggers(["3.49.a", "3.49.b"])
    errors = list(card_validator.iter_errors(card))
    assert not errors, f"unique triggers must still validate; got: {[e.message for e in errors]}"


# ---------------------------------------------------------------------------
# VAL-FIX-INCSCHEMA-003 — harm_distribution_basis set determinism
# ---------------------------------------------------------------------------


def test_public_card_rejects_duplicate_harm_distribution_basis(
    card_validator: Draft202012Validator,
) -> None:
    """VAL-FIX-INCSCHEMA-003 (RED→GREEN).

    ``harm_distribution_basis`` is a closed protected-attribute axis array,
    §5.10 order-insensitive (sorted before hashing). Pre-fix it allows duplicates
    (no ``uniqueItems``), so ``["race","race"]`` VALIDATES today. After adding
    ``uniqueItems: true`` it MUST be rejected.
    """
    card = _card_with_basis(["race", "race"])
    errors = list(card_validator.iter_errors(card))
    assert errors, (
        "RED defect: a public card with duplicate harm_distribution_basis "
        "['race','race'] validates with no error — uniqueItems missing"
    )
    assert any(e.validator == "uniqueItems" for e in errors), (
        f"expected a uniqueItems violation, got: {[e.validator for e in errors]}"
    )


def test_public_card_accepts_unique_harm_distribution_basis(
    card_validator: Draft202012Validator,
) -> None:
    """VAL-FIX-INCSCHEMA-003: unique basis still validates (no over-rejection)."""
    card = _card_with_basis(["race", "sex"])
    errors = list(card_validator.iter_errors(card))
    assert not errors, f"unique basis must still validate; got: {[e.message for e in errors]}"


# ---------------------------------------------------------------------------
# VAL-FIX-INCSCHEMA-001 — Appendix B card_source required-set reconciliation
# ---------------------------------------------------------------------------


def _appendix_b_card_source_excerpt() -> dict[str, Any]:
    """Parse the Appendix B card_source overlay JSON excerpt out of the RFC body.

    Locates the ```json fenced block whose ``$id`` is the card_source overlay and
    whose ``properties`` carries the ``card_source`` member, and returns the parsed
    object. Raises if no such block is present (the excerpt must exist and parse).
    """
    text = _RFC_PATH.read_text(encoding="utf-8")
    blocks = re.findall(r"```json\n(.*?)```", text, re.S)
    for block in blocks:
        if "incident_report.card_source.schema.json" in block and '"card_source"' in block:
            parsed = json.loads(block)
            if "card_source" in parsed.get("properties", {}):
                return parsed
    raise AssertionError("Appendix B card_source overlay JSON excerpt not found in RFC")


def test_appendix_b_card_source_requires_eu_ai_act_facts() -> None:
    """VAL-FIX-INCSCHEMA-001 (RED→GREEN).

    The Appendix B normative ``card_source`` excerpt MUST list ``eu_ai_act_facts``
    in its ``required`` array (the sixth member the shipped schema enforces so a
    confidential Art.73 report validates before any public card exists, §5.7).
    Pre-fix the excerpt lists only five members and this FAILS.
    """
    excerpt = _appendix_b_card_source_excerpt()
    required = excerpt["properties"]["card_source"]["required"]
    assert "eu_ai_act_facts" in required, (
        "RED defect: Appendix B card_source.required omits eu_ai_act_facts "
        f"(lists only {required}); shipped schema makes it required"
    )


def test_appendix_b_card_source_required_equals_shipped_schema() -> None:
    """VAL-FIX-INCSCHEMA-001 reconciliation invariant.

    The Appendix B excerpt's ``required`` set MUST EQUAL the shipped
    ``incident_report.card_source.schema.json`` ``required`` set, so two conformant
    implementations — one built from the normative text, one from the shipped
    schema — agree on whether a ``card_source`` lacking ``eu_ai_act_facts`` is valid.
    """
    excerpt = _appendix_b_card_source_excerpt()
    excerpt_required = set(excerpt["properties"]["card_source"]["required"])
    shipped_required = set(_load(_CARD_SOURCE_PATH)["required"])
    assert excerpt_required == shipped_required, (
        "Appendix B excerpt required set must equal the shipped card_source "
        f"required set; excerpt={sorted(excerpt_required)} "
        f"shipped={sorted(shipped_required)}"
    )


# ---------------------------------------------------------------------------
# VAL-FIX-INCSCHEMA-002 reconciliation — Appendix B incident_card excerpt
# harm_distribution_basis uniqueItems matches the shipped schema
# ---------------------------------------------------------------------------


def _appendix_b_incident_card_excerpt() -> dict[str, Any]:
    """Parse the Appendix B incident_card JSON excerpt out of the RFC body.

    Locates the ```json fenced block whose ``$id`` is the incident_card schema and
    whose ``properties`` carries ``harm_distribution_basis`` (the public-card
    excerpt, distinct from the card_source overlay block). Raises if absent.
    """
    text = _RFC_PATH.read_text(encoding="utf-8")
    blocks = re.findall(r"```json\n(.*?)```", text, re.S)
    for block in blocks:
        if "incident_card.schema.json" in block and '"harm_distribution_basis"' in block:
            parsed = json.loads(block)
            props = parsed.get("properties", {})
            if "harm_distribution_basis" in props:
                return parsed
    raise AssertionError("Appendix B incident_card JSON excerpt not found in RFC")


def test_appendix_b_harm_distribution_basis_declares_unique_items() -> None:
    """VAL-FIX-INCSCHEMA-002 reconciliation (RED→GREEN).

    The shipped ``incident_card.schema.json`` now constrains
    ``harm_distribution_basis`` with ``uniqueItems: true`` (a duplicate
    ``["race","race"]`` is rejected). The Appendix B normative excerpt documents the
    same property as a plain array WITHOUT ``uniqueItems``, so an RFC-derived
    implementation would accept duplicates the shipped schema rejects. The excerpt
    MUST carry ``uniqueItems: true``. Pre-fix the excerpt omits it and this FAILS.
    """
    excerpt = _appendix_b_incident_card_excerpt()
    hdb = excerpt["properties"]["harm_distribution_basis"]
    assert hdb.get("uniqueItems") is True, (
        "RED defect: Appendix B incident_card.harm_distribution_basis lacks "
        "uniqueItems:true; shipped schema now rejects duplicates"
    )


def test_appendix_b_harm_distribution_basis_matches_shipped_schema() -> None:
    """VAL-FIX-INCSCHEMA-002 reconciliation invariant.

    The Appendix B excerpt's ``harm_distribution_basis`` constraints (``type``,
    ``items``, ``uniqueItems``) MUST EQUAL the shipped ``incident_card.schema.json``
    property, so an implementation built from the normative text and one built from
    the shipped schema agree on whether a duplicate axis is valid.
    """
    excerpt = _appendix_b_incident_card_excerpt()["properties"]["harm_distribution_basis"]
    shipped = _load(_INCIDENT_CARD_PATH)["properties"]["harm_distribution_basis"]
    for key in ("type", "items", "uniqueItems"):
        assert excerpt.get(key) == shipped.get(key), (
            f"Appendix B harm_distribution_basis.{key} ({excerpt.get(key)!r}) must equal shipped ({shipped.get(key)!r})"
        )


# ---------------------------------------------------------------------------
# VAL-FIX-INCSCHEMA-001 reconciliation — Appendix B nested card_source
# eu_ai_act_facts.serious_incident_triggers matches the shipped schema
# ---------------------------------------------------------------------------


def _appendix_b_card_source_triggers() -> dict[str, Any]:
    """Return the Appendix B card_source eu_ai_act_facts.serious_incident_triggers
    constraint object from the RFC excerpt."""
    excerpt = _appendix_b_card_source_excerpt()
    return excerpt["properties"]["card_source"]["properties"]["eu_ai_act_facts"]["properties"][
        "serious_incident_triggers"
    ]


def _shipped_card_source_triggers() -> dict[str, Any]:
    """Return the shipped card_source eu_ai_act_facts.serious_incident_triggers
    constraint object from the shipped overlay schema."""
    return _load(_CARD_SOURCE_PATH)["properties"]["eu_ai_act_facts"]["properties"]["serious_incident_triggers"]


def test_appendix_b_nested_triggers_declare_minitems_and_unique() -> None:
    """VAL-FIX-INCSCHEMA-001 nested reconciliation (RED→GREEN).

    The shipped ``incident_report.card_source.schema.json`` constrains
    ``eu_ai_act_facts.serious_incident_triggers`` with ``minItems: 1`` and
    ``uniqueItems: true`` (and a string item ``type``). The Appendix B excerpt omits
    these, so an RFC-derived implementation could accept empty/duplicate
    source-backed trigger arrays the actual schema rejects. The nested excerpt MUST
    carry both constraints. Pre-fix the excerpt omits them and this FAILS.
    """
    triggers = _appendix_b_card_source_triggers()
    assert triggers.get("minItems") == 1, (
        "RED defect: Appendix B card_source serious_incident_triggers lacks minItems:1"
    )
    assert triggers.get("uniqueItems") is True, (
        "RED defect: Appendix B card_source serious_incident_triggers lacks uniqueItems:true"
    )
    assert triggers.get("items", {}).get("type") == "string", (
        "RED defect: Appendix B card_source serious_incident_triggers items lack a string type"
    )


def test_appendix_b_nested_triggers_match_shipped_schema() -> None:
    """VAL-FIX-INCSCHEMA-001 nested reconciliation invariant.

    The Appendix B nested ``serious_incident_triggers`` constraints
    (``type``, ``minItems``, ``uniqueItems``, ``items``) MUST EQUAL the shipped
    ``incident_report.card_source.schema.json`` property, so the normative text and
    the shipped schema agree on whether an empty/duplicate source-backed trigger set
    is valid.
    """
    excerpt = _appendix_b_card_source_triggers()
    shipped = _shipped_card_source_triggers()
    for key in ("type", "minItems", "uniqueItems", "items"):
        assert excerpt.get(key) == shipped.get(key), (
            f"Appendix B nested serious_incident_triggers.{key} ({excerpt.get(key)!r}) "
            f"must equal shipped ({shipped.get(key)!r})"
        )


# ---------------------------------------------------------------------------
# INCVAL-005 carry — validator-enforced public Art.73 fact-block RFC note
# ---------------------------------------------------------------------------


def test_rfc_documents_validator_enforced_public_art73_fact_block() -> None:
    """INCVAL-005 carry (RED→GREEN).

    The public ``eu_ai_act`` subschema makes ``widespread``/``death_involved``
    OPTIONAL (only ``edition`` is required), but the validator
    (``incident_rules._art73_facts_complete``) requires a PUBLIC Art.73 card's
    ``taxonomy_crosswalk.eu_ai_act`` to carry ``serious_incident_triggers`` +
    ``widespread`` + ``death_involved`` (a missing boolean would wrongly accept a
    15-day clock). A per-record JSON Schema cannot express the manifest-profile
    condition, so the drift is closed by a normative RFC note. This asserts that
    note's reconciliation sentence is present in the RFC body.
    """
    text = _RFC_PATH.read_text(encoding="utf-8")
    # The note must (a) name the three required public Art.73 facts and (b) state
    # the validator (not the record schema) enforces the profile-conditional rule.
    assert "serious_incident_triggers" in text
    note_present = (
        re.search(
            r"PUBLIC Art\.\s*73.*?MUST carry.*?serious_incident_triggers.*?"
            r"widespread.*?death_involved",
            text,
            re.S | re.I,
        )
        is not None
    )
    validator_enforces = (
        re.search(
            r"validator enforces this.*?(profile-conditional|Art\.\s*73)",
            text,
            re.S | re.I,
        )
        is not None
    )
    assert note_present, (
        "RED defect: RFC lacks the INCVAL-005 note that a PUBLIC Art.73 fact block "
        "MUST carry serious_incident_triggers + widespread + death_involved"
    )
    assert validator_enforces, (
        "RED defect: RFC lacks the statement that the VALIDATOR (not the record "
        "schema) enforces the public Art.73 profile-conditional requirement"
    )


# ---------------------------------------------------------------------------
# Backward-compat — the v1.1 uniqueItems additions do not touch the frozen v1.0
# surface, and an existing v1.0 incident_report bundle validates unchanged.
# ---------------------------------------------------------------------------

_V1_DIR = _PROJECT_ROOT / "acef-conventions" / "v1"
_V1_INCIDENT_REPORT_PATH = _V1_DIR / "incident_report.schema.json"

# A representative v1.0 incident_report payload (frozen v1/ surface: required
# incident_type, severity, description). It carries NONE of the v1.1 set fields
# (serious_incident_triggers / harm_distribution_basis) — the frozen v1.0 schema
# does not define them — so the v1.1 uniqueItems additions cannot affect it.
_V1_0_INCIDENT_REPORT: dict[str, Any] = {
    "incident_type": "operational_failure",
    "severity": "major",
    "description": "A representative v1.0 incident_report payload.",
    "incident_id": "INC-2024-0001",
    "occurrence_date": "2024-05-01T00:00:00Z",
}


def test_frozen_v1_schemas_byte_unchanged_vs_head() -> None:
    """The v1.1-only uniqueItems edits leave the FROZEN v1.0 schemas byte-identical.

    Compares the on-disk frozen v1.0 incident_report (and the parent v1/ directory
    is guarded byte-for-byte by ``git diff acef-conventions/v1/`` in CI) against the
    committed HEAD bytes. A non-empty diff here means a frozen-path regression.
    """
    head_bytes = subprocess.run(
        ["git", "show", "HEAD:acef-conventions/v1/incident_report.schema.json"],
        capture_output=True,
        text=True,
        check=True,
        cwd=str(_PROJECT_ROOT),
    ).stdout
    on_disk = _V1_INCIDENT_REPORT_PATH.read_text(encoding="utf-8")
    assert on_disk == head_bytes, "FROZEN v1.0 incident_report.schema.json changed — frozen-path regression"


def test_v1_0_incident_report_validates_unaffected() -> None:
    """A v1.0 incident_report bundle still validates against the frozen v1.0 schema.

    Proves the v1.1 ``uniqueItems`` additions are additive and byte-neutral for the
    v1.0 surface: the frozen v1.0 incident_report schema does NOT define
    ``serious_incident_triggers`` or ``harm_distribution_basis``, so a v1.0 payload
    is structurally unaffected by the v1.1 edits and validates with zero errors.
    """
    v1_schema = _load(_V1_INCIDENT_REPORT_PATH)
    # The v1.1 set fields do not exist on the frozen v1.0 surface.
    schema_text = json.dumps(v1_schema)
    assert "serious_incident_triggers" not in schema_text
    assert "harm_distribution_basis" not in schema_text
    errors = list(Draft202012Validator(v1_schema).iter_errors(_V1_0_INCIDENT_REPORT))
    assert not errors, f"v1.0 incident_report must validate unchanged; got: {[e.message for e in errors]}"
