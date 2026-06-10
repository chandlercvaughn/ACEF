"""Integration: v1.1 incident schemas resolve through the PRODUCTION validator.

F-M2-SCHEMA-GATING capstone. These tests drive the production validation path
(``acef.schemas.registry.validate_record_payload``), NOT a test-local
``referencing.Registry``. Before this feature, ``validate_record_payload(...,
"incident_card", "v1.1")`` raised ``Unresolvable`` because the production
``Draft202012Validator`` was built with no registry, so the relative ``$ref``
graph (incident_card -> {harm-core-taxonomy, taxonomy_crosswalk, severity_vector,
coordinated_disclosure}) could not resolve. This is the roborev "production
resolver wiring" High.

After GATING wires a ``referencing.Registry`` of every
``acef-conventions/v1.1/*.schema.json`` (+ ``harm-core-taxonomy.json``) keyed by
``$id`` into the production validator for v1.1 bundles, the full graph resolves
and the validator returns REAL validation errors (not crashes).

Assertion: VAL-SCH-001.

Determinism: every fixture is a static literal; no wall-clock / random values.
"""

from __future__ import annotations

from typing import Any

from acef.schemas.registry import (
    schema_version_for_core_version,
    validate_record_payload,
)

# A 26-char Crockford-base32 suffix (>=128 bits, the pattern minimum).
_VALID_SUFFIX = "0123456789ABCDEFGHJKMNPQRS"
_VALID_PUBLIC_INCIDENT_ID = f"AIIC-OPENAI-2026-{_VALID_SUFFIX}"

_VALID_HARM_CORE: dict[str, Any] = {
    "realization": "harm_event",
    "causality": {
        "entity": "ai",
        "intent": "unintentional",
        "timing": "post_deployment",
    },
    "harm_class": "physical_health",
}


def _valid_incident_card() -> dict[str, Any]:
    return {
        "public_incident_id": _VALID_PUBLIC_INCIDENT_ID,
        "id_grade": "self-asserted",
        "harm_core": dict(_VALID_HARM_CORE),
    }


def _valid_card_source() -> dict[str, Any]:
    return {
        "public_incident_id": _VALID_PUBLIC_INCIDENT_ID,
        "id_grade": "self-asserted",
        "id_state": "RESERVED",
        "harm_core": dict(_VALID_HARM_CORE),
        "publishability_map": {"/root_cause_analysis": "regulator-only"},
        "eu_ai_act_facts": {
            "edition": "reg-2024-1689",
            "serious_incident_triggers": ["3.49.a"],
            "widespread": False,
            "death_involved": True,
        },
    }


# --------------------------------------------------------------------------- #
# core_version routing                                                         #
# --------------------------------------------------------------------------- #


def test_core_version_routing_1_1_0_routes_to_v1_1() -> None:
    """``core_version: 1.1.0`` routes to the v1.1 schema set (VAL-SCH-001)."""
    assert schema_version_for_core_version("1.1.0") == "v1.1"


def test_core_version_routing_1_0_0_stays_on_v1() -> None:
    """``core_version: 1.0.0`` stays on the frozen v1 schema set (VAL-SCH-001)."""
    assert schema_version_for_core_version("1.0.0") == "v1"


# --------------------------------------------------------------------------- #
# incident_card through the production resolver                               #
# --------------------------------------------------------------------------- #


def test_incident_card_valid_resolves_with_no_errors() -> None:
    """A valid incident_card validates with NO errors THROUGH the production
    path (VAL-SCH-001).

    This is the resolver-wiring proof: the relative ``$ref`` graph
    (harm-core-taxonomy, severity_vector, taxonomy_crosswalk,
    coordinated_disclosure) must resolve via the production ``referencing``
    registry, not crash with ``Unresolvable``.
    """
    errors = validate_record_payload(_valid_incident_card(), "incident_card", "v1.1")
    assert errors == [], [e.message for e in errors]


def test_incident_card_hg_less_severity_vector_rejected() -> None:
    """An HG-less / unbandable severity_vector is rejected through the card
    ``$ref`` to the severity_vector companion (VAL-SCH-001)."""
    card = _valid_incident_card()
    card["severity_vector"] = "ACEF-SEV:1.0/HT:S"
    errors = validate_record_payload(card, "incident_card", "v1.1")
    assert errors, "HG-less severity_vector must be rejected through the production resolver"


def test_incident_card_registry_canonical_id_grade_rejected() -> None:
    """``id_grade: registry-canonical`` (v1.2-only) is rejected on the v1.1
    surface through the production path (VAL-SCH-001 / VAL-IDSCH-001)."""
    card = _valid_incident_card()
    card["id_grade"] = "registry-canonical"
    errors = validate_record_payload(card, "incident_card", "v1.1")
    assert errors, "registry-canonical id_grade must be rejected on the v1.1 surface"


def test_incident_card_unknown_key_rejected() -> None:
    """An unknown, non-``x-*``, non-``_commitment`` top-level key is rejected by
    ``additionalProperties: false`` through the production path (VAL-SCH-001)."""
    card = _valid_incident_card()
    card["bogus_unknown_key"] = "x"
    errors = validate_record_payload(card, "incident_card", "v1.1")
    assert errors, "unknown top-level key must be rejected by additionalProperties: false"


def test_incident_card_short_suffix_id_rejected() -> None:
    """A <26-char suffix public_incident_id is rejected through the production
    path (VAL-SCH-001 / VAL-IDSCH-001)."""
    card = _valid_incident_card()
    card["public_incident_id"] = f"AIIC-OPENAI-2026-{_VALID_SUFFIX[:-1]}"
    errors = validate_record_payload(card, "incident_card", "v1.1")
    assert errors, "short-suffix public_incident_id must be rejected"


# --------------------------------------------------------------------------- #
# incident_report overlay (+ card_source) through the production resolver     #
# --------------------------------------------------------------------------- #


def test_incident_report_without_card_source_validates() -> None:
    """A v1.0-style incident_report (no card_source) validates UNCHANGED under
    the v1.1 overlay through the production path (VAL-SCH-001)."""
    report = {"incident_type": "safety", "severity": "major", "description": "x"}
    errors = validate_record_payload(report, "incident_report", "v1.1")
    assert errors == [], [e.message for e in errors]


def test_incident_report_with_valid_card_source_validates() -> None:
    """An incident_report carrying a valid card_source validates THROUGH the
    overlay -> card_source -> {harm_core, severity_vector, ...} ``$ref`` graph
    via the production resolver (VAL-SCH-001)."""
    report = {
        "incident_type": "safety",
        "severity": "major",
        "description": "x",
        "card_source": _valid_card_source(),
    }
    errors = validate_record_payload(report, "incident_report", "v1.1")
    assert errors == [], [e.message for e in errors]


def test_incident_report_with_empty_card_source_rejected() -> None:
    """An empty ``card_source: {}`` is REJECTED through the production overlay
    (its six requireds fail) (VAL-SCH-001 / VAL-SRC-001)."""
    report = {
        "incident_type": "safety",
        "severity": "major",
        "description": "x",
        "card_source": {},
    }
    errors = validate_record_payload(report, "incident_report", "v1.1")
    assert errors, "empty card_source must be rejected by the overlay's requireds"


def test_card_source_payload_valid_resolves() -> None:
    """A standalone card_source payload validates THROUGH the production path
    (VAL-SCH-001 / VAL-SRC-001)."""
    errors = validate_record_payload(_valid_card_source(), "incident_report.card_source", "v1.1")
    assert errors == [], [e.message for e in errors]


def test_card_source_empty_payload_rejected() -> None:
    """An empty card_source payload is rejected through the production path
    (VAL-SCH-001 / VAL-SRC-001)."""
    errors = validate_record_payload({}, "incident_report.card_source", "v1.1")
    assert errors, "empty card_source payload must be rejected by its requireds"
