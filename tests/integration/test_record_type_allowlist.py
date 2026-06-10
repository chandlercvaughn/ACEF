"""Integration: companion sub-schemas claimed as ``record_type`` are REJECTED.

F-M2-SCHEMA-GATING correctness regression (roborev codex finding on
``e3a49bbc``). The companion-vs-record-type allowlist was recorded in
``list_record_type_schemas()`` / ``RECORD_TYPES`` but NOT ENFORCED by the
production record validator (:func:`acef.validation.schema_validator.
validate_record_schemas`). Because a companion such as
``incident_report.card_source`` ships a ``*.schema.json`` FILE under the version
directory, the validator's ``load_schema(record_type)`` succeeded and the
companion's payload was validated AS A RECORD instead of being rejected as an
unknown/invalid ``record_type``.

The fix: BEFORE validating a record's payload against ``{record_type}``, the
validator confirms ``record_type`` is an allowed top-level record type
(:func:`acef.schemas.registry.list_record_type_schemas`) OR an ``x-``-namespaced
vendor extension. A companion (whose schema FILE exists but which is NOT a
record type) emits **ACEF-003** (unknown/invalid record type) — it is usable
only via ``$ref`` from a record schema, never as a top-level ``record_type``.

Assertion: VAL-SCH-001.

Determinism: every fixture is a static literal; no wall-clock / random values.
"""

from __future__ import annotations

from typing import Any

from acef.validation.schema_validator import validate_record_schemas

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


def _valid_card_source_payload() -> dict[str, Any]:
    """An OTHERWISE-VALID card_source payload.

    This is the dangerous case: if the validator naively loaded
    ``incident_report.card_source.schema.json`` and validated this payload, it
    would pass with zero errors — silently treating a companion as a record.
    The allowlist gate must reject the ``record_type`` itself instead.
    """
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


def _envelope(record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    """A minimal but envelope-valid record wrapper around a payload."""
    return {
        "record_id": "rec-0001",
        "record_type": record_type,
        "timestamp": "2026-01-01T00:00:00Z",
        "obligation_role": "provider",
        "confidentiality": "internal",
        "payload": payload,
    }


def _codes(diagnostics: list[Any]) -> set[str]:
    return {d.code for d in diagnostics}


# --------------------------------------------------------------------------- #
# Companions claimed as record_type must be REJECTED (ACEF-003)               #
# --------------------------------------------------------------------------- #


def test_card_source_as_record_type_rejected_with_acef_003() -> None:
    """``incident_report.card_source`` (a COMPANION) claimed as a top-level
    ``record_type`` is REJECTED with ACEF-003 — its otherwise-valid payload is
    NOT validated as a record (VAL-SCH-001)."""
    record = _envelope("incident_report.card_source", _valid_card_source_payload())
    diagnostics = validate_record_schemas([record], "v1.1")
    assert "ACEF-003" in _codes(diagnostics), (
        "A companion sub-schema (incident_report.card_source) claimed as a "
        "record_type must be rejected with ACEF-003, not validated as a record. "
        f"Got: {[(d.code, d.message) for d in diagnostics]}"
    )


def test_harm_core_taxonomy_as_record_type_rejected() -> None:
    """``harm-core-taxonomy`` (a COMPANION) is not an independently claimable
    ``record_type`` — ACEF-003 (VAL-SCH-001)."""
    record = _envelope("harm-core-taxonomy", dict(_VALID_HARM_CORE))
    diagnostics = validate_record_schemas([record], "v1.1")
    assert "ACEF-003" in _codes(diagnostics), (
        "harm-core-taxonomy companion claimed as record_type must be ACEF-003. "
        f"Got: {[(d.code, d.message) for d in diagnostics]}"
    )


def test_severity_vector_as_record_type_rejected() -> None:
    """``severity_vector`` (a COMPANION) is not a top-level ``record_type`` —
    ACEF-003 (VAL-SCH-001)."""
    record = _envelope("severity_vector", {"vector": "ACEF-SEV:1.0/HG:H"})
    diagnostics = validate_record_schemas([record], "v1.1")
    assert "ACEF-003" in _codes(diagnostics), (
        "severity_vector companion claimed as record_type must be ACEF-003. "
        f"Got: {[(d.code, d.message) for d in diagnostics]}"
    )


def test_taxonomy_crosswalk_as_record_type_rejected() -> None:
    """``taxonomy_crosswalk`` (a COMPANION) is not a top-level ``record_type`` —
    ACEF-003 (VAL-SCH-001)."""
    record = _envelope("taxonomy_crosswalk", {"eu_ai_act": {}})
    diagnostics = validate_record_schemas([record], "v1.1")
    assert "ACEF-003" in _codes(diagnostics), (
        "taxonomy_crosswalk companion claimed as record_type must be ACEF-003. "
        f"Got: {[(d.code, d.message) for d in diagnostics]}"
    )


def test_coordinated_disclosure_as_record_type_rejected() -> None:
    """``coordinated_disclosure`` (a COMPANION) is not a top-level
    ``record_type`` — ACEF-003 (VAL-SCH-001)."""
    record = _envelope("coordinated_disclosure", {"status": "embargoed"})
    diagnostics = validate_record_schemas([record], "v1.1")
    assert "ACEF-003" in _codes(diagnostics), (
        "coordinated_disclosure companion claimed as record_type must be ACEF-003. "
        f"Got: {[(d.code, d.message) for d in diagnostics]}"
    )


def test_companion_as_record_type_not_validated_as_record() -> None:
    """The companion's payload must NOT be schema-validated as a record: ACEF-003
    fires INSTEAD of an ACEF-004 payload-shape pass/fail (VAL-SCH-001).

    A bare ``{}`` card_source payload validated against the card_source schema
    would emit ACEF-004 (six requireds missing). Under the allowlist gate the
    record_type is rejected FIRST, so we must see ACEF-003 and must NOT have the
    payload re-validated against the companion schema.
    """
    record = _envelope("incident_report.card_source", {})
    diagnostics = validate_record_schemas([record], "v1.1")
    codes = _codes(diagnostics)
    assert "ACEF-003" in codes, "companion-as-record_type must emit ACEF-003"


# --------------------------------------------------------------------------- #
# Preserved behavior: real record types, x- extensions, unknown types         #
# --------------------------------------------------------------------------- #


def test_real_v1_1_record_type_still_validates() -> None:
    """A genuine v1.1 record type (``incident_card``) is NOT rejected by the
    allowlist gate — no ACEF-003 (VAL-SCH-001)."""
    payload = {
        "public_incident_id": _VALID_PUBLIC_INCIDENT_ID,
        "id_grade": "self-asserted",
        "harm_core": dict(_VALID_HARM_CORE),
    }
    record = _envelope("incident_card", payload)
    diagnostics = validate_record_schemas([record], "v1.1")
    assert "ACEF-003" not in _codes(diagnostics), (
        "incident_card is a genuine record type and must NOT be rejected. "
        f"Got: {[(d.code, d.message) for d in diagnostics]}"
    )


def test_real_v1_0_record_type_still_validates() -> None:
    """A v1.0 record type (``risk_register``) still validates cleanly under the
    allowlist gate (VAL-SCH-001 preserves existing behavior)."""
    payload = {"description": "A risk", "likelihood": "high", "severity": "high"}
    record = _envelope("risk_register", payload)
    diagnostics = validate_record_schemas([record], "v1")
    assert "ACEF-003" not in _codes(diagnostics), (
        "risk_register is a genuine v1 record type and must NOT be rejected. "
        f"Got: {[(d.code, d.message) for d in diagnostics]}"
    )


def test_x_extension_record_type_passes_allowlist() -> None:
    """An ``x-``-namespaced vendor-extension ``record_type`` is allowed through
    the allowlist gate without ACEF-003 (the extension exception is preserved)
    (VAL-SCH-001)."""
    record = _envelope("x-vendor-metric", {"vendor_score": 99})
    diagnostics = validate_record_schemas([record], "v1.1")
    assert "ACEF-003" not in _codes(diagnostics), (
        "x- vendor-extension record types must pass the allowlist gate. "
        f"Got: {[(d.code, d.message) for d in diagnostics]}"
    )


def test_unknown_record_type_still_acef_003() -> None:
    """A genuinely unknown (non-existent, non-``x-``) ``record_type`` still emits
    ACEF-003 (VAL-SCH-001 preserves existing behavior)."""
    record = _envelope("completely_unknown_type", {"k": "v"})
    diagnostics = validate_record_schemas([record], "v1.1")
    assert "ACEF-003" in _codes(diagnostics), (
        f"An unknown record_type must still emit ACEF-003. Got: {[(d.code, d.message) for d in diagnostics]}"
    )
