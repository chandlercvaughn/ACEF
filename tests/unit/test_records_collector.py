"""collector round-trip fidelity tests (VAL-FIX-RECORDS-001).

record-envelope.schema.json:47-69 declares ``collector`` as
``oneOf [object, string]``. The string branch is ``{"type": "string"}`` with
NO ``minLength``, so the empty string ``""`` is a valid wire shape that MUST
round-trip verbatim per the §6.4 lossless-export MUST (records-payloads-1).

RED-first reproduction of the roborev finding on records.py:221: the load path
used ``if data.get("collector"):`` — a truthiness check that drops a valid
EMPTY-string collector (``""`` is falsy). The dropped collector then re-exports
as the DEFAULT collector OBJECT ``{"name": "unknown", "version": ""}`` via
``to_jsonl_dict``, reshaping the bytes and breaking lossless round-trip +
Python/TS parity. The fix is a key-PRESENCE check (``if "collector" in data:``)
that preserves string values verbatim even when empty, applying the default
ONLY when the key is ABSENT.
"""

from __future__ import annotations

from acef.models.records import CollectorInfo, dict_to_record_envelope


def _base_record(collector: object | None = None, *, include_collector: bool) -> dict:
    """A minimal valid envelope dict; optionally carrying ``collector``."""
    data: dict = {
        "record_id": "urn:acef:rec:00000000-0000-0000-0000-000000000001",
        "record_type": "risk_register",
        "timestamp": "2026-05-01T00:00:00Z",
        "payload": {"k": "v"},
    }
    if include_collector:
        data["collector"] = collector
    return data


def test_empty_string_collector_preserved_verbatim() -> None:
    """RED: ``collector: ""`` must survive load→export as the string ``""``.

    Before the fix this re-exported as the default OBJECT
    ``{"name": "unknown", "version": ""}`` (a reshaped wire form).
    """
    record = dict_to_record_envelope(_base_record("", include_collector=True))
    assert record.collector == ""

    out = record.to_jsonl_dict()
    # Verbatim empty string — NOT the default object.
    assert out["collector"] == ""
    assert not isinstance(out["collector"], dict)


def test_collector_absent_applies_default_object() -> None:
    """When the key is ABSENT, the spec-required default object is applied."""
    record = dict_to_record_envelope(_base_record(include_collector=False))
    assert record.collector is None

    out = record.to_jsonl_dict()
    assert out["collector"] == {"name": "unknown", "version": ""}


def test_non_empty_string_collector_round_trips() -> None:
    """A non-empty string collector round-trips verbatim (regression guard)."""
    record = dict_to_record_envelope(_base_record("alice@example.com", include_collector=True))
    assert record.collector == "alice@example.com"

    out = record.to_jsonl_dict()
    assert out["collector"] == "alice@example.com"


def test_object_form_collector_round_trips() -> None:
    """The object form maps to CollectorInfo and round-trips verbatim."""
    record = dict_to_record_envelope(_base_record({"name": "scanner", "version": "2.1"}, include_collector=True))
    assert isinstance(record.collector, CollectorInfo)
    assert record.collector.name == "scanner"
    assert record.collector.version == "2.1"

    out = record.to_jsonl_dict()
    assert out["collector"] == {"name": "scanner", "version": "2.1"}
