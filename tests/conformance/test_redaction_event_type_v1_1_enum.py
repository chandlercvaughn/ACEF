"""Conformance: v1.1 event_log overlay permits event_type='redaction'.

Background
----------
``src/acef/redaction.py::apply_redaction()`` constructs a redaction
attestation as an ``event_log`` record with ``event_type: "redaction"``
(see ``redaction.py:177``). The v1.0 ``event_log`` schema does NOT include
"redaction" in its enum, so under v1.0 such a payload MUST be rejected
(per VAL-SCHEMA-010 — v1.0 schemas are FROZEN). The v1.1 overlay schema
at ``acef-conventions/v1.1/event_log.schema.json`` adds "redaction" to the
enum so that v1.1 bundles using the auto-populated X1/X2 redaction path
validate cleanly.

This test pins both halves of that contract:

* v1.1 accepts ``event_type="redaction"`` (zero schema errors).
* v1.0 rejects ``event_type="redaction"`` (schema enum violation).
* The R0 snapshot of v1.0 schema hashes is unchanged.

Also asserts the ``EventType`` Python enum exposes ``REDACTION="redaction"``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from acef.models.enums import EventType
from acef.schemas.registry import load_schema, validate_record_payload


def test_event_type_python_enum_has_redaction() -> None:
    """``EventType.REDACTION`` exists and serializes to ``"redaction"``."""
    assert EventType.REDACTION.value == "redaction"
    # Round-trip via the enum constructor (the str-Enum lookup).
    assert EventType("redaction") is EventType.REDACTION


def test_v1_1_event_log_enum_includes_redaction() -> None:
    """v1.1 overlay schema lists ``"redaction"`` in event_type enum."""
    schema = load_schema("event_log", version="v1.1")
    enum_values = schema["properties"]["event_type"]["enum"]
    assert "redaction" in enum_values, f"v1.1 event_log enum missing 'redaction'; got {enum_values!r}"
    # Sanity — all v1.0 enum members must still be present
    # (v1.1 is a superset overlay, not a replacement).
    for legacy in [
        "inference",
        "training",
        "evaluation",
        "deployment",
        "override",
        "error",
        "marking",
        "disclosure",
        "logging_spec",
    ]:
        assert legacy in enum_values, f"v1.1 event_log enum dropped legacy value {legacy!r}; got {enum_values!r}"


def test_v1_0_event_log_enum_excludes_redaction() -> None:
    """v1.0 schema (FROZEN) MUST NOT include ``"redaction"``."""
    schema = load_schema("event_log", version="v1")
    enum_values = schema["properties"]["event_type"]["enum"]
    assert "redaction" not in enum_values, (
        "v1.0 event_log schema has been mutated to include 'redaction' — "
        "this violates VAL-SCHEMA-010 (v1.0 is frozen). Add the value "
        "ONLY to the v1.1 overlay."
    )


def test_v1_1_validation_accepts_redaction_event_type() -> None:
    """A payload with ``event_type="redaction"`` validates under v1.1."""
    payload = {
        "event_type": "redaction",
        "correlation_id": "corr-001",
    }
    errors = validate_record_payload(payload, "event_log", version="v1.1")
    assert errors == [], f"v1.1 validation rejected event_type='redaction' unexpectedly: {[e.message for e in errors]}"


def test_v1_0_validation_rejects_redaction_event_type() -> None:
    """A payload with ``event_type="redaction"`` is REJECTED under v1.0.

    This is the version-gate guarantee: v1.0 bundles MUST NOT silently
    inherit v1.1-only schema relaxations.
    """
    payload = {
        "event_type": "redaction",
        "correlation_id": "corr-001",
    }
    errors = validate_record_payload(payload, "event_log", version="v1")
    assert len(errors) >= 1, (
        "v1.0 validation unexpectedly accepted event_type='redaction'. "
        "v1.0 schemas MUST remain frozen — 'redaction' belongs in v1.1 only."
    )
    # The specific failure should be an enum violation on event_type.
    messages = " ".join(e.message for e in errors)
    assert "redaction" in messages or "enum" in messages.lower(), (
        f"Expected enum violation citing 'redaction'; got: {messages}"
    )


def test_v1_0_schema_hash_snapshot_unchanged() -> None:
    """R0 snapshot at v1.0-schema-hashes.json still matches v1/ on disk.

    Verifies we did NOT mutate any v1.0 schema while adding the v1.1
    overlay. This complements the dedicated
    ``test_error_registry_snapshot.py`` snapshot test by pinning the
    specific event_log.schema.json hash and the snapshot file content.
    """
    project_root = Path(__file__).resolve().parents[2]
    snapshot_path = project_root / "tests" / "conformance" / "fixtures" / "v1.0-schema-hashes.json"
    schema_dir = project_root / "acef-conventions" / "v1"

    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))

    for filename, recorded_hash in snapshot.items():
        on_disk = schema_dir / filename
        assert on_disk.exists(), f"v1.0 schema file missing: {filename}"
        # Hash the bytes exactly as the snapshot does (raw file content,
        # not canonicalized — the snapshot pins the on-disk bytes).
        actual = hashlib.sha256(on_disk.read_bytes()).hexdigest()
        assert actual == recorded_hash, (
            f"v1.0 schema {filename} was mutated: snapshot={recorded_hash} "
            f"actual={actual}. v1.0 schemas are FROZEN (VAL-SCHEMA-010)."
        )
