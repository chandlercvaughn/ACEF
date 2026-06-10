#!/usr/bin/env python3
"""Validate every ACEF JSON Schema and prove the v1.1 incident $ref graph resolves.

This is the manifest ``validate_schemas`` command (``python scripts/validate_schemas.py``)
for the ``acef-rfc0002-incident-reporting`` operation (F-M2-SCHEMA-GATING). It is a
deterministic, byte-stable sweep over the versioned schema registry — no wall-clock,
no random, no network — and exits non-zero on any failure.

Checks
------
C1. SCHEMA WELL-FORMEDNESS: every ``*.json`` / ``*.schema.json`` under
    ``acef-conventions/v1/`` and ``acef-conventions/v1.1/`` parses as JSON, and every
    one that declares ``$schema``/``$id`` (i.e. is a JSON Schema, not a plain data
    registry) passes ``Draft202012Validator.check_schema``.

C2. RESOLVER REGISTRY: a ``referencing.Registry`` is built over the production
    ``acef.schemas.registry.build_schema_registry('v1.1')`` and every v1.1 schema
    carrying a ``$id`` is registered.

C3. INCIDENT $ref GRAPH FULLY RESOLVES: the v1.1 ``incident_card`` and
    ``incident_report`` (overlay) schemas are loaded through the PRODUCTION validator
    and a representative valid payload validates with NO ``Unresolvable`` /
    ``Unretrievable`` error — proving the relative ``$ref`` graph
    (incident_card -> {harm-core-taxonomy, taxonomy_crosswalk, severity_vector,
    coordinated_disclosure}; incident_report -> incident_report.card_source ->
    {harm_core, severity_vector, coordinated_disclosure}) resolves locally rather
    than crashing on a network fetch.

C4. NEGATIVE CONTROL: a deliberately malformed incident_card (an unknown top-level
    key) produces a REAL validation error through the same production path, proving
    the validator is actually enforcing the schema (not silently passing everything).

Exit codes
----------
* ``0`` — all checks PASS.
* ``1`` — one or more checks FAILED (with a clear message).

Usage
-----
``python scripts/validate_schemas.py``
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Ensure the in-repo `src/` layout is importable when run as a bare script.
_SRC = _PROJECT_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from acef.schemas.registry import (  # noqa: E402  (path bootstrap must precede import)
    build_schema_registry,
    schema_version_for_core_version,
    validate_record_payload,
)

_CONVENTIONS = _PROJECT_ROOT / "acef-conventions"
_SCHEMA_VERSIONS = ("v1", "v1.1")

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

_VALID_INCIDENT_CARD: dict[str, Any] = {
    "public_incident_id": _VALID_PUBLIC_INCIDENT_ID,
    "id_grade": "self-asserted",
    "harm_core": dict(_VALID_HARM_CORE),
}

_VALID_CARD_SOURCE: dict[str, Any] = {
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

_VALID_INCIDENT_REPORT: dict[str, Any] = {
    "incident_type": "safety",
    "severity": "major",
    "description": "Representative valid v1.1 incident_report carrying a card_source.",
    "card_source": dict(_VALID_CARD_SOURCE),
}


class CheckError(Exception):
    """A single named validation check failed."""


def _iter_schema_files(version: str) -> list[Path]:
    schema_dir = _CONVENTIONS / version
    if not schema_dir.is_dir():
        raise CheckError(f"schema directory not found: {schema_dir}")
    return sorted(schema_dir.glob("*.json"))


def check_schema_well_formedness() -> list[str]:
    """C1: every schema file parses and (if it is a schema) is a valid 2020-12 schema."""
    messages: list[str] = []
    for version in _SCHEMA_VERSIONS:
        for path in _iter_schema_files(version):
            try:
                contents = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise CheckError(f"invalid JSON in {path}: {exc}") from exc
            if not isinstance(contents, dict):
                # A non-object top-level is not a JSON Schema; skip schema-shape check.
                continue
            # Only run check_schema on files that declare a JSON Schema dialect.
            if "$schema" in contents or "type" in contents or "$defs" in contents or "properties" in contents:
                try:
                    Draft202012Validator.check_schema(contents)
                except Exception as exc:  # noqa: BLE001 — surface any schema-shape error verbatim
                    raise CheckError(f"{path} is not a valid Draft 2020-12 schema: {exc}") from exc
            messages.append(f"  OK  {version}/{path.name}")
    return messages


def check_resolver_registry() -> list[str]:
    """C2: the production v1.1 registry registers every $id-bearing v1.1 schema."""
    registry = build_schema_registry("v1.1")
    expected_ids: set[str] = set()
    for version in _SCHEMA_VERSIONS:
        for path in _iter_schema_files(version):
            contents = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(contents, dict):
                schema_id = contents.get("$id")
                if isinstance(schema_id, str) and schema_id:
                    expected_ids.add(schema_id)
    missing: list[str] = []
    for schema_id in sorted(expected_ids):
        try:
            registry.get_or_retrieve(schema_id)
        except Exception:  # noqa: BLE001 — any retrieval failure means the id is unregistered
            missing.append(schema_id)
    if missing:
        raise CheckError("resolver registry missing schema $ids: " + ", ".join(missing))
    return [f"  OK  registered {len(expected_ids)} schema $ids in the v1.1 resolver registry"]


def _assert_resolves(payload: dict[str, Any], record_type: str) -> None:
    """Validate a payload through the production path, raising on $ref resolution failure."""
    try:
        errors = validate_record_payload(payload, record_type, "v1.1")
    except Exception as exc:  # noqa: BLE001 — an Unresolvable/Unretrievable surfaces here
        raise CheckError(
            f"the v1.1 {record_type} $ref graph did NOT resolve through the production validator: {exc}"
        ) from exc
    if errors:
        raise CheckError(
            f"expected the representative valid {record_type} to validate, but got errors: "
            + "; ".join(e.message for e in errors)
        )


def check_incident_ref_graph_resolves() -> list[str]:
    """C3: the incident_card + incident_report $ref graphs resolve and a valid payload passes."""
    if schema_version_for_core_version("1.1.0") != "v1.1":
        raise CheckError("core_version 1.1.0 does not route to the v1.1 schema set")
    if schema_version_for_core_version("1.0.0") != "v1":
        raise CheckError("core_version 1.0.0 must stay on the frozen v1 schema set")

    _assert_resolves(_VALID_INCIDENT_CARD, "incident_card")
    _assert_resolves(_VALID_CARD_SOURCE, "incident_report.card_source")
    _assert_resolves(_VALID_INCIDENT_REPORT, "incident_report")
    return [
        "  OK  incident_card $ref graph resolves (harm-core-taxonomy, severity_vector, "
        "taxonomy_crosswalk, coordinated_disclosure)",
        "  OK  incident_report overlay -> card_source -> companion $ref graph resolves",
    ]


def check_negative_control() -> list[str]:
    """C4: a malformed incident_card produces a real validation error (not a silent pass)."""
    malformed = dict(_VALID_INCIDENT_CARD)
    malformed["bogus_unknown_top_level_key"] = "x"
    errors = validate_record_payload(malformed, "incident_card", "v1.1")
    if not errors:
        raise CheckError(
            "negative control FAILED: a malformed incident_card (unknown top-level key) "
            "produced NO validation error — the production validator is not enforcing the schema"
        )
    return ["  OK  malformed incident_card is rejected (validator enforces additionalProperties: false)"]


def main() -> int:
    checks = (
        ("C1 schema well-formedness", check_schema_well_formedness),
        ("C2 resolver registry", check_resolver_registry),
        ("C3 incident $ref graph resolution", check_incident_ref_graph_resolves),
        ("C4 negative control", check_negative_control),
    )
    failures = 0
    for name, fn in checks:
        try:
            lines = fn()
        except CheckError as exc:
            print(f"FAIL {name}: {exc}")
            failures += 1
            continue
        print(f"PASS {name}")
        for line in lines:
            print(line)
    if failures:
        print(f"\nvalidate_schemas: {failures} check(s) FAILED")
        return 1
    print("\nvalidate_schemas: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
