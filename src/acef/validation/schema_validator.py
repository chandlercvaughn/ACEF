"""ACEF schema validation — manifest, envelope, and payload validation.

Phase 1 of the 4-phase validation pipeline.
Collects ALL errors within the phase before stopping.
"""

from __future__ import annotations

from typing import Any

from acef.errors import ValidationDiagnostic
from acef.schemas.registry import list_record_type_schemas, validate_against_schema


def validate_manifest_schema(
    manifest_data: dict[str, Any],
    version: str = "v1",
) -> list[ValidationDiagnostic]:
    """Validate manifest against the manifest JSON Schema.

    Args:
        manifest_data: The parsed acef-manifest.json.
        version: Schema-dir token ("v1" or "v1.1") selected upstream from
            ``manifest.versioning.core_version``. See
            :func:`acef.schemas.registry.schema_version_for_core_version`.

    Returns:
        List of diagnostics. Empty means valid.
    """
    diagnostics: list[ValidationDiagnostic] = []

    errors = validate_against_schema(manifest_data, "manifest", version)
    for error in errors:
        diagnostics.append(
            ValidationDiagnostic(
                "ACEF-002",
                f"Manifest schema violation: {error.message}",
                path=_json_path(error.absolute_path),
            )
        )

    return diagnostics


def validate_record_schemas(
    records: list[dict[str, Any]],
    version: str = "v1",
) -> list[ValidationDiagnostic]:
    """Validate all records against envelope and payload schemas.

    Args:
        records: Parsed record dicts (envelope + payload).
        version: Schema-dir token ("v1" or "v1.1") selected upstream from
            ``manifest.versioning.core_version``. Controls both the
            envelope schema and per-record-type payload schema selection.

    For each record:
    1. Validate against record-envelope.schema.json
    2. Validate payload against {record_type}.schema.json

    Returns:
        List of diagnostics. Collects all errors.
    """
    diagnostics: list[ValidationDiagnostic] = []

    # Top-level record-type ALLOWLIST for this version's fallback chain. This is
    # the set of independently claimable ``record_type`` values; it EXCLUDES the
    # structural schemas (manifest, record-envelope, ...) AND the companion
    # sub-schemas (harm-core-taxonomy, taxonomy_crosswalk, severity_vector,
    # coordinated_disclosure, incident_report.card_source). Companions ship as
    # ``*.schema.json`` files and are reachable only via ``$ref`` from a record
    # schema — they are NOT valid top-level ``record_type`` values. Without this
    # gate, a record could declare ``record_type: "incident_report.card_source"``
    # and have its payload validated AS A RECORD (because the companion's schema
    # FILE exists), instead of being rejected (the roborev "companion looks like
    # a record type" finding).
    allowed_record_types = set(list_record_type_schemas(version))

    for i, record in enumerate(records):
        # Validate envelope
        envelope_errors = validate_against_schema(record, "record-envelope", version)
        for error in envelope_errors:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-004",
                    f"Record envelope schema violation (record {i}): {error.message}",
                    path=f"/records/{i}" + _json_path(error.absolute_path),
                )
            )

        # Validate payload against type-specific schema. Always validate
        # when record_type is present — even an empty {} payload must be
        # checked so that schema-mandated required fields can fire ACEF-004
        # and unknown record types can fire ACEF-003. Previously
        # `if payload:` short-circuited the entire validation for empty
        # dicts, letting malformed records evade Phase 1 checks.
        record_type = record.get("record_type", "")
        payload = record.get("payload", {}) if isinstance(record.get("payload"), dict) else {}
        # A validator MUST NEVER crash on malformed input. ``record_type`` may be
        # a non-string (number, bool, array, object) in malformed JSON, which
        # would raise AttributeError on the ``.startswith(...)`` / allowlist-
        # membership calls below. The record-envelope schema already flags a
        # wrong-typed ``record_type`` (ACEF-004), so a non-string is handled
        # exactly like a missing/empty one: skip the allowlist + payload path and
        # rely on the envelope diagnostic. ``not record_type`` already covers the
        # empty-string / None / empty-collection cases; the isinstance guard
        # covers truthy non-strings (e.g. ``123``, ``True``, ``[\"x\"]``).
        if not record_type or not isinstance(record_type, str):
            continue

        # ``x-``-namespaced record types are vendor extensions: they have no
        # core schema and are passed through without payload validation (kept
        # consistent with Package.record() which accepts ``x-`` types). They are
        # exempt from the allowlist gate.
        if record_type.startswith("x-"):
            continue

        # ALLOWLIST gate: a record_type that is NOT an allowed top-level record
        # type is unknown/invalid — emit ACEF-003 and DO NOT validate the payload
        # against a (possibly-existing) companion schema. This rejects companion
        # sub-schemas (e.g. incident_report.card_source) claimed as record_type
        # before their payload can be mistaken for a record.
        if record_type not in allowed_record_types:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-003",
                    f"Unknown record_type: {record_type!r}",
                    path=f"/records/{i}/record_type",
                )
            )
            continue

        payload_errors = validate_against_schema(payload, record_type, version)
        for error in payload_errors:
            # Don't report as error if schema not found (ACEF-003 instead). The
            # allowlist gate above normally precludes this branch, but it is
            # retained as a defensive fallback (e.g. an allowlisted name whose
            # schema file is absent in the resolved chain).
            if "not found" in str(error.message):
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-003",
                        f"Unknown record_type: {record_type!r}",
                        path=f"/records/{i}/record_type",
                    )
                )
            else:
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-004",
                        f"Payload schema violation for {record_type} (record {i}): {error.message}",
                        path=f"/records/{i}/payload" + _json_path(error.absolute_path),
                    )
                )

    return diagnostics


def _json_path(path_deque: Any) -> str:
    """Convert a jsonschema path deque to a JSON Pointer string."""
    if not path_deque:
        return ""
    parts = list(path_deque)
    return "/" + "/".join(str(p) for p in parts)
