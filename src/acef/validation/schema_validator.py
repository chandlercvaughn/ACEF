"""ACEF schema validation — manifest, envelope, and payload validation.

Phase 1 of the 4-phase validation pipeline.
Collects ALL errors within the phase before stopping.
"""

from __future__ import annotations

import re
from typing import Any

from acef.errors import ValidationDiagnostic
from acef.schemas.registry import list_record_type_schemas, validate_against_schema

# ---------------------------------------------------------------------------
# Commitment-shaped payload validation (fix-F-M2-REDACTION).
#
# Since F-M2-REDACTION, a record whose ``confidentiality`` is
# ``hash-committed`` or ``redacted`` STORES the commitment shape minted by
# :func:`acef.redaction.apply_redaction` — NOT the cleartext payload::
#
#     {
#         "redaction_method": "sha256-hash-commitment",
#         "redacted_payload_hash": "<64 lowercase hex chars>",
#         "redaction_policy_version": "<policy semver>",
#         "access_policy": {...}   # optional
#     }
#
# Validating that stored payload against the per-record-type schema is a
# category error (a redacted risk_register has no ``risk_id`` BY DESIGN), so
# a conformant redacted bundle emitted spurious ACEF-004s. Such records are
# routed to commitment-shape validation instead.
#
# Routing is FAIL-CLOSED: the commitment route engages ONLY when the envelope
# carries BOTH X1 (``redaction_policy_version``) and X2
# (``redaction_attestation_ref``) as non-empty strings — the surface
# ``Package.record`` / ``redact_record`` always emit alongside the commitment
# (spec §6.3, enforced as ACEF-074/ACEF-078 by
# ``acef.validation.cross_record``). A record merely LABELED
# hash-committed/redacted without that surface falls through to per-type
# payload validation and fails on a cleartext-looking payload — there is no
# bypass lane for mislabeled records.
# ---------------------------------------------------------------------------

# Confidentiality levels whose stored payload is a content TRANSFORM (the
# commitment). Access-class levels (regulator-only / under-nda) are
# distribution restrictions that RETAIN the cleartext payload and keep
# per-type validation.
_COMMITMENT_CONFIDENTIALITY = frozenset({"hash-committed", "redacted"})

# Mirrors ``acef.redaction._SUPPORTED_REDACTION_METHODS``. Kept local so the
# validation layer does not import the redaction module (which transitively
# imports the Package builder). A drift-guard test asserts the two sets stay
# equal: tests/integration/test_commitment_payload_validation.py::
# test_supported_method_sets_do_not_drift.
_SUPPORTED_COMMITMENT_METHODS = frozenset({"sha256-hash-commitment"})

# ``acef.integrity.sha256_hex`` mints BARE lowercase hex (no "sha256:"
# prefix) — that is the producer shape ``apply_redaction`` stores.
_SHA256_BARE_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

_COMMITMENT_REQUIRED_KEYS = frozenset({"redaction_method", "redacted_payload_hash", "redaction_policy_version"})
_COMMITMENT_OPTIONAL_KEYS = frozenset({"access_policy"})


def _is_commitment_routed(record: dict[str, Any], version: str) -> bool:
    """True when this record's payload must be the apply_redaction commitment.

    The commitment concept (hash-commitment payloads carrying X1
    ``redaction_policy_version`` / X2 ``redaction_attestation_ref``) is
    v1.1-ONLY. For a v1.0 (schema-dir ``"v1"``) bundle X1/X2 are simply
    preserved EXTENSION fields that MUST NOT alter validation — such a record
    falls through to per-record-type payload validation exactly as before
    F-M2-REDACTION. Without this version gate a v1.0 hash-committed/redacted
    record carrying X1/X2 would skip its per-type schema and dodge the
    ACEF-004 it correctly emitted (the roborev version-leak finding).

    Requires the v1.1 schema dir AND the transform-class confidentiality label
    AND both X1 and X2 as non-empty strings on the envelope (fail-closed — see
    module comment).
    """
    if version != "v1.1":
        return False
    if record.get("confidentiality") not in _COMMITMENT_CONFIDENTIALITY:
        return False
    x1 = record.get("redaction_policy_version")
    x2 = record.get("redaction_attestation_ref")
    return isinstance(x1, str) and bool(x1) and isinstance(x2, str) and bool(x2)


def _commitment_shape_problems(payload: dict[str, Any]) -> list[tuple[str, str]]:
    """Validate a payload against the commitment shape.

    Returns ``(message, relative_json_pointer)`` pairs — empty means the
    commitment is well-formed. Collects ALL problems (Phase-1 discipline).
    """
    problems: list[tuple[str, str]] = []

    method = payload.get("redaction_method")
    if not isinstance(method, str) or method not in _SUPPORTED_COMMITMENT_METHODS:
        problems.append(
            (
                f"redaction_method must be one of {sorted(_SUPPORTED_COMMITMENT_METHODS)!r}; got {method!r}",
                "/redaction_method",
            )
        )

    payload_hash = payload.get("redacted_payload_hash")
    if not isinstance(payload_hash, str) or not _SHA256_BARE_HEX_RE.match(payload_hash):
        problems.append(
            (
                "redacted_payload_hash must be 64 lowercase hex characters "
                f"(bare SHA-256 digest); got {payload_hash!r}",
                "/redacted_payload_hash",
            )
        )

    policy_version = payload.get("redaction_policy_version")
    if not isinstance(policy_version, str) or not policy_version:
        problems.append(
            (
                f"redaction_policy_version must be a non-empty string; got {policy_version!r}",
                "/redaction_policy_version",
            )
        )

    if "access_policy" in payload and not isinstance(payload["access_policy"], dict):
        problems.append(
            (
                f"access_policy must be an object when present; got {payload['access_policy']!r}",
                "/access_policy",
            )
        )

    extras = sorted(set(payload) - _COMMITMENT_REQUIRED_KEYS - _COMMITMENT_OPTIONAL_KEYS)
    if extras:
        problems.append(
            (
                f"unexpected key(s) {extras!r} — a commitment payload must "
                f"contain exactly {sorted(_COMMITMENT_REQUIRED_KEYS)!r} "
                f"(plus optional {sorted(_COMMITMENT_OPTIONAL_KEYS)!r}); "
                "leftover cleartext fields are not a valid redaction",
                "",
            )
        )

    return problems


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

        # Commitment route (fail-closed, v1.1-ONLY — see module comment): a
        # v1.1 hash-committed/redacted record carrying BOTH X1 and X2 stores the
        # apply_redaction commitment, not the cleartext payload. Validate
        # the commitment shape itself; per-type validation does not apply. A
        # v1.0 record (where X1/X2 are mere extension fields) never routes here.
        if _is_commitment_routed(record, version):
            for message, relative_pointer in _commitment_shape_problems(payload):
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-004",
                        f"Redaction commitment violation for {record_type} (record {i}): {message}",
                        path=f"/records/{i}/payload{relative_pointer}",
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
