"""ACEF schema registry — loading, validation, variant resolution.

Schemas are stored in acef-conventions/v{major}/ and discovered by convention:
- manifest.schema.json
- record-envelope.schema.json
- assessment-bundle.schema.json
- {record_type}.schema.json per record type
- variant-registry.json for payload variant lookup
"""

from __future__ import annotations

import copy
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

from acef.errors import ACEFSchemaError

# The format checker used for every envelope/record schema validation. It is
# the draft2020-12 ``FORMAT_CHECKER`` UNCHANGED: ``"format": "date"`` is STRICT
# (a ``date-time`` value fails the ``date`` check), ``"format": "date-time"`` is
# strict, ``"format": "uuid"``/``"uri"``/… keep their semantics. This enforces
# the ISO-8601 MUST (ENVELOPE-001) while preserving the date-ONLY contract of
# fields documented "ISO 8601" / "ISO 8601 date" (``evaluation_report.evaluation_date``,
# ``governance_policy.approval_date``, ``risk_treatment.implementation_date``, …)
# — those REJECT a date-time. The narrow set of fields whose schema DESCRIPTION
# documents "date or date-time" (the manifest ``lifecycle_timeline[].start_date`` /
# ``end_date``) is handled NOT by weakening the checker but by an in-memory
# schema patch in :func:`_patch_date_or_datetime_fields`, so the leniency is
# scoped to exactly those fields. ``date-time`` checking relies on the installed
# ``rfc3339-validator`` dependency.
_STRICT_FORMAT_CHECKER = Draft202012Validator.FORMAT_CHECKER


# Substring that, when present in a ``format: date`` field's ``description``,
# marks the documented "ISO 8601 date OR date-time" contract (currently only
# the manifest ``lifecycle_timeline[].start_date`` / ``end_date`` fields). Any
# field carrying this phrase is patched IN MEMORY to accept date or date-time.
_DATE_OR_DATETIME_DESCRIPTION_MARKER = "date or date-time"


def _patch_date_or_datetime_fields(node: Any) -> bool:
    """Recursively patch ``format: date`` fields documented "date or date-time".

    A field that declares ``"format": "date"`` while its ``"description"``
    documents the "ISO 8601 date OR date-time" contract (the manifest
    ``lifecycle_timeline[].start_date`` / ``end_date`` fields) must accept a
    plain date OR a date-time, yet the FROZEN (v1) / other-feature-owned (v1.1)
    on-disk schema cannot express that. We patch the IN-MEMORY loaded copy of
    the schema, rewriting each such field's ``type``/``format`` assertion to::

        "anyOf": [
            {"type": "string", "format": "date"},
            {"type": "string", "format": "date-time"}
        ]

    preserving any ``null`` allowance (``end_date`` is ``["string", "null"]``).
    A bogus value (``"not-a-date"``) is still rejected because it is neither a
    valid ``date`` nor a valid ``date-time``. Every OTHER ``format: date`` field
    (documented "ISO 8601" only) is left STRICT, so it rejects a date-time.

    The function mutates ``node`` in place (the caller passes a private copy) and
    returns ``True`` if any field was patched (for test/observability).
    """
    patched = False
    if isinstance(node, dict):
        is_date_field = (
            node.get("format") == "date"
            and isinstance(node.get("description"), str)
            and _DATE_OR_DATETIME_DESCRIPTION_MARKER in node["description"]
        )
        if is_date_field:
            allows_null = isinstance(node.get("type"), list) and "null" in node["type"]
            options: list[dict[str, Any]] = [
                {"type": "string", "format": "date"},
                {"type": "string", "format": "date-time"},
            ]
            if allows_null:
                options.append({"type": "null"})
            # Drop the now-superseded type/format assertions and graft the
            # anyOf, keeping the description and any sibling keywords intact.
            node.pop("type", None)
            node.pop("format", None)
            node["anyOf"] = options
            patched = True
        for value in node.values():
            if _patch_date_or_datetime_fields(value):
                patched = True
    elif isinstance(node, list):
        for item in node:
            if _patch_date_or_datetime_fields(item):
                patched = True
    return patched


# Schema base directories — searched in order.
# First: relative to project root (development layout)
# Second: relative to the installed acef package (pip install layout)
_SCHEMA_DIRS: list[Path] = [
    Path(__file__).resolve().parents[3] / "acef-conventions",  # project root/acef-conventions
    Path(__file__).resolve().parent.parent / "acef-conventions",  # package-sibling fallback
]

# Ordered fallback chain per schema-version token.
# v1.1 falls back to v1 for record types unchanged in the v1.1 minor release.
# v1 has no fallback — a v1.0-declared bundle MUST NOT silently inherit
# schemas added in v1.1 (this is the version-gate guarantee per
# brief §8.1 + VAL-VALIDATION-002).
_VERSION_FALLBACK: dict[str, tuple[str, ...]] = {
    "v1": ("v1",),
    "v1.1": ("v1.1", "v1"),
}

# Companion sub-schemas that ship as *.schema.json files under a version
# directory but are NOT independently claimable record types. They are
# projection building blocks referenced by $ref from the incident record types
# (RFC-0002 §5.2/§5.4/§5.5/§5.6) and from the card_source overlay block.
# Without this exclusion they would leak into list_record_type_schemas() and be
# treated as record types (the "companion looks like a record type" finding).
# Note: harm-core-taxonomy.json has no .schema.json suffix and is therefore
# already excluded by the *.schema.json glob; it is named here for clarity and
# for the SDK record-type inventory guard.
_COMPANION_SUBSCHEMAS: frozenset[str] = frozenset(
    {
        "harm-core-taxonomy",
        "taxonomy_crosswalk",
        "severity_vector",
        "coordinated_disclosure",
        "incident_report.card_source",
    }
)


def parse_core_version_minor(core_version: str | None) -> tuple[int, int | None] | None:
    """Parse ``core_version`` into a numeric ``(major, minor)`` result.

    This is the single, semver-correct parse for every ``core_version``
    minor-gating decision (schema selection, the v1.1 version gate, the X1/X2
    redaction auto-population gate) — callers MUST NOT re-implement
    lexicographic string comparison (``core_v >= "1.1"``), which is not
    semver-correct (e.g. it accepts ``"1.1abc"`` and is fragile across widening
    version strings; audit records-payloads-6 / redaction-5).

    The result PRESERVES the major whenever it is numeric, so callers can
    distinguish "no parseable major at all" from "major=N, minor malformed"
    (roborev finding 1). Previously a malformed minor collapsed to ``None`` and
    DISCARDED the major, so an unsupported-major version with a bad minor (e.g.
    ``"2.x"``) was silently mishandled — :func:`schema_version_for_core_version`
    fell back to ``"v1"`` instead of rejecting the unsupported major, and
    ``Package._ensure_v1_1`` rewrote it to ``"1.1.0"``.

    Args:
        core_version: The value of ``manifest.versioning.core_version`` (or
            ``None`` if absent).

    Returns:
        - ``None`` when there is NO parseable major at all (the version is
          absent/empty or the major segment is non-numeric, e.g. ``"garbage"``).
          Callers treat ``None`` as a legacy/unparseable bundle and route to
          their established lenient floor.
        - ``(major, None)`` when the major segment parses but the minor segment
          is present and non-numeric (e.g. ``"1.x"``, ``"2.abc"``,
          ``"1.1abc"``). Callers MUST NOT treat a ``None`` minor as a valid v1.1
          declaration; they decide per major whether to reject or floor.
        - ``(major, minor)`` when both the major and the (present) minor parse
          as integers. A bare major (``"1"``) yields ``(1, 0)`` — minor
          defaults to 0.
    """
    if core_version is None or core_version == "":
        return None

    parts = core_version.split(".")
    try:
        major = int(parts[0])
    except (ValueError, IndexError):
        # No parseable major at all — a fully-unparseable / legacy version.
        return None

    if len(parts) < 2:
        return (major, 0)

    try:
        minor = int(parts[1])
    except ValueError:
        # A non-numeric minor segment (e.g. "1.x", "1.1abc", "2.x") is NOT a
        # valid numeric minor. Preserve the major and signal the malformed
        # minor as ``None`` so the major-1 v1.1 gate does not accept "1.1abc"
        # as a v1.1 declaration AND an unsupported major (2.x) is still
        # rejectable by the major check rather than masked as fully-unparseable.
        return (major, None)

    return (major, minor)


def schema_version_for_core_version(core_version: str | None) -> str:
    """Map ``manifest.versioning.core_version`` to a schema directory token.

    Args:
        core_version: The value of ``manifest.versioning.core_version`` from
            the bundle's acef-manifest.json, or ``None`` if the field is
            absent.

    Returns:
        ``"v1"`` for 1.0.x (or absent/empty/fully-unparseable — backwards-compat
        for legacy bundles whose version string lacks a numeric major),
        ``"v1.1"`` for 1.1.x and any future v1.y where y > 1 (falls through to
        the most-recent known minor schema dir; the v1.1 → v1 fallback in
        :func:`load_schema` ensures unchanged record types still resolve).

    Raises:
        ACEFSchemaError: code ACEF-001, when the major version is parseable but
            not 1 (validator does not support core 2.x — REGARDLESS of whether
            the minor parses, so ``"2.x"``/``"2.abc"``/``"2.0"`` all reject), or
            when the major is 1 but the minor segment is malformed (e.g.
            ``"1.x"``) — a v1.* bundle with an unparseable minor MUST NOT be
            silently routed to v1 or v1.1.
    """
    parsed = parse_core_version_minor(core_version)
    if parsed is None:
        # No parseable major at all ("garbage", "", absent) — lenient fallback
        # for legacy/odd bundles. Phase 1 schema validation diagnoses the
        # malformed version string itself; we just route through v1.
        return "v1"

    major, minor = parsed
    if major != 1:
        # An unsupported major is rejected even when the minor is malformed
        # ("2.x"): the major is preserved through the parse, so we never fall
        # back to v1 for an unsupported-major bundle (roborev finding 1).
        raise ACEFSchemaError(
            f"Incompatible core_version: {core_version!r} (validator supports 1.x only)",
            code="ACEF-001",
        )

    if minor is None:
        # Major is 1 but the minor segment is malformed ("1.x"). We MUST NOT
        # silently route a v1.* bundle with an unparseable minor to v1 or v1.1;
        # the version string is malformed and is rejected with ACEF-001.
        raise ACEFSchemaError(
            f"Incompatible core_version: {core_version!r} (malformed minor segment)",
            code="ACEF-001",
        )

    if minor <= 0:
        return "v1"
    # Any minor >= 1 routes to v1.1 (the most-recent known minor); future
    # v1.y bundles benefit from v1.1's superset + v1 fallback.
    return "v1.1"


def _find_schema_dir(version: str = "v1") -> Path:
    """Find the schema directory for a given version."""
    for base in _SCHEMA_DIRS:
        candidate = base / version
        if candidate.exists():
            return candidate
    raise ACEFSchemaError(
        f"Schema directory not found for version {version}. Searched: {[str(b) for b in _SCHEMA_DIRS]}",
        code="ACEF-001",
    )


@lru_cache(maxsize=64)
def load_schema(schema_name: str, version: str = "v1") -> dict[str, Any]:
    """Load a JSON Schema by name from the registry.

    Args:
        schema_name: Schema filename without .schema.json suffix,
                     e.g., 'manifest', 'record-envelope', 'risk_register'.
        version: Schema version directory, e.g., 'v1', 'v1.1'.

    Returns:
        The parsed JSON Schema dict.

    Raises:
        ACEFSchemaError: If the schema file is not found or invalid.

    Notes:
        Version fallback chain per :data:`_VERSION_FALLBACK`. For
        ``version="v1.1"``, lookup tries v1.1/ first then falls back to v1/
        — record types unchanged in the v1.1 minor release are still
        resolved by the v1/ schema. For ``version="v1"``, no fallback: a
        v1.0-declared bundle MUST NOT silently inherit v1.1-only record
        types (the version gate enforced by VAL-VALIDATION-002).
    """
    chain = _VERSION_FALLBACK.get(version, (version,))

    last_error: ACEFSchemaError | None = None
    for candidate_version in chain:
        try:
            schema_dir = _find_schema_dir(candidate_version)
        except ACEFSchemaError as exc:
            last_error = exc
            continue

        schema_file = schema_dir / f"{schema_name}.schema.json"
        if not schema_file.exists():
            continue

        try:
            with open(schema_file, encoding="utf-8") as f:
                return json.load(f)  # type: ignore[no-any-return]
        except json.JSONDecodeError as e:
            raise ACEFSchemaError(
                f"Invalid JSON in schema {schema_name}: {e}",
                code="ACEF-002",
            ) from e

    if last_error is not None and last_error.code == "ACEF-001":
        # Schema directory itself missing — surface the directory error
        # rather than reporting an "unknown record_type" condition.
        raise last_error
    raise ACEFSchemaError(
        f"Schema not found: {schema_name} in {version}",
        code="ACEF-003",
    )


@lru_cache(maxsize=8)
def build_schema_registry(version: str = "v1") -> Registry[Any]:
    """Build a ``referencing.Registry`` of every schema in a version's chain.

    Every ``*.schema.json`` and ``*.json`` resource carrying a ``$id`` under the
    version's fallback-chain directories is registered by its ``$id``. This lets
    the production :class:`~jsonschema.Draft202012Validator` resolve relative
    ``$ref``\\s (e.g. ``harm-core-taxonomy.json#/$defs/harm_class``,
    ``coordinated_disclosure.schema.json``, ``severity_vector.schema.json``,
    ``taxonomy_crosswalk.schema.json``, ``incident_report.card_source.schema.json``)
    against each schema's ``$id`` base — instead of the validator attempting a
    network fetch of ``https://acef.ai/...`` and crashing with ``Unresolvable``
    / ``Unretrievable`` (the v1.1 incident ``$ref`` graph). Both the higher
    (leftmost) and fallback directories are scanned; on a duplicate ``$id`` the
    higher-priority version wins (matching :data:`_VERSION_FALLBACK` semantics).

    The registry is the resolution backbone for the v1.1 incident schemas
    (F-M2-SCHEMA-GATING / VAL-SCH-001). A ``referencing.Registry`` is immutable
    and hashable on its contents, so it is safe to cache and reuse across
    validations.

    Args:
        version: Schema-dir token ("v1" or "v1.1"). The returned registry covers
            the full fallback chain for that token.

    Returns:
        An immutable :class:`referencing.Registry` keyed by schema ``$id``.
    """
    chain = _VERSION_FALLBACK.get(version, (version,))

    # Walk the chain in reverse so the higher-priority (leftmost) version's
    # resources are registered last and override any earlier $id collision.
    resources_by_id: dict[str, Resource[Any]] = {}
    for candidate_version in reversed(chain):
        try:
            schema_dir = _find_schema_dir(candidate_version)
        except ACEFSchemaError:
            continue

        for schema_file in sorted(schema_dir.glob("*.json")):
            try:
                contents = json.loads(schema_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                # A malformed schema file is surfaced by load_schema /
                # validate_schemas.py, not here; skip it for registry purposes.
                continue
            if not isinstance(contents, dict):
                continue
            schema_id = contents.get("$id")
            if not isinstance(schema_id, str) or not schema_id:
                continue
            resources_by_id[schema_id] = Resource.from_contents(contents)

    return Registry().with_resources([(rid, res) for rid, res in resources_by_id.items()])


def validate_against_schema(
    data: dict[str, Any],
    schema_name: str,
    version: str = "v1",
) -> list[ValidationError]:
    """Validate data against a named JSON Schema.

    For schemas whose ``$ref``\\s point at sibling companion schemas (notably the
    v1.1 incident graph), the validator is constructed with a
    :func:`build_schema_registry` registry so every relative ``$ref`` resolves
    locally against its schema's ``$id`` base instead of being fetched over the
    network.

    Args:
        data: The data to validate.
        schema_name: The schema name (without .schema.json suffix).
        version: Schema version.

    Returns:
        List of validation errors. Empty list means valid.
    """
    try:
        schema = load_schema(schema_name, version)
    except ACEFSchemaError:
        return [ValidationError(f"Schema {schema_name} not found")]

    # ``load_schema`` is ``lru_cache``d, so its return value is SHARED across
    # callers. Deep-copy BEFORE the in-memory patch so we never mutate the cached
    # (and on-disk-frozen) schema. The copy lets us narrowly relax exactly the
    # fields whose DESCRIPTION documents "ISO 8601 date OR date-time" (the
    # manifest ``lifecycle_timeline[].start_date`` / ``end_date``) to an
    # ``anyOf [{format: date}, {format: date-time}]`` while every OTHER
    # ``format: date`` field (documented date-ONLY) stays strict.
    schema = copy.deepcopy(schema)
    _patch_date_or_datetime_fields(schema)

    # Register the STRICT draft2020-12 FORMAT_CHECKER so ``"format": "date-time"``
    # / ``"format": "date"`` assertions FIRE (in jsonschema, ``format`` is
    # annotation-only and does NOT assert without a checker). This enforces the
    # ISO 8601 MUST on every timestamp/date field in the envelope/record hash
    # domain (metadata.timestamp, audit_trail[].timestamp,
    # lifecycle_timeline.start_date/end_date, record-envelope.timestamp) so a
    # non-ISO value surfaces as ACEF-002 (manifest) / ACEF-004 (record payload)
    # rather than passing silently and corrupting the deterministic
    # timestamp-ascending JSONL ordering (envelope-manifest-1). ``date-time``
    # checking relies on the installed ``rfc3339-validator`` dependency. Unlike
    # the previous date-or-date-time-lenient checker, this STRICT checker keeps
    # date-ONLY fields (evaluation_date, approval_date, implementation_date, …)
    # rejecting a date-time; the documented date-or-date-time fields were already
    # relaxed by the schema patch above.
    validator = Draft202012Validator(
        schema,
        registry=build_schema_registry(version),
        format_checker=_STRICT_FORMAT_CHECKER,
    )
    return list(validator.iter_errors(data))


def validate_manifest(manifest_data: dict[str, Any], version: str = "v1") -> list[ValidationError]:
    """Validate an acef-manifest.json against the manifest schema."""
    return validate_against_schema(manifest_data, "manifest", version)


def validate_record_envelope(record_data: dict[str, Any], version: str = "v1") -> list[ValidationError]:
    """Validate a record against the record-envelope schema."""
    return validate_against_schema(record_data, "record-envelope", version)


def validate_record_payload(
    payload: dict[str, Any],
    record_type: str,
    version: str = "v1",
) -> list[ValidationError]:
    """Validate a record payload against its type-specific schema."""
    return validate_against_schema(payload, record_type, version)


@lru_cache(maxsize=4)
def load_variant_registry(version: str = "v1") -> list[dict[str, str]]:
    """Load the variant registry for bidirectional variant lookup.

    For ``version="v1.1"`` the returned list is the UNION of v1/'s registry
    and v1.1/'s registry: v1.1 adds new artifact names without removing
    existing ones. If the same ``artifact_name`` appears in both registries,
    the v1.1 entry takes precedence (override semantics).

    Returns:
        List of variant entries with artifact_name, record_type,
        discriminator_field, and discriminator_value.
    """
    chain = _VERSION_FALLBACK.get(version, (version,))

    # Walk the chain in reverse so the higher-priority (leftmost) version
    # overrides earlier entries on artifact_name collision.
    entries_by_name: dict[str, dict[str, str]] = {}
    for candidate_version in reversed(chain):
        try:
            schema_dir = _find_schema_dir(candidate_version)
        except ACEFSchemaError:
            continue

        registry_file = schema_dir / "variant-registry.json"
        if not registry_file.exists():
            continue

        with open(registry_file, encoding="utf-8") as f:
            data = json.load(f)

        for entry in data.get("variants", []):
            artifact_name = entry.get("artifact_name")
            if artifact_name:
                entries_by_name[artifact_name] = entry

    return list(entries_by_name.values())


def resolve_variant(artifact_name: str, version: str = "v1") -> dict[str, str] | None:
    """Resolve an artifact name to its parent record type and discriminator.

    Args:
        artifact_name: The artifact/variant name (e.g., 'management_review').
        version: Schema version.

    Returns:
        Dict with record_type, discriminator_field, discriminator_value,
        or None if not found.
    """
    for entry in load_variant_registry(version):
        if entry.get("artifact_name") == artifact_name:
            return entry
    return None


def resolve_record_type_for_variant(artifact_name: str, version: str = "v1") -> str | None:
    """Get the parent record type for a variant artifact name."""
    entry = resolve_variant(artifact_name, version)
    return entry["record_type"] if entry else None


def list_record_type_schemas(version: str = "v1") -> list[str]:
    """List all available record type schemas.

    For ``version="v1.1"`` returns the UNION of v1/'s record-type schemas
    and v1.1/'s record-type schemas (deduplicated). This makes v1.1 a
    superset of v1 — unchanged record types resolve via the fallback chain
    in :func:`load_schema`. For ``version="v1"`` returns only v1/'s
    record-type schemas (no fallback the other direction, enforcing the
    version gate per VAL-VALIDATION-002).

    Returns:
        Sorted list of record type names that have schemas available in
        the selected version's fallback chain.
    """
    # Structural schemas + companion sub-schemas are not record types. The
    # companions (severity_vector, taxonomy_crosswalk, coordinated_disclosure,
    # incident_report.card_source, harm-core-taxonomy) are $ref'd projection
    # building blocks, NOT independently claimable record_type values.
    excluded = {"manifest", "record-envelope", "assessment-bundle", "template"} | set(_COMPANION_SUBSCHEMAS)
    chain = _VERSION_FALLBACK.get(version, (version,))

    names: set[str] = set()
    for candidate_version in chain:
        try:
            schema_dir = _find_schema_dir(candidate_version)
        except ACEFSchemaError:
            continue
        for f in schema_dir.glob("*.schema.json"):
            name = f.name.replace(".schema.json", "")
            if name not in excluded:
                names.add(name)

    return sorted(names)
