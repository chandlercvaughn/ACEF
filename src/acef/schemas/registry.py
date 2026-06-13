"""ACEF schema registry — loading, validation, variant resolution.

Schemas are stored in acef-conventions/v{major}/ and discovered by convention:
- manifest.schema.json
- record-envelope.schema.json
- assessment-bundle.schema.json
- {record_type}.schema.json per record type
- variant-registry.json for payload variant lookup
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

from acef.errors import ACEFSchemaError


def _build_date_or_datetime_format_checker() -> FormatChecker:
    """Return a format checker whose ``date`` format accepts date OR date-time.

    The draft2020-12 ``FORMAT_CHECKER`` asserts ``"format": "date"`` strictly
    (a ``date-time`` value FAILS the ``date`` check). But several manifest fields
    declare ``"format": "date"`` while their schema descriptions explicitly say
    "ISO 8601 date or date-time" — notably ``lifecycle_timeline[].start_date`` /
    ``end_date`` (acef-conventions/v1 and v1.1 manifest schema). Those schemas are
    FROZEN (v1) or owned by other features (v1.1), so the contract cannot be
    expressed as ``anyOf [{format: date}, {format: date-time}]`` in the schema
    itself. Instead we register a CUSTOM ``date`` checker that conforms when the
    value is a valid ``date`` OR a valid ``date-time``.

    ``date-time`` stays STRICT (a bare date or a bogus string still fails), so a
    genuine timestamp field (``metadata.timestamp``, ``audit_trail[].timestamp``,
    record-envelope ``timestamp``) is unaffected. A non-ISO ``date`` value (e.g.
    "not-a-date") is still rejected — preserving the ENVELOPE-001 ISO-8601 MUST.
    """
    base = Draft202012Validator.FORMAT_CHECKER
    date_func, _ = base.checkers["date"]
    datetime_func, _ = base.checkers["date-time"]

    # Seed a fresh checker with EVERY draft2020-12 format (``date-time``,
    # ``uuid``, ``uri``, …) so all formats keep their strict semantics. Mutating
    # ``base`` directly would corrupt the shared class-level checker.
    checker = FormatChecker()
    checker.checkers = dict(base.checkers)

    # Override ONLY ``date`` to conform on a valid date OR date-time. The
    # underlying ``is_date`` raises ``ValueError`` and ``is_datetime`` raises
    # nothing (it returns False), so the decorator registers ``ValueError`` as a
    # conformance-non-error and we additionally guard with a broad try/except to
    # be robust to either checker's failure mode.
    @checker.checks("date", raises=(ValueError,))
    def _is_date_or_datetime(value: object) -> bool:
        # jsonschema only invokes a format checker on instances matching the
        # format's primitive type (string). Non-strings conform vacuously so the
        # ``type`` keyword — not ``format`` — owns the type error.
        if not isinstance(value, str):
            return True
        try:
            if bool(date_func(value)):
                return True
        except ValueError:
            pass
        try:
            if bool(datetime_func(value)):
                return True
        except ValueError:
            pass
        return False

    return checker


# Module-level singleton: the format checker used for every envelope/record
# schema validation. ``date`` accepts date-or-date-time; everything else strict.
_DATE_OR_DATETIME_FORMAT_CHECKER = _build_date_or_datetime_format_checker()

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


def schema_version_for_core_version(core_version: str | None) -> str:
    """Map ``manifest.versioning.core_version`` to a schema directory token.

    Args:
        core_version: The value of ``manifest.versioning.core_version`` from
            the bundle's acef-manifest.json, or ``None`` if the field is
            absent.

    Returns:
        ``"v1"`` for 1.0.x (or absent/empty/unparseable — backwards-compat
        for legacy bundles), ``"v1.1"`` for 1.1.x and any future v1.y where
        y > 1 (falls through to the most-recent known minor schema dir; the
        v1.1 → v1 fallback in :func:`load_schema` ensures unchanged record
        types still resolve).

    Raises:
        ACEFSchemaError: code ACEF-001, when the major version is not 1
            (validator does not support core 2.x).
    """
    if core_version is None or core_version == "":
        return "v1"

    parts = core_version.split(".")
    try:
        major = int(parts[0])
    except (ValueError, IndexError):
        # Garbage like "garbage" or "" after split — lenient fallback.
        # Phase 1 schema validation will diagnose the malformed version
        # string itself; we just route through v1.
        return "v1"

    if major != 1:
        raise ACEFSchemaError(
            f"Incompatible core_version: {core_version!r} (validator supports 1.x only)",
            code="ACEF-001",
        )

    # major == 1 — inspect the minor.
    try:
        minor = int(parts[1]) if len(parts) >= 2 else 0
    except ValueError:
        # e.g. "1.x" — treat as v1.0 floor.
        minor = 0

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

    # Register the draft2020-12 FORMAT_CHECKER so ``"format": "date-time"`` /
    # ``"format": "date"`` assertions FIRE (in jsonschema, ``format`` is
    # annotation-only and does NOT assert without a checker). This enforces the
    # ISO 8601 MUST on every timestamp/date field in the envelope/record hash
    # domain (metadata.timestamp, audit_trail[].timestamp,
    # lifecycle_timeline.start_date/end_date, record-envelope.timestamp) so a
    # non-ISO value surfaces as ACEF-002 (manifest) / ACEF-004 (record payload)
    # rather than passing silently and corrupting the deterministic
    # timestamp-ascending JSONL ordering (envelope-manifest-1). ``date-time``
    # checking relies on the installed ``rfc3339-validator`` dependency. The
    # checker is the ``date``-or-``date-time``-lenient
    # ``_DATE_OR_DATETIME_FORMAT_CHECKER`` so a ``format: date`` field documented
    # as "date OR date-time" (lifecycle_timeline.start_date/end_date) accepts a
    # date-time value while genuine ``date-time``-only fields stay strict and a
    # bogus value is still rejected.
    validator = Draft202012Validator(
        schema,
        registry=build_schema_registry(version),
        format_checker=_DATE_OR_DATETIME_FORMAT_CHECKER,
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
