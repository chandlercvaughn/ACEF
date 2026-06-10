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

from jsonschema import Draft202012Validator, ValidationError

from acef.errors import ACEFSchemaError

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


def validate_against_schema(
    data: dict[str, Any],
    schema_name: str,
    version: str = "v1",
) -> list[ValidationError]:
    """Validate data against a named JSON Schema.

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

    validator = Draft202012Validator(schema)
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
    excluded = {"manifest", "record-envelope", "assessment-bundle", "template"}
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
