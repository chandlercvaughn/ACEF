"""ACEF template registry — discovery, loading, and digest computation."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from acef.errors import ACEFProfileError
from acef.integrity import canonicalize, sha256_hex
from acef.templates.models import Template

# Template directory — bundled with the SDK
_TEMPLATE_DIR = Path(__file__).parent


def _get_template_dir() -> Path:
    """Get the template directory."""
    return _TEMPLATE_DIR


@lru_cache(maxsize=16)
def _load_template_cached(template_id: str) -> Template:
    """Inner cached loader — returns the single shared Template instance.

    DO NOT call this directly from outside this module. Callers MUST use
    :func:`load_template`, which returns an independent deep copy so that
    in-place mutation (now or in the future) does not corrupt the cache.
    """
    template_dir = _get_template_dir()
    template_file = template_dir / f"{template_id}.json"

    if not template_file.exists():
        raise ACEFProfileError(
            f"Template not found: {template_id}",
            code="ACEF-030",
        )

    try:
        with open(template_file, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ACEFProfileError(
            f"Invalid JSON in template {template_id}: {e}",
            code="ACEF-030",
        ) from e

    return Template.model_validate(data)


def load_template(template_id: str) -> Template:
    """Load a regulation mapping template by ID.

    Templates are JSON files in the templates/ directory named
    ``{template_id}.json``. Caching keeps the file read cost out of the
    hot path; the returned object is an independent copy of the cached
    Template, so callers may mutate it freely without corrupting other
    callers' views.

    Args:
        template_id: The template identifier, e.g., 'eu-ai-act-2024'.

    Returns:
        Parsed :class:`Template`. Each call returns a fresh instance.

    Raises:
        ACEFProfileError: If the template file is not found.
    """
    # ``Template.model_copy(deep=True)`` returns a structurally
    # independent copy — provisions/evaluation lists, dict params etc.
    # are all newly constructed, so any in-place mutation in one caller
    # cannot leak into another.
    return _load_template_cached(template_id).model_copy(deep=True)


def clear_template_cache() -> None:
    """Invalidate the in-process template cache.

    Tests and long-running processes that update template JSON on disk
    must call this to force a re-read on the next :func:`load_template`.
    """
    _load_template_cached.cache_clear()


# Backward-compatibility: callers that already invoked ``load_template.cache_clear()``
# (the lru_cache method on the previous implementation) keep working.
load_template.cache_clear = _load_template_cached.cache_clear  # type: ignore[attr-defined]
load_template.cache_info = _load_template_cached.cache_info  # type: ignore[attr-defined]


def compute_template_digest(template_id: str) -> str:
    """Compute the SHA-256 digest of a template's canonical on-disk form.

    The digest commits to the on-disk JSON bytes (canonicalized via
    RFC 8785) rather than a Pydantic re-serialization. That ensures two
    implementations claiming ``compute_template_digest("eu-ai-act-2024")``
    will agree regardless of whether they share the exact same Pydantic
    model definitions — a Pydantic-based digest could diverge if either
    side adds or removes optional fields.
    """
    template_dir = _get_template_dir()
    template_file = template_dir / f"{template_id}.json"
    if not template_file.exists():
        raise ACEFProfileError(
            f"Template not found: {template_id}",
            code="ACEF-030",
        )
    try:
        on_disk = json.loads(template_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ACEFProfileError(
            f"Invalid JSON in template {template_id}: {e}",
            code="ACEF-030",
        ) from e
    canonical = canonicalize(on_disk)
    digest = sha256_hex(canonical)
    return f"sha256:{digest}"


def list_templates() -> list[str]:
    """List all available template IDs.

    Returns:
        List of template IDs found in the templates directory.
    """
    template_dir = _get_template_dir()
    result: list[str] = []
    for f in sorted(template_dir.glob("*.json")):
        result.append(f.stem)
    return result


