"""Tests for `schema_version_for_core_version` (F-M1-VALIDATOR-VERSION-SELECTION).

Covers VAL-VALIDATION-001 partial: the pure version-selector helper that
maps `manifest.versioning.core_version` to the schema directory token used
by `acef.schemas.registry` loaders.

Contract:
- None / "" -> "v1" (backwards-compat for v1.0 bundles that lack the field
  or for tooling that constructs minimal manifests).
- "1.0.x" -> "v1".
- "1.1.x" -> "v1.1".
- "1.y.z" where y > 1 -> "v1.1" (future minors fall through to the most
  recent known schema dir; the v1.1 -> v1 fallback in load_schema handles
  schemas that weren't redefined in v1.1).
- Major != 1 -> ACEFSchemaError(code="ACEF-001").
- Garbage -> "v1" (lenient fallback; Phase 1 schema validation will diagnose
  the malformed version string separately).
"""

from __future__ import annotations

import pytest

from acef.errors import ACEFSchemaError
from acef.schemas.registry import (
    parse_core_version_minor,
    schema_version_for_core_version,
)


def test_none_returns_v1() -> None:
    assert schema_version_for_core_version(None) == "v1"


def test_empty_string_returns_v1() -> None:
    assert schema_version_for_core_version("") == "v1"


def test_v1_0_0_returns_v1() -> None:
    assert schema_version_for_core_version("1.0.0") == "v1"


def test_v1_0_5_returns_v1() -> None:
    assert schema_version_for_core_version("1.0.5") == "v1"


def test_v1_1_0_returns_v1_1() -> None:
    assert schema_version_for_core_version("1.1.0") == "v1.1"


def test_v1_1_7_returns_v1_1() -> None:
    assert schema_version_for_core_version("1.1.7") == "v1.1"


def test_future_v1_minor_falls_through_to_v1_1() -> None:
    # Future v1.x minor releases (>=1.2) fall through to the most-recent
    # known minor schema dir. The v1.1 -> v1 fallback in load_schema
    # ensures unchanged record types still resolve.
    assert schema_version_for_core_version("1.2.0") == "v1.1"


def test_v2_0_0_raises_incompatible() -> None:
    with pytest.raises(ACEFSchemaError) as exc:
        schema_version_for_core_version("2.0.0")
    assert exc.value.code == "ACEF-001"


def test_garbage_returns_v1_fallback() -> None:
    # Unparseable -> default to v1; Phase 1 schema validation will diagnose
    # the malformed version string itself.
    assert schema_version_for_core_version("garbage") == "v1"


def test_partial_garbage_returns_v1_fallback() -> None:
    # e.g. "1" with no dot -> int("1") works but minor is missing; treat as
    # 1.0 -> v1.
    assert schema_version_for_core_version("1") == "v1"


# ---------------------------------------------------------------------------
# Unsupported-major + malformed-minor (roborev finding 1): the MAJOR must be
# preserved through the parse so an unsupported major is REJECTED with ACEF-001
# regardless of whether the minor segment parses. Previously a value like "2.x"
# parsed to None (minor unparseable swallowed the major) and silently routed to
# "v1" — a forged/typo'd unsupported-major version was mishandled, not rejected.
# ---------------------------------------------------------------------------


def test_v2_malformed_minor_raises_incompatible() -> None:
    # "2.x" — major 2 is unsupported; the malformed minor MUST NOT mask that.
    with pytest.raises(ACEFSchemaError) as exc:
        schema_version_for_core_version("2.x")
    assert exc.value.code == "ACEF-001"


def test_v2_alpha_minor_raises_incompatible() -> None:
    with pytest.raises(ACEFSchemaError) as exc:
        schema_version_for_core_version("2.abc")
    assert exc.value.code == "ACEF-001"


def test_v2_0_no_patch_raises_incompatible() -> None:
    # "2.0" — major 2, valid minor 0; still an unsupported major.
    with pytest.raises(ACEFSchemaError) as exc:
        schema_version_for_core_version("2.0")
    assert exc.value.code == "ACEF-001"


def test_v3_major_raises_incompatible() -> None:
    with pytest.raises(ACEFSchemaError) as exc:
        schema_version_for_core_version("3.0.0")
    assert exc.value.code == "ACEF-001"


def test_major_1_malformed_minor_raises_incompatible() -> None:
    # "1.x" — major 1 but the minor segment is malformed. We MUST NOT silently
    # route a v1.* bundle with an unparseable minor to either v1 or v1.1; the
    # version string is malformed and is rejected with ACEF-001.
    with pytest.raises(ACEFSchemaError) as exc:
        schema_version_for_core_version("1.x")
    assert exc.value.code == "ACEF-001"


def test_v1_10_0_still_routes_to_v1_1() -> None:
    # Numeric-vs-lexicographic divergence guard: 1.10 > 1.1 numerically.
    assert schema_version_for_core_version("1.10.0") == "v1.1"


# ---------------------------------------------------------------------------
# parse_core_version_minor — the richer (major, minor|None) | None shape. The
# parse MUST preserve the MAJOR whenever it is numeric, so callers can tell
# "no parseable major at all" (None) from "major=N, minor malformed"
# ((N, None)). Previously a malformed minor returned None and discarded the
# major (roborev finding 1).
# ---------------------------------------------------------------------------


def test_parse_none_and_empty_return_none() -> None:
    assert parse_core_version_minor(None) is None
    assert parse_core_version_minor("") is None


def test_parse_non_numeric_major_returns_none() -> None:
    # No parseable major at all.
    assert parse_core_version_minor("garbage") is None


def test_parse_bare_major_defaults_minor_zero() -> None:
    assert parse_core_version_minor("1") == (1, 0)
    assert parse_core_version_minor("2") == (2, 0)


def test_parse_valid_major_minor() -> None:
    assert parse_core_version_minor("1.0.0") == (1, 0)
    assert parse_core_version_minor("1.1.0") == (1, 1)
    assert parse_core_version_minor("1.10.0") == (1, 10)
    assert parse_core_version_minor("2.0") == (2, 0)


def test_parse_malformed_minor_preserves_major() -> None:
    # Minor unparseable but major numeric -> (major, None), NOT None.
    assert parse_core_version_minor("1.x") == (1, None)
    assert parse_core_version_minor("1.1abc") == (1, None)
    assert parse_core_version_minor("2.x") == (2, None)
    assert parse_core_version_minor("2.abc") == (2, None)
