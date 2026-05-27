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
from acef.schemas.registry import schema_version_for_core_version


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
