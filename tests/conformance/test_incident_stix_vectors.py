"""VAL-BUILD-STIX-001 — RFC-0002 §5.8 STIX emit-only conformance vectors.

Drives the byte-stable on-disk vectors under ``test-vectors/incident-stix/``
through the PRODUCTION validator (:func:`acef.validation.engine.validate_bundle`)
and the v1.1 ``incident_card`` schema. The two vectors prove the emit/omit gate
plus the §5.10 canonical-byte sort:

- ``with-stix`` — a public ``incident_card`` built with supplied STIX object_refs
  emits ``taxonomy_crosswalk.stix = {"edition": "2.1", "object_refs": [...]}`` whose
  array byte-equals the §5.10 sort recomputed INDEPENDENTLY here (RFC-8785 canonical
  byte order via :func:`acef.integrity.utf16_collation_key`), is de-duplicated, and
  whose every element matches the STIX 2.1 ``<type>--<uuidv4>`` schema pattern.
- ``without-stix`` — the SAME card with NO STIX input OMITS the optional ``stix``
  member entirely.

The vectors live OUTSIDE ``test-vectors/incident/`` so the exact-inventory driver
``tests/conformance/test_incident_vectors.py`` (which pins that corpus) is not
perturbed. They are regenerated deterministically by
``test-vectors/incident-stix/generate.py`` (fixed clock + deterministic URNs +
unsigned, since signatures are outside the hash domain).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from acef.integrity import utf16_collation_key
from acef.schemas.registry import validate_record_payload
from acef.validation.engine import validate_bundle

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_STIX_DIR = _REPO_ROOT / "test-vectors" / "incident-stix"
_VECTORS_MANIFEST = _STIX_DIR / "vectors.json"

# The STIX 2.1 id grammar mirrored from
# acef-conventions/v1.1/taxonomy_crosswalk.schema.json (stix.object_refs items.pattern),
# including the absolute end anchor (?![\s\S]) (not $) that rejects a trailing newline.
_STIX_ID_PATTERN = re.compile(
    r"^[a-z][a-z0-9-]{2,249}--[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])"
)

# The pre-existing, feature-unrelated SDK quirk (empty audit_trail actor_ref) that
# every vanilla SDK-built bundle exhibits — excluded from the zero-ERROR assertion,
# mirroring tests/integration/test_report_incident_e2e.py.
_PRE_EXISTING_SDK_ERROR_PATHS: frozenset[str] = frozenset({"/audit_trail/0/actor_ref"})


def _load_manifest() -> dict[str, Any]:
    assert _VECTORS_MANIFEST.is_file(), (
        f"missing {_VECTORS_MANIFEST} — run `python test-vectors/incident-stix/generate.py`"
    )
    return json.loads(_VECTORS_MANIFEST.read_text(encoding="utf-8"))


_MANIFEST = _load_manifest()
_VECTORS: list[dict[str, Any]] = _MANIFEST.get("vectors", [])


def _vector(name: str) -> dict[str, Any]:
    for v in _VECTORS:
        if v.get("name") == name:
            return v
    raise AssertionError(f"vector {name!r} not declared in vectors.json")


def _bundle_dir(vector: dict[str, Any]) -> Path:
    return _STIX_DIR / str(vector.get("path"))


def _card_payload(vector: dict[str, Any]) -> dict[str, Any]:
    record_path = _bundle_dir(vector) / "records" / "incident_card.jsonl"
    assert record_path.is_file(), f"{vector.get('name')!r} missing incident_card.jsonl"
    record = json.loads(record_path.read_text(encoding="utf-8").splitlines()[0])
    payload = record.get("payload")
    assert isinstance(payload, dict)
    return payload


def _incident_error_diags(assessment: Any) -> list[dict[str, Any]]:
    return [
        e
        for e in assessment.structural_errors
        if e.get("severity") in {"error", "fatal"} and e.get("path") not in _PRE_EXISTING_SDK_ERROR_PATHS
    ]


# ---------------------------------------------------------------------------
# Inventory sanity.
# ---------------------------------------------------------------------------


def test_both_vectors_present() -> None:
    names = {str(v.get("name")) for v in _VECTORS}
    assert names == {"with-stix", "without-stix"}, f"unexpected STIX vector corpus: {sorted(names)!r}"


# ---------------------------------------------------------------------------
# Emit / omit gate on disk.
# ---------------------------------------------------------------------------


def test_with_stix_vector_emits_sorted_pattern_valid_member() -> None:
    vector = _vector("with-stix")
    stix = _card_payload(vector)["taxonomy_crosswalk"]["stix"]
    assert stix["edition"] == "2.1"
    refs = stix["object_refs"]

    # Every ref matches the STIX 2.1 id schema pattern.
    for ref in refs:
        assert _STIX_ID_PATTERN.match(ref), f"emitted object_ref {ref!r} is not a valid STIX 2.1 id"

    # The array equals the §5.10 sort of the UNIQUE supplied input, recomputed
    # INDEPENDENTLY here (RFC-8785 canonical byte order), proving de-dup + sort.
    supplied = _MANIFEST["stix_object_refs_input"]
    expected = sorted(set(supplied), key=utf16_collation_key)
    assert refs == expected, "on-disk object_refs[] is not the §5.10 canonical-byte sort of the deduped input"

    # The committed array is already in canonical order (sorting it is a no-op).
    assert refs == sorted(refs, key=utf16_collation_key)


def test_without_stix_vector_omits_member() -> None:
    vector = _vector("without-stix")
    crosswalk = _card_payload(vector)["taxonomy_crosswalk"]
    assert "stix" not in crosswalk, "the without-stix vector MUST omit the optional stix crosswalk member"


# ---------------------------------------------------------------------------
# Schema + production-validator conformance.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["with-stix", "without-stix"])
def test_vector_card_validates_against_v1_1_schema(name: str) -> None:
    payload = _card_payload(_vector(name))
    errors = validate_record_payload(payload, "incident_card", "v1.1")
    assert errors == [], f"{name} incident_card failed v1.1 schema validation: {errors}"


@pytest.mark.parametrize("name", ["with-stix", "without-stix"])
def test_vector_bundle_validates_clean(name: str) -> None:
    vector = _vector(name)
    assessment = validate_bundle(_bundle_dir(vector), profiles=["eu-ai-act-art73-2026"])
    errors = _incident_error_diags(assessment)
    assert errors == [], f"{name} bundle emitted unexpected ERROR/FATAL diagnostics: {errors}"


# ---------------------------------------------------------------------------
# Byte-stability across two validations (the vectors are static, deterministic).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["with-stix", "without-stix"])
def test_validation_is_byte_stable(name: str) -> None:
    vector = _vector(name)

    def _projection(assessment: Any) -> str:
        rows = sorted(
            (str(e.get("code")), str(e.get("severity")), str(e.get("message"))) for e in assessment.structural_errors
        )
        return json.dumps(rows, sort_keys=True, ensure_ascii=False)

    first = _projection(validate_bundle(_bundle_dir(vector), profiles=["eu-ai-act-art73-2026"]))
    second = _projection(validate_bundle(_bundle_dir(vector), profiles=["eu-ai-act-art73-2026"]))
    assert first == second, f"{name} validation is not byte-stable across two runs"
