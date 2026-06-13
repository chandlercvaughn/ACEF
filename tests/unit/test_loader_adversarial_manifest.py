"""Adversarial / malformed-manifest robustness for ``acef.load()`` (F-M4-LOADER-ROBUST).

``acef.load()`` is a documented public deserialization API
(``acef.__init__`` exports it in ``__all__``). Before F-M4-LOADER-ROBUST the
``_load_directory`` body consumed every manifest section
(``metadata_raw.get(...)``, ``ProducerInfo(**producer_raw)``,
``Versioning(**versioning_raw)``, ``entities_raw.get(...)``,
``ProfileEntry(**prof_data)``, ``AuditTrailEntry(**at_data)``,
``subjects``/``lifecycle_timeline`` iteration) WITHOUT type-guarding the
untrusted manifest. A hostile or merely malformed manifest therefore escaped
as a RAW Python ``AttributeError`` / ``TypeError`` / Pydantic
``ValidationError`` rather than a structured ACEF diagnostic — finding
``loader-roundtrip-8`` (low/security): the bundle fails CLOSED (load never
succeeds) but the error surface is unstructured, so a caller cannot map the
failure to the ACEF taxonomy.

The fix (approach (b) — per-section ``isinstance`` guards + wrapped model
construction) is chosen over approach (a) (full manifest-schema validation at
load time) because the loader is a LENIENT deserializer: it intentionally
loads bundles the strict conformance schema rejects (empty ``subjects`` =
``minItems:1`` violation, non-strict ``namespaces`` keys, ...). The
conformance gate is ``acef.validation.engine.validate_bundle``, NOT
``load``. Imposing full schema conformance at load time would over-reject and
break the documented round-trip contract. So we structure-guard exactly the
sections ``_load_directory`` consumes and re-raise model failures as
``ACEFSchemaError`` (ACEF-002) / ``ACEFFormatError`` (ACEF-050).

Every test here:
  1. builds a malformed manifest in a tmp bundle directory, and
  2. asserts ``acef.load()`` raises a structured ``acef.errors.ACEFError`` with
     code ACEF-002 or ACEF-050 (never a raw ``AttributeError`` / ``TypeError``
     / ``ValidationError``), and that the message names the offending section.

A final positive test pins that a VALID bundle still loads and round-trips
byte-identically (no over-rejection).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import acef
from acef.errors import ACEFError, ACEFFormatError, ACEFSchemaError


def _write_manifest(bundle: Path, manifest: dict) -> None:
    """Write only ``acef-manifest.json`` into ``bundle`` (created if absent)."""
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def _valid_manifest(**top_overrides: object) -> dict:
    """A minimal, well-formed manifest the loader accepts."""
    base: dict = {
        "metadata": {
            "package_id": "urn:acef:pkg:11111111-1111-1111-1111-111111111111",
            "timestamp": "2026-01-01T00:00:00Z",
            "producer": {"name": "test-producer", "version": "1.0.0"},
        },
        "versioning": {"core_version": "1.0.0", "profiles_version": "1.0.0"},
        "subjects": [],
        "entities": {
            "components": [],
            "datasets": [],
            "actors": [],
            "relationships": [],
        },
        "profiles": [],
        "record_files": [],
        "audit_trail": [],
    }
    base.update(top_overrides)
    return base


# ---------------------------------------------------------------------------
# RED: each malformed section must surface as a STRUCTURED ACEF error.
# ---------------------------------------------------------------------------


def test_metadata_is_a_list_raises_structured_error(tmp_path: Path) -> None:
    """``metadata`` as a list (not object) must raise ACEF-002, not a raw
    ``AttributeError: 'list' object has no attribute 'get'``."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest()
    manifest["metadata"] = []
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "metadata" in exc.value.message


def test_producer_not_a_dict_raises_structured_error(tmp_path: Path) -> None:
    """``metadata.producer`` as a string must raise ACEF-002, not a raw
    ``TypeError`` / ``AttributeError``."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest()
    manifest["metadata"]["producer"] = "acme-corp"
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "producer" in exc.value.message


def test_producer_missing_required_fields_raises_structured_error(tmp_path: Path) -> None:
    """``producer`` = ``{}`` (missing required name/version) must raise
    ACEF-002 — wrapping Pydantic's ``ValidationError`` rather than leaking it."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest()
    manifest["metadata"]["producer"] = {}
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "producer" in exc.value.message


def test_retention_policy_not_a_dict_raises_structured_error(tmp_path: Path) -> None:
    """A non-object ``metadata.retention_policy`` must raise ACEF-002."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest()
    manifest["metadata"]["retention_policy"] = "forever"
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "retention_policy" in exc.value.message


def test_versioning_is_a_string_raises_structured_error(tmp_path: Path) -> None:
    """``versioning`` as a string must raise ACEF-002, not a raw
    ``TypeError: argument after ** must be a mapping, not str``."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(versioning="v1")
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "versioning" in exc.value.message


def test_subjects_is_a_dict_raises_structured_error(tmp_path: Path) -> None:
    """``subjects`` as a dict (not array) must raise ACEF-002, not a raw
    iteration ``AttributeError``."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(subjects={"a": 1})
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "subjects" in exc.value.message


def test_subject_entry_not_a_dict_raises_structured_error(tmp_path: Path) -> None:
    """A non-object entry inside ``subjects`` must raise ACEF-002."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(subjects=["not-an-object"])
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "subjects" in exc.value.message


def test_lifecycle_timeline_non_list_raises_structured_error(tmp_path: Path) -> None:
    """A non-array ``subjects[].lifecycle_timeline`` must raise ACEF-002, not a
    raw ``TypeError`` from ``LifecycleEntry(**e)`` iterating a string."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(
        subjects=[
            {
                "subject_id": "urn:acef:sub:1",
                "lifecycle_timeline": "not-a-list",
            }
        ]
    )
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "lifecycle_timeline" in exc.value.message


def test_entities_is_an_int_raises_structured_error(tmp_path: Path) -> None:
    """``entities`` as an int (not object) must raise ACEF-002, not a raw
    ``AttributeError: 'int' object has no attribute 'get'``."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(entities=5)
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "entities" in exc.value.message


def test_entities_components_non_list_raises_structured_error(tmp_path: Path) -> None:
    """A non-array ``entities.components`` must raise ACEF-002."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(entities={"components": "x", "datasets": [], "actors": [], "relationships": []})
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "components" in exc.value.message


def test_component_entry_not_a_dict_raises_structured_error(tmp_path: Path) -> None:
    """A non-object entry inside ``entities.components`` must raise ACEF-002."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(entities={"components": ["x"], "datasets": [], "actors": [], "relationships": []})
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "components" in exc.value.message


def test_profiles_is_a_string_raises_structured_error(tmp_path: Path) -> None:
    """``profiles`` as a string must raise ACEF-002, not a raw iteration error."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(profiles="eu-ai-act")
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "profiles" in exc.value.message


def test_profile_entry_not_a_dict_raises_structured_error(tmp_path: Path) -> None:
    """A non-object entry inside ``profiles`` must raise ACEF-002, not a raw
    ``TypeError`` from ``ProfileEntry(**prof_data)``."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(profiles=["eu-ai-act"])
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "profiles" in exc.value.message


def test_profile_entry_missing_required_fields_raises_structured_error(tmp_path: Path) -> None:
    """A ``profiles`` entry missing the required ``profile_id`` must raise
    ACEF-002 — wrapping Pydantic's ``ValidationError`` rather than leaking it.

    (``template_version`` / ``applicable_provisions`` carry model defaults, so
    an entry that omits THEM is a valid ``ProfileEntry``; the schema's stricter
    ``minItems:1`` on ``applicable_provisions`` is the conformance validator's
    job, not the lenient loader's. Only the genuinely model-required
    ``profile_id`` triggers a construction failure here.)"""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(profiles=[{"template_version": "1.0.0"}])
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "profiles" in exc.value.message


def test_audit_trail_is_a_string_raises_structured_error(tmp_path: Path) -> None:
    """``audit_trail`` as a string must raise ACEF-002, not a raw iteration error."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(audit_trail="created")
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "audit_trail" in exc.value.message


def test_audit_trail_entry_not_a_dict_raises_structured_error(tmp_path: Path) -> None:
    """A non-object entry inside ``audit_trail`` must raise ACEF-002, not a raw
    ``TypeError`` from ``AuditTrailEntry(**at_data)``."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(audit_trail=["created"])
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFSchemaError)
    assert exc.value.code == "ACEF-002"
    assert "audit_trail" in exc.value.message


def test_record_files_non_list_raises_structured_error(tmp_path: Path) -> None:
    """``record_files`` as a string must raise a structured ACEF error, not a
    raw iteration ``AttributeError``."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(record_files="records/foo.jsonl")
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    # record_files structural issues belong to the ACEF-050/ACEF-002 surface;
    # either structured code is acceptable, but never a raw exception.
    assert isinstance(exc.value, ACEFError)
    assert exc.value.code in {"ACEF-002", "ACEF-050"}
    assert "record_files" in exc.value.message


def test_record_files_entry_not_a_dict_raises_structured_error(tmp_path: Path) -> None:
    """A non-object entry inside ``record_files`` must raise a structured error,
    not a raw ``AttributeError`` from ``rf_entry.get('path')``."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(record_files=["records/foo.jsonl"])
    _write_manifest(bundle, manifest)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFError)
    assert exc.value.code in {"ACEF-002", "ACEF-050"}
    assert "record_files" in exc.value.message


def test_manifest_top_level_is_a_list_raises_structured_error(tmp_path: Path) -> None:
    """A manifest whose TOP-LEVEL JSON is an array (not object) must raise a
    structured ACEF error, not a raw ``AttributeError`` from ``.get(...)``."""
    bundle = tmp_path / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "acef-manifest.json").write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, (ACEFSchemaError, ACEFFormatError))
    assert exc.value.code in {"ACEF-002", "ACEF-050"}


def test_no_raw_exception_leaks_across_malformed_sections(tmp_path: Path) -> None:
    """Defense-in-depth sweep: a battery of malformed manifests must each
    surface a structured ``ACEFError`` — never a raw ``AttributeError`` /
    ``TypeError`` / Pydantic ``ValidationError``."""
    malformed_overrides: list[dict] = [
        {"metadata": []},
        {"metadata": "x"},
        {"versioning": 7},
        {"subjects": {"k": "v"}},
        {"entities": "x"},
        {"profiles": 3},
        {"audit_trail": {"k": "v"}},
        {"record_files": 9},
    ]
    for i, override in enumerate(malformed_overrides):
        bundle = tmp_path / f"bundle-{i}"
        _write_manifest(bundle, _valid_manifest(**override))
        with pytest.raises(ACEFError):
            acef.load(str(bundle))


# ---------------------------------------------------------------------------
# GREEN guard: a VALID bundle must still load AND round-trip byte-identically.
# ---------------------------------------------------------------------------


def test_valid_bundle_still_loads(tmp_path: Path) -> None:
    """A well-formed manifest still loads cleanly — no over-rejection."""
    bundle = tmp_path / "bundle"
    _write_manifest(bundle, _valid_manifest())

    pkg = acef.load(str(bundle))
    assert pkg.metadata.package_id == "urn:acef:pkg:11111111-1111-1111-1111-111111111111"
    assert pkg.metadata.producer.name == "test-producer"


def test_valid_lenient_bundle_with_extensions_still_loads(tmp_path: Path) -> None:
    """The loader must remain a LENIENT deserializer: a bundle the strict
    conformance schema rejects (empty ``subjects`` = minItems:1, non-strict
    ``namespaces`` keys) must STILL load and preserve its extensions — proving
    the fix uses approach (b) (structural type-guards) not approach (a)
    (full-schema validation, which would over-reject these)."""
    bundle = tmp_path / "bundle"
    manifest = _valid_manifest(
        analysis_mode="subscriber",
        namespaces={"x-test/extension": {"foo": "bar"}},
        **{"x-vendor-top/meta": {"k": "v"}},
    )
    manifest["versioning"]["core_version"] = "1.1.0"
    _write_manifest(bundle, manifest)

    pkg = acef.load(str(bundle))
    out = pkg.build_manifest().to_dict()
    assert out["analysis_mode"] == "subscriber"
    assert out["namespaces"] == {"x-test/extension": {"foo": "bar"}}
    assert out["x-vendor-top/meta"] == {"k": "v"}


def test_valid_bundle_round_trips_byte_identically(tmp_path: Path) -> None:
    """Create → export → load → re-export produces bit-identical
    content-hashes.json — the fix must not perturb the lossless round-trip."""
    src = tmp_path / "src"
    _write_manifest(src, _valid_manifest())

    pkg1 = acef.load(str(src))
    export1 = tmp_path / "export1"
    pkg1.export(str(export1))
    hashes1 = (export1 / "hashes" / "content-hashes.json").read_bytes()

    pkg2 = acef.load(str(export1))
    export2 = tmp_path / "export2"
    pkg2.export(str(export2))
    hashes2 = (export2 / "hashes" / "content-hashes.json").read_bytes()

    assert hashes1 == hashes2
