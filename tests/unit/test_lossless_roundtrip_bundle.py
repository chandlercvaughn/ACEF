"""Bundle-level lossless round-trip tests (F-M4-LOSSLESS).

These tests exercise the REAL loader/exporter path — ``acef.load()`` then
``Package.build_manifest()`` / ``RecordEnvelope.to_jsonl_dict()`` — rather
than the pure-model layer that ``tests/unit/test_v1_1_model_roundtrip.py``
covers. The model layer preserves the v1.1 manifest fields (the Manifest
model declares ``analysis_mode``/``namespaces`` and inherits
``extra='allow'``), so a model-only test passes GREEN while the loader/
exporter silently drops them (audit findings loader-roundtrip-1/2/3,
envelope-manifest-2, records-payloads-1).

Spec §6.4 rule 5: "ACEF Evidence Bundle export MUST be lossless to the open
core, even if a commercial product adds extra metadata in vendor-namespaced
extensions." §6.5: "Round-trip | Create → export → load → re-export produces
bit-identical content-hashes.json" and "Vendor-namespaced extensions are
preserved on round-trip".
"""

from __future__ import annotations

import json
from pathlib import Path

import acef


def _write_bundle(
    bundle: Path,
    *,
    manifest: dict,
    record: dict,
) -> None:
    """Write a minimal directory bundle to ``bundle`` from raw dicts.

    Only the pieces the loader reads are written (manifest + one JSONL
    record + an empty content-hashes.json so the artifacts dir is sane).
    """
    (bundle / "records").mkdir(parents=True, exist_ok=True)
    (bundle / "hashes").mkdir(parents=True, exist_ok=True)
    (bundle / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (bundle / "records" / "risk_register.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    (bundle / "hashes" / "content-hashes.json").write_text("{}", encoding="utf-8")


def _manifest(**top_overrides) -> dict:
    base = {
        "metadata": {
            "package_id": "urn:acef:pkg:11111111-1111-1111-1111-111111111111",
            "timestamp": "2026-01-01T00:00:00Z",
            "producer": {"name": "test-producer", "version": "1.0.0"},
        },
        "versioning": {"core_version": "1.1.0", "profiles_version": "1.0.0"},
        "subjects": [],
        "entities": {
            "components": [],
            "datasets": [],
            "actors": [],
            "relationships": [],
        },
        "profiles": [],
        "record_files": [
            {
                "path": "records/risk_register.jsonl",
                "record_type": "risk_register",
                "count": 1,
            }
        ],
        "audit_trail": [],
    }
    base.update(top_overrides)
    return base


def _record(**overrides) -> dict:
    base = {
        "record_id": "urn:acef:rec:11111111-1111-1111-1111-111111111111",
        "record_type": "risk_register",
        "timestamp": "2026-01-01T00:00:00Z",
        "lifecycle_phase": "development",
        "collector": {"name": "test-tool", "version": "1.0.0"},
        "obligation_role": "provider",
        "confidentiality": "public",
        "trust_level": "self-attested",
        "entity_refs": {
            "subject_refs": [],
            "component_refs": [],
            "dataset_refs": [],
            "actor_refs": [],
        },
        "payload": {},
    }
    base.update(overrides)
    return base


# ----- VAL-FIX-LOADER-001 (HIGH) — top-level analysis_mode (X5) -----


def test_analysis_mode_survives_bundle_roundtrip(tmp_path: Path) -> None:
    """X5 (analysis_mode) survives acef.load() → build_manifest()."""
    bundle = tmp_path / "bundle"
    _write_bundle(
        bundle,
        manifest=_manifest(analysis_mode="subscriber"),
        record=_record(),
    )

    pkg = acef.load(str(bundle))
    out = pkg.build_manifest().to_dict()

    assert out["analysis_mode"] == "subscriber"


# ----- VAL-FIX-LOADER-001 (HIGH) — top-level namespaces (X6) -----


def test_namespaces_survives_bundle_roundtrip(tmp_path: Path) -> None:
    """X6 (namespaces) survives acef.load() → build_manifest()."""
    namespaces = {"x-test/extension": {"foo": "bar", "nested": {"k": [1, 2]}}}
    bundle = tmp_path / "bundle"
    _write_bundle(
        bundle,
        manifest=_manifest(namespaces=namespaces),
        record=_record(),
    )

    pkg = acef.load(str(bundle))
    out = pkg.build_manifest().to_dict()

    assert out["namespaces"] == namespaces


# ----- VAL-FIX-ENVELOPE-002 — top-level vendor x-* extension -----


def test_top_level_vendor_extension_survives_bundle_roundtrip(tmp_path: Path) -> None:
    """A manifest-root x-* vendor key survives acef.load() → build_manifest()."""
    bundle = tmp_path / "bundle"
    _write_bundle(
        bundle,
        manifest=_manifest(**{"x-vendor-top/meta": {"k": "v", "n": 42}}),
        record=_record(),
    )

    pkg = acef.load(str(bundle))
    out = pkg.build_manifest().to_dict()

    assert out["x-vendor-top/meta"] == {"k": "v", "n": 42}


def test_entities_block_vendor_extension_survives_bundle_roundtrip(tmp_path: Path) -> None:
    """F18: an entities-CONTAINER x-* vendor key survives acef.load() → build_manifest().

    The four child entity types (Component/Dataset/Actor/Relationship) already thread their
    extras, but the loader built ``EntitiesBlock()`` fresh WITHOUT the container-level extras,
    so an ``entities.x-vendor/*`` key was silently DROPPED (§6.4 open-boundary lossless
    violation)."""
    bundle = tmp_path / "bundle"
    manifest = _manifest()
    manifest["entities"]["x-vendor/entities-meta"] = {"custom_field": "should_survive", "data": {"nested": "value"}}
    _write_bundle(bundle, manifest=manifest, record=_record())

    pkg = acef.load(str(bundle))
    out = pkg.build_manifest().to_dict()

    assert out["entities"]["x-vendor/entities-meta"] == {"custom_field": "should_survive", "data": {"nested": "value"}}


# ----- VAL-FIX-LOADER-002 — metadata-object vendor x-* + created_at -----


def test_metadata_vendor_extension_survives_bundle_roundtrip(tmp_path: Path) -> None:
    """A metadata-object x-* vendor key + created_at survive round-trip."""
    bundle = tmp_path / "bundle"
    manifest = _manifest()
    manifest["metadata"]["x-vendor/meta"] = {"team": "compliance"}
    manifest["metadata"]["created_at"] = "2025-12-31T23:59:59Z"
    _write_bundle(bundle, manifest=manifest, record=_record())

    pkg = acef.load(str(bundle))
    out = pkg.build_manifest().to_dict()

    assert out["metadata"]["x-vendor/meta"] == {"team": "compliance"}
    assert out["metadata"]["created_at"] == "2025-12-31T23:59:59Z"


# ----- VAL-FIX-RECORDS-001 — string-form collector -----


def test_string_collector_survives_bundle_roundtrip(tmp_path: Path) -> None:
    """A string-form collector re-exports as a bare string (not an object)."""
    bundle = tmp_path / "bundle"
    _write_bundle(
        bundle,
        manifest=_manifest(),
        record=_record(collector="alice@example.com"),
    )

    pkg = acef.load(str(bundle))
    emitted = pkg.records[0].to_jsonl_dict()

    assert emitted["collector"] == "alice@example.com"


def test_object_collector_still_round_trips(tmp_path: Path) -> None:
    """The object-form collector must continue to round-trip as an object."""
    bundle = tmp_path / "bundle"
    _write_bundle(
        bundle,
        manifest=_manifest(),
        record=_record(collector={"name": "test-tool", "version": "2.0.0"}),
    )

    pkg = acef.load(str(bundle))
    emitted = pkg.records[0].to_jsonl_dict()

    assert emitted["collector"] == {"name": "test-tool", "version": "2.0.0"}


# ----- VAL-FIX-LOADER-003 — combined bit-identical content-hashes.json -----


def test_full_export_load_reexport_bit_identical_content_hashes(tmp_path: Path) -> None:
    """Create → export → load → re-export produces bit-identical hashes.

    This is the canonical §6.5 round-trip MUST exercised with all of:
    analysis_mode (X5), namespaces (X6), top-level x-*, metadata x-*, and a
    string-form collector record. The gold standard is that the re-export's
    content-hashes.json equals the original's byte-for-byte.
    """
    src = tmp_path / "src"
    manifest = _manifest(
        analysis_mode="subscriber",
        namespaces={"x-test/extension": {"foo": "bar"}},
        **{"x-vendor-top/meta": {"k": "v"}},
    )
    manifest["metadata"]["x-vendor/meta"] = {"team": "compliance"}
    manifest["metadata"]["created_at"] = "2025-12-31T23:59:59Z"
    _write_bundle(src, manifest=manifest, record=_record(collector="alice@example.com"))

    # First real export (canonical bytes) from the loaded package.
    pkg1 = acef.load(str(src))
    export1 = tmp_path / "export1"
    pkg1.export(str(export1))
    hashes1 = (export1 / "hashes" / "content-hashes.json").read_bytes()

    # Round-trip: load the exported bundle and re-export.
    pkg2 = acef.load(str(export1))
    export2 = tmp_path / "export2"
    pkg2.export(str(export2))
    hashes2 = (export2 / "hashes" / "content-hashes.json").read_bytes()

    # The canonical content-hashes.json must be bit-identical across the
    # export → load → re-export cycle. If any X5/X6/x-*/collector field were
    # dropped or reshaped, the manifest/record bytes would diverge and these
    # would differ.
    assert hashes1 == hashes2

    # And the preserved fields are actually present in the re-exported manifest.
    manifest2 = json.loads((export2 / "acef-manifest.json").read_text(encoding="utf-8"))
    assert manifest2["analysis_mode"] == "subscriber"
    assert manifest2["namespaces"] == {"x-test/extension": {"foo": "bar"}}
    assert manifest2["x-vendor-top/meta"] == {"k": "v"}
    assert manifest2["metadata"]["x-vendor/meta"] == {"team": "compliance"}
    assert manifest2["metadata"]["created_at"] == "2025-12-31T23:59:59Z"
