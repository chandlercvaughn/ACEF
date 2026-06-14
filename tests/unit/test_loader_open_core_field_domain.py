"""Loader domain-guards for the open-core v1.1 manifest fields (X5/X6).

P1 stability-shakedown: ``acef.loader.load`` captured ``analysis_mode`` (X5) and
``namespaces`` (X6) VERBATIM with no type/domain guard, threading them into
``Package._init_from_parts`` and storing them on ``pkg._analysis_mode`` /
``pkg._namespaces`` — BYPASSING the validation the public builder setters
``set_analysis_mode`` / ``add_namespace`` perform.

``load()`` itself succeeded (lenient). The CRASH was on the SUPPORTED
load→export round-trip: ``build_manifest()`` constructs
``Manifest(analysis_mode=..., namespaces=...)`` whose model types are a closed
``Literal`` and ``dict[str, dict[str, Any]] | None``. A loaded value outside
those domains made ``Manifest(...)`` raise a RAW
``pydantic_core._pydantic_core.ValidationError`` that escaped UNCAUGHT from the
public ``export()`` / ``export_directory()`` / ``export_archive()`` —
e.g. for ``analysis_mode="bogus_mode"``::

    pydantic_core._pydantic_core.ValidationError: 1 validation error for Manifest
    analysis_mode
      Input should be 'subscriber', 'public_artifact', 'canary' or
      'unattributed_artifact' [type=literal_error, input_value='bogus_mode', ...]

This breaks the round-trip-lossless contract AND the "public surface raises
structured ACEF errors, never raw framework exceptions" invariant.

Fix (chosen layer: LOAD-time validation): the loader validates
``analysis_mode`` / ``namespaces`` with the SAME shared checks the builder
setters apply (``acef.package.validate_analysis_mode`` /
``validate_namespaces``), so ``load()`` reconstructs only VALID package state
and an out-of-domain value raises ``ACEFSchemaError`` (ACEF-002) at ``load()``
naming the offending field+value — never a raw pydantic error on export.

A VALID ``analysis_mode`` / ``namespaces`` value still round-trips
byte-identically (lossless preserved).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import acef
from acef.errors import ACEFSchemaError
from acef.package import Package

# ---------------------------------------------------------------------------
# Minimal self-consistent directory-bundle shape the loader reads.
# ---------------------------------------------------------------------------


def _record() -> dict:
    return {
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


def _manifest(**top_overrides: object) -> dict:
    base: dict = {
        "metadata": {
            "package_id": "urn:acef:pkg:11111111-1111-1111-1111-111111111111",
            "timestamp": "2026-01-01T00:00:00Z",
            "producer": {"name": "test-producer", "version": "1.0.0"},
        },
        # v1.1 core_version so analysis_mode/namespaces are admissible fields.
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


def _write_bundle(bundle: Path, manifest: dict) -> None:
    (bundle / "records").mkdir(parents=True, exist_ok=True)
    (bundle / "hashes").mkdir(parents=True, exist_ok=True)
    (bundle / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (bundle / "records" / "risk_register.jsonl").write_text(json.dumps(_record()) + "\n", encoding="utf-8")
    (bundle / "hashes" / "content-hashes.json").write_text("{}", encoding="utf-8")


# ---------------------------------------------------------------------------
# RED: out-of-domain analysis_mode on the load→export round-trip.
# ---------------------------------------------------------------------------


class TestLoadAnalysisModeDomain:
    def test_bad_string_analysis_mode_raises_structured_acef_002_at_load(self, tmp_path: Path) -> None:
        """A loaded analysis_mode outside the closed Literal domain raises a
        STRUCTURED ACEFSchemaError (ACEF-002) at load() — not a raw pydantic
        ValidationError later at export."""
        bundle = tmp_path / "b"
        _write_bundle(bundle, _manifest(analysis_mode="bogus_mode"))
        with pytest.raises(ACEFSchemaError) as exc:
            acef.load(str(bundle))
        assert exc.value.code == "ACEF-002"
        # The message names the offending field + value.
        assert "analysis_mode" in str(exc.value)
        assert "bogus_mode" in str(exc.value)

    def test_non_string_analysis_mode_raises_structured_acef_002_at_load(self, tmp_path: Path) -> None:
        """A non-string analysis_mode (e.g. the JSON integer 5) is rejected by
        the same membership test (no non-str literal in the domain)."""
        bundle = tmp_path / "b"
        _write_bundle(bundle, _manifest(analysis_mode=5))
        with pytest.raises(ACEFSchemaError) as exc:
            acef.load(str(bundle))
        assert exc.value.code == "ACEF-002"
        assert "analysis_mode" in str(exc.value)

    def test_bad_analysis_mode_never_surfaces_raw_pydantic_on_export(self, tmp_path: Path) -> None:
        """Defense in depth: even if a Package somehow carries an out-of-domain
        analysis_mode, the public export path must not leak a raw pydantic
        ValidationError. With load-time validation, load() rejects first; this
        asserts the public surface only ever raises ACEFSchemaError here."""
        bundle = tmp_path / "b"
        _write_bundle(bundle, _manifest(analysis_mode="bogus_mode"))
        # Confirm the failure is a structured ACEF error at the public load()
        # boundary, and NOT a raw pydantic error from a later export.
        with pytest.raises(ACEFSchemaError):
            pkg = acef.load(str(bundle))
            pkg.export(str(tmp_path / "out"))


# ---------------------------------------------------------------------------
# RED: out-of-domain namespaces on the load→export round-trip.
# ---------------------------------------------------------------------------


class TestLoadNamespacesDomain:
    def test_non_object_namespaces_raises_structured_acef_002_at_load(self, tmp_path: Path) -> None:
        """A non-object namespaces (the JSON string "oops") raises ACEF-002 at
        load() rather than a raw pydantic dict_type error at export."""
        bundle = tmp_path / "b"
        _write_bundle(bundle, _manifest(namespaces="oops"))
        with pytest.raises(ACEFSchemaError) as exc:
            acef.load(str(bundle))
        assert exc.value.code == "ACEF-002"
        assert "namespaces" in str(exc.value)

    def test_array_namespaces_raises_structured_acef_002_at_load(self, tmp_path: Path) -> None:
        """A JSON array namespaces is not an object → ACEF-002 at load()."""
        bundle = tmp_path / "b"
        _write_bundle(bundle, _manifest(namespaces=["x-vendor"]))
        with pytest.raises(ACEFSchemaError) as exc:
            acef.load(str(bundle))
        assert exc.value.code == "ACEF-002"
        assert "namespaces" in str(exc.value)

    def test_wrong_shape_namespaces_value_raises_structured_acef_002_at_load(self, tmp_path: Path) -> None:
        """A namespaces entry whose VALUE is not an object (schema pins each
        value to type:object) raises ACEF-002 at load()."""
        bundle = tmp_path / "b"
        _write_bundle(bundle, _manifest(namespaces={"x-vendor": "notobj"}))
        with pytest.raises(ACEFSchemaError) as exc:
            acef.load(str(bundle))
        assert exc.value.code == "ACEF-002"
        assert "x-vendor" in str(exc.value)

    def test_lenient_non_strict_namespaces_key_loads_and_round_trips(self, tmp_path: Path) -> None:
        """The loader is a documented LENIENT deserializer for namespaces KEYS:
        a non-strict key (``x-test/extension``, which the strict x-vendor
        pattern rejects) does NOT cause the raw-Pydantic crash (the Manifest
        model does not enforce the key pattern), so the loader preserves it for
        round-trip rather than over-rejecting. This proves the load-time guard
        enforces ONLY the structural dict-container/dict-value domain that
        actually crashes export — matching the existing lenient-deserializer
        contract (test_loader_adversarial_manifest)."""
        bundle = tmp_path / "b"
        _write_bundle(bundle, _manifest(namespaces={"x-test/extension": {"foo": "bar"}}))
        pkg = acef.load(str(bundle))
        assert pkg._namespaces == {"x-test/extension": {"foo": "bar"}}
        out = tmp_path / "out"
        pkg.export(str(out))
        reparsed = json.loads((out / "acef-manifest.json").read_text(encoding="utf-8"))
        assert reparsed["namespaces"] == {"x-test/extension": {"foo": "bar"}}


# ---------------------------------------------------------------------------
# GREEN guard: VALID values still round-trip byte-identically (lossless).
# ---------------------------------------------------------------------------


class TestValidOpenCoreFieldsRoundTripByteIdentical:
    def test_valid_analysis_mode_and_namespaces_round_trip_is_byte_identical(self, tmp_path: Path) -> None:
        """A VALID analysis_mode + namespaces survives load→export unchanged and
        the re-exported manifest bytes are byte-identical to a second export of
        the re-loaded package (determinism + lossless preserved)."""
        src = tmp_path / "src"
        _write_bundle(
            src,
            _manifest(
                analysis_mode="public_artifact",
                namespaces={"x-vendor": {"k": "v"}, "x-vendor-ns": {"a": 1}},
            ),
        )

        pkg = acef.load(str(src))
        assert pkg._analysis_mode == "public_artifact"
        assert pkg._namespaces == {"x-vendor": {"k": "v"}, "x-vendor-ns": {"a": 1}}

        out1 = tmp_path / "out1"
        pkg.export(str(out1))
        manifest1 = (out1 / "acef-manifest.json").read_bytes()

        # Re-load the exported bundle and export again: byte-identical manifest.
        pkg2 = acef.load(str(out1))
        out2 = tmp_path / "out2"
        pkg2.export(str(out2))
        manifest2 = (out2 / "acef-manifest.json").read_bytes()

        assert manifest1 == manifest2

        # The open-core fields survived the round-trip with correct values.
        reparsed = json.loads(manifest1.decode("utf-8"))
        assert reparsed["analysis_mode"] == "public_artifact"
        assert reparsed["namespaces"] == {"x-vendor": {"k": "v"}, "x-vendor-ns": {"a": 1}}

    def test_absent_open_core_fields_round_trip_unchanged(self, tmp_path: Path) -> None:
        """A v1.0-shaped bundle with neither field loads and re-exports without
        emitting analysis_mode/namespaces (no regression for legacy bundles)."""
        src = tmp_path / "src"
        manifest = _manifest()
        manifest["versioning"]["core_version"] = "1.0.0"
        _write_bundle(src, manifest)

        pkg = acef.load(str(src))
        assert pkg._analysis_mode is None
        assert pkg._namespaces is None

        out = tmp_path / "out"
        pkg.export(str(out))
        reparsed = json.loads((out / "acef-manifest.json").read_text(encoding="utf-8"))
        assert "analysis_mode" not in reparsed
        assert "namespaces" not in reparsed


# ---------------------------------------------------------------------------
# Shared-validation reuse: the loader uses the SAME helpers as the setters.
# ---------------------------------------------------------------------------


class TestSharedValidationReuse:
    def test_setter_and_loader_reject_identically(self) -> None:
        """The builder setter rejects the same out-of-domain analysis_mode the
        loader rejects (single source of truth)."""
        pkg = Package()
        with pytest.raises(ACEFSchemaError) as setter_exc:
            pkg.set_analysis_mode("bogus_mode")
        assert setter_exc.value.code == "ACEF-002"

    def test_setter_rejects_non_object_namespace_value(self) -> None:
        pkg = Package()
        with pytest.raises(ACEFSchemaError) as setter_exc:
            pkg.add_namespace("x-vendor", "notobj")  # type: ignore[arg-type]
        assert setter_exc.value.code == "ACEF-002"

    def test_setter_rejects_non_x_vendor_key(self) -> None:
        pkg = Package()
        with pytest.raises(ACEFSchemaError) as setter_exc:
            pkg.add_namespace("vendor", {"k": "v"})
        assert setter_exc.value.code == "ACEF-002"


class TestUnhashableAnalysisModeFailsClosed:
    """roborev follow-up on the P1 fix: ``validate_analysis_mode`` used set
    membership (``mode not in _ANALYSIS_MODES``) on an arbitrary object, so an
    unhashable JSON value (``[]`` / ``{}``) raised a raw ``TypeError:
    unhashable type`` BEFORE the structured ``ACEFSchemaError`` — leaking an
    unstructured exception for a malformed manifest. The type-check-first guard
    rejects every non-string value with a clean ACEF-002."""

    @pytest.mark.parametrize("bad", [[], {}, [1, 2], {"k": "v"}, 5, 1.5, True, None])
    def test_validate_analysis_mode_rejects_non_string_without_raising_typeerror(self, bad: object) -> None:
        from acef.package import validate_analysis_mode

        with pytest.raises(ACEFSchemaError) as exc:
            validate_analysis_mode(bad)
        assert exc.value.code == "ACEF-002"

    @pytest.mark.parametrize("bad", [[], {}, [1, 2]])
    def test_load_unhashable_analysis_mode_raises_structured_not_typeerror(self, bad: object, tmp_path: Path) -> None:
        """The same fail-closed behavior end-to-end through ``acef.load`` (the
        loader applies the shared validator), so an unhashable ``analysis_mode``
        in the manifest surfaces ACEF-002, never a raw ``TypeError``."""
        bundle = tmp_path / "b"
        _write_bundle(bundle, _manifest(analysis_mode=bad))
        with pytest.raises(ACEFSchemaError) as exc:
            acef.load(str(bundle))
        assert exc.value.code == "ACEF-002"
