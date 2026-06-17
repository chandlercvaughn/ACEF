"""Envelope / manifest builder + loader hygiene fixes (F-M7-ENVELOPE).

Covers audit findings envelope-manifest-3/4/5/6/7:

* ENVELOPE-003 — ``add_profile`` must reject empty/None ``provisions`` so the
  builder cannot emit a manifest the frozen schema rejects (minItems:1).
* ENVELOPE-004 — ``validate_urn`` must match the frozen schema's lowercase-only
  hex domain (covered in ``test_urns.py``; a schema-agreement guard lives here).
* ENVELOPE-005 — for the role-split record types
  ``{transparency_marking, disclosure_labeling, event_log}`` an explicit
  ``obligation_role`` is REQUIRED (spec §3.1 line 419); the SDK must not invent
  ``provider``.
* ENVELOPE-006 — the Package builder must expose setters so the standard builder
  path can AUTHOR a v1.1 manifest declaring ``analysis_mode`` (X5) / ``namespaces``
  (X6); F-M4-LOSSLESS already threads them through ``build_manifest`` on the
  round-trip path.
* ENVELOPE-007 — the loader must construct ``PackageMetadata`` WITH the inbound
  ``package_id``/``timestamp`` directly and surface ACEF-002 when either is
  absent, rather than silently minting a fresh random URN / wall-clock value via
  the model default factory.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import acef
from acef.errors import ACEFSchemaError
from acef.models.enums import ObligationRole
from acef.models.urns import validate_urn
from acef.package import Package
from acef.schemas.registry import validate_manifest

# ---------------------------------------------------------------------------
# Shared helpers (mirror the minimal directory-bundle shape the loader reads).
# ---------------------------------------------------------------------------


def _manifest(**top_overrides: object) -> dict:
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


def _record(**overrides: object) -> dict:
    base: dict = {
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


def _write_bundle(bundle: Path, *, manifest: dict, record: dict) -> None:
    (bundle / "records").mkdir(parents=True, exist_ok=True)
    (bundle / "hashes").mkdir(parents=True, exist_ok=True)
    (bundle / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (bundle / "records" / "risk_register.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    (bundle / "hashes" / "content-hashes.json").write_text("{}", encoding="utf-8")


# ---------------------------------------------------------------------------
# ENVELOPE-003 — add_profile must reject empty applicable_provisions.
# ---------------------------------------------------------------------------


class TestAddProfileRequiresProvisions:
    def test_add_profile_omitted_provisions_is_required_kwarg(self) -> None:
        """provisions is a REQUIRED keyword — omitting it entirely is a
        TypeError at the call boundary (the parameter has no default)."""
        pkg = Package()
        with pytest.raises(TypeError, match="provisions"):
            pkg.add_profile("eu-ai-act")  # type: ignore[call-arg]

    def test_add_profile_with_none_raises_acef_002(self) -> None:
        """An explicit provisions=None must raise ACEFSchemaError, not silently
        produce an empty applicable_provisions. None is not a concrete ordered
        sequence, so it is caught by the type gate (roborev: provisions must be
        a list/tuple, checked before any iteration)."""
        pkg = Package()
        with pytest.raises(ACEFSchemaError, match="must be a list or tuple"):
            pkg.add_profile("eu-ai-act", provisions=None)  # type: ignore[arg-type]
        # The error is still ACEF-002 (the documented schema-invalid-input code).
        with pytest.raises(ACEFSchemaError) as exc:
            pkg.add_profile("eu-ai-act", provisions=None)  # type: ignore[arg-type]
        assert exc.value.code == "ACEF-002"

    def test_add_profile_with_empty_list_raises(self) -> None:
        pkg = Package()
        with pytest.raises(ACEFSchemaError, match="applicable_provisions"):
            pkg.add_profile("eu-ai-act", provisions=[])

    def test_add_profile_error_code_is_acef_002(self) -> None:
        pkg = Package()
        with pytest.raises(ACEFSchemaError) as exc:
            pkg.add_profile("eu-ai-act", provisions=[])
        assert exc.value.code == "ACEF-002"

    def test_add_profile_with_provisions_succeeds(self) -> None:
        pkg = Package()
        entry = pkg.add_profile("eu-ai-act", provisions=["article-9"])
        assert entry.applicable_provisions == ["article-9"]

    def test_built_manifest_with_profile_passes_frozen_schema(self) -> None:
        """A manifest built via add_profile must pass the frozen v1 schema.

        Before the fix, an empty-provisions profile failed
        validate_manifest with '[] should be non-empty' at
        profiles[0].applicable_provisions (ACEF-002).
        """
        pkg = Package()
        pkg.add_subject("ai_system", name="System")
        pkg.add_profile("eu-ai-act", provisions=["article-9"])
        pkg.record("risk_register", payload={"description": "r"})
        manifest = pkg.build_manifest().to_dict()
        errors = validate_manifest(manifest, "v1")
        provision_errors = [e for e in errors if "applicable_provisions" in list(e.absolute_path)]
        assert provision_errors == []


# ---------------------------------------------------------------------------
# ENVELOPE-004 — validate_urn agrees with the frozen lowercase-only schema.
# ---------------------------------------------------------------------------


class TestUrnSchemaAgreement:
    def test_uppercase_hex_urn_rejected_by_validate_urn(self) -> None:
        """Uppercase-hex URNs are rejected by the frozen schema, so the model
        validator MUST reject them too (model/schema agreement)."""
        upper = "urn:acef:pkg:550E8400-E29B-41D4-A716-446655440000"
        assert validate_urn(upper) is False

    def test_lowercase_hex_urn_accepted_by_both_layers(self) -> None:
        lower = "urn:acef:pkg:550e8400-e29b-41d4-a716-446655440000"
        assert validate_urn(lower) is True
        manifest = _manifest()
        manifest["metadata"]["package_id"] = lower
        errors = validate_manifest(manifest, "v1")
        pkg_errors = [e for e in errors if list(e.absolute_path) == ["metadata", "package_id"]]
        assert pkg_errors == []

    def test_uppercase_package_id_rejected_by_schema(self) -> None:
        """The schema rejects an uppercase package_id — proving the prior
        validate_urn(upper)=True was a model/schema disagreement."""
        manifest = _manifest()
        manifest["metadata"]["package_id"] = "urn:acef:pkg:550E8400-E29B-41D4-A716-446655440000"
        errors = validate_manifest(manifest, "v1")
        pkg_errors = [e for e in errors if list(e.absolute_path) == ["metadata", "package_id"]]
        assert len(pkg_errors) == 1


# ---------------------------------------------------------------------------
# ENVELOPE-005 — explicit obligation_role for role-split record types.
# ---------------------------------------------------------------------------

ROLE_SPLIT_TYPES = ("transparency_marking", "disclosure_labeling", "event_log")


class TestObligationRoleRoleSplit:
    @pytest.mark.parametrize("record_type", ROLE_SPLIT_TYPES)
    def test_role_split_type_requires_explicit_role(self, record_type: str) -> None:
        """Omitting obligation_role on a role-split type must raise — the SDK
        must not silently invent 'provider' (spec §3.1 line 419)."""
        pkg = Package()
        with pytest.raises(ACEFSchemaError, match="obligation_role"):
            pkg.record(record_type, payload={"k": "v"})

    @pytest.mark.parametrize("record_type", ROLE_SPLIT_TYPES)
    def test_role_split_type_with_explicit_role_succeeds(self, record_type: str) -> None:
        pkg = Package()
        rec = pkg.record(record_type, payload={"k": "v"}, obligation_role="deployer")
        assert rec.obligation_role == ObligationRole.DEPLOYER

    @pytest.mark.parametrize("record_type", ROLE_SPLIT_TYPES)
    def test_role_split_type_explicit_provider_succeeds(self, record_type: str) -> None:
        pkg = Package()
        rec = pkg.record(record_type, payload={"k": "v"}, obligation_role="provider")
        assert rec.obligation_role == ObligationRole.PROVIDER

    def test_non_role_split_type_still_defaults_to_provider(self) -> None:
        """A non-role-split record type keeps the convenience default."""
        pkg = Package()
        rec = pkg.record("risk_register", payload={"description": "r"})
        assert rec.obligation_role == ObligationRole.PROVIDER

    def test_role_split_error_code_is_acef_002(self) -> None:
        pkg = Package()
        with pytest.raises(ACEFSchemaError) as exc:
            pkg.record("transparency_marking", payload={})
        assert exc.value.code == "ACEF-002"


# ---------------------------------------------------------------------------
# ENVELOPE-006 — builder setters for v1.1 manifest fields (X5/X6).
# ---------------------------------------------------------------------------


class TestBuilderAuthorsV11ManifestFields:
    def test_set_analysis_mode_emits_in_manifest(self) -> None:
        """A builder-authored Package can declare analysis_mode (X5)."""
        pkg = Package()
        pkg.set_analysis_mode("subscriber")
        manifest = pkg.build_manifest().to_dict()
        assert manifest["analysis_mode"] == "subscriber"

    def test_set_analysis_mode_bumps_core_version_to_v1_1(self) -> None:
        """Declaring a v1.1-only manifest field bumps the version gate so the
        validator resolves the v1.1 schema (not v1)."""
        pkg = Package()
        pkg.set_analysis_mode("public_artifact")
        assert pkg.versioning.core_version == "1.1.0"

    def test_set_analysis_mode_rejects_unknown_mode(self) -> None:
        pkg = Package()
        with pytest.raises(ACEFSchemaError, match="analysis_mode"):
            pkg.set_analysis_mode("not-a-mode")

    def test_add_namespace_emits_in_manifest(self) -> None:
        """A builder-authored Package can declare namespaces (X6).

        The key matches the v1.1 schema pattern ``^x-[a-z0-9-]+/?(?![\\s\\S])`` so
        the authored manifest is schema-valid (a key with a segment after the
        slash, e.g. 'x-vendor/extension', is rejected by additionalProperties).
        """
        pkg = Package()
        pkg.add_namespace("x-vendor", {"foo": "bar"})
        manifest = pkg.build_manifest().to_dict()
        assert manifest["namespaces"] == {"x-vendor": {"foo": "bar"}}

    def test_add_namespace_accumulates(self) -> None:
        pkg = Package()
        pkg.add_namespace("x-a", {"k": 1})
        pkg.add_namespace("x-b", {"k": 2})
        manifest = pkg.build_manifest().to_dict()
        assert manifest["namespaces"] == {"x-a": {"k": 1}, "x-b": {"k": 2}}

    def test_add_namespace_rejects_non_x_prefixed_key(self) -> None:
        """X6 namespace top-level keys MUST be x-vendor-prefixed."""
        pkg = Package()
        with pytest.raises(ACEFSchemaError, match="namespace"):
            pkg.add_namespace("vendor-extension", {"foo": "bar"})

    def test_add_namespace_rejects_key_with_slash_segment(self) -> None:
        """A key with a path segment after the slash is rejected (the frozen
        schema's additionalProperties:false rejects it)."""
        pkg = Package()
        with pytest.raises(ACEFSchemaError, match="namespace"):
            pkg.add_namespace("x-vendor/extension", {"foo": "bar"})

    def test_builder_authored_namespace_passes_v1_1_schema(self) -> None:
        """A builder-authored namespaces block passes the v1.1 manifest schema
        — proving the setter cannot emit a schema-invalid namespaces field."""
        pkg = Package()
        pkg.add_subject("ai_system", name="System")
        pkg.set_analysis_mode("subscriber")
        pkg.add_namespace("x-vendor", {"foo": "bar"})
        manifest = pkg.build_manifest().to_dict()
        errors = validate_manifest(manifest, "v1.1")
        ns_errors = [e for e in errors if "namespaces" in list(e.absolute_path)]
        assert ns_errors == []

    def test_default_package_emits_no_v1_1_manifest_fields(self) -> None:
        """A vanilla Package must NOT carry analysis_mode/namespaces — v1.0
        manifests stay byte-unchanged."""
        pkg = Package()
        manifest = pkg.build_manifest().to_dict()
        assert "analysis_mode" not in manifest
        assert "namespaces" not in manifest

    def test_builder_authored_v1_1_manifest_survives_export_load(self, tmp_path: Path) -> None:
        """End-to-end: a builder-authored v1.1 bundle round-trips X5/X6."""
        pkg = Package()
        pkg.set_analysis_mode("subscriber")
        pkg.add_namespace("x-vendor-ns", {"team": "compliance"})
        pkg.add_subject("ai_system", name="System")
        pkg.record("risk_register", payload={"description": "r"})
        out = tmp_path / "bundle"
        pkg.export(str(out))

        reloaded = acef.load(str(out))
        manifest = reloaded.build_manifest().to_dict()
        assert manifest["analysis_mode"] == "subscriber"
        assert manifest["namespaces"] == {"x-vendor-ns": {"team": "compliance"}}


# ---------------------------------------------------------------------------
# ENVELOPE-007 — loader constructs identity scalars directly (no mutation).
# ---------------------------------------------------------------------------


class TestLoaderConstructsIdentityDirectly:
    def test_missing_package_id_raises_acef_002(self, tmp_path: Path) -> None:
        """A manifest missing metadata.package_id must raise ACEF-002 rather
        than silently minting a fresh random urn:acef:pkg:."""
        bundle = tmp_path / "bundle"
        manifest = _manifest()
        del manifest["metadata"]["package_id"]
        _write_bundle(bundle, manifest=manifest, record=_record())
        with pytest.raises(ACEFSchemaError) as exc:
            acef.load(str(bundle))
        assert exc.value.code == "ACEF-002"
        assert "package_id" in str(exc.value)

    def test_missing_timestamp_raises_acef_002(self, tmp_path: Path) -> None:
        """A manifest missing metadata.timestamp must raise ACEF-002 rather
        than falling back to a fresh wall-clock value."""
        bundle = tmp_path / "bundle"
        manifest = _manifest()
        del manifest["metadata"]["timestamp"]
        _write_bundle(bundle, manifest=manifest, record=_record())
        with pytest.raises(ACEFSchemaError) as exc:
            acef.load(str(bundle))
        assert exc.value.code == "ACEF-002"
        assert "timestamp" in str(exc.value)

    def test_inbound_identity_constructed_directly(self, tmp_path: Path) -> None:
        """A valid manifest's package_id/timestamp are carried verbatim — no
        fresh values fabricated."""
        bundle = tmp_path / "bundle"
        _write_bundle(bundle, manifest=_manifest(), record=_record())
        pkg = acef.load(str(bundle))
        assert pkg.metadata.package_id == "urn:acef:pkg:11111111-1111-1111-1111-111111111111"
        assert pkg.metadata.timestamp == "2026-01-01T00:00:00Z"

    def test_identity_survives_export_load_reexport(self, tmp_path: Path) -> None:
        """The on-disk identity must be byte-stable across a round-trip — a
        fabricated package_id would diverge on re-export."""
        src = tmp_path / "src"
        _write_bundle(src, manifest=_manifest(), record=_record())
        pkg1 = acef.load(str(src))
        out1 = tmp_path / "out1"
        pkg1.export(str(out1))
        manifest1 = json.loads((out1 / "acef-manifest.json").read_text(encoding="utf-8"))

        pkg2 = acef.load(str(out1))
        out2 = tmp_path / "out2"
        pkg2.export(str(out2))
        manifest2 = json.loads((out2 / "acef-manifest.json").read_text(encoding="utf-8"))

        assert manifest1["metadata"]["package_id"] == manifest2["metadata"]["package_id"]
        assert manifest1["metadata"]["package_id"] == "urn:acef:pkg:11111111-1111-1111-1111-111111111111"
        assert manifest1["metadata"]["timestamp"] == manifest2["metadata"]["timestamp"]
