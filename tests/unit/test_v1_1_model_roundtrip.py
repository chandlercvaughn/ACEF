"""Round-trip tests for v1.1 envelope (X1-X4) and manifest (X5-X6) fields.

Per VAL-MODEL-ROUNDTRIP-001..006: load → export must preserve X1-X6 fields
byte-identically. These tests build minimal valid envelope/manifest dicts
inline and verify that ``Model.model_validate(d).model_dump(mode="json",
exclude_none=True) == d``.

The "exclude_none" filter ensures unrelated optional fields don't pollute
the round-trip comparison; only fields explicitly present in the input
must reappear identically on the output.
"""

from __future__ import annotations

from acef.models.manifest import Manifest
from acef.models.records import RecordEnvelope


def _minimal_envelope_dict(**overrides):
    """Build a minimal RecordEnvelope dict with all required fields populated.

    Per record-envelope.schema.json v1.1 the canonical required set is
    record_id, record_type, timestamp, lifecycle_phase, obligation_role,
    confidentiality, trust_level, entity_refs, payload (and a collector
    object). The Pydantic model permits more leniency, but for round-trip
    purposes we include the schema-required ones so the dict is realistic.
    """
    base = {
        "record_id": "urn:acef:rec:11111111-1111-1111-1111-111111111111",
        "record_type": "risk_register",
        "provisions_addressed": [],
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
        "attachments": [],
    }
    base.update(overrides)
    return base


def _minimal_manifest_dict(**overrides):
    """Build a minimal Manifest dict with required fields populated."""
    base = {
        "metadata": {
            "package_id": "urn:acef:pkg:11111111-1111-1111-1111-111111111111",
            "created_at": "2026-01-01T00:00:00Z",
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
        "record_files": [],
        "audit_trail": [],
    }
    base.update(overrides)
    return base


def _roundtrip_envelope(d):
    """Return the round-tripped envelope dict (model_validate → model_dump)."""
    return RecordEnvelope.model_validate(d).model_dump(mode="json", exclude_none=True)


def _roundtrip_manifest(d):
    """Return the round-tripped manifest dict (model_validate → model_dump)."""
    return Manifest.model_validate(d).model_dump(mode="json", exclude_none=True)


# ----- VAL-MODEL-ROUNDTRIP-001 — X1 redaction_policy_version -----


def test_redaction_policy_version_roundtrip():
    """VAL-MODEL-ROUNDTRIP-001: X1 survives load→export byte-identically."""
    d = _minimal_envelope_dict(
        confidentiality="redacted",
        redaction_policy_version="1.0.0",
    )
    out = _roundtrip_envelope(d)
    assert out["redaction_policy_version"] == "1.0.0"
    assert out == d


# ----- VAL-MODEL-ROUNDTRIP-002 — X2 redaction_attestation_ref -----


def test_redaction_attestation_ref_roundtrip():
    """VAL-MODEL-ROUNDTRIP-002: X2 survives load→export byte-identically."""
    d = _minimal_envelope_dict(
        confidentiality="redacted",
        redaction_attestation_ref=("urn:acef:rec:22222222-2222-2222-2222-222222222222"),
    )
    out = _roundtrip_envelope(d)
    assert out["redaction_attestation_ref"] == ("urn:acef:rec:22222222-2222-2222-2222-222222222222")
    assert out == d


# ----- VAL-MODEL-ROUNDTRIP-003 — X3 tenant_label -----


def test_tenant_label_roundtrip():
    """VAL-MODEL-ROUNDTRIP-003: X3 survives load→export byte-identically."""
    d = _minimal_envelope_dict(tenant_label="urn:acef:tenant:acme-corp")
    out = _roundtrip_envelope(d)
    assert out["tenant_label"] == "urn:acef:tenant:acme-corp"
    assert out == d


# ----- VAL-MODEL-ROUNDTRIP-004 — X4 causation_chain -----


def test_causation_chain_roundtrip():
    """VAL-MODEL-ROUNDTRIP-004: X4 survives load→export preserving order."""
    chain = [
        "urn:acef:rec:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "urn:acef:rec:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "urn:acef:rec:cccccccc-cccc-cccc-cccc-cccccccccccc",
    ]
    d = _minimal_envelope_dict(causation_chain=chain)
    out = _roundtrip_envelope(d)
    assert out["causation_chain"] == chain  # order preserved
    assert out == d


# ----- VAL-MODEL-ROUNDTRIP-005 — X5 analysis_mode + namespaces (combined) -----


def test_analysis_mode_and_namespaces_roundtrip():
    """VAL-MODEL-ROUNDTRIP-005: X5 + X6 on Manifest survive byte-identically."""
    namespaces = {"x-test/extension": {"foo": "bar", "nested": {"k": [1, 2]}}}
    d = _minimal_manifest_dict(
        analysis_mode="subscriber",
        namespaces=namespaces,
    )
    out = _roundtrip_manifest(d)
    assert out["analysis_mode"] == "subscriber"
    assert out["namespaces"] == namespaces
    assert out == d


# ----- VAL-MODEL-ROUNDTRIP-006 — Full envelope X1-X4 + vendor extension -----


def test_full_envelope_x1_x4_plus_vendor_extension_roundtrip():
    """VAL-MODEL-ROUNDTRIP-006: All X1-X4 + extra='allow' vendor key survives."""
    d = _minimal_envelope_dict(
        confidentiality="redacted",
        redaction_policy_version="2.1.0",
        redaction_attestation_ref=("urn:acef:rec:33333333-3333-3333-3333-333333333333"),
        tenant_label="urn:acef:tenant:test-tenant",
        causation_chain=[
            "urn:acef:rec:dddddddd-dddd-dddd-dddd-dddddddddddd",
        ],
    )
    # Add a vendor-extension top-level key (verifies extra='allow').
    d["x-vendor-foo/bar"] = {"k": "v", "n": 42}

    out = _roundtrip_envelope(d)

    # All four X-fields survive.
    assert out["redaction_policy_version"] == "2.1.0"
    assert out["redaction_attestation_ref"] == ("urn:acef:rec:33333333-3333-3333-3333-333333333333")
    assert out["tenant_label"] == "urn:acef:tenant:test-tenant"
    assert out["causation_chain"] == [
        "urn:acef:rec:dddddddd-dddd-dddd-dddd-dddddddddddd",
    ]
    # Vendor extension survives (proves extra='allow' integrity).
    assert out["x-vendor-foo/bar"] == {"k": "v", "n": 42}
    # Full byte-identical round-trip.
    assert out == d
