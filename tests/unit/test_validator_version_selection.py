"""Tests for validator version routing (F-M1-VALIDATOR-VERSION-SELECTION).

Covers VAL-VALIDATION-002 in full and VAL-VALIDATION-001 end-to-end:
- A v1.0-declared bundle containing a v1.1-only record type
  (harness_attestation) fails with ACEF-003 ("unknown record_type").
- The same bundle declaring core_version 1.1.0 does NOT emit ACEF-003 for
  that record_type (the v1.1 schema dir resolves it).

The validator may emit other diagnostics for the v1.1 path (e.g., the
harness_attestation payload may fail its own required-field checks because
we hand-craft a minimal stub). We only assert presence/absence of ACEF-003
on the specific record_type that distinguishes the two paths.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acef.validation.engine import validate_bundle

# ----- helpers -----


def _write_minimal_bundle(
    bundle_dir: Path,
    *,
    core_version: str,
    record_type: str,
    payload: dict,
) -> None:
    """Write a minimal directory-layout bundle with one record.

    The bundle is intentionally not signed and not hashed — the validator
    will emit integrity diagnostics, but those are orthogonal to the
    version-selection question being tested. We only inspect ACEF-003
    diagnostics here.
    """
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "records").mkdir(parents=True, exist_ok=True)

    record = {
        "record_id": "urn:acef:rec:22222222-2222-2222-2222-222222222222",
        "record_type": record_type,
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
        "payload": payload,
        "attachments": [],
    }

    record_path = bundle_dir / "records" / f"{record_type}.jsonl"
    record_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    manifest = {
        "metadata": {
            "package_id": "urn:acef:pkg:22222222-2222-2222-2222-222222222222",
            "created_at": "2026-01-01T00:00:00Z",
            "timestamp": "2026-01-01T00:00:00Z",
            "producer": {"name": "test-producer", "version": "1.0.0"},
        },
        "versioning": {"core_version": core_version, "profiles_version": "1.0.0"},
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
                "count": 1,
                "path": f"records/{record_type}.jsonl",
                "record_type": record_type,
            }
        ],
        "audit_trail": [],
    }
    (bundle_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def _minimal_harness_attestation_payload() -> dict:
    """A payload that satisfies enough of harness_attestation.schema.json
    for the v1.1 path to NOT fire ACEF-003. The payload may still fail
    other validators; that's fine — we only assert ACEF-003 absence here.
    """
    return {
        "attestation_id": "urn:acef:att:33333333-3333-3333-3333-333333333333",
        "state_class": "attestation",
        "state_transition": "active",
        "bound_evidence_refs": ["urn:acef:rec:99999999-9999-9999-9999-999999999999"],
        "verifier": {
            "verifier_id": "urn:acef:act:44444444-4444-4444-4444-444444444444",
            "verifier_class": "deterministic",
        },
        "claim": "test attestation",
        "fake_green_test_ref": "urn:acef:fg:55555555-5555-5555-5555-555555555555",
        "signed_at": "2026-01-01T00:00:00Z",
        "signer_kid": "test-key-1",
    }


def _acef_003_for_record_type(diagnostics: list, record_type: str) -> list:
    """Filter diagnostics to ACEF-003 entries mentioning `record_type`."""
    out = []
    for d in diagnostics:
        if d.get("code") != "ACEF-003":
            continue
        msg = d.get("message", "")
        if record_type in msg:
            out.append(d)
    return out


# ----- VAL-VALIDATION-002: v1.0 bundle + v1.1-only record type -----


def test_v1_0_bundle_with_v1_1_only_record_type_emits_acef_003(
    tmp_path: Path,
) -> None:
    """A v1.0-declared bundle with a harness_attestation record fails with
    ACEF-003 because the v1.0 schema registry has no such record type.
    """
    bundle = tmp_path / "v1-0-bundle"
    _write_minimal_bundle(
        bundle,
        core_version="1.0.0",
        record_type="harness_attestation",
        payload=_minimal_harness_attestation_payload(),
    )

    assessment = validate_bundle(bundle)
    diagnostics = assessment.structural_errors

    matched = _acef_003_for_record_type(diagnostics, "harness_attestation")
    assert matched, (
        "Expected ACEF-003 diagnostic mentioning 'harness_attestation', "
        f"got: {[d for d in diagnostics if d.get('code') == 'ACEF-003']!r}"
    )


@pytest.mark.parametrize(
    "record_type",
    [
        "authorized_test_scope",
        "scope_boundary_event",
        "finding_record",
        "delivery_verdict",
        "harness_attestation",
    ],
)
def test_v1_0_bundle_rejects_each_v1_1_only_record_type(tmp_path: Path, record_type: str) -> None:
    """Every v1.1-only standalone record type must trigger ACEF-003 under
    v1.0 schema selection.
    """
    bundle = tmp_path / f"v1-0-{record_type}"
    # Use an empty payload — the type itself is unknown so payload shape
    # doesn't matter; we just need the record_type to route through schema
    # lookup.
    _write_minimal_bundle(
        bundle,
        core_version="1.0.0",
        record_type=record_type,
        payload={},
    )

    assessment = validate_bundle(bundle)
    matched = _acef_003_for_record_type(assessment.structural_errors, record_type)
    assert matched, f"Expected ACEF-003 for {record_type!r} under core_version=1.0.0"


# ----- VAL-VALIDATION-001: v1.1 bundle resolves new record type -----


def test_v1_1_bundle_with_v1_1_record_type_no_acef_003(tmp_path: Path) -> None:
    """A v1.1-declared bundle with a harness_attestation record must NOT
    emit ACEF-003 for that record_type — the v1.1 schema dir resolves it.

    Other diagnostics (integrity, payload shape) may be emitted; we only
    assert ACEF-003 absence on this specific record_type.
    """
    bundle = tmp_path / "v1-1-bundle"
    _write_minimal_bundle(
        bundle,
        core_version="1.1.0",
        record_type="harness_attestation",
        payload=_minimal_harness_attestation_payload(),
    )

    assessment = validate_bundle(bundle)
    matched = _acef_003_for_record_type(assessment.structural_errors, "harness_attestation")
    assert not matched, f"v1.1 bundle should not emit ACEF-003 for harness_attestation; got: {matched!r}"


def test_v1_1_bundle_resolves_unchanged_record_type_via_fallback(
    tmp_path: Path,
) -> None:
    """A v1.1-declared bundle with a v1.0 record type (risk_register) must
    NOT emit ACEF-003 — the v1.1 -> v1 fallback resolves the schema.
    """
    bundle = tmp_path / "v1-1-risk-register"
    _write_minimal_bundle(
        bundle,
        core_version="1.1.0",
        record_type="risk_register",
        payload={},
    )

    assessment = validate_bundle(bundle)
    matched = _acef_003_for_record_type(assessment.structural_errors, "risk_register")
    assert not matched, f"v1.1 bundle should resolve risk_register via fallback to v1/; got: {matched!r}"
