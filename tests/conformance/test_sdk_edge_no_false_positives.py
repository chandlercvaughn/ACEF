"""VAL-SDK-EDGE-001 — no false-positive ACEF-070 on non-state-class records.

ACEF-070 is reserved for ``harness_attestation`` records that cite a
banned ``verifier_class`` (persona/llm) or — at the SDK level — empty
``bound_evidence_refs``. The validator-level check at
``src/acef/validation/cross_record.py:enforce_harness_verifier_class``
inspects ONLY records whose ``record_type == 'harness_attestation'``. A
record of any other type (e.g., ``authorized_test_scope``) with absent
or empty ``bound_evidence_refs`` MUST NOT trigger ACEF-070.

This regression test guards against an over-broad future change to the
checker that would fire on any record with empty refs.
"""

from __future__ import annotations

from pathlib import Path

from acef.validation.engine import validate_bundle
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
    write_bundle,
)


def test_authorized_test_scope_without_bound_evidence_refs_no_acef_070(
    tmp_path: Path,
) -> None:
    """A bundle with one authorized_test_scope record (no
    bound_evidence_refs field at all — it's irrelevant for non-state-class
    records) MUST validate without emitting ACEF-070.
    """
    bundle = tmp_path / "edge-no-bound-refs"
    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:a0000000-0000-0000-0000-000000000001",
                record_type="authorized_test_scope",
                payload={
                    "scope_id": "scope-001",
                    "scope_version": "1.0.0",
                    "subject_ref": "urn:acef:sub:s-001",
                    "authorized_surfaces": [
                        {
                            "surface_type": "api_endpoint",
                            "surface_identifier": "https://x.test/p",
                            "authorization_level": "read_only",
                        }
                    ],
                    "authorized_identities": [
                        {
                            "identity_type": "test_account",
                            "identity_ref": "urn:acef:actor:a1",
                            "scope_constraint": "sandbox",
                        }
                    ],
                    "side_effect_policy": {"default_disposition": "default_deny"},
                    "sandbox_boundary": {
                        "ownership_ledger_ref": "urn:acef:rec:s-001",
                        "preflight_method": "tenant_label",
                    },
                    "ownership_proof": {
                        "proof_method": "dns_txt",
                        "proof_artifact_ref": "urn:acef:rec:p-001",
                        "verified_at": "2026-01-01T00:00:00Z",
                    },
                    "effective_from": "2026-01-01T00:00:00Z",
                    "authorizing_actor_ref": "urn:acef:actor:auth-001",
                    # Deliberately NO bound_evidence_refs key — it is not
                    # part of this record type's schema.
                },
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-070" not in found, (
        f"ACEF-070 must NOT fire on a non-state-class record like "
        f"authorized_test_scope, regardless of bound_evidence_refs. "
        f"Got: {found!r}"
    )


def test_authorized_test_scope_with_explicitly_empty_bound_refs_no_acef_070(
    tmp_path: Path,
) -> None:
    """Even if a non-state-class record CARRIES an (irrelevant)
    bound_evidence_refs key set to an empty list, ACEF-070 must not fire.

    Justification: ACEF-070's domain is harness_attestation state
    classes; any defensive over-broad check that fires on
    ``bound_evidence_refs == []`` for arbitrary record types is a bug.
    """
    bundle = tmp_path / "edge-empty-bound-refs"
    rec = base_record(
        record_id="urn:acef:rec:a0000000-0000-0000-0000-000000000002",
        record_type="authorized_test_scope",
        payload={
            "scope_id": "scope-002",
            "scope_version": "1.0.0",
            "subject_ref": "urn:acef:sub:s-002",
            "authorized_surfaces": [
                {
                    "surface_type": "api_endpoint",
                    "surface_identifier": "https://x.test/q",
                    "authorization_level": "read_only",
                }
            ],
            "authorized_identities": [
                {
                    "identity_type": "test_account",
                    "identity_ref": "urn:acef:actor:a2",
                    "scope_constraint": "sandbox",
                }
            ],
            "side_effect_policy": {"default_disposition": "default_deny"},
            "sandbox_boundary": {
                "ownership_ledger_ref": "urn:acef:rec:s-002",
                "preflight_method": "tenant_label",
            },
            "ownership_proof": {
                "proof_method": "dns_txt",
                "proof_artifact_ref": "urn:acef:rec:p-002",
                "verified_at": "2026-01-01T00:00:00Z",
            },
            "effective_from": "2026-01-01T00:00:00Z",
            "authorizing_actor_ref": "urn:acef:actor:auth-002",
            # Explicitly empty — must not trigger any state-class check.
            "bound_evidence_refs": [],
        },
    )
    write_bundle(bundle, manifest=base_manifest(), records=[rec])

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-070" not in found, (
        f"ACEF-070 must remain scoped to harness_attestation state-class records. Got: {found!r}"
    )
