"""VAL-LOAD-005: Loader and validator agree on ACEF-NNN codes.

For every condition that :func:`acef.load` rejects with a structured
:class:`LoadRejection`, this test confirms that
:func:`acef.validation.engine.validate_bundle` (the alternate entry point)
emits the same ACEF-NNN code as a :class:`ValidationDiagnostic` in the
returned :class:`AssessmentBundle.structural_errors` list.

This guarantees byte-equivalent code attribution regardless of which
validation entry point a caller uses — important for tools that fan out
both paths (e.g., the CLI runs validate_bundle; SDK helpers run load).

The matrix denied-cell sub-tests are driven from the same source of truth
as the unit-level loader tests:
:func:`acef.validation.authority_matrix.all_cells`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acef.errors import LoadRejection
from acef.loader import load
from acef.validation.authority_matrix import all_cells
from acef.validation.engine import validate_bundle

# ---------------------------------------------------------------------------
# Bundle construction helpers (self-contained; mirrors the unit-test helpers
# so the conformance suite is not coupled to the unit suite).
# ---------------------------------------------------------------------------


def _base_manifest(
    *,
    entities_actors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "metadata": {
            "package_id": "urn:acef:pkg:22222222-2222-2222-2222-222222222222",
            "created_at": "2026-01-01T00:00:00Z",
            "timestamp": "2026-01-01T00:00:00Z",
            "producer": {"name": "test-producer", "version": "1.0.0"},
        },
        "versioning": {"core_version": "1.1.0", "profiles_version": "1.0.0"},
        "subjects": [],
        "entities": {
            "components": [],
            "datasets": [],
            "actors": entities_actors or [],
            "relationships": [],
        },
        "profiles": [],
        "audit_trail": [],
    }


def _envelope(
    *,
    record_id: str,
    record_type: str,
    payload: dict[str, Any],
    entity_refs: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "record_id": record_id,
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
    if entity_refs is not None:
        rec["entity_refs"] = {
            "subject_refs": entity_refs.get("subject_refs", []),
            "component_refs": entity_refs.get("component_refs", []),
            "dataset_refs": entity_refs.get("dataset_refs", []),
            "actor_refs": entity_refs.get("actor_refs", []),
        }
    return rec


def _write_bundle(
    bundle_dir: Path,
    *,
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
) -> Path:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "records").mkdir(parents=True, exist_ok=True)
    rec_path = bundle_dir / "records" / "all.jsonl"
    rec_path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )
    first_type = records[0]["record_type"] if records else "risk_register"
    manifest = dict(manifest)
    manifest["record_files"] = [
        {"path": "records/all.jsonl", "record_type": first_type, "count": len(records)},
    ]
    (bundle_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir


def _harness_payload(verifier_class: str) -> dict[str, Any]:
    return {
        "attestation_id": "urn:acef:att:00000000-0000-0000-0000-000000000001",
        "state_class": "step",
        "state_transition": {
            "from_state": "init",
            "to_state": "verified",
            "transitioned_at": "2026-01-01T00:00:00Z",
        },
        "bound_evidence_refs": ["urn:acef:rec:00000000-0000-0000-0000-000000000002"],
        "verifier": {
            "verifier_id": "urn:acef:ver:test",
            "verifier_class": verifier_class,
            "verifier_version": "1.0.0",
        },
        "claim": "test claim",
        "fake_green_test_ref": "urn:acef:rec:00000000-0000-0000-0000-000000000003",
        "signed_at": "2026-01-01T00:00:00Z",
        "signer_kid": "test-kid",
        "attestation_signature": {
            "alg": "RS256",
            "value": "AAAA",
            "signed_fields": [
                "attestation_id",
                "state_class",
                "state_transition",
                "bound_evidence_refs",
                "verifier",
                "claim",
                "fake_green_test_ref",
                "signed_at",
                "signer_kid",
            ],
        },
    }


def _disposition_payload(
    *,
    internal_state_unchanged: bool = True,
    authority_class: str = "priority",
    authority_granted: bool = False,
    actor_ref: str | None = None,
) -> dict[str, Any]:
    auth: dict[str, Any] = {
        "authority_class": authority_class,
        "authority_granted": authority_granted,
    }
    if actor_ref is not None:
        auth["actor_ref"] = actor_ref
    return {
        "treatment_subtype": "external_disposition",
        "disposition_id": "urn:acef:disp:00000000-0000-0000-0000-000000000010",
        "finding_ref": "urn:acef:rec:00000000-0000-0000-0000-000000000011",
        "external_state": {
            "external_state_value": "accepted",
            "external_state_authority": "test-authority",
            "external_state_observed_at": "2026-01-01T00:00:00Z",
        },
        "internal_state_unchanged": internal_state_unchanged,
        "authority_check": auth,
        "reconciliation_evidence_ref": ("urn:acef:rec:00000000-0000-0000-0000-000000000012"),
    }


def _diag_codes(structural_errors: list[dict[str, Any]]) -> list[str]:
    """Extract .code values from structural_errors list."""
    return [d.get("code") for d in structural_errors if isinstance(d, dict)]


# ---------------------------------------------------------------------------
# VAL-LOAD-005 (a): persona / llm verifier — ACEF-070 via both paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("verifier_class", ["persona", "llm"])
def test_load_validate_agree_acef_070(
    tmp_path: Path,
    verifier_class: str,
) -> None:
    """For a harness_attestation with banned verifier_class:
    - load() raises LoadRejection(code=ACEF-070)
    - validate_bundle() emits ValidationDiagnostic with code ACEF-070
    """
    bundle = tmp_path / f"verifier-{verifier_class}"
    _write_bundle(
        bundle,
        manifest=_base_manifest(),
        records=[
            _envelope(
                record_id="urn:acef:rec:00000000-0000-0000-0000-000000000100",
                record_type="harness_attestation",
                payload=_harness_payload(verifier_class),
            )
        ],
    )

    # Load path
    with pytest.raises(LoadRejection) as excinfo:
        load(str(bundle))
    load_code = excinfo.value.code

    # Validate path
    assessment = validate_bundle(bundle)
    validate_codes = _diag_codes(assessment.structural_errors)

    assert load_code == "ACEF-070", f"load() emitted {load_code!r}, expected ACEF-070"
    assert "ACEF-070" in validate_codes, (
        f"validate_bundle() did NOT emit ACEF-070 for verifier_class={verifier_class!r}. All codes: {validate_codes!r}"
    )


# ---------------------------------------------------------------------------
# VAL-LOAD-005 (b): internal_state_unchanged=false — ACEF-076 via both paths
# ---------------------------------------------------------------------------


def test_load_validate_agree_acef_076(tmp_path: Path) -> None:
    """For a disposition_record with internal_state_unchanged=false:
    - load() raises LoadRejection(code=ACEF-076)
    - validate_bundle() emits ValidationDiagnostic with code ACEF-076
    """
    bundle = tmp_path / "isu-false"
    _write_bundle(
        bundle,
        manifest=_base_manifest(),
        records=[
            _envelope(
                record_id="urn:acef:rec:00000000-0000-0000-0000-000000000200",
                record_type="risk_treatment",
                payload=_disposition_payload(internal_state_unchanged=False),
            )
        ],
    )

    # Load path
    with pytest.raises(LoadRejection) as excinfo:
        load(str(bundle))
    load_code = excinfo.value.code

    # Validate path
    assessment = validate_bundle(bundle)
    validate_codes = _diag_codes(assessment.structural_errors)

    assert load_code == "ACEF-076"
    assert "ACEF-076" in validate_codes, (
        f"validate_bundle() did NOT emit ACEF-076 for internal_state_unchanged=false. All codes: {validate_codes!r}"
    )


# ---------------------------------------------------------------------------
# VAL-LOAD-005 (c): §14.5 denied authority cells — ACEF-080 via both paths
# ---------------------------------------------------------------------------


_DENIED_CELLS: list[tuple[str, str]] = [(ac, ar) for ac, ar, granted in all_cells() if not granted]


@pytest.mark.parametrize(
    "authority_class,actor_role",
    _DENIED_CELLS,
    ids=[f"{ac}-{ar}" for ac, ar in _DENIED_CELLS],
)
def test_load_validate_agree_acef_080(
    tmp_path: Path,
    authority_class: str,
    actor_role: str,
) -> None:
    """For each denied (authority_class × actor_role) cell:
    - load() raises LoadRejection(code=ACEF-080)
    - validate_bundle() emits ValidationDiagnostic with code ACEF-080
    """
    bundle = tmp_path / f"matrix-{authority_class}-{actor_role}"
    actor_id = "urn:acef:act:00000000-0000-0000-0000-000000000300"
    manifest = _base_manifest(
        entities_actors=[
            {
                "actor_id": actor_id,
                "role": actor_role,
                "name": "test-actor",
                "organization": "test-org",
            }
        ],
    )
    _write_bundle(
        bundle,
        manifest=manifest,
        records=[
            _envelope(
                record_id="urn:acef:rec:00000000-0000-0000-0000-000000000301",
                record_type="risk_treatment",
                entity_refs={"actor_refs": [actor_id]},
                payload=_disposition_payload(
                    internal_state_unchanged=True,
                    authority_class=authority_class,
                    authority_granted=True,
                    actor_ref=actor_id,
                ),
            )
        ],
    )

    # Load path
    with pytest.raises(LoadRejection) as excinfo:
        load(str(bundle))
    load_code = excinfo.value.code

    # Validate path
    assessment = validate_bundle(bundle)
    validate_codes = _diag_codes(assessment.structural_errors)

    assert load_code == "ACEF-080"
    assert "ACEF-080" in validate_codes, (
        f"validate_bundle() did NOT emit ACEF-080 for cell "
        f"({authority_class!r}, {actor_role!r}). All codes: {validate_codes!r}"
    )
