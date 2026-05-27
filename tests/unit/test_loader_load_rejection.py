"""VAL-LOAD-001..004: Load-time rejection paths in :func:`acef.loader.load`.

These tests construct minimal on-disk v1.1 bundles that trip each of the
load-rejection rules and assert :class:`acef.errors.LoadRejection` is raised
with the correct ACEF-NNN code attached.

The bundles are deliberately minimal — they bypass signing and
content-hashes.json because :func:`acef.load` does not run the integrity
phase (that lives in :func:`acef.validation.engine.validate_bundle`). The
load-rejection check fires post-parse, pre-Package-construction, so all we
need is a well-formed manifest + a single JSONL record that exercises the
rule.

Authority-matrix denied cells (VAL-LOAD-004) are derived from
:func:`acef.validation.authority_matrix.all_cells` so the same source of
truth drives both the validator-side and loader-side tests — see
tests/conformance/test_cross_record_disposition_authority.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acef.errors import LoadRejection
from acef.loader import load
from acef.validation.authority_matrix import all_cells


# ---------------------------------------------------------------------------
# Bundle construction helpers (self-contained — do not import from
# tests/conformance/_v1_1_bundle_helpers.py to keep this unit module
# independent of the conformance tier).
# ---------------------------------------------------------------------------


def _base_manifest(
    *,
    entities_actors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Minimal v1.1 manifest with no analysis_mode (load-rejection is
    mode-independent — these rules fire on raw record content)."""
    return {
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
    """Minimal record envelope (loader-parseable, no signature/hash needed)."""
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
    """Write a one-file bundle and return its directory path."""
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


def _harness_attestation_payload(verifier_class: str) -> dict[str, Any]:
    """Build a harness_attestation payload with the given verifier_class.

    Per VAL-LOAD-001/002 the loader rejects on verifier_class == 'persona'
    or 'llm' BEFORE any deeper schema validation. We do not need the rest
    of the payload to be schema-correct for the loader-rejection test —
    the rejection fires on the verifier_class field alone.
    """
    return {
        "attestation_id": "urn:acef:att:00000000-0000-0000-0000-000000000001",
        "state_class": "step",
        "state_transition": {
            "from_state": "init",
            "to_state": "verified",
            "transitioned_at": "2026-01-01T00:00:00Z",
        },
        "bound_evidence_refs": [
            "urn:acef:rec:00000000-0000-0000-0000-000000000002",
        ],
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
    """Build a disposition_record payload (risk_treatment / external_disposition)."""
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


# ---------------------------------------------------------------------------
# VAL-LOAD-001: harness_attestation with verifier_class='persona' -> ACEF-070
# ---------------------------------------------------------------------------


def test_val_load_001_persona_verifier_rejected(tmp_path: Path) -> None:
    """A harness_attestation with verifier_class='persona' raises
    LoadRejection(code='ACEF-070') at load time.
    """
    bundle = tmp_path / "persona-bundle"
    _write_bundle(
        bundle,
        manifest=_base_manifest(),
        records=[
            _envelope(
                record_id="urn:acef:rec:00000000-0000-0000-0000-000000000001",
                record_type="harness_attestation",
                payload=_harness_attestation_payload(verifier_class="persona"),
            )
        ],
    )

    with pytest.raises(LoadRejection) as excinfo:
        load(str(bundle))
    assert excinfo.value.code == "ACEF-070", (
        f"Expected ACEF-070; got {excinfo.value.code!r} with message {excinfo.value.message!r}"
    )


# ---------------------------------------------------------------------------
# VAL-LOAD-002: harness_attestation with verifier_class='llm' -> ACEF-070
# ---------------------------------------------------------------------------


def test_val_load_002_llm_verifier_rejected(tmp_path: Path) -> None:
    """A harness_attestation with verifier_class='llm' raises
    LoadRejection(code='ACEF-070') at load time.
    """
    bundle = tmp_path / "llm-bundle"
    _write_bundle(
        bundle,
        manifest=_base_manifest(),
        records=[
            _envelope(
                record_id="urn:acef:rec:00000000-0000-0000-0000-000000000001",
                record_type="harness_attestation",
                payload=_harness_attestation_payload(verifier_class="llm"),
            )
        ],
    )

    with pytest.raises(LoadRejection) as excinfo:
        load(str(bundle))
    assert excinfo.value.code == "ACEF-070"


# ---------------------------------------------------------------------------
# VAL-LOAD-003: disposition_record internal_state_unchanged: false -> ACEF-076
# ---------------------------------------------------------------------------


def test_val_load_003_internal_state_unchanged_false_rejected(tmp_path: Path) -> None:
    """A disposition_record with internal_state_unchanged=false raises
    LoadRejection(code='ACEF-076').

    Per brief §V3: external dispositions are advisory and MUST NOT mutate
    internal evidence state; internal_state_unchanged=false is the
    forbidden state.
    """
    bundle = tmp_path / "isu-false-bundle"
    _write_bundle(
        bundle,
        manifest=_base_manifest(),
        records=[
            _envelope(
                record_id="urn:acef:rec:00000000-0000-0000-0000-000000000020",
                record_type="risk_treatment",
                payload=_disposition_payload(internal_state_unchanged=False),
            )
        ],
    )

    with pytest.raises(LoadRejection) as excinfo:
        load(str(bundle))
    assert excinfo.value.code == "ACEF-076", (
        f"Expected ACEF-076; got {excinfo.value.code!r} with message {excinfo.value.message!r}"
    )


def test_val_load_003_internal_state_unchanged_true_clean(tmp_path: Path) -> None:
    """Sanity check: internal_state_unchanged=true does NOT raise."""
    bundle = tmp_path / "isu-true-bundle"
    _write_bundle(
        bundle,
        manifest=_base_manifest(),
        records=[
            _envelope(
                record_id="urn:acef:rec:00000000-0000-0000-0000-000000000021",
                record_type="risk_treatment",
                payload=_disposition_payload(internal_state_unchanged=True),
            )
        ],
    )
    # Should not raise.
    pkg = load(str(bundle))
    assert pkg is not None


# ---------------------------------------------------------------------------
# VAL-LOAD-004: §14.5 denied (authority_class × actor_role) cells -> ACEF-080
# ---------------------------------------------------------------------------


# 7 denied cells derived from the matrix (3 from accepted_risk_request,
# 2 from false_positive_assertion, 2 from evidence_dispute).
_DENIED_CELLS: list[tuple[str, str]] = [(ac, ar) for ac, ar, granted in all_cells() if not granted]
assert len(_DENIED_CELLS) == 7, f"Expected 7 denied cells in the §14.5 matrix; got {len(_DENIED_CELLS)}"


@pytest.mark.parametrize(
    "authority_class,actor_role",
    _DENIED_CELLS,
    ids=[f"{ac}-{ar}" for ac, ar in _DENIED_CELLS],
)
def test_val_load_004_denied_authority_cell_rejected(
    tmp_path: Path,
    authority_class: str,
    actor_role: str,
) -> None:
    """For each denied (authority_class × actor_role) cell, loading a
    disposition_record with authority_granted=true raises
    LoadRejection(code='ACEF-080').
    """
    bundle = tmp_path / f"{authority_class}-{actor_role}"
    actor_id = "urn:acef:act:00000000-0000-0000-0000-000000000099"

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
                record_id="urn:acef:rec:00000000-0000-0000-0000-000000000030",
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

    with pytest.raises(LoadRejection) as excinfo:
        load(str(bundle))
    assert excinfo.value.code == "ACEF-080", (
        f"Cell ({authority_class!r}, {actor_role!r}) expected ACEF-080; "
        f"got {excinfo.value.code!r} ({excinfo.value.message!r})"
    )


def test_val_load_004_granted_cell_clean(tmp_path: Path) -> None:
    """Sanity check: a granted cell (priority × provider) does NOT raise."""
    bundle = tmp_path / "granted-cell"
    actor_id = "urn:acef:act:00000000-0000-0000-0000-000000000098"
    manifest = _base_manifest(
        entities_actors=[
            {
                "actor_id": actor_id,
                "role": "provider",
                "name": "p",
                "organization": "o",
            }
        ],
    )
    _write_bundle(
        bundle,
        manifest=manifest,
        records=[
            _envelope(
                record_id="urn:acef:rec:00000000-0000-0000-0000-000000000031",
                record_type="risk_treatment",
                entity_refs={"actor_refs": [actor_id]},
                payload=_disposition_payload(
                    internal_state_unchanged=True,
                    authority_class="priority",
                    authority_granted=True,
                    actor_ref=actor_id,
                ),
            )
        ],
    )
    pkg = load(str(bundle))
    assert pkg is not None
