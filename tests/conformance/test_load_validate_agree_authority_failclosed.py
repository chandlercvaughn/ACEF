"""Load/validate parity for the fail-closed disposition-authority semantics.

VAL-FIX-AUTH-005 / VAL-FIX-AUTH-006 landed the fail-closed §14.5 rules in
:func:`acef.validation.cross_record.enforce_disposition_authority` (commit
1a665671); roborev found the loader mirror in :mod:`acef.load_rejections`
still carried both bypasses. This suite is the parity guarantee:

- every authority case the validator rejects with ACEF-080 is ALSO rejected
  at the :func:`acef.load` surface with ``LoadRejection(code="ACEF-080")``;
- every legitimate-skip positive both LOADS cleanly and produces NO
  ACEF-080 from :func:`validate_bundle`.

Scenario shapes mirror tests/conformance/test_load_validate_agree.py
(VAL-LOAD-005) and tests/unit/test_loader_authority_failclosed.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acef.errors import LoadRejection
from acef.loader import load
from acef.validation.engine import validate_bundle

_DEPLOYER = "urn:acef:act:abc12345-0000-0000-0000-0000000000d1"
_PROVIDER = "urn:acef:act:abc12345-0000-0000-0000-0000000000c1"
_AUDITOR = "urn:acef:act:abc12345-0000-0000-0000-0000000000a1"
_UNDECLARED = "urn:acef:act:abc12345-0000-0000-0000-0000000000ee"
_REC_ID = "urn:acef:rec:abc12345-0000-0000-0000-000000000001"

# ---------------------------------------------------------------------------
# Bundle construction helpers (self-contained; mirrors the unit-test helpers
# so the conformance suite is not coupled to the unit suite).
# ---------------------------------------------------------------------------


def _manifest(*actors: tuple[str, str]) -> dict[str, Any]:
    return {
        "metadata": {
            "package_id": "urn:acef:pkg:44444444-4444-4444-4444-444444444444",
            "created_at": "2026-01-01T00:00:00Z",
            "timestamp": "2026-01-01T00:00:00Z",
            "producer": {"name": "test-producer", "version": "1.0.0"},
        },
        "versioning": {"core_version": "1.1.0", "profiles_version": "1.0.0"},
        "subjects": [],
        "entities": {
            "components": [],
            "datasets": [],
            "actors": [
                {
                    "actor_id": actor_id,
                    "role": role,
                    "name": "test-actor",
                    "organization": "test-org",
                }
                for actor_id, role in actors
            ],
            "relationships": [],
        },
        "profiles": [],
        "audit_trail": [],
    }


def _disposition_record(
    *,
    authority_check: dict[str, Any] | None,
    actor_refs: list[str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "treatment_subtype": "external_disposition",
        "disposition_id": "urn:acef:disp:00000000-0000-0000-0000-000000000010",
        "finding_ref": "urn:acef:rec:00000000-0000-0000-0000-000000000011",
        "external_state": {
            "external_state_value": "accepted",
            "external_state_authority": "test-authority",
            "external_state_observed_at": "2026-01-01T00:00:00Z",
        },
        "internal_state_unchanged": True,
        "reconciliation_evidence_ref": ("urn:acef:rec:00000000-0000-0000-0000-000000000012"),
    }
    if authority_check is not None:
        payload["authority_check"] = authority_check
    return {
        "record_id": _REC_ID,
        "record_type": "risk_treatment",
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
            "actor_refs": actor_refs or [],
        },
        "payload": payload,
        "attachments": [],
    }


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
    manifest = dict(manifest)
    manifest["record_files"] = [
        {"path": "records/all.jsonl", "record_type": "risk_treatment", "count": len(records)},
    ]
    (bundle_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir


def _diag_codes(structural_errors: list[dict[str, Any]]) -> list[str]:
    return [d.get("code") for d in structural_errors if isinstance(d, dict)]


# ---------------------------------------------------------------------------
# Scenario table. Each entry: (id, manifest, record, expect_acef_080).
# ---------------------------------------------------------------------------

_SCENARIOS: list[tuple[str, dict[str, Any], dict[str, Any], bool]] = [
    # --- negatives: validator rejects → loader MUST reject -----------------
    (
        "typo-authority_clas-key",
        _manifest((_PROVIDER, "provider")),
        _disposition_record(
            authority_check={
                "authority_clas": "accepted_risk_request",  # typo'd key
                "authority_granted": True,
                "actor_ref": _PROVIDER,
            },
            actor_refs=[_PROVIDER],
        ),
        True,
    ),
    (
        "authority_class-key-absent",
        _manifest((_PROVIDER, "provider")),
        _disposition_record(
            authority_check={"authority_granted": True, "actor_ref": _PROVIDER},
            actor_refs=[_PROVIDER],
        ),
        True,
    ),
    (
        "authority_class-empty-string",
        _manifest((_PROVIDER, "provider")),
        _disposition_record(
            authority_check={
                "authority_class": "",
                "authority_granted": True,
                "actor_ref": _PROVIDER,
            },
            actor_refs=[_PROVIDER],
        ),
        True,
    ),
    (
        "authority_class-non-string",
        _manifest((_PROVIDER, "provider")),
        _disposition_record(
            authority_check={
                "authority_class": 42,
                "authority_granted": True,
                "actor_ref": _PROVIDER,
            },
            actor_refs=[_PROVIDER],
        ),
        True,
    ),
    (
        "authority_class-unrecognized",
        _manifest((_PROVIDER, "provider")),
        _disposition_record(
            authority_check={
                "authority_class": "self_certified_blanket_waiver",
                "authority_granted": True,
                "actor_ref": _PROVIDER,
            },
            actor_refs=[_PROVIDER],
        ),
        True,
    ),
    (
        "denied-actor-hidden-behind-permitted-first",
        _manifest((_DEPLOYER, "deployer"), (_PROVIDER, "provider")),
        _disposition_record(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
                # no actor_ref → fallback evaluates ALL actor_refs
            },
            actor_refs=[_DEPLOYER, _PROVIDER],
        ),
        True,
    ),
    (
        "undeclared-actor-second-in-fallback",
        _manifest((_DEPLOYER, "deployer")),
        _disposition_record(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
            },
            actor_refs=[_DEPLOYER, _UNDECLARED],
        ),
        True,
    ),
    (
        "explicit-denied-actor_ref",
        _manifest((_DEPLOYER, "deployer"), (_PROVIDER, "provider")),
        _disposition_record(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
                "actor_ref": _PROVIDER,
            },
            actor_refs=[_DEPLOYER, _PROVIDER],
        ),
        True,
    ),
    (
        "granted-no-resolvable-actor",
        _manifest((_DEPLOYER, "deployer")),
        _disposition_record(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
            },
        ),
        True,
    ),
    # --- positives: legitimate skips → loader loads, validator silent ------
    (
        "legit-granted-explicit-permitted-actor",
        _manifest((_DEPLOYER, "deployer")),
        _disposition_record(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
                "actor_ref": _DEPLOYER,
            },
            actor_refs=[_DEPLOYER],
        ),
        False,
    ),
    (
        "multi-actor-all-permitted-fallback",
        _manifest((_DEPLOYER, "deployer"), (_AUDITOR, "auditor")),
        _disposition_record(
            authority_check={
                "authority_class": "priority",
                "authority_granted": True,
            },
            actor_refs=[_DEPLOYER, _AUDITOR],
        ),
        False,
    ),
    (
        "explicit-permitted-actor_ref-shadows-denied-entity-ref",
        _manifest((_DEPLOYER, "deployer"), (_PROVIDER, "provider")),
        _disposition_record(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
                "actor_ref": _DEPLOYER,
            },
            actor_refs=[_DEPLOYER, _PROVIDER],
        ),
        False,
    ),
    (
        "no-authority_check-block",
        _manifest((_PROVIDER, "provider")),
        _disposition_record(authority_check=None, actor_refs=[_PROVIDER]),
        False,
    ),
    (
        "authority_granted-false",
        _manifest((_PROVIDER, "provider")),
        _disposition_record(
            authority_check={
                "authority_class": "accepted_risk_request",
                "authority_granted": False,
                "actor_ref": _PROVIDER,
            },
            actor_refs=[_PROVIDER],
        ),
        False,
    ),
    (
        "authority_granted-absent-with-typo-class",
        _manifest((_PROVIDER, "provider")),
        _disposition_record(
            authority_check={"authority_clas": "accepted_risk_request"},
            actor_refs=[_PROVIDER],
        ),
        False,
    ),
]


@pytest.mark.parametrize(
    "scenario_id,manifest,record,expect_080",
    _SCENARIOS,
    ids=[s[0] for s in _SCENARIOS],
)
def test_load_validate_agree_authority_failclosed(
    tmp_path: Path,
    scenario_id: str,
    manifest: dict[str, Any],
    record: dict[str, Any],
    expect_080: bool,
) -> None:
    """Loader and validator agree on every fail-closed authority case."""
    bundle = _write_bundle(
        tmp_path / scenario_id,
        manifest=manifest,
        records=[record],
    )

    # Validate path: ACEF-080 present iff the scenario is a violation.
    assessment = validate_bundle(bundle)
    validate_codes = _diag_codes(assessment.structural_errors)

    if expect_080:
        assert "ACEF-080" in validate_codes, (
            f"[{scenario_id}] validate_bundle() did NOT emit ACEF-080. All codes: {validate_codes!r}"
        )
        with pytest.raises(LoadRejection) as excinfo:
            load(str(bundle))
        assert excinfo.value.code == "ACEF-080", (
            f"[{scenario_id}] load() raised {excinfo.value.code!r}, expected ACEF-080 ({excinfo.value.message!r})"
        )
    else:
        assert "ACEF-080" not in validate_codes, (
            f"[{scenario_id}] validate_bundle() emitted spurious ACEF-080. All codes: {validate_codes!r}"
        )
        pkg = load(str(bundle))
        assert pkg is not None, f"[{scenario_id}] legitimate-skip positive failed to load"
