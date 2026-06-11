"""VAL-FIX-AUTH-005 / VAL-FIX-AUTH-006 at the :func:`acef.load` surface.

roborev review of commit 1a665671 found the two authority bypasses fixed in
:func:`acef.validation.cross_record.enforce_disposition_authority` were still
alive in the loader mirror (:mod:`acef.load_rejections`):

- (High, load_rejections.py:200) ``check_load_rejections`` ran the §14.5
  ACEF-080 logic only under ``if isinstance(ac, str) and ac`` — a disposition
  claiming ``authority_check.authority_granted: true`` with a missing /
  typo'd / empty / non-string ``authority_class`` silently LOADED via
  :func:`acef.load` even though :func:`validate_bundle` now rejects it.
- (Medium, load_rejections.py:116) absent an explicit
  ``authority_check.actor_ref``, the loader resolved only
  ``entity_refs.actor_refs[0]`` — permitted-first / denied-second ordering
  still hid a denied actor from SDK callers.

These tests pin the loader to the validator's fail-closed semantics:

- ``authority_granted: true`` + missing / non-string / empty / unrecognized
  ``authority_class`` → ``LoadRejection(code="ACEF-080")`` (fail closed);
- absent ``actor_ref`` → EVERY non-empty string in
  ``entity_refs.actor_refs[]`` is evaluated; ANY denied or undeclared actor
  rejects the load;
- an explicit ``authority_check.actor_ref`` keeps single-actor semantics;
- NO authority claim (``authority_granted`` absent or not ``True``) → the
  bundle still loads cleanly (legitimate skip preserved).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acef.errors import LoadRejection
from acef.loader import load

_DEPLOYER = "urn:acef:act:abc12345-0000-0000-0000-0000000000d1"
_PROVIDER = "urn:acef:act:abc12345-0000-0000-0000-0000000000c1"
_AUDITOR = "urn:acef:act:abc12345-0000-0000-0000-0000000000a1"
_UNDECLARED = "urn:acef:act:abc12345-0000-0000-0000-0000000000ee"
_REC_ID = "urn:acef:rec:abc12345-0000-0000-0000-000000000001"

_AUTHORITY_PHRASE = "authority matrix denies"

# ---------------------------------------------------------------------------
# Bundle construction helpers (self-contained — mirrors
# tests/unit/test_loader_load_rejection.py so this module stays independent).
# ---------------------------------------------------------------------------


def _manifest(*actors: tuple[str, str]) -> dict[str, Any]:
    """Minimal v1.1 manifest with entities.actors from (actor_id, role)."""
    return {
        "metadata": {
            "package_id": "urn:acef:pkg:33333333-3333-3333-3333-333333333333",
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
    """A loader-parseable risk_treatment / external_disposition envelope.

    ``authority_check`` is taken verbatim (so tests can express typo'd
    keys, missing keys, and non-string values exactly as an attacker
    would serialize them).
    """
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


def _assert_load_rejected_080(bundle: Path) -> LoadRejection:
    with pytest.raises(LoadRejection) as excinfo:
        load(str(bundle))
    assert excinfo.value.code == "ACEF-080", (
        f"Expected ACEF-080; got {excinfo.value.code!r} with message {excinfo.value.message!r}"
    )
    return excinfo.value


# ---------------------------------------------------------------------------
# VAL-FIX-AUTH-005 (loader mirror): missing / typo'd / non-string /
# unrecognized authority_class fails CLOSED at load time (ACEF-080),
# never a silent skip.
# ---------------------------------------------------------------------------


class TestLoadAuthorityClassFailsClosed:
    def test_typo_authority_clas_key_rejected_at_load(self, tmp_path: Path) -> None:
        """roborev's exact exploit: `authority_clas` (typo) carrying a
        matrix-DENIED accepted_risk_request grant currently loads cleanly
        via acef.load() — must raise LoadRejection(code='ACEF-080')."""
        bundle = _write_bundle(
            tmp_path / "typo-key",
            manifest=_manifest((_PROVIDER, "provider")),
            records=[
                _disposition_record(
                    authority_check={
                        "authority_clas": "accepted_risk_request",  # typo'd key
                        "authority_granted": True,
                        "actor_ref": _PROVIDER,
                    },
                    actor_refs=[_PROVIDER],
                )
            ],
        )
        exc = _assert_load_rejected_080(bundle)
        assert "authority_class" in exc.message
        assert "missing" in exc.message
        assert _REC_ID in exc.message

    def test_authority_class_key_absent_rejected_at_load(self, tmp_path: Path) -> None:
        bundle = _write_bundle(
            tmp_path / "absent-key",
            manifest=_manifest((_PROVIDER, "provider")),
            records=[
                _disposition_record(
                    authority_check={"authority_granted": True, "actor_ref": _PROVIDER},
                    actor_refs=[_PROVIDER],
                )
            ],
        )
        exc = _assert_load_rejected_080(bundle)
        assert "authority_class" in exc.message
        assert "missing" in exc.message

    def test_empty_string_authority_class_rejected_at_load(self, tmp_path: Path) -> None:
        bundle = _write_bundle(
            tmp_path / "empty-string",
            manifest=_manifest((_PROVIDER, "provider")),
            records=[
                _disposition_record(
                    authority_check={
                        "authority_class": "",
                        "authority_granted": True,
                        "actor_ref": _PROVIDER,
                    },
                    actor_refs=[_PROVIDER],
                )
            ],
        )
        exc = _assert_load_rejected_080(bundle)
        assert "authority_class" in exc.message

    def test_non_string_authority_class_rejected_at_load(self, tmp_path: Path) -> None:
        bundle = _write_bundle(
            tmp_path / "non-string",
            manifest=_manifest((_PROVIDER, "provider")),
            records=[
                _disposition_record(
                    authority_check={
                        "authority_class": 42,
                        "authority_granted": True,
                        "actor_ref": _PROVIDER,
                    },
                    actor_refs=[_PROVIDER],
                )
            ],
        )
        exc = _assert_load_rejected_080(bundle)
        assert "authority_class" in exc.message

    def test_unrecognized_authority_class_rejected_at_load(self, tmp_path: Path) -> None:
        """A non-empty string outside the five §14.5 classes must produce
        the PRECISE 'unrecognized authority_class' rejection at load."""
        bundle = _write_bundle(
            tmp_path / "unrecognized",
            manifest=_manifest((_PROVIDER, "provider")),
            records=[
                _disposition_record(
                    authority_check={
                        "authority_class": "self_certified_blanket_waiver",
                        "authority_granted": True,
                        "actor_ref": _PROVIDER,
                    },
                    actor_refs=[_PROVIDER],
                )
            ],
        )
        exc = _assert_load_rejected_080(bundle)
        assert "unrecognized" in exc.message
        assert "self_certified_blanket_waiver" in exc.message


# ---------------------------------------------------------------------------
# VAL-FIX-AUTH-006 (loader mirror): EVERY entity_refs.actor_refs[] entry is
# evaluated when authority_check.actor_ref is absent — ANY denied or
# undeclared actor rejects the load.
# ---------------------------------------------------------------------------


class TestLoadEveryActorEvaluated:
    def test_denied_actor_hidden_behind_permitted_first_actor(self, tmp_path: Path) -> None:
        """roborev's exact exploit: deployer (permitted for
        accepted_risk_request) listed FIRST hides provider (DENIED) listed
        second — the loader currently resolves only actor_refs[0] and loads
        cleanly. Must raise LoadRejection(code='ACEF-080')."""
        bundle = _write_bundle(
            tmp_path / "ordering-bypass",
            manifest=_manifest((_DEPLOYER, "deployer"), (_PROVIDER, "provider")),
            records=[
                _disposition_record(
                    authority_check={
                        "authority_class": "accepted_risk_request",
                        "authority_granted": True,
                        # no actor_ref → fallback must check ALL actor_refs
                    },
                    actor_refs=[_DEPLOYER, _PROVIDER],
                )
            ],
        )
        exc = _assert_load_rejected_080(bundle)
        assert _AUTHORITY_PHRASE in exc.message
        assert _PROVIDER in exc.message
        assert "provider" in exc.message

    def test_undeclared_actor_in_fallback_list_rejected_at_load(self, tmp_path: Path) -> None:
        bundle = _write_bundle(
            tmp_path / "undeclared-second",
            manifest=_manifest((_DEPLOYER, "deployer")),
            records=[
                _disposition_record(
                    authority_check={
                        "authority_class": "accepted_risk_request",
                        "authority_granted": True,
                    },
                    actor_refs=[_DEPLOYER, _UNDECLARED],
                )
            ],
        )
        exc = _assert_load_rejected_080(bundle)
        assert _UNDECLARED in exc.message
        assert "not declared" in exc.message

    def test_explicit_denied_actor_ref_still_rejected_at_load(self, tmp_path: Path) -> None:
        """Explicit actor_ref keeps single-actor semantics — and a denied
        explicit claim still rejects."""
        bundle = _write_bundle(
            tmp_path / "explicit-denied",
            manifest=_manifest((_DEPLOYER, "deployer"), (_PROVIDER, "provider")),
            records=[
                _disposition_record(
                    authority_check={
                        "authority_class": "accepted_risk_request",
                        "authority_granted": True,
                        "actor_ref": _PROVIDER,  # denied; explicit claim
                    },
                    actor_refs=[_DEPLOYER, _PROVIDER],
                )
            ],
        )
        exc = _assert_load_rejected_080(bundle)
        assert _AUTHORITY_PHRASE in exc.message
        assert _PROVIDER in exc.message

    def test_granted_with_no_resolvable_actor_rejected_at_load(self, tmp_path: Path) -> None:
        """No actor_ref AND no entity_refs.actor_refs: a granted disposition
        with no authorizing actor stays a §14.5 violation (fail closed)."""
        bundle = _write_bundle(
            tmp_path / "no-actor",
            manifest=_manifest((_DEPLOYER, "deployer")),
            records=[
                _disposition_record(
                    authority_check={
                        "authority_class": "accepted_risk_request",
                        "authority_granted": True,
                    },
                )
            ],
        )
        _assert_load_rejected_080(bundle)


# ---------------------------------------------------------------------------
# Legitimate skip paths preserved at the load() surface (positives).
# ---------------------------------------------------------------------------


class TestLoadLegitimateSkipsPreserved:
    def test_legit_granted_disposition_loads(self, tmp_path: Path) -> None:
        bundle = _write_bundle(
            tmp_path / "legit-granted",
            manifest=_manifest((_DEPLOYER, "deployer")),
            records=[
                _disposition_record(
                    authority_check={
                        "authority_class": "accepted_risk_request",
                        "authority_granted": True,
                        "actor_ref": _DEPLOYER,
                    },
                    actor_refs=[_DEPLOYER],
                )
            ],
        )
        assert load(str(bundle)) is not None

    def test_multi_actor_all_permitted_loads(self, tmp_path: Path) -> None:
        bundle = _write_bundle(
            tmp_path / "all-permitted",
            manifest=_manifest((_DEPLOYER, "deployer"), (_AUDITOR, "auditor")),
            records=[
                _disposition_record(
                    authority_check={
                        "authority_class": "priority",
                        "authority_granted": True,
                    },
                    actor_refs=[_DEPLOYER, _AUDITOR],
                )
            ],
        )
        assert load(str(bundle)) is not None

    def test_explicit_permitted_actor_ref_keeps_single_actor_semantics(self, tmp_path: Path) -> None:
        """An explicit authority_check.actor_ref is an explicit claim: only
        that actor is evaluated, even if a denied actor appears in
        entity_refs.actor_refs."""
        bundle = _write_bundle(
            tmp_path / "explicit-permitted",
            manifest=_manifest((_DEPLOYER, "deployer"), (_PROVIDER, "provider")),
            records=[
                _disposition_record(
                    authority_check={
                        "authority_class": "accepted_risk_request",
                        "authority_granted": True,
                        "actor_ref": _DEPLOYER,  # permitted; explicit claim
                    },
                    actor_refs=[_DEPLOYER, _PROVIDER],
                )
            ],
        )
        assert load(str(bundle)) is not None

    def test_no_authority_check_block_loads(self, tmp_path: Path) -> None:
        bundle = _write_bundle(
            tmp_path / "no-auth-block",
            manifest=_manifest((_PROVIDER, "provider")),
            records=[
                _disposition_record(authority_check=None, actor_refs=[_PROVIDER]),
            ],
        )
        assert load(str(bundle)) is not None

    def test_authority_granted_false_loads(self, tmp_path: Path) -> None:
        bundle = _write_bundle(
            tmp_path / "granted-false",
            manifest=_manifest((_PROVIDER, "provider")),
            records=[
                _disposition_record(
                    authority_check={
                        "authority_class": "accepted_risk_request",
                        "authority_granted": False,
                        "actor_ref": _PROVIDER,
                    },
                    actor_refs=[_PROVIDER],
                )
            ],
        )
        assert load(str(bundle)) is not None

    def test_authority_granted_absent_with_typo_class_loads(self, tmp_path: Path) -> None:
        """No authority_granted key = no authority claimed = legitimate
        skip, even with a typo'd/absent authority_class."""
        bundle = _write_bundle(
            tmp_path / "granted-absent",
            manifest=_manifest((_PROVIDER, "provider")),
            records=[
                _disposition_record(
                    authority_check={"authority_clas": "accepted_risk_request"},
                    actor_refs=[_PROVIDER],
                )
            ],
        )
        assert load(str(bundle)) is not None
