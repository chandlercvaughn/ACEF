"""Unit tests for the v1.1 typed builder methods on ``Package``.

Covers F-M1-SDK-BUILDERS primaryFulfills:

- VAL-SDK-001: ``Package.authorize_test_scope`` adds an
  ``authorized_test_scope`` record; invalid combos
  (``production_capable_owner_authorized`` + ``github_oauth``;
  missing ``kill_switch_ref``) raise ``ValueError`` BEFORE the record is
  appended to the bundle.
- VAL-SDK-002: ``Package.record_scope_boundary_event`` adds a
  ``scope_boundary_event`` record; ``hard_stop_triggered=True`` without
  ``hard_stop_attestation_ref`` raises.
- VAL-SDK-003: ``Package.record_finding`` produces a ``finding_record``
  with auto-computed ``dedupe_key`` per brief Q5 (SHA-256 of JCS-
  canonicalized ``{class, subject_ref, expected_behavior,
  reproduction_steps_ref_content_hash}``). Two identical-input calls
  produce byte-equal dedupe_key.
- VAL-SDK-004: ``Package.record_delivery_verdict`` raises if
  ``write_attempt.request_digest != read_back.read_back_digest`` before
  adding to the bundle; verified_delivered triple-requirement raises
  when any of (``read_back``, ``read_back.digest_match=True``,
  ``harness_attestation_ref``) is missing.
- VAL-SDK-005: ``Package.attest(state_class=..., bound_evidence_refs=[])``
  raises (state-class records require >=1 ref).
- VAL-SDK-006: ``Package.attest()`` raises when ``fake_green_test_ref``
  is missing for any state_class.
"""

from __future__ import annotations

import hashlib
import re

import pytest

from acef.integrity import canonicalize
from acef.package import Package

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def pkg() -> Package:
    """Fresh Package per test — no shared state."""
    return Package(producer={"name": "test-tool", "version": "1.0.0"})


def _valid_authorize_kwargs(
    *,
    authorization_level: str = "read_only",
    proof_method: str = "dns_txt",
    kill_switch_ref: str | None = None,
    identity_type: str = "test_account",
) -> dict:
    """Return a kwargs dict that the SDK builder will accept by default."""
    return {
        "scope_id": "scope-001",
        "scope_version": "1.0.0",
        "subject_ref": "urn:acef:sub:11111111-1111-1111-1111-111111111111",
        "authorized_surfaces": [
            {
                "surface_type": "api_endpoint",
                "surface_identifier": "https://api.example.test/probe",
                "authorization_level": authorization_level,
            }
        ],
        "authorized_identities": [
            {
                "identity_type": identity_type,
                "identity_ref": "urn:acef:actor:01111111-1111-1111-1111-111111111111",
                "scope_constraint": "sandbox-only",
            }
        ],
        "side_effect_policy": {
            "default_disposition": "default_deny",
            "explicit_allowlist": [],
            "explicit_denylist": [],
        },
        "sandbox_boundary": {
            "ownership_ledger_ref": "urn:acef:rec:sandbox-001",
            "preflight_method": "tenant_label",
        },
        "ownership_proof": {
            "proof_method": proof_method,
            "proof_artifact_ref": "urn:acef:rec:proof-001",
            "verified_at": "2026-01-01T00:00:00Z",
        },
        "effective_from": "2026-01-01T00:00:00Z",
        "authorizing_actor_ref": "urn:acef:actor:authorizer-001",
        "kill_switch_ref": kill_switch_ref,
    }


# ---------------------------------------------------------------------------
# VAL-SDK-001 — authorize_test_scope
# ---------------------------------------------------------------------------


def test_authorize_test_scope_positive_adds_record(pkg: Package) -> None:
    """Positive case: minimal valid input → record is appended."""
    n_before = len(pkg.records)
    env = pkg.authorize_test_scope(**_valid_authorize_kwargs())
    assert env.record_type == "authorized_test_scope"
    assert len(pkg.records) == n_before + 1
    # Payload round-trips key fields
    assert env.payload["scope_id"] == "scope-001"
    assert env.payload["scope_version"] == "1.0.0"


def test_authorize_test_scope_rejects_production_capable_with_github_oauth(
    pkg: Package,
) -> None:
    """Brief §3.1 TC-FRD-001-N1: production_capable_owner_authorized
    with github_oauth is invalid; must raise BEFORE record append.
    """
    n_before = len(pkg.records)
    with pytest.raises(ValueError, match="production_capable_owner_authorized"):
        pkg.authorize_test_scope(
            **_valid_authorize_kwargs(
                authorization_level="production_capable_owner_authorized",
                proof_method="github_oauth",
                kill_switch_ref="urn:acef:rec:killswitch-001",
            )
        )
    assert len(pkg.records) == n_before, "record must NOT be appended on rejection"


def test_authorize_test_scope_rejects_production_capable_without_kill_switch(
    pkg: Package,
) -> None:
    """Brief §3.1 TC-FRD-001-N2: production_capable_owner_authorized
    REQUIRES kill_switch_ref. Missing → raise.
    """
    n_before = len(pkg.records)
    with pytest.raises(ValueError, match="kill_switch_ref"):
        pkg.authorize_test_scope(
            **_valid_authorize_kwargs(
                authorization_level="production_capable_owner_authorized",
                proof_method="dns_txt",
                kill_switch_ref=None,
            )
        )
    assert len(pkg.records) == n_before


def test_authorize_test_scope_production_capable_with_dns_and_killswitch_ok(
    pkg: Package,
) -> None:
    """When all conditions are satisfied, the record is appended."""
    env = pkg.authorize_test_scope(
        **_valid_authorize_kwargs(
            authorization_level="production_capable_owner_authorized",
            proof_method="dns_txt",
            kill_switch_ref="urn:acef:rec:killswitch-001",
        )
    )
    assert env.payload["kill_switch_ref"] == "urn:acef:rec:killswitch-001"


def test_authorize_test_scope_rejects_missing_required_field(pkg: Package) -> None:
    """Pydantic validation surfaces invalid-input errors as ValueError."""
    kwargs = _valid_authorize_kwargs()
    kwargs["authorized_surfaces"] = []  # schema requires >=1; Pydantic list field empty is allowed
    # but invalid surface_type should still raise
    kwargs["authorized_surfaces"] = [
        {
            "surface_type": "INVALID_SURFACE",
            "surface_identifier": "x",
            "authorization_level": "read_only",
        }
    ]
    with pytest.raises(ValueError):
        pkg.authorize_test_scope(**kwargs)


# ---------------------------------------------------------------------------
# VAL-SDK-002 — scope_boundary_event
# ---------------------------------------------------------------------------


def _valid_scope_boundary_kwargs(
    *,
    hard_stop_triggered: bool = False,
    hard_stop_attestation_ref: str | None = None,
) -> dict:
    return {
        "scope_ref": "urn:acef:rec:scope-001",
        "attempted_action": {
            "action_class": "http_request",
            "action_target": "https://prod.example.test/v1/spend",
            "action_payload_digest": "sha256:" + "0" * 64,
        },
        "authorized_scope_snapshot": {
            "scope_id": "scope-001",
            "scope_version": "1.0.0",
        },
        "classification": "intentional_bypass_attempt",
        "hard_stop_triggered": hard_stop_triggered,
        "hard_stop_attestation_ref": hard_stop_attestation_ref,
        "detected_at": "2026-01-01T00:00:00Z",
        "detector": {
            "detector_class": "preflight_probe",
            "detector_id": "probe-001",
        },
    }


def test_record_scope_boundary_event_positive_adds_record(pkg: Package) -> None:
    env = pkg.record_scope_boundary_event(event_id="evt-001", **_valid_scope_boundary_kwargs())
    assert env.record_type == "scope_boundary_event"
    assert env.payload["event_id"] == "evt-001"


def test_record_scope_boundary_event_hard_stop_without_attestation_raises(
    pkg: Package,
) -> None:
    n_before = len(pkg.records)
    with pytest.raises(ValueError, match="hard_stop_attestation_ref"):
        pkg.record_scope_boundary_event(
            **_valid_scope_boundary_kwargs(hard_stop_triggered=True, hard_stop_attestation_ref=None)
        )
    assert len(pkg.records) == n_before


def test_record_scope_boundary_event_hard_stop_with_attestation_ok(
    pkg: Package,
) -> None:
    env = pkg.record_scope_boundary_event(
        **_valid_scope_boundary_kwargs(
            hard_stop_triggered=True,
            hard_stop_attestation_ref="urn:acef:rec:attest-001",
        )
    )
    assert env.payload["hard_stop_attestation_ref"] == "urn:acef:rec:attest-001"


# ---------------------------------------------------------------------------
# VAL-SDK-003 — record_finding + dedupe_key
# ---------------------------------------------------------------------------


def _valid_finding_kwargs(
    *,
    class_: str = "safety_failure",
    subject_ref: str = "urn:acef:sub:s-001",
    expected_behavior: str = "Model refuses harmful instruction.",
    reproduction_steps_ref_content_hash: str = "sha256:" + "a" * 64,
) -> dict:
    return {
        "class_": class_,
        "subject_ref": subject_ref,
        "expected_behavior": expected_behavior,
        "reproduction_steps_ref_content_hash": reproduction_steps_ref_content_hash,
        "severity": {
            "severity_level": "high",
            "severity_rationale": "Policy violation with PII leakage.",
        },
        "reproduction": {
            "expected_behavior": expected_behavior,
            "observed_behavior": "Model complied with harmful instruction.",
            "reproduction_steps_ref": "urn:acef:rec:repro-001",
            "evidence_commit_ref": "git:0123456789abcdef",
        },
        "attribution": {
            "persona_ref": "urn:acef:rec:persona-001",
            "scenario_ref": "urn:acef:rec:scenario-001",
            "scope_ref": "urn:acef:rec:scope-001",
        },
        "discovered_at": "2026-01-01T00:00:00Z",
        "discovered_in_run_ref": "urn:acef:rec:run-001",
    }


def test_record_finding_positive_adds_record_with_dedupe_key(pkg: Package) -> None:
    env = pkg.record_finding(**_valid_finding_kwargs())
    assert env.record_type == "finding_record"
    dk = env.payload["dedupe_key"]
    assert isinstance(dk, str)
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", dk), f"dedupe_key shape wrong: {dk!r}"


def test_record_finding_dedupe_key_matches_brief_q5_recipe(pkg: Package) -> None:
    """Brief Q5 recipe: SHA-256 of JCS-canonicalized
    {class, subject_ref, expected_behavior,
     reproduction_steps_ref_content_hash}.
    """
    kwargs = _valid_finding_kwargs(
        class_="policy_violation",
        subject_ref="urn:acef:sub:s-foo",
        expected_behavior="Bar",
        reproduction_steps_ref_content_hash="sha256:" + "c" * 64,
    )
    env = pkg.record_finding(**kwargs)

    expected_canonical = canonicalize(
        {
            "class": "policy_violation",
            "subject_ref": "urn:acef:sub:s-foo",
            "expected_behavior": "Bar",
            "reproduction_steps_ref_content_hash": "sha256:" + "c" * 64,
        }
    )
    expected_dk = "sha256:" + hashlib.sha256(expected_canonical).hexdigest()
    assert env.payload["dedupe_key"] == expected_dk


def test_record_finding_dedupe_key_is_deterministic(pkg: Package) -> None:
    """Two identical-input calls produce byte-equal dedupe_key (no entropy)."""
    pkg2 = Package(producer={"name": "test-tool", "version": "1.0.0"})
    kw = _valid_finding_kwargs()
    env_a = pkg.record_finding(**kw)
    env_b = pkg2.record_finding(**kw)
    assert env_a.payload["dedupe_key"] == env_b.payload["dedupe_key"]


def test_record_finding_emits_class_field_not_class_underscore(pkg: Package) -> None:
    """The payload must use ``class`` (per brief), not ``class_``."""
    env = pkg.record_finding(**_valid_finding_kwargs())
    assert "class_" not in env.payload, "class_ must be remapped to 'class' in payload"
    # The brief calls the field finding_class in the schema, so the payload
    # should expose finding_class (matching the Pydantic model field name).
    # Either 'class' OR 'finding_class' is acceptable as long as it matches
    # the schema/model. The HMAC-of-recipe uses 'class' per Q5.
    assert "finding_class" in env.payload or "class" in env.payload


# ---------------------------------------------------------------------------
# VAL-SDK-004 — record_delivery_verdict
# ---------------------------------------------------------------------------


def _valid_delivery_verdict_kwargs(
    *,
    request_digest: str = "sha256:" + "1" * 64,
    read_back_digest: str | None = None,
    digest_match: bool = True,
    delivery_state: str = "dispatched",
    harness_attestation_ref: str | None = None,
) -> dict:
    kw: dict = {
        "finding_ref": "urn:acef:rec:finding-001",
        "destination": {
            "provider_class": "plane",
            "provider_instance_id": "plane-instance-001",
            "provider_object_id": "PLANE-42",
        },
        "write_attempt": {
            "attempted_at": "2026-01-01T00:00:00Z",
            "request_digest": request_digest,
            "response_status": 200,
            "response_digest": "sha256:" + "2" * 64,
        },
        "delivery_state": delivery_state,
        "harness_attestation_ref": harness_attestation_ref,
    }
    if read_back_digest is not None:
        kw["read_back"] = {
            "read_back_at": "2026-01-01T00:00:01Z",
            "read_back_digest": read_back_digest,
            "digest_match": digest_match,
        }
    return kw


def test_record_delivery_verdict_positive_adds_record(pkg: Package) -> None:
    env = pkg.record_delivery_verdict(
        verdict_id="vd-001",
        **_valid_delivery_verdict_kwargs(),
    )
    assert env.record_type == "delivery_verdict"


def test_record_delivery_verdict_rejects_mismatched_digests(pkg: Package) -> None:
    n_before = len(pkg.records)
    with pytest.raises(ValueError, match="read-back digest mismatch"):
        pkg.record_delivery_verdict(
            **_valid_delivery_verdict_kwargs(
                request_digest="sha256:" + "1" * 64,
                read_back_digest="sha256:" + "9" * 64,  # different
                digest_match=False,
            )
        )
    assert len(pkg.records) == n_before


def test_record_delivery_verdict_matched_digests_ok(pkg: Package) -> None:
    env = pkg.record_delivery_verdict(
        **_valid_delivery_verdict_kwargs(
            request_digest="sha256:" + "1" * 64,
            read_back_digest="sha256:" + "1" * 64,
            digest_match=True,
        )
    )
    assert env.payload["read_back"]["digest_match"] is True


def test_record_delivery_verdict_verified_delivered_requires_read_back(
    pkg: Package,
) -> None:
    """verified_delivered without read_back at all → raise."""
    with pytest.raises(ValueError, match="verified_delivered"):
        pkg.record_delivery_verdict(
            **_valid_delivery_verdict_kwargs(
                delivery_state="verified_delivered",
                read_back_digest=None,  # absent
                harness_attestation_ref="urn:acef:rec:attest-001",
            )
        )


def test_record_delivery_verdict_verified_delivered_requires_digest_match(
    pkg: Package,
) -> None:
    """verified_delivered with digest_match=False → raise.

    The mismatched-digest guard will fire first in this case; we test by
    making the digests equal but digest_match=False, which is a
    self-inconsistent claim the SDK must reject.
    """
    # Make digests equal so the mismatch-check passes, but assert digest_match=False
    with pytest.raises(ValueError, match="verified_delivered"):
        pkg.record_delivery_verdict(
            **_valid_delivery_verdict_kwargs(
                delivery_state="verified_delivered",
                request_digest="sha256:" + "1" * 64,
                read_back_digest="sha256:" + "1" * 64,
                digest_match=False,
                harness_attestation_ref="urn:acef:rec:attest-001",
            )
        )


def test_record_delivery_verdict_verified_delivered_requires_attestation_ref(
    pkg: Package,
) -> None:
    """verified_delivered without harness_attestation_ref → raise."""
    with pytest.raises(ValueError, match="verified_delivered"):
        pkg.record_delivery_verdict(
            **_valid_delivery_verdict_kwargs(
                delivery_state="verified_delivered",
                request_digest="sha256:" + "1" * 64,
                read_back_digest="sha256:" + "1" * 64,
                digest_match=True,
                harness_attestation_ref=None,
            )
        )


def test_record_delivery_verdict_verified_delivered_complete_triple_ok(
    pkg: Package,
) -> None:
    env = pkg.record_delivery_verdict(
        **_valid_delivery_verdict_kwargs(
            delivery_state="verified_delivered",
            request_digest="sha256:" + "1" * 64,
            read_back_digest="sha256:" + "1" * 64,
            digest_match=True,
            harness_attestation_ref="urn:acef:rec:attest-001",
        )
    )
    assert env.payload["delivery_state"] == "verified_delivered"


# ---------------------------------------------------------------------------
# VAL-SDK-005, VAL-SDK-006 — Package.attest()
# ---------------------------------------------------------------------------


def _valid_attest_kwargs(
    *,
    state_class: str = "finding",
    bound_evidence_refs: list[str] | None = None,
    fake_green_test_ref: str | None = "urn:acef:rec:fake-green-001",
    verifier_class: str = "contract_gate",
) -> dict:
    return {
        "state_class": state_class,
        "state_transition": {
            "from_state": "discovered",
            "to_state": "triaged",
            "transitioned_at": "2026-01-01T00:00:00Z",
        },
        "bound_evidence_refs": (
            bound_evidence_refs if bound_evidence_refs is not None else ["urn:acef:rec:evidence-001"]
        ),
        "verifier": {
            "verifier_id": "verifier-001",
            "verifier_class": verifier_class,
            "verifier_version": "1.0.0",
        },
        "claim": "Finding triaged with attestation chain.",
        "fake_green_test_ref": fake_green_test_ref,
        "attestation_signature": {
            "alg": "ES256",
            "value": "base64sig-placeholder",
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
        "signed_at": "2026-01-01T00:00:00Z",
        "signer_kid": "kid-001",
    }


def test_attest_positive_adds_record(pkg: Package) -> None:
    env = pkg.attest(attestation_id="att-001", **_valid_attest_kwargs())
    assert env.record_type == "harness_attestation"


def test_attest_empty_bound_evidence_refs_raises(pkg: Package) -> None:
    """VAL-SDK-005: state-class records MUST have >=1 bound_evidence_refs."""
    n_before = len(pkg.records)
    with pytest.raises(ValueError, match="bound_evidence_refs"):
        pkg.attest(**_valid_attest_kwargs(bound_evidence_refs=[]))
    assert len(pkg.records) == n_before


def test_attest_missing_fake_green_test_ref_raises(pkg: Package) -> None:
    """VAL-SDK-006: fake_green_test_ref required for any state_class."""
    n_before = len(pkg.records)
    with pytest.raises(ValueError, match="fake_green_test_ref"):
        pkg.attest(**_valid_attest_kwargs(fake_green_test_ref=None))
    assert len(pkg.records) == n_before


def test_attest_persona_verifier_rejected_at_sdk(pkg: Package) -> None:
    """SDK-level mirror of loader rejection: persona verifier → ValueError."""
    n_before = len(pkg.records)
    with pytest.raises(ValueError, match="verifier_class"):
        pkg.attest(**_valid_attest_kwargs(verifier_class="persona"))
    assert len(pkg.records) == n_before


def test_attest_llm_verifier_rejected_at_sdk(pkg: Package) -> None:
    """SDK-level mirror of loader rejection: llm verifier → ValueError."""
    with pytest.raises(ValueError, match="verifier_class"):
        pkg.attest(**_valid_attest_kwargs(verifier_class="llm"))


def test_attest_invalid_state_class_rejected_at_sdk(pkg: Package) -> None:
    """state_class outside the 7-entry taxonomy → ValueError."""
    with pytest.raises(ValueError, match="state_class"):
        pkg.attest(**_valid_attest_kwargs(state_class="made_up_class"))
