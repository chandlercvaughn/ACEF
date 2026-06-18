"""Fresh systems committee (CONF-C-HARNESS-SIG-UNVERIFIED / TC9 @905302e): the
``harness_attestation.attestation_signature`` MUST be cryptographically verified
on the validate path. Before the fix it was never verified — a forged or tampered
signature validated clean (``verify_harness_attestation`` was dead code).

These drive the real validation entry point ``run_cross_record_validation`` and
assert the ACEF-012 negative path, the gap the isolated signing-helper tests
(``test_signatures_harness_attestation.py``) could not catch.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from acef.signing import HARNESS_ATTESTATION_SIGNED_FIELDS, sign_harness_attestation
from acef.validation.cross_record import run_cross_record_validation

_MANIFEST: dict[str, Any] = {"metadata": {}}


@pytest.fixture(scope="module")
def rsa_key() -> Any:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _signed_harness_record(key: Any, *, signer_kid: str = "harness-kid-1") -> dict[str, Any]:
    nine = {
        "attestation_id": "urn:acef:att:11111111-1111-4111-8111-111111111111",
        "state_class": "delivery",
        "state_transition": {
            "from_state": "pending",
            "to_state": "verified",
            "transitioned_at": "2026-05-27T12:00:00Z",
        },
        "bound_evidence_refs": ["urn:acef:rec:22222222-2222-4222-8222-222222222222"],
        "verifier": {
            "verifier_id": "urn:acef:actor:70",
            "verifier_class": "contract_gate",
            "verifier_version": "1.0.0",
        },
        "claim": "delivery.pending.verified:ok",
        "fake_green_test_ref": "urn:acef:fg:1",
        "signed_at": "2026-05-27T12:00:01Z",
        "signer_kid": signer_kid,
    }
    jws = sign_harness_attestation(nine, private_key=key, signer_kid=signer_kid)
    payload = {
        **nine,
        "attestation_signature": {
            "alg": "RS256",
            "value": jws,
            "signed_fields": list(HARNESS_ATTESTATION_SIGNED_FIELDS),
        },
    }
    return {"record_type": "harness_attestation", "record_id": "urn:acef:rec:30", "payload": payload}


def _has_012_or_013(diags: list[Any]) -> bool:
    return any(d.code in ("ACEF-012", "ACEF-013") for d in diags)


def test_validly_signed_harness_attestation_passes(rsa_key: Any) -> None:
    """A correctly RS256-signed harness_attestation produces no signature diagnostic."""
    rec = _signed_harness_record(rsa_key)
    diags = run_cross_record_validation(_MANIFEST, [rec], signature_count=0)
    assert not _has_012_or_013(diags), [d.code for d in diags]


def test_forged_signature_value_rejected(rsa_key: Any) -> None:
    """The committee's exact reproduction: a garbage (non-JWS) attestation_signature
    value must be rejected (ACEF-012), not validate clean."""
    rec = _signed_harness_record(rsa_key)
    rec["payload"]["attestation_signature"]["value"] = "this-is-not-a-jws-at-all-totally-forged"
    diags = run_cross_record_validation(_MANIFEST, [rec], signature_count=0)
    assert any(d.code == "ACEF-012" for d in diags), [d.code for d in diags]


def test_tc9_tampered_bound_evidence_ref_rejected(rsa_key: Any) -> None:
    """TC9 (brief :591): altering a bound_evidence_ref AFTER signing MUST cause
    signature verification failure (ACEF-012), not merely a hash-comparison failure."""
    rec = _signed_harness_record(rsa_key)
    rec["payload"]["bound_evidence_refs"] = ["urn:acef:rec:99999999-9999-4999-8999-999999999999"]
    diags = run_cross_record_validation(_MANIFEST, [rec], signature_count=0)
    assert any(d.code == "ACEF-012" for d in diags), [d.code for d in diags]


def test_tampered_claim_rejected(rsa_key: Any) -> None:
    """Tampering any signed field (here ``claim``) breaks verification."""
    rec = _signed_harness_record(rsa_key)
    rec["payload"]["claim"] = "delivery.pending.verified:TAMPERED"
    diags = run_cross_record_validation(_MANIFEST, [rec], signature_count=0)
    assert any(d.code == "ACEF-012" for d in diags), [d.code for d in diags]


def test_wrong_signed_fields_scope_rejected(rsa_key: Any) -> None:
    """A signed_fields scope narrower than the required 9 fields is rejected
    (VAL-SIGNATURE-001) — the signature attests less than the record claims."""
    rec = _signed_harness_record(rsa_key)
    rec["payload"]["attestation_signature"]["signed_fields"] = ["attestation_id"]
    diags = run_cross_record_validation(_MANIFEST, [rec], signature_count=0)
    assert any(d.code == "ACEF-012" for d in diags), [d.code for d in diags]
