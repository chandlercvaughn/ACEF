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


def test_signed_fields_non_list_is_structured_not_typeerror(rsa_key: Any) -> None:
    """roborev Medium on d33d239: a non-list signed_fields (e.g. 5) must produce a
    structured ACEF-012, not a TypeError that the ACEF-001 backstop swallows."""
    rec = _signed_harness_record(rsa_key)
    rec["payload"]["attestation_signature"]["signed_fields"] = 5  # malformed JSON value
    diags = run_cross_record_validation(_MANIFEST, [rec], signature_count=0)  # must not raise
    assert any(d.code == "ACEF-012" for d in diags), [d.code for d in diags]


def test_anchored_mode_rejects_jwk_only_attestation(rsa_key: Any) -> None:
    """roborev High on d33d239: when trust_anchors are configured the validate path
    must NOT silently self-attest — a jwk-only attestation (no x5c chain to an
    anchor) does NOT verify, closing the re-signing-attacker bypass for callers who
    supply trust material. Without anchors it is self-attested (tamper-evidence
    only) and passes; with anchors it requires an anchored x5c chain."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    rec = _signed_harness_record(rsa_key)
    # No anchors -> self-attested -> passes (the offline default).
    assert not any(
        d.code in ("ACEF-012", "ACEF-013") for d in run_cross_record_validation(_MANIFEST, [rec], signature_count=0)
    )
    # Anchors configured -> jwk-only attestation is not anchored -> ACEF-012.
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "harness-anchor")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    diags = run_cross_record_validation(_MANIFEST, [rec], signature_count=0, trust_anchors=[ca])
    assert any(d.code in ("ACEF-012", "ACEF-013") for d in diags), [d.code for d in diags]


def test_jwk_only_attestation_rejected_with_empty_anchor_list(rsa_key: Any) -> None:
    """roborev Low on 18fbd98: an EMPTY trust-anchor list (non-None) is an explicit
    anchoring request — a jwk-only harness attestation must emit ACEF-012 through the
    real run_cross_record_validation path (fail closed)."""
    rec = _signed_harness_record(rsa_key)  # jwk-only (no x5c)
    diags = run_cross_record_validation(_MANIFEST, [rec], signature_count=0, trust_anchors=[])
    assert any(d.code in ("ACEF-012", "ACEF-013") for d in diags), [d.code for d in diags]


def _x5c_harness_record(nvb: Any, nva: Any) -> tuple[dict[str, Any], Any]:
    """A harness_attestation record whose attestation_signature is an x5c chain
    (root CA + leaf); returns (record, root_cert) for anchoring."""
    import base64

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from acef.integrity import canonicalize
    from acef.signing import HARNESS_ATTESTATION_SIGNED_FIELDS, create_detached_jws

    root_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hx-root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nvb)
        .not_valid_after(nva)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hx-leaf")]))
        .issuer_name(root.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nvb)
        .not_valid_after(nva)
        .sign(root_key, hashes.SHA256())
    )

    def _b64(c: Any) -> str:
        return base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode("ascii")

    nine = {
        "attestation_id": "urn:acef:att:11111111-1111-4111-8111-111111111111",
        "state_class": "delivery",
        "state_transition": {
            "from_state": "pending",
            "to_state": "verified",
            "transitioned_at": "2025-01-01T00:00:00Z",
        },
        "bound_evidence_refs": ["urn:acef:rec:22222222-2222-4222-8222-222222222222"],
        "verifier": {
            "verifier_id": "urn:acef:actor:70",
            "verifier_class": "contract_gate",
            "verifier_version": "1.0.0",
        },
        "claim": "delivery.pending.verified:ok",
        "fake_green_test_ref": "urn:acef:fg:1",
        "signed_at": "2025-01-01T00:00:01Z",
        "signer_kid": "hx-leaf-kid",
    }
    subset = {f: nine[f] for f in HARNESS_ATTESTATION_SIGNED_FIELDS if f in nine}
    jws = create_detached_jws(canonicalize(subset), leaf_key, kid="hx-leaf-kid", x5c=[_b64(leaf), _b64(root)])
    payload = {
        **nine,
        "attestation_signature": {
            "alg": "ES256",
            "value": jws,
            "signed_fields": list(HARNESS_ATTESTATION_SIGNED_FIELDS),
        },
    }
    rec = {"record_type": "harness_attestation", "record_id": "urn:acef:rec:30", "payload": payload}
    return rec, root


def test_expired_x5c_harness_attestation_rejected_at_manifest_timestamp() -> None:
    """roborev Low on 18fbd98: an EXPIRED x5c harness attestation must emit ACEF-012
    through run_cross_record_validation, with validity anchored to
    manifest.metadata.timestamp (NOT wall-clock)."""
    import datetime

    window_start = datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC)
    window_end = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    rec, root = _x5c_harness_record(window_start, window_end)

    # manifest timestamp INSIDE the window + anchored -> no signature diagnostic.
    manifest_ok = {"metadata": {"timestamp": "2025-06-01T00:00:00Z"}}
    diags_ok = run_cross_record_validation(manifest_ok, [rec], signature_count=0, trust_anchors=[root])
    assert not any(d.code in ("ACEF-012", "ACEF-013") for d in diags_ok), [d.code for d in diags_ok]

    # manifest timestamp AFTER expiry -> ACEF-012 (cert expired at the manifest time).
    manifest_expired = {"metadata": {"timestamp": "2027-06-01T00:00:00Z"}}
    diags_exp = run_cross_record_validation(manifest_expired, [rec], signature_count=0, trust_anchors=[root])
    assert any(d.code in ("ACEF-012", "ACEF-013") for d in diags_exp), [d.code for d in diags_exp]
