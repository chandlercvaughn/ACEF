"""Tests for harness_attestation signature scope (VAL-SIGNATURE-001..004).

Per the contract (`contract.md` §SIGNATURE), a `harness_attestation` JWS
signature MUST cover EXACTLY these nine fields, in this order:

    attestation_id, state_class, state_transition, bound_evidence_refs,
    verifier, claim, fake_green_test_ref, signed_at, signer_kid

The signature scope is normative — fields outside the envelope are
explicitly untrusted (verifier MUST NOT rely on them), and tampering ANY
field inside MUST invalidate verification. The whitelist of allowed JWS
algorithms is {RS256, ES256}; any other algorithm emits ACEF-013.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from acef.errors import ACEFSigningError
from acef.signing import (
    HARNESS_ATTESTATION_SIGNED_FIELDS,
    sign_harness_attestation,
    verify_harness_attestation,
)

# ---------- fixtures ----------


@pytest.fixture
def rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture
def ec_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def _attestation_payload(**overrides):
    """Construct a fully-populated harness_attestation payload dict.

    Returns the inner payload (post-envelope) — the dict whose 9 fields
    listed in HARNESS_ATTESTATION_SIGNED_FIELDS form the signing scope.
    """
    base = {
        "attestation_id": "urn:acef:rec:11111111-1111-4111-8111-111111111111",
        "state_class": "finding",
        "state_transition": {
            "from_state": "open",
            "to_state": "verified",
            "transitioned_at": "2026-05-27T12:00:00Z",
        },
        "bound_evidence_refs": [
            "urn:acef:rec:22222222-2222-4222-8222-222222222222",
            "urn:acef:rec:33333333-3333-4333-8333-333333333333",
        ],
        "verifier": {
            "verifier_id": "contract-gate-v3",
            "verifier_class": "contract_gate",
            "verifier_version": "3.0.1",
        },
        "claim": "finding-marked-verified-on-read-back",
        "fake_green_test_ref": "urn:acef:rec:44444444-4444-4444-8444-444444444444",
        "signed_at": "2026-05-27T12:00:01Z",
        "signer_kid": "harness-kid-1",
    }
    base.update(overrides)
    return base


# ---------- VAL-SIGNATURE-001 ----------


def test_signed_fields_constant_matches_normative_list():
    """The exported constant is the 9-field list in the documented order."""
    assert HARNESS_ATTESTATION_SIGNED_FIELDS == (
        "attestation_id",
        "state_class",
        "state_transition",
        "bound_evidence_refs",
        "verifier",
        "claim",
        "fake_green_test_ref",
        "signed_at",
        "signer_kid",
    )


def test_val_signature_001_outside_field_tamper_does_not_invalidate(rsa_keys):
    """VAL-SIGNATURE-001: tampering OUTSIDE the 9-field envelope does NOT
    invalidate the signature."""
    private_key, public_key = rsa_keys
    payload = _attestation_payload()
    # Add a decorative vendor-prefixed field outside the signed envelope.
    payload["x-test/decorative"] = "original"
    payload["extra_top_level"] = 7

    sig = sign_harness_attestation(payload, private_key=private_key, signer_kid="harness-kid-1")

    # Mutate ONLY the unsigned decorative fields.
    payload["x-test/decorative"] = "tampered"
    payload["extra_top_level"] = 99

    # Verification MUST still succeed because the signature covers exactly
    # the 9 normative fields (none of which were touched).
    assert verify_harness_attestation(payload, sig, public_key=public_key) is True


def test_val_signature_001_inside_field_tamper_invalidates(rsa_keys):
    """VAL-SIGNATURE-001: tampering an INSIDE field (attestation_id) MUST
    invalidate the signature."""
    private_key, public_key = rsa_keys
    payload = _attestation_payload()
    sig = sign_harness_attestation(payload, private_key=private_key, signer_kid="harness-kid-1")

    # Mutate attestation_id (an inside field).
    payload["attestation_id"] = "urn:acef:rec:99999999-9999-4999-8999-999999999999"

    assert verify_harness_attestation(payload, sig, public_key=public_key) is False


def test_val_signature_001_works_with_es256(ec_keys):
    """The signature scope contract holds for ES256 as well as RS256."""
    private_key, public_key = ec_keys
    payload = _attestation_payload()
    payload["x-vendor/note"] = "untrusted"

    sig = sign_harness_attestation(payload, private_key=private_key, signer_kid="harness-kid-1")

    payload["x-vendor/note"] = "still untrusted, still ignored"
    assert verify_harness_attestation(payload, sig, public_key=public_key) is True

    payload["claim"] = "different-claim"
    assert verify_harness_attestation(payload, sig, public_key=public_key) is False


# ---------- VAL-SIGNATURE-002 ----------


def test_val_signature_002_swap_bound_evidence_ref_invalidates(rsa_keys):
    """VAL-SIGNATURE-002: swapping a URN inside bound_evidence_refs
    invalidates the signature."""
    private_key, public_key = rsa_keys
    payload = _attestation_payload()
    sig = sign_harness_attestation(payload, private_key=private_key, signer_kid="harness-kid-1")

    # Swap one of the URN entries.
    payload["bound_evidence_refs"] = [
        payload["bound_evidence_refs"][0],
        "urn:acef:rec:deadbeef-dead-4dea-8dea-deadbeefdead",
    ]

    assert verify_harness_attestation(payload, sig, public_key=public_key) is False


def test_val_signature_002_reorder_bound_evidence_refs_invalidates(rsa_keys):
    """Reordering bound_evidence_refs MUST also invalidate (list order is
    part of the signed scope)."""
    private_key, public_key = rsa_keys
    payload = _attestation_payload()
    sig = sign_harness_attestation(payload, private_key=private_key, signer_kid="harness-kid-1")

    # Reverse the list.
    payload["bound_evidence_refs"] = list(reversed(payload["bound_evidence_refs"]))

    assert verify_harness_attestation(payload, sig, public_key=public_key) is False


# ---------- VAL-SIGNATURE-003 ----------


def test_val_signature_003_tamper_verifier_id_invalidates(rsa_keys):
    """VAL-SIGNATURE-003: mutating verifier.verifier_id invalidates."""
    private_key, public_key = rsa_keys
    payload = _attestation_payload()
    sig = sign_harness_attestation(payload, private_key=private_key, signer_kid="harness-kid-1")

    payload["verifier"]["verifier_id"] = "rogue-verifier-v0"

    assert verify_harness_attestation(payload, sig, public_key=public_key) is False


def test_val_signature_003_tamper_verifier_subfield_invalidates(ec_keys):
    """Any nested mutation under `verifier` invalidates (the whole verifier
    object is in the signed scope)."""
    private_key, public_key = ec_keys
    payload = _attestation_payload()
    sig = sign_harness_attestation(payload, private_key=private_key, signer_kid="harness-kid-1")

    payload["verifier"]["verifier_version"] = "0.0.0-evil"

    assert verify_harness_attestation(payload, sig, public_key=public_key) is False


# ---------- VAL-SIGNATURE-004 ----------


def _forge_jws_with_alg(alg: str) -> str:
    """Build a syntactically valid JWS with a forbidden header alg, so the
    verify path is exercised against a non-whitelisted algorithm."""
    header = {"alg": alg, "kid": "evil-key"}
    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    h_b64 = base64.urlsafe_b64encode(header_json).rstrip(b"=").decode("ascii")
    # Detached JWS form: header..signature; signature bytes are arbitrary —
    # the alg check fires before any cryptographic verification.
    s_b64 = base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=").decode("ascii")
    return f"{h_b64}..{s_b64}"


def test_val_signature_004_hs256_rejected_with_acef_013(rsa_keys):
    """VAL-SIGNATURE-004: HS256 header is rejected with ACEF-013."""
    _, public_key = rsa_keys
    payload = _attestation_payload()
    forged = _forge_jws_with_alg("HS256")

    with pytest.raises(ACEFSigningError) as exc_info:
        verify_harness_attestation(payload, forged, public_key=public_key)
    assert exc_info.value.code == "ACEF-013"


def test_val_signature_004_eddsa_rejected_with_acef_013(rsa_keys):
    """VAL-SIGNATURE-004: EdDSA header is rejected with ACEF-013."""
    _, public_key = rsa_keys
    payload = _attestation_payload()
    forged = _forge_jws_with_alg("EdDSA")

    with pytest.raises(ACEFSigningError) as exc_info:
        verify_harness_attestation(payload, forged, public_key=public_key)
    assert exc_info.value.code == "ACEF-013"


def test_val_signature_004_none_rejected_with_acef_013(rsa_keys):
    """The infamous `alg: "none"` MUST also be rejected with ACEF-013."""
    _, public_key = rsa_keys
    payload = _attestation_payload()
    forged = _forge_jws_with_alg("none")

    with pytest.raises(ACEFSigningError) as exc_info:
        verify_harness_attestation(payload, forged, public_key=public_key)
    assert exc_info.value.code == "ACEF-013"


def test_val_signature_004_rs256_accepted(rsa_keys):
    """Positive control: RS256 is on the whitelist."""
    private_key, public_key = rsa_keys
    payload = _attestation_payload()
    sig = sign_harness_attestation(payload, private_key=private_key, signer_kid="harness-kid-1")
    assert verify_harness_attestation(payload, sig, public_key=public_key) is True


def test_val_signature_004_es256_accepted(ec_keys):
    """Positive control: ES256 is on the whitelist."""
    private_key, public_key = ec_keys
    payload = _attestation_payload()
    sig = sign_harness_attestation(payload, private_key=private_key, signer_kid="harness-kid-1")
    assert verify_harness_attestation(payload, sig, public_key=public_key) is True


# ---------- supplementary: subset projection semantics ----------


def test_missing_inside_field_is_signed_as_absent(rsa_keys):
    """If an optional-in-payload field (e.g., signer_kid) is absent from
    the payload at sign time, verify with same absent field still works,
    but verify with the field newly added (claim of presence) MUST fail.

    This protects against an attacker who, post-signature, drops a field
    in (or removes one) without re-signing.
    """
    private_key, public_key = rsa_keys
    payload = _attestation_payload()
    # Make a sparse payload: remove signer_kid before signing.
    del payload["signer_kid"]
    sig = sign_harness_attestation(payload, private_key=private_key, signer_kid="harness-kid-1")

    # Replay the verify path with the same absent field — passes.
    assert verify_harness_attestation(payload, sig, public_key=public_key) is True

    # Add signer_kid back — verification fails (field now claims a value
    # that wasn't covered by the original signature).
    payload["signer_kid"] = "harness-kid-1"
    assert verify_harness_attestation(payload, sig, public_key=public_key) is False


# ---------- PhD re-review CRYPTO-3: insecure-by-default keyless verification ----------
#
# verify_harness_attestation resolved the verification key from the JWS's OWN
# embedded jwk when no out-of-band key was supplied, with no signer_kid<->header
# kid binding and no trust-anchor path. An attacker who controls the payload can
# flip claim/state_class, re-sign with their own auto-embedded key, set the signed
# signer_kid to any value, and a KEYLESS verify returned True. The embedded-jwk-
# only path is self-attested, NOT forgery-resistant, so it must not be the
# silent default.


def test_crypto3_keyless_embedded_jwk_resign_attack_rejected(rsa_keys):
    """The committee's exact attack: re-sign a tampered payload with the
    attacker's own (auto-embedded) key. A KEYLESS verify MUST NOT return True."""
    attacker_key, _ = rsa_keys
    forged = _attestation_payload(claim="tests-NEVER-faked", state_class="passed", signer_kid="official-key")
    forged_sig = sign_harness_attestation(forged, private_key=attacker_key, signer_kid="official-key")
    with pytest.raises(ACEFSigningError) as exc:
        verify_harness_attestation(forged, forged_sig)
    assert exc.value.code == "ACEF-012"


def test_crypto3_out_of_band_key_still_verifies(rsa_keys):
    """An out-of-band public_key remains the secure path and still verifies a
    legitimate attestation (unchanged)."""
    private_key, public_key = rsa_keys
    payload = _attestation_payload()
    sig = sign_harness_attestation(payload, private_key=private_key, signer_kid="harness-kid-1")
    assert verify_harness_attestation(payload, sig, public_key=public_key) is True


def test_crypto3_self_attested_opt_in_verifies_legit(rsa_keys):
    """The embedded-jwk (self-attested) path is available only via an EXPLICIT
    allow_self_attested=True opt-in, by which the caller acknowledges it is not
    forgery-resistant."""
    private_key, _ = rsa_keys
    payload = _attestation_payload()
    sig = sign_harness_attestation(payload, private_key=private_key, signer_kid="harness-kid-1")
    assert verify_harness_attestation(payload, sig, allow_self_attested=True) is True


def test_crypto3_signer_kid_header_binding(rsa_keys):
    """With an out-of-band key, a JWS header kid that disagrees with the SIGNED
    signer_kid field is rejected (binding)."""
    private_key, public_key = rsa_keys
    payload = _attestation_payload(signer_kid="claimed-kid")
    sig = sign_harness_attestation(payload, private_key=private_key, signer_kid="actual-kid")
    assert verify_harness_attestation(payload, sig, public_key=public_key) is False


def test_crypto3_trust_anchors_do_not_rescue_jwk_only_forgery(rsa_keys):
    """roborev High on da59fe9: passing trust_anchors must NOT make a jwk-only
    (embedded-key) attestation 'secure'. verify_detached_jws ignores anchors for a
    jwk-only signature, so an attacker re-signing with their own auto-embedded key
    must still be rejected when no out-of-band key is supplied."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    attacker_key, _ = rsa_keys
    forged = _attestation_payload(claim="tests-NEVER-faked", signer_kid="official-key")
    forged_sig = sign_harness_attestation(forged, private_key=attacker_key, signer_kid="official-key")

    # An unrelated CA trust anchor. The harness attestation is jwk-only (no x5c),
    # so verify_detached_jws ignores this anchor entirely — the point is that
    # merely CONFIGURING anchors must not be treated as a secure path.
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unrelated-anchor")])
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
    with pytest.raises(ACEFSigningError) as exc:
        verify_harness_attestation(forged, forged_sig, trust_anchors=[ca])
    assert exc.value.code == "ACEF-012"


def _x5c_harness_attestation(payload: dict, leaf_key, x5c_chain: list[str]) -> str:
    """Sign the 9-field harness subset with an x5c chain in the JWS header."""
    from acef.integrity import canonicalize
    from acef.signing import HARNESS_ATTESTATION_SIGNED_FIELDS, create_detached_jws

    subset = {f: payload[f] for f in HARNESS_ATTESTATION_SIGNED_FIELDS if f in payload}
    return create_detached_jws(canonicalize(subset), leaf_key, kid=payload["signer_kid"], x5c=x5c_chain)


def _ca_and_leaf(nvb, nva):
    import base64
    import datetime  # noqa: F401  (nvb/nva are datetimes supplied by caller)

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    root_key = ec.generate_private_key(ec.SECP256R1())
    root = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "harness-root")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "harness-root")]))
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
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "harness-leaf")]))
        .issuer_name(root.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nvb)
        .not_valid_after(nva)
        .sign(root_key, hashes.SHA256())
    )
    b64 = lambda c: base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode("ascii")  # noqa: E731
    return root, leaf_key, [b64(leaf), b64(root)]


def test_anchored_x5c_harness_cert_validity_anchored_to_manifest_timestamp(rsa_keys):
    """roborev High on e7827f4: anchored harness verification MUST anchor x5c cert
    validity to the manifest timestamp (§3.1.3, NOT wall-clock). An x5c chain whose
    certs are EXPIRED at the manifest timestamp must NOT verify even though it
    chains to the configured anchor."""
    import datetime

    window_start = datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC)
    window_end = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    payload = _attestation_payload(signer_kid="harness-x5c-kid")
    root, leaf_key, x5c = _ca_and_leaf(window_start, window_end)
    jws = _x5c_harness_attestation(payload, leaf_key, x5c)

    # Inside the validity window + chains to anchor -> verifies.
    assert (
        verify_harness_attestation(payload, jws, trust_anchors=[root], manifest_timestamp="2025-06-01T00:00:00Z")
        is True
    )
    # AFTER expiry at the manifest timestamp -> cert validity fails -> ACEF-012
    # (the chain itself is rejected; a cross-record caller turns this into an
    # ACEF-012 diagnostic).
    with pytest.raises(ACEFSigningError) as exc:
        verify_harness_attestation(payload, jws, trust_anchors=[root], manifest_timestamp="2027-06-01T00:00:00Z")
    assert exc.value.code == "ACEF-012"
