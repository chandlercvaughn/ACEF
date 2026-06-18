"""Signer-identity binding reporting (PhD-review finding 2).

A valid signature proves *someone* signed these content-hashes bytes; it does not
prove the signer is the manifest's declared producer. The validator previously
emitted no diagnostic distinguishing "signed by the claimed provider" from
"signed by anybody". ``classify_signature_binding`` closes that gap: it reports
the binding LEVEL (anchored / self-attested / unverified), surfaces the leaf
certificate subject for an anchored signature, and checks it against a configured
expected producer (spec Appendix D.3).
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acef.integrity import canonicalize
from acef.signing import create_detached_jws
from acef.validation.integrity_checker import classify_signature_binding

_CANON = canonicalize({"acef-manifest.json": "abc123", "records/r.jsonl": "def456"})


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _self_signed(common_name: str, key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    """A self-signed CA cert usable as both leaf and trust anchor (test fixture)."""
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    not_before = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
    not_after = datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )


def _b64_der(cert: x509.Certificate) -> str:
    import base64

    from cryptography.hazmat.primitives.serialization import Encoding

    return base64.b64encode(cert.public_bytes(Encoding.DER)).decode("ascii")


class TestSignatureBindingClassification:
    def test_jwk_only_is_self_attested_with_no_subject(self) -> None:
        key = _key()
        jws = create_detached_jws(_CANON, key, kid="k1")
        b = classify_signature_binding(jws, _CANON)
        assert b.binding_level == "self-attested"
        assert b.signer_subject is None
        assert b.matches_expected_producer is None

    def test_x5c_without_trust_anchors_is_self_attested_but_surfaces_subject(self) -> None:
        key = _key()
        cert = _self_signed("acme-corp-signer", key)
        jws = create_detached_jws(_CANON, key, kid="k1", x5c=[_b64_der(cert)])
        b = classify_signature_binding(jws, _CANON)  # no trust anchors configured
        assert b.binding_level == "self-attested"
        assert b.signer_subject is not None and "acme-corp-signer" in b.signer_subject

    def test_anchored_when_chain_terminates_at_a_configured_anchor(self) -> None:
        key = _key()
        cert = _self_signed("acme-corp-signer", key)
        jws = create_detached_jws(_CANON, key, kid="k1", x5c=[_b64_der(cert)])
        b = classify_signature_binding(jws, _CANON, trust_anchors=[cert])
        assert b.binding_level == "anchored"
        assert "acme-corp-signer" in (b.signer_subject or "")

    def test_anchored_subject_matches_expected_producer(self) -> None:
        key = _key()
        cert = _self_signed("acme-corp-signer", key)
        jws = create_detached_jws(_CANON, key, kid="k1", x5c=[_b64_der(cert)])
        ok = classify_signature_binding(jws, _CANON, trust_anchors=[cert], expected_producer="acme-corp-signer")
        assert ok.matches_expected_producer is True
        # The "valid signature, wrong signer" case: anchored, but the subject is NOT
        # the producer the deployment expected -> mismatch is reported (not silent).
        wrong = classify_signature_binding(jws, _CANON, trust_anchors=[cert], expected_producer="other-company")
        assert wrong.matches_expected_producer is False

    def test_tampered_input_is_unverified(self) -> None:
        key = _key()
        jws = create_detached_jws(_CANON, key, kid="k1")
        tampered = canonicalize({"acef-manifest.json": "TAMPERED", "records/r.jsonl": "def456"})
        b = classify_signature_binding(jws, tampered)
        assert b.binding_level == "unverified"
