"""RFC 7518 / RFC 7515 hardening tests for acef.signing (F-M1-SIGNING-HARDENING).

Covers audit findings signing-jws-2..5:

- VAL-FIX-SIGNING-002 (signing-jws-2): RSA >= 2048-bit floor enforced at BOTH
  sign and verify per RFC 7518 §3.3 ("A key of size 2048 bits or larger MUST
  be used with these algorithms").
- VAL-FIX-SIGNING-003 (signing-jws-3): any JWS ``crit`` header parameter is
  rejected per RFC 7515 §4.1.11 — ACEF understands no extension header
  parameters, so presence of ``crit`` (any shape) invalidates the JWS.
- VAL-FIX-SIGNING-004 (signing-jws-4): strict base64url (RFC 4648 §5 alphabet,
  no padding) for JWS header/signature segments per RFC 7515 §2. Standard
  base64 '+'/'/'/'=' spellings and whitespace are rejected. x5c entries are
  standard base64 (RFC 7515 §4.1.6) and remain unaffected.
- VAL-FIX-SIGNING-005 (signing-jws-5): ES256 high-S malleability is PINNED as
  documented-accepted behavior (not an RFC violation; low-S enforcement would
  diverge from the TS SDK verify path).
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from acef.errors import ACEFSigningError
from acef.signing import (
    _derive_jwk,
    _detect_algorithm,
    _load_public_key_from_jwk,
    _load_public_key_from_pem,
    create_detached_jws,
    verify_detached_jws,
)

# NIST P-256 (secp256r1) group order n — fixed curve parameter.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

PAYLOAD = b'{"records/evidence.jsonl": "sha256-deadbeef"}'


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _encode_header(header: dict[str, Any]) -> str:
    return _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _manual_rs256_jws(private_key: rsa.RSAPrivateKey, payload: bytes, header: dict[str, Any]) -> str:
    """Build a detached RS256 JWS bypassing create_detached_jws.

    Lets tests craft signatures with sub-floor keys or hostile headers that
    the hardened sign path refuses to produce — exactly what an external
    attacker would present to the verify path.
    """
    header_b64 = _encode_header(header)
    signing_input = f"{header_b64}.{_b64url(payload)}".encode("ascii")
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}..{_b64url(sig)}"


def _manual_es256_jws(private_key: ec.EllipticCurvePrivateKey, payload: bytes, header: dict[str, Any]) -> str:
    """Build a detached ES256 JWS bypassing create_detached_jws (hostile headers)."""
    header_b64 = _encode_header(header)
    signing_input = f"{header_b64}.{_b64url(payload)}".encode("ascii")
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return f"{header_b64}..{_b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


@pytest.fixture(scope="module")
def rsa_1024() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


@pytest.fixture(scope="module")
def rsa_2048() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def rsa_3072() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(scope="module")
def ec_p256() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


# ---------------------------------------------------------------------------
# VAL-FIX-SIGNING-002 — RSA >= 2048 floor (RFC 7518 §3.3) at sign AND verify
# ---------------------------------------------------------------------------


class TestRSAKeySizeFloor:
    def test_sign_and_verify_2048_passes(self, rsa_2048: rsa.RSAPrivateKey) -> None:
        jws = create_detached_jws(PAYLOAD, rsa_2048, kid="k2048")
        header = verify_detached_jws(jws, PAYLOAD, rsa_2048.public_key())
        assert header["alg"] == "RS256"

    def test_sign_and_verify_3072_passes(self, rsa_3072: rsa.RSAPrivateKey) -> None:
        jws = create_detached_jws(PAYLOAD, rsa_3072, kid="k3072")
        header = verify_detached_jws(jws, PAYLOAD, rsa_3072.public_key())
        assert header["alg"] == "RS256"

    def test_detect_algorithm_rejects_1024(self, rsa_1024: rsa.RSAPrivateKey) -> None:
        with pytest.raises(ACEFSigningError, match="2048") as exc_info:
            _detect_algorithm(rsa_1024)
        assert exc_info.value.code == "ACEF-013"

    def test_sign_rejects_1024(self, rsa_1024: rsa.RSAPrivateKey) -> None:
        with pytest.raises(ACEFSigningError, match="2048") as exc_info:
            create_detached_jws(PAYLOAD, rsa_1024, kid="k1024")
        assert exc_info.value.code == "ACEF-013"

    def test_verify_rejects_1024_via_embedded_jwk(self, rsa_1024: rsa.RSAPrivateKey) -> None:
        """A 1024-bit RS256 JWS with embedded JWK must be rejected at verify."""
        header = {"alg": "RS256", "kid": "k1024", "jwk": _derive_jwk(rsa_1024)}
        jws = _manual_rs256_jws(rsa_1024, PAYLOAD, header)
        with pytest.raises(ACEFSigningError, match="2048") as exc_info:
            verify_detached_jws(jws, PAYLOAD)
        assert exc_info.value.code == "ACEF-013"

    def test_verify_rejects_1024_via_explicit_public_key(self, rsa_1024: rsa.RSAPrivateKey) -> None:
        header = {"alg": "RS256", "kid": "k1024", "jwk": _derive_jwk(rsa_1024)}
        jws = _manual_rs256_jws(rsa_1024, PAYLOAD, header)
        with pytest.raises(ACEFSigningError, match="2048") as exc_info:
            verify_detached_jws(jws, PAYLOAD, rsa_1024.public_key())
        assert exc_info.value.code == "ACEF-013"

    def test_verify_rejects_1024_via_pem_key_data(self, rsa_1024: rsa.RSAPrivateKey) -> None:
        pem = rsa_1024.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        header = {"alg": "RS256", "kid": "k1024", "jwk": _derive_jwk(rsa_1024)}
        jws = _manual_rs256_jws(rsa_1024, PAYLOAD, header)
        with pytest.raises(ACEFSigningError, match="2048") as exc_info:
            verify_detached_jws(jws, PAYLOAD, key_data=pem)
        assert exc_info.value.code == "ACEF-013"

    def test_jwk_loader_rejects_tiny_modulus(self) -> None:
        """A hand-crafted 24-bit modulus (n=0xC0FFEE) must not load (audit repro)."""
        tiny_jwk = {
            "kty": "RSA",
            "n": _b64url((0xC0FFEE).to_bytes(3, "big")),
            "e": _b64url((65537).to_bytes(3, "big")),
        }
        with pytest.raises(ACEFSigningError, match="2048") as exc_info:
            _load_public_key_from_jwk(tiny_jwk)
        assert exc_info.value.code == "ACEF-013"

    def test_jwk_loader_rejects_1024_modulus(self, rsa_1024: rsa.RSAPrivateKey) -> None:
        with pytest.raises(ACEFSigningError, match="2048") as exc_info:
            _load_public_key_from_jwk(_derive_jwk(rsa_1024))
        assert exc_info.value.code == "ACEF-013"

    def test_jwk_loader_accepts_2048_modulus(self, rsa_2048: rsa.RSAPrivateKey) -> None:
        key = _load_public_key_from_jwk(_derive_jwk(rsa_2048))
        assert isinstance(key, rsa.RSAPublicKey)
        assert key.key_size == 2048

    def test_pem_loader_rejects_1024(self, rsa_1024: rsa.RSAPrivateKey) -> None:
        pem = rsa_1024.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(ACEFSigningError, match="2048") as exc_info:
            _load_public_key_from_pem(pem)
        assert exc_info.value.code == "ACEF-013"

    def test_pem_loader_accepts_2048(self, rsa_2048: rsa.RSAPrivateKey) -> None:
        pem = rsa_2048.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key = _load_public_key_from_pem(pem)
        assert isinstance(key, rsa.RSAPublicKey)
        assert key.key_size == 2048

    def test_ec_keys_unaffected_by_rsa_floor(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        jws = create_detached_jws(PAYLOAD, ec_p256, kid="k-ec")
        header = verify_detached_jws(jws, PAYLOAD, ec_p256.public_key())
        assert header["alg"] == "ES256"


# ---------------------------------------------------------------------------
# VAL-FIX-SIGNING-003 — JWS `crit` header rejection (RFC 7515 §4.1.11)
# ---------------------------------------------------------------------------


class TestCritHeaderRejection:
    def _jws_with_crit(self, ec_p256: ec.EllipticCurvePrivateKey, crit: Any, **extra: Any) -> str:
        header: dict[str, Any] = {
            "alg": "ES256",
            "kid": "crit-key",
            "jwk": _derive_jwk(ec_p256),
            "crit": crit,
        }
        header.update(extra)
        return _manual_es256_jws(ec_p256, PAYLOAD, header)

    def test_crit_unknown_extension_rejected(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        """A validly-signed JWS declaring crit:["acef-unknown-ext"] must be rejected."""
        jws = self._jws_with_crit(ec_p256, ["acef-unknown-ext"], **{"acef-unknown-ext": "value"})
        with pytest.raises(ACEFSigningError, match="crit") as exc_info:
            verify_detached_jws(jws, PAYLOAD)
        assert exc_info.value.code == "ACEF-013"

    def test_crit_listing_standard_param_rejected(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        jws = self._jws_with_crit(ec_p256, ["alg"])
        with pytest.raises(ACEFSigningError, match="crit") as exc_info:
            verify_detached_jws(jws, PAYLOAD)
        assert exc_info.value.code == "ACEF-013"

    def test_crit_empty_list_rejected(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        """RFC 7515 §4.1.11 forbids an empty crit array."""
        jws = self._jws_with_crit(ec_p256, [])
        with pytest.raises(ACEFSigningError, match="crit") as exc_info:
            verify_detached_jws(jws, PAYLOAD)
        assert exc_info.value.code == "ACEF-013"

    def test_crit_non_list_rejected(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        jws = self._jws_with_crit(ec_p256, "acef-unknown-ext")
        with pytest.raises(ACEFSigningError, match="crit") as exc_info:
            verify_detached_jws(jws, PAYLOAD)
        assert exc_info.value.code == "ACEF-013"

    def test_crit_non_string_members_rejected(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        jws = self._jws_with_crit(ec_p256, [42])
        with pytest.raises(ACEFSigningError, match="crit") as exc_info:
            verify_detached_jws(jws, PAYLOAD)
        assert exc_info.value.code == "ACEF-013"

    def test_crit_null_rejected(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        jws = self._jws_with_crit(ec_p256, None)
        with pytest.raises(ACEFSigningError, match="crit") as exc_info:
            verify_detached_jws(jws, PAYLOAD)
        assert exc_info.value.code == "ACEF-013"

    def test_jws_without_crit_unaffected(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        jws = create_detached_jws(PAYLOAD, ec_p256, kid="no-crit")
        header = verify_detached_jws(jws, PAYLOAD, ec_p256.public_key())
        assert "crit" not in header


# ---------------------------------------------------------------------------
# VAL-FIX-SIGNING-004 — strict base64url for JWS segments (RFC 7515 §2)
# ---------------------------------------------------------------------------


def _jws_with_translatable_signature() -> tuple[str, ec.EllipticCurvePublicKey]:
    """Produce a valid JWS whose SIGNATURE segment contains '-' or '_'.

    The signature segment encodes 64 random-looking bytes, so it contains a
    url-safe-only character with probability ~1-(62/64)^86 ≈ 93% per attempt;
    ECDSA's fresh per-signature nonce re-randomizes each iteration. (The
    HEADER segment cannot be produced this way: base64url of pure-ASCII JSON
    yields '-'/'_' only from bytes like '>' at offset ≡ 2 mod 3 — see
    test_header_standard_alphabet_rejected.)
    """
    key = ec.generate_private_key(ec.SECP256R1())
    for _ in range(200):
        jws = create_detached_jws(PAYLOAD, key, kid="b64url-key")
        segment = jws.split(".")[2]
        if "-" in segment or "_" in segment:
            return jws, key.public_key()
    pytest.fail("could not produce a JWS signature segment containing '-' or '_' in 200 attempts")


def _respell_standard_alphabet(segment: str) -> str:
    return segment.replace("-", "+").replace("_", "/")


class TestStrictBase64url:
    def test_signature_standard_alphabet_rejected(self) -> None:
        """A signature segment re-spelled with '+'/'/' must be rejected (ACEF-012)."""
        jws, public_key = _jws_with_translatable_signature()
        head, _, sig = jws.split(".")
        forged = f"{head}..{_respell_standard_alphabet(sig)}"
        assert forged != jws
        with pytest.raises(ACEFSigningError, match="base64url") as exc_info:
            verify_detached_jws(forged, PAYLOAD, public_key)
        assert exc_info.value.code == "ACEF-012"

    def test_signature_trailing_padding_rejected(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        """A signature segment with appended '=' padding must be rejected (ACEF-012)."""
        jws = create_detached_jws(PAYLOAD, ec_p256, kid="b64url-key")
        head, _, sig = jws.split(".")
        with pytest.raises(ACEFSigningError, match="base64url") as exc_info:
            verify_detached_jws(f"{head}..{sig}=", PAYLOAD, ec_p256.public_key())
        assert exc_info.value.code == "ACEF-012"

    def test_signature_embedded_newline_rejected(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        jws = create_detached_jws(PAYLOAD, ec_p256, kid="b64url-key")
        head, _, sig = jws.split(".")
        mutated = f"{head}..{sig[:10]}\n\n{sig[10:]}"
        with pytest.raises(ACEFSigningError, match="base64url") as exc_info:
            verify_detached_jws(mutated, PAYLOAD, ec_p256.public_key())
        assert exc_info.value.code == "ACEF-012"

    def test_signature_embedded_space_rejected(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        jws = create_detached_jws(PAYLOAD, ec_p256, kid="b64url-key")
        head, _, sig = jws.split(".")
        mutated = f"{head}..{sig[:10]}    {sig[10:]}"
        with pytest.raises(ACEFSigningError, match="base64url") as exc_info:
            verify_detached_jws(mutated, PAYLOAD, ec_p256.public_key())
        assert exc_info.value.code == "ACEF-012"

    def test_header_standard_alphabet_rejected(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        """A header segment re-spelled with '+'/'/' must be rejected at decode,

        not merely fail signature verification downstream (the strict parser
        rejects the spelling itself, before any cryptographic work; the
        pre-fix code could only fail later with 'Signature verification
        failed', never with the strict 'base64url' diagnostic asserted here).

        Construction note: base64url over pure-ASCII JSON cannot produce
        '-'/'_' from alphanumerics — only bytes like '>' (0x3E) at offset
        ≡ 2 mod 3 yield 6-bit group 62. A kid containing a run of six '>'
        characters guarantees at least one aligned `>>>` triple, whose
        encoding ends in '-', making a standard-alphabet re-spelling
        possible deterministically.
        """
        jws = create_detached_jws(PAYLOAD, ec_p256, kid=">>>>>>")
        head, _, sig = jws.split(".")
        assert "-" in head or "_" in head, "construction must force a url-safe-only char"
        forged = f"{_respell_standard_alphabet(head)}..{sig}"
        assert forged != jws
        with pytest.raises(ACEFSigningError, match="base64url") as exc_info:
            verify_detached_jws(forged, PAYLOAD, ec_p256.public_key())
        assert exc_info.value.code == "ACEF-012"

    def test_header_trailing_padding_rejected(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        jws = create_detached_jws(PAYLOAD, ec_p256, kid="b64url-key")
        head, _, sig = jws.split(".")
        with pytest.raises(ACEFSigningError, match="base64url") as exc_info:
            verify_detached_jws(f"{head}=..{sig}", PAYLOAD, ec_p256.public_key())
        assert exc_info.value.code == "ACEF-012"

    def test_jwk_parameter_with_padding_rejected(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        """JWK params are Base64urlUInt (RFC 7518 §2) — padded spellings rejected."""
        jwk = _derive_jwk(ec_p256)
        jwk["x"] = jwk["x"] + "=="
        header = {"alg": "ES256", "kid": "jwk-pad", "jwk": jwk}
        jws = _manual_es256_jws(ec_p256, PAYLOAD, header)
        with pytest.raises(ACEFSigningError, match="base64url") as exc_info:
            verify_detached_jws(jws, PAYLOAD)
        assert exc_info.value.code == "ACEF-012"

    def test_canonical_jws_still_verifies(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        """The canonical spelling our own exporter emits must remain accepted."""
        jws = create_detached_jws(PAYLOAD, ec_p256, kid="b64url-key")
        header = verify_detached_jws(jws, PAYLOAD, ec_p256.public_key())
        assert header["alg"] == "ES256"

    def test_canonical_rs256_jws_still_verifies(self, rsa_2048: rsa.RSAPrivateKey) -> None:
        jws = create_detached_jws(PAYLOAD, rsa_2048, kid="b64url-key")
        header = verify_detached_jws(jws, PAYLOAD, rsa_2048.public_key())
        assert header["alg"] == "RS256"


# ---------------------------------------------------------------------------
# VAL-FIX-SIGNING-005 — ES256 high-S malleability: documented, pinned
# ---------------------------------------------------------------------------


class TestES256HighSDocumentedBehavior:
    def test_es256_high_s_documented_behavior(self, ec_p256: ec.EllipticCurvePrivateKey) -> None:
        """PINNING test: the (r, n-s) malleable variant currently VERIFIES.

        This is deliberate, documented behavior (audit signing-jws-5):
        RFC 7515/7518 do NOT require low-S canonical form, the content is
        still authenticated, and enforcing low-S would gratuitously diverge
        from the TS SDK verify path. If this test ever fails, someone has
        silently changed the malleability posture — that change must be
        made consciously, in lockstep with the TS SDK, and only if
        dedupe-on-signature-bytes is introduced downstream.
        """
        jws = create_detached_jws(PAYLOAD, ec_p256, kid="high-s")
        head, _, sig_b64 = jws.split(".")
        sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")

        # The original signature verifies.
        assert verify_detached_jws(jws, PAYLOAD, ec_p256.public_key())["alg"] == "ES256"

        # The malleable variant (r, n - s) ALSO verifies — accepted by design.
        s_variant = P256_ORDER - s
        assert 0 < s_variant < P256_ORDER
        variant_sig = r.to_bytes(32, "big") + s_variant.to_bytes(32, "big")
        variant_jws = f"{head}..{_b64url(variant_sig)}"
        assert variant_jws != jws
        header = verify_detached_jws(variant_jws, PAYLOAD, ec_p256.public_key())
        assert header["alg"] == "ES256"
