"""ACEF signing module — JWS detached signatures (RS256, ES256).

Implements bundle and record signing per spec Section 3.1.3:
- RS256 and ES256 only — all other algorithms rejected (ACEF-013)
- Detached JWS over content-hashes.json
- JWS header MUST include x5c or jwk per spec
- x5c certificate chain support
- JWK public key embedding
- Assessment Bundle signing
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.x509 import (
    BasicConstraints,
    Certificate,
    ExtensionNotFound,
    KeyUsage,
    load_der_x509_certificate,
    load_pem_x509_certificate,
)

from acef.errors import ACEFSigningError

# Whitelist of allowed JWS algorithms per spec
_ALLOWED_ALGORITHMS = frozenset({"RS256", "ES256"})


# ---------------------------------------------------------------------------
# Harness-attestation signed-fields scope (VAL-SIGNATURE-001..004).
#
# Per contract.md §SIGNATURE, the JWS detached signature on a
# `harness_attestation` record covers EXACTLY these nine fields, in this
# order, JCS-canonicalized as a JSON object. Any field outside this list
# (including future-spec or vendor extensions appearing in the payload)
# is explicitly OUTSIDE the signature envelope and verifiers MUST NOT
# trust it. Any field inside the list, if tampered with after signing,
# MUST cause verification to fail.
#
# RFC 8785 (JCS) handles object-key ordering deterministically (sorted
# code-point ascending), so the *tuple order* here is the source of
# truth for documentation, registry, and audit purposes — not for
# canonicalization byte-order.
# ---------------------------------------------------------------------------
HARNESS_ATTESTATION_SIGNED_FIELDS: tuple[str, ...] = (
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


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# RFC 4648 §5 url-safe alphabet, unpadded. Empty segments are permitted at
# this layer (the detached-JWS payload slot is empty by construction); callers
# enforce their own non-emptiness where required.
_BASE64URL_STRICT_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def _base64url_decode(s: str) -> bytes:
    """Strict base64url decode (RFC 4648 §5) with padding restoration.

    RFC 7515 §2 defines JWS segments as BASE64URL: alphabet ``A-Z a-z 0-9 -
    _`` with NO padding. Python's ``base64.urlsafe_b64decode`` silently
    conflates the standard-base64 alphabet (``+``, ``/``) with the url-safe
    one and tolerates ``=`` padding and (via ``b64decode``'s default
    ``validate=False``) embedded whitespace — so distinct on-wire spellings
    would decode to identical bytes, breaking canonical-input strictness
    (audit signing-jws-4). Any deviation is rejected with ACEF-012 BEFORE
    decoding.

    Scope note: x5c certificate entries are standard base64 per RFC 7515
    §4.1.6 and are decoded separately in :func:`_parse_x5c_chain` via
    ``base64.b64decode(validate=True)`` — they MUST NOT flow through this
    function. JWK parameters (``n``/``e``/``x``/``y``) ARE base64url per
    RFC 7518 §2 (Base64urlUInt) and correctly share this strict path.
    """
    if not _BASE64URL_STRICT_RE.fullmatch(s):
        raise ACEFSigningError(
            "Invalid base64url segment: character(s) outside the RFC 4648 §5 "
            "url-safe alphabet (A-Za-z0-9, '-', '_'); standard-base64 '+'/'/', "
            "'=' padding, and whitespace are rejected (RFC 7515 §2)",
            code="ACEF-012",
        )
    # No valid base64url encoding has length ≡ 1 (mod 4): the final character
    # of a segment carries at most 6 bits — less than one byte — so 1 byte
    # encodes to 2 chars, 2 bytes to 3, 3 bytes to 4. Reject this length
    # class explicitly BEFORE restoring padding; padding such input (e.g.
    # "A" -> "A===") would hand the stdlib decoder structurally invalid bytes
    # and make the diagnostic depend on its internal error text.
    remainder = len(s) % 4
    if remainder == 1:
        raise ACEFSigningError(
            f"Invalid base64url segment: length {len(s)} is congruent to 1 "
            "(mod 4); no valid base64url encoding has this length class "
            "(RFC 4648 §5)",
            code="ACEF-012",
        )
    # Restore padding for the decoder (only when length is not a multiple of 4).
    if remainder:
        s = s + "=" * (4 - remainder)
    try:
        return base64.urlsafe_b64decode(s)
    except (binascii.Error, ValueError) as exc:
        # Defensive backstop only — the alphabet and length-class checks
        # above should make this unreachable. binascii.Error is a ValueError
        # subclass in CPython, but it is named explicitly so the contract
        # ("no raw decoder exception escapes as anything but ACEF-012") does
        # not silently depend on that subclassing.
        raise ACEFSigningError(
            f"Invalid base64url segment: {exc}",
            code="ACEF-012",
        ) from exc


# RFC 7518 §3.3: "A key of size 2048 bits or larger MUST be used with these
# algorithms" (RS256). Enforced at BOTH sign and verify (audit signing-jws-2):
# a sub-2048 modulus is factorable at the low end, and accepting one on the
# verify path would let an attacker present a JWK weak enough to forge
# RS256 signatures over chosen content-hashes.json bytes.
_RSA_MIN_KEY_BITS = 2048


def _enforce_rsa_min_key_size(bits: int, context: str) -> None:
    """Reject RSA keys below the RFC 7518 §3.3 floor for RS256 (ACEF-013)."""
    if bits < _RSA_MIN_KEY_BITS:
        raise ACEFSigningError(
            f"RSA key too small for RS256: {bits} bits in {context}. "
            f"RFC 7518 §3.3 requires a key of {_RSA_MIN_KEY_BITS} bits or larger.",
            code="ACEF-013",
        )


def _detect_algorithm(private_key: PrivateKeyTypes) -> str:
    """Detect JWS algorithm from private key type.

    For RSA keys, enforces the RFC 7518 §3.3 minimum key size (2048 bits)
    at the SIGN side. For EC keys, validates that the curve is P-256 (NIST
    secp256r1) since ACEF only allows ES256 per spec Section 3.1.3.
    """
    if isinstance(private_key, rsa.RSAPrivateKey):
        _enforce_rsa_min_key_size(private_key.key_size, "private signing key")
        return "RS256"
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve = private_key.curve
        if not isinstance(curve, ec.SECP256R1):
            raise ACEFSigningError(
                f"Unsupported EC curve: {curve.name!r}. ACEF requires P-256 (secp256r1) for ES256.",
                code="ACEF-013",
            )
        return "ES256"
    else:
        raise ACEFSigningError(
            f"Unsupported key type: {type(private_key).__name__}",
            code="ACEF-013",
        )


def _parse_x5c_chain(x5c: list[str]) -> list[Certificate]:
    """Decode an x5c JWS header value into a list of X.509 certificates.

    JWS x5c entries are base64-encoded DER (not base64url). Each entry has a
    size cap (65536 bytes) to bound parse work.
    """
    certs: list[Certificate] = []
    for idx, entry in enumerate(x5c):
        if not isinstance(entry, str):
            raise ACEFSigningError(
                f"x5c entry {idx} is not a string",
                code="ACEF-012",
            )
        if len(entry) > 65536:
            raise ACEFSigningError(
                f"x5c entry {idx} too large: {len(entry)} bytes (max 65536)",
                code="ACEF-012",
            )
        try:
            cert_der = base64.b64decode(entry, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ACEFSigningError(
                f"x5c entry {idx} is not valid base64: {exc}",
                code="ACEF-012",
            ) from exc
        try:
            certs.append(load_der_x509_certificate(cert_der))
        except Exception as exc:
            raise ACEFSigningError(
                f"x5c entry {idx} is not a valid DER X.509 certificate: {exc}",
                code="ACEF-012",
            ) from exc
    return certs


def _cert_validity_covers(cert: Certificate, instant: datetime) -> tuple[bool, str | None]:
    """Return (True, None) if ``instant`` is within ``cert`` validity, else (False, reason).

    Uses ``not_valid_before_utc`` / ``not_valid_after_utc`` from the
    cryptography library (timezone-aware) so comparisons against the
    timezone-aware ``instant`` are well-defined.
    """
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        # Older cryptography versions exposed naive UTC datetimes.
        not_before = cert.not_valid_before.replace(tzinfo=UTC)
        not_after = cert.not_valid_after.replace(tzinfo=UTC)
    if instant < not_before:
        return False, f"certificate not yet valid (not_before={not_before.isoformat()})"
    if instant > not_after:
        return False, f"certificate expired (not_after={not_after.isoformat()})"
    return True, None


def _verify_cert_signed_by(child: Certificate, parent: Certificate) -> bool:
    """Verify ``child`` was signed by ``parent``'s public key."""
    parent_public_key = parent.public_key()
    hash_algorithm = child.signature_hash_algorithm
    if hash_algorithm is None:
        # Certificates signed with algorithms that lack a hash (e.g. Ed25519)
        # are not part of ACEF's RS256/ES256 chain model; treat as unverifiable.
        return False
    try:
        # cryptography exposes algorithm-specific verify on each public key.
        if isinstance(parent_public_key, rsa.RSAPublicKey):
            parent_public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_algorithm,
            )
        elif isinstance(parent_public_key, ec.EllipticCurvePublicKey):
            parent_public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(hash_algorithm),
            )
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _issuer_constraint_violation(issuer: Certificate, *, ca_certs_below: int) -> str | None:
    """Return a violation description if ``issuer`` may not act as a CA, else None.

    RFC 5280 §4.2.1.9 / §6.1.4: every certificate that ISSUES another
    certificate in a path MUST be a CA. Concretely:

    - it MUST carry a BasicConstraints extension with ``ca=True`` (a
      missing extension means end-entity — fail closed);
    - when a KeyUsage extension is present, it MUST assert
      ``keyCertSign`` (absent KeyUsage is permitted — BasicConstraints
      alone then governs);
    - when ``path_length`` (pathLenConstraint) is set, at most that many
      CA certificates may follow it in the path toward the leaf.
      ``ca_certs_below`` is that count for the position being checked.

    Without these checks a CA-issued END-ENTITY certificate could act as
    an intermediate and sign a forged leaf that would then verify as
    anchored. The LEAF itself is exempt — it never issues, so callers
    only invoke this for certificates in the issuer role.
    """
    try:
        bc_ext = issuer.extensions.get_extension_for_class(BasicConstraints)
    except ExtensionNotFound:
        return "no BasicConstraints extension (end-entity certificate, not a CA)"
    except Exception as exc:  # noqa: BLE001 — malformed/duplicate extensions on an untrusted cert: fail closed
        return f"certificate extensions could not be parsed: {exc}"
    if not bc_ext.value.ca:
        return "not a CA (BasicConstraints ca=False)"
    path_length = bc_ext.value.path_length
    if path_length is not None and ca_certs_below > path_length:
        return f"BasicConstraints path_length={path_length} exceeded ({ca_certs_below} CA cert(s) below it in the path)"
    try:
        ku_ext = issuer.extensions.get_extension_for_class(KeyUsage)
    except ExtensionNotFound:
        return None  # KeyUsage absent — BasicConstraints alone governs
    except Exception as exc:  # noqa: BLE001 — malformed/duplicate extensions on an untrusted cert: fail closed
        return f"certificate extensions could not be parsed: {exc}"
    if not ku_ext.value.key_cert_sign:
        return "KeyUsage extension present but keyCertSign not asserted"
    return None


def _path_length_exposure(chain: list[Certificate], issuer_index: int) -> int:
    """Count CA certs below ``chain[issuer_index]`` that consume pathLen budget.

    RFC 5280 §6.1.4(l): ``max_path_length`` is decremented only for
    certificates that are NOT self-issued. A certificate is self-issued
    when the same name appears in its OWN subject and issuer fields
    (§6.1) — the CA key-rollover shape. Such certs MUST NOT count
    against a superior CA's pathLenConstraint.

    The certificates below the issuer are ``chain[1 .. issuer_index-1]``:
    the leaf at ``chain[0]`` never counts (it issues nothing), and each
    self-issued intermediate is excluded. Pass
    ``issuer_index=len(chain)`` for a trust anchor acting as the issuer
    of the chain's final certificate.
    """
    return sum(1 for cert in chain[1:issuer_index] if cert.subject != cert.issuer)


def verify_x5c_chain(
    x5c: list[str],
    *,
    manifest_timestamp: str | None = None,
    trust_anchors: list[Certificate] | None = None,
) -> PublicKeyTypes:
    """Verify an x5c certificate chain and return the leaf's public key.

    Per spec §3.1.3 "Signature trust model":

    - The leaf certificate is at ``x5c[0]``; each subsequent entry is its
      issuer (so ``x5c[1]`` signs ``x5c[0]``, ``x5c[2]`` signs ``x5c[1]``,
      etc.). The final entry is either self-signed (when chaining to a
      trust anchor present in ``trust_anchors``) or signed by a cert in
      ``trust_anchors``.
    - Every certificate in the ISSUER role (each cert that signs another,
      including a trust anchor matched via the signed-by rule) MUST
      satisfy the X.509 path constraints of RFC 5280: BasicConstraints
      ``ca=True``, ``keyCertSign`` when a KeyUsage extension is present,
      issuer/subject name chaining, and ``path_length`` when set. The
      LEAF is exempt (it never issues). These constraints apply in BOTH
      anchored and self-attested modes — a non-CA issuer is an invalid
      X.509 path regardless of anchoring.
    - Certificate expiry MUST be checked against the bundle's
      ``manifest.timestamp`` (NOT wall-clock). This gives reproducible
      verification: a bundle signed before its cert expired still
      verifies after the cert has rolled over.
    - Revocation (CRL/OCSP) is RECOMMENDED but not REQUIRED for v1, so
      this function does not perform it.

    Args:
        x5c: The list of base64-encoded DER X.509 certs from a JWS header.
        manifest_timestamp: ISO 8601 timestamp from the bundle manifest.
            If provided, every certificate's validity window MUST cover
            this instant.
        trust_anchors: Locally configured trust anchor certificates. If
            provided, the chain MUST terminate at one of these (either
            the chain's final cert is in this set, OR the chain's final
            cert is signed by one of these). If None, the chain links
            are still verified but no external root anchoring is
            enforced — appropriate for "self-attested" trust per spec.

    Returns:
        The leaf certificate's public key, suitable for verifying the JWS
        signing input.

    Raises:
        ACEFSigningError: If the chain is empty, any link fails to verify,
            any cert's validity does not cover ``manifest_timestamp``, or
            ``trust_anchors`` is provided and the chain does not terminate
            at one of them.
    """
    if not x5c:
        raise ACEFSigningError("x5c chain is empty", code="ACEF-012")

    chain = _parse_x5c_chain(x5c)

    # Validate expiry against manifest_timestamp (or skip if not provided —
    # callers SHOULD always provide one).
    if manifest_timestamp is not None:
        ts_norm = manifest_timestamp
        if ts_norm.endswith("Z"):
            ts_norm = ts_norm[:-1] + "+00:00"
        try:
            instant = datetime.fromisoformat(ts_norm)
        except ValueError as exc:
            raise ACEFSigningError(
                f"Invalid manifest_timestamp for cert validity check: {manifest_timestamp!r}: {exc}",
                code="ACEF-012",
            ) from exc
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=UTC)
        for idx, cert in enumerate(chain):
            ok, reason = _cert_validity_covers(cert, instant)
            if not ok:
                raise ACEFSigningError(
                    f"x5c[{idx}] {reason} at manifest_timestamp {manifest_timestamp}",
                    code="ACEF-012",
                )

    # Walk chain links: each cert (except the last) must be signed by the
    # next one in the list, names must chain (child.issuer == issuer.subject),
    # and every ISSUER must satisfy the RFC 5280 path constraints — see
    # _issuer_constraint_violation. The LEAF (x5c[0]) is exempt from CA
    # requirements; it never issues. These checks run in BOTH anchored and
    # self-attested (no-anchors) modes: a non-CA issuer is an invalid X.509
    # path regardless of anchoring.
    for idx in range(len(chain) - 1):
        child = chain[idx]
        issuer = chain[idx + 1]
        if not _verify_cert_signed_by(child, issuer):
            raise ACEFSigningError(
                f"x5c[{idx}] is not signed by x5c[{idx + 1}] (broken chain)",
                code="ACEF-012",
            )
        if child.issuer != issuer.subject:
            raise ACEFSigningError(
                f"x5c[{idx}] issuer name does not match x5c[{idx + 1}] subject (broken name chaining)",
                code="ACEF-012",
            )
        # The issuer at index idx+1 has the certs chain[1..idx] between
        # itself and the leaf; its pathLenConstraint exposure counts only
        # the NON-self-issued ones (RFC 5280 §6.1.4(l) — key-rollover
        # certs with subject == issuer are excluded).
        violation = _issuer_constraint_violation(issuer, ca_certs_below=_path_length_exposure(chain, idx + 1))
        if violation is not None:
            raise ACEFSigningError(
                f"x5c[{idx + 1}] cannot act as an issuer: {violation}",
                code="ACEF-012",
            )

    # Anchor termination. If trust_anchors supplied, the chain MUST end at
    # one of them (by DER equality) OR be signed by one of them. An anchor
    # matched via the signed-by rule acts as the ISSUER of the chain tail,
    # so it must satisfy the same X.509 issuer constraints (CA bits + name
    # chaining + path_length over the NON-self-issued CA certs below it,
    # per RFC 5280 §6.1.4(l)); an anchor failing them simply does not
    # anchor this chain.
    if trust_anchors is not None:
        if not trust_anchors:
            raise ACEFSigningError(
                "trust_anchors list is empty — cannot anchor chain",
                code="ACEF-012",
            )
        tail = chain[-1]
        tail_der = tail.public_bytes(serialization.Encoding.DER)
        anchor_ders = {anchor.public_bytes(serialization.Encoding.DER) for anchor in trust_anchors}
        if tail_der in anchor_ders:
            anchored = True
        else:
            anchor_exposure = _path_length_exposure(chain, len(chain))
            anchored = any(
                _verify_cert_signed_by(tail, anchor)
                and tail.issuer == anchor.subject
                and _issuer_constraint_violation(anchor, ca_certs_below=anchor_exposure) is None
                for anchor in trust_anchors
            )
        if not anchored:
            raise ACEFSigningError(
                "x5c chain does not terminate at any configured trust anchor",
                code="ACEF-012",
            )

    return chain[0].public_key()


def _load_private_key(key_path: str) -> PrivateKeyTypes:
    """Load a PEM-encoded private key."""
    key_data = Path(key_path).read_bytes()
    try:
        return serialization.load_pem_private_key(key_data, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        raise ACEFSigningError(f"Failed to load private key: {e}", code="ACEF-012") from e


def _load_public_key_from_pem(key_data: bytes) -> PublicKeyTypes:
    """Load a PEM-encoded public key or certificate.

    RSA keys below the RFC 7518 §3.3 floor (2048 bits) are rejected with
    ACEF-013 — the verify path must never accept a factorable modulus.
    """
    key: PublicKeyTypes
    try:
        key = serialization.load_pem_public_key(key_data)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        # Try loading as certificate
        try:
            cert = load_pem_x509_certificate(key_data)
            key = cert.public_key()
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            raise ACEFSigningError(f"Failed to load public key: {e}", code="ACEF-012") from e
    if isinstance(key, rsa.RSAPublicKey):
        _enforce_rsa_min_key_size(key.key_size, "PEM public key")
    return key


def _derive_jwk(private_key: PrivateKeyTypes) -> dict[str, str]:
    """Derive a JWK representation of the public key from a private key.

    Per spec Section 3.1.3: JWS header MUST include x5c or jwk.
    When x5c is not provided, the public key is auto-embedded as a JWK.

    Args:
        private_key: The private signing key.

    Returns:
        A JWK dict suitable for embedding in the JWS header.
    """
    public_key = private_key.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        public_numbers = public_key.public_numbers()
        # Encode n and e as base64url unsigned big-endian integers
        n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder="big")
        e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder="big")
        return {
            "kty": "RSA",
            "n": _base64url_encode(n_bytes),
            "e": _base64url_encode(e_bytes),
        }
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        ec_public_numbers = public_key.public_numbers()
        # For P-256, coordinates are 32 bytes each
        x_bytes = ec_public_numbers.x.to_bytes(32, byteorder="big")
        y_bytes = ec_public_numbers.y.to_bytes(32, byteorder="big")
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _base64url_encode(x_bytes),
            "y": _base64url_encode(y_bytes),
        }
    else:
        raise ACEFSigningError(
            f"Cannot derive JWK from key type: {type(public_key).__name__}",
            code="ACEF-013",
        )


def _load_public_key_from_jwk(jwk: dict[str, Any]) -> PublicKeyTypes:
    """Load a public key from a JWK dictionary.

    Supports RSA and EC (P-256) key types per spec Section 3.1.3.

    Args:
        jwk: JWK dictionary with key type and parameters.

    Returns:
        The deserialized public key.

    Raises:
        ACEFSigningError: If the JWK is malformed or uses unsupported parameters.
    """
    kty = jwk.get("kty", "")

    if kty == "RSA":
        n_b64 = jwk.get("n", "")
        e_b64 = jwk.get("e", "")
        if not n_b64 or not e_b64:
            raise ACEFSigningError(
                "RSA JWK missing required 'n' or 'e' parameters",
                code="ACEF-012",
            )
        n_bytes = _base64url_decode(n_b64)
        e_bytes = _base64url_decode(e_b64)
        n = int.from_bytes(n_bytes, byteorder="big")
        e = int.from_bytes(e_bytes, byteorder="big")
        # RFC 7518 §3.3 floor BEFORE key construction: an attacker-supplied
        # JWK with a tiny/factorable modulus (audit signing-jws-2 repro:
        # n=0xC0FFEE) must never materialize as a usable verification key.
        _enforce_rsa_min_key_size(n.bit_length(), "RSA JWK modulus 'n'")
        public_numbers = rsa.RSAPublicNumbers(e=e, n=n)
        return public_numbers.public_key()

    elif kty == "EC":
        crv = jwk.get("crv", "")
        if crv != "P-256":
            raise ACEFSigningError(
                f"Unsupported EC curve in JWK: {crv!r}. ACEF requires P-256.",
                code="ACEF-013",
            )
        x_b64 = jwk.get("x", "")
        y_b64 = jwk.get("y", "")
        if not x_b64 or not y_b64:
            raise ACEFSigningError(
                "EC JWK missing required 'x' or 'y' parameters",
                code="ACEF-012",
            )
        x_bytes = _base64url_decode(x_b64)
        y_bytes = _base64url_decode(y_b64)
        x = int.from_bytes(x_bytes, byteorder="big")
        y = int.from_bytes(y_bytes, byteorder="big")
        ec_public_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
        return ec_public_numbers.public_key()

    else:
        raise ACEFSigningError(
            f"Unsupported JWK key type: {kty!r}. ACEF requires RSA or EC.",
            code="ACEF-012",
        )


def create_detached_jws(
    payload: bytes,
    private_key: PrivateKeyTypes,
    *,
    kid: str = "",
    x5c: list[str] | None = None,
) -> str:
    """Create a detached JWS signature.

    Per spec Section 3.1.3: JWS with empty payload (detached), RS256 or ES256 only.
    The header MUST include x5c or jwk. If x5c is not provided, the public key
    is auto-derived from the private key and embedded as a jwk.

    Args:
        payload: The data to sign (raw bytes).
        private_key: The signing key.
        kid: Key identifier.
        x5c: Certificate chain (base64-encoded DER certificates).

    Returns:
        JWS compact serialization with empty payload (header..signature).
    """
    alg = _detect_algorithm(private_key)

    # Build JWS header.
    # Per spec §3.1.3 #5: the header MUST include `alg`, `kid`, and `x5c` or
    # `jwk`. ``kid`` is mandatory — refusing to omit it preserves the
    # key-rotation/identification contract.
    if not kid:
        raise ACEFSigningError(
            "JWS 'kid' parameter is required (spec §3.1.3 mandates kid in every header)",
            code="ACEF-013",
        )
    header: dict[str, Any] = {"alg": alg, "kid": kid}
    if x5c:
        header["x5c"] = x5c
    else:
        # Auto-embed public key as JWK when no x5c provided.
        # Spec §3.1.3: header MUST include x5c or jwk.
        header["jwk"] = _derive_jwk(private_key)

    # Encode header. sort_keys=True ensures any two callers building the same
    # logical header (same alg/kid/x5c-or-jwk) produce byte-identical JWS
    # output, preserving the determinism contract from spec §3.1.3 / §6.5.
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _base64url_encode(payload)

    # Sign
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    if alg == "RS256":
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ACEFSigningError("Key type mismatch for RS256", code="ACEF-013")
        signature = private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    elif alg == "ES256":
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ACEFSigningError("Key type mismatch for ES256", code="ACEF-013")
        der_sig = private_key.sign(
            signing_input,
            ec.ECDSA(hashes.SHA256()),
        )
        # Convert DER to raw r||s format for JWS (32 bytes each for P-256)
        r, s = utils.decode_dss_signature(der_sig)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        raise ACEFSigningError(f"Unsupported algorithm: {alg}", code="ACEF-013")

    sig_b64 = _base64url_encode(signature)

    # Detached JWS: header..signature (empty payload)
    return f"{header_b64}..{sig_b64}"


def verify_detached_jws(
    jws_str: str,
    payload: bytes,
    public_key: PublicKeyTypes | None = None,
    *,
    key_data: bytes | None = None,
    manifest_timestamp: str | None = None,
    trust_anchors: list[Certificate] | None = None,
) -> dict[str, Any]:
    """Verify a detached JWS signature.

    Args:
        jws_str: The JWS compact serialization (header..signature).
        payload: The original signed data.
        public_key: The verification key (optional if key_data provided).
        key_data: PEM-encoded public key or certificate (alternative to public_key).
        manifest_timestamp: ISO 8601 ``metadata.timestamp`` from the bundle
            manifest. When the header carries ``x5c``, certificate validity
            is checked against THIS instant, not wall-clock time (spec
            §3.1.3 — reproducible verification).
        trust_anchors: Locally configured trust-anchor certificates. When
            the header carries ``x5c``, the chain MUST terminate at one of
            these (spec §3.1.3 trust model); ``None`` (default) performs
            chain-link and expiry checks only — self-attested trust, no
            anchor enforcement. Ignored for ``jwk``-only signatures, which
            per the trust model prove data integrity but not organizational
            identity.

    Returns:
        The decoded JWS header.

    Raises:
        ACEFSigningError: If verification fails.

    Note:
        ES256 verification deliberately accepts ECDSA-malleable signatures
        (audit signing-jws-5): for any valid ``(r, s)`` the variant
        ``(r, n - s)`` also verifies. RFC 7515/7518 do NOT require low-S
        canonical form, the payload remains fully authenticated either way,
        and enforcing low-S here would gratuitously diverge from the TS SDK
        verify path. Revisit ONLY if dedupe-on-signature-bytes is ever
        introduced downstream. Pinned by
        ``test_es256_high_s_documented_behavior``.
    """
    parts = jws_str.split(".")
    if len(parts) != 3:
        raise ACEFSigningError("Invalid JWS format: expected 3 parts", code="ACEF-012")

    header_b64 = parts[0]
    sig_b64 = parts[2]

    # Decode header. json.loads is typed to return Any; a JWS protected header
    # is a JSON object, so we narrow the type with cast (no runtime change — the
    # subsequent dict access preserves the pre-existing behavior for any input).
    try:
        header = cast("dict[str, Any]", json.loads(_base64url_decode(header_b64)))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as e:
        raise ACEFSigningError(f"Invalid JWS header: {e}", code="ACEF-012") from e

    alg = header.get("alg", "")
    if alg not in _ALLOWED_ALGORITHMS:
        raise ACEFSigningError(
            f"Unsupported JWS algorithm: {alg!r} (allowed: {sorted(_ALLOWED_ALGORITHMS)})",
            code="ACEF-013",
        )

    # Spec §3.1.3 #5: every JWS header MUST include kid. Reject signatures
    # that lack one — key-rotation and identification depend on this.
    if not header.get("kid"):
        raise ACEFSigningError(
            "JWS header missing required 'kid' field (spec §3.1.3)",
            code="ACEF-013",
        )

    # RFC 7515 §4.1.11: a recipient MUST reject a JWS whose `crit` header
    # lists any extension parameter it does not understand. ACEF understands
    # NO extension header parameters, so the mere PRESENCE of `crit` —
    # whatever its shape — makes the JWS invalid (audit signing-jws-3).
    # Malformed shapes (non-array, empty array — itself forbidden by RFC
    # 7515 — or non-string members) are subsumed by this presence rejection.
    if "crit" in header:
        raise ACEFSigningError(
            "JWS 'crit' header parameter rejected: ACEF understands no "
            "extension header parameters, so any crit-listed parameter is "
            "not understood and the JWS is invalid (RFC 7515 §4.1.11)",
            code="ACEF-013",
        )

    # Get public key
    if public_key is None:
        if key_data is not None:
            public_key = _load_public_key_from_pem(key_data)
        elif "x5c" in header and header["x5c"]:
            # Spec §3.1.3 mandates full-chain validation, NOT just leaf-key
            # extraction. verify_x5c_chain walks links, checks expiry
            # against manifest_timestamp (when provided), and anchors to
            # trust_anchors (when provided).
            public_key = verify_x5c_chain(
                header["x5c"],
                manifest_timestamp=manifest_timestamp,
                trust_anchors=trust_anchors,
            )
        elif "jwk" in header:
            # JWK-based key resolution (spec §3.1.3 trust model:
            # signatures via embedded JWK prove data integrity but not
            # organizational identity — callers SHOULD treat as
            # self-attested).
            public_key = _load_public_key_from_jwk(header["jwk"])
        else:
            raise ACEFSigningError(
                "No public key available: neither x5c nor jwk in header",
                code="ACEF-012",
            )

    # Validate EC public key curve for ES256
    if alg == "ES256" and isinstance(public_key, ec.EllipticCurvePublicKey):
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise ACEFSigningError(
                f"EC public key curve mismatch: {public_key.curve.name!r}, expected P-256",
                code="ACEF-013",
            )

    # RFC 7518 §3.3 floor for RS256, enforced CENTRALLY after key resolution
    # so EVERY path is covered: explicit ``public_key`` argument, PEM
    # ``key_data``, x5c leaf key, and embedded jwk (the loaders also guard
    # their own paths — defense in depth; this check is the backstop for
    # caller-supplied and x5c-derived keys).
    if alg == "RS256" and isinstance(public_key, rsa.RSAPublicKey):
        _enforce_rsa_min_key_size(public_key.key_size, "RS256 verification key")

    # Reconstruct signing input
    payload_b64 = _base64url_encode(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _base64url_decode(sig_b64)

    try:
        if alg == "RS256":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ACEFSigningError("Public key is not RSA for RS256 verification", code="ACEF-012")
            public_key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        elif alg == "ES256":
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise ACEFSigningError("Public key is not EC for ES256 verification", code="ACEF-012")
            # Convert raw r||s back to DER (32 bytes each for P-256)
            if len(signature) != 64:
                raise ACEFSigningError(
                    f"Invalid ES256 signature length: {len(signature)} (expected 64)",
                    code="ACEF-012",
                )
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            # ECDSA malleability — documented, accepted (audit signing-jws-5):
            # the cryptography library verifies BOTH s and n-s for the same
            # message, so a high-S re-encoding of a valid signature also
            # passes here. This is NOT an RFC violation (RFC 7518 §3.4
            # requires r,s in [1, n-1] but does not mandate low-S canonical
            # form) and the content stays authenticated; only the signature
            # BYTES are non-unique. Low-S is deliberately NOT enforced — it
            # would diverge from the TS SDK verify path. Revisit only if
            # dedupe-on-signature-bytes is introduced. Pinned by
            # test_es256_high_s_documented_behavior.
            der_sig = utils.encode_dss_signature(r, s)
            public_key.verify(
                der_sig,
                signing_input,
                ec.ECDSA(hashes.SHA256()),
            )
    except ACEFSigningError:
        raise
    except Exception as e:
        raise ACEFSigningError(f"Signature verification failed: {e}", code="ACEF-012") from e

    return header


def _project_harness_attestation_subset(payload: dict[str, Any]) -> dict[str, Any]:
    """Project a harness_attestation payload down to its signed-fields scope.

    Per :data:`HARNESS_ATTESTATION_SIGNED_FIELDS`, the signature covers
    exactly the 9 normative fields. Fields *absent* from the input are
    *absent* from the projection — i.e., signing a payload that lacks
    ``signer_kid`` produces a subset without that key, and any later
    re-injection of the field by an attacker will perturb the JCS bytes
    and fail verification. This "present-only" projection (as opposed
    to filling absent fields with ``None``) is the design choice that
    makes drop-or-inject tampering detectable.

    Fields *outside* the 9-field list are excluded entirely, so vendor
    extensions and future-spec fields carried alongside the payload
    have no effect on the signature.
    """
    if not isinstance(payload, dict):
        raise ACEFSigningError(
            f"harness_attestation payload must be a dict, got {type(payload).__name__}",
            code="ACEF-012",
        )
    subset: dict[str, Any] = {}
    for field in HARNESS_ATTESTATION_SIGNED_FIELDS:
        if field in payload:
            subset[field] = payload[field]
    return subset


def sign_harness_attestation(
    payload: dict[str, Any],
    *,
    private_key: PrivateKeyTypes,
    signer_kid: str,
) -> str:
    """Produce a JWS detached signature over the harness_attestation
    signed-fields scope (VAL-SIGNATURE-001..004).

    Builds a sub-dict of ``payload`` limited to the 9 normative fields
    listed in :data:`HARNESS_ATTESTATION_SIGNED_FIELDS`, RFC 8785
    canonicalizes that sub-dict, and produces a detached JWS over the
    canonical bytes. The JWS header includes ``alg`` (RS256 or ES256
    auto-detected from the key type per :func:`_detect_algorithm`),
    ``kid`` (the supplied ``signer_kid``), and an auto-embedded JWK so
    that verifiers without out-of-band key material can still verify.

    Args:
        payload: The full harness_attestation payload (may contain
            additional fields beyond the 9-field signed scope; they
            are excluded from signing).
        private_key: RSA-2048+ or EC P-256 private key. Other key
            types raise ``ACEFSigningError(code="ACEF-013")`` via
            :func:`_detect_algorithm`.
        signer_kid: The key identifier to embed in the JWS header.
            Required per spec §3.1.3 #5. Empty kid raises.

    Returns:
        JWS compact serialization in detached form
        ``"<header_b64>..<signature_b64>"``.

    Raises:
        ACEFSigningError: For unsupported algorithms, malformed input,
            or cryptographic failures.
    """
    # Import locally to avoid a top-of-module cycle (integrity imports
    # nothing from signing, but the lazy form keeps the dependency
    # direction explicit).
    from acef.integrity import canonicalize

    subset = _project_harness_attestation_subset(payload)
    canonical = canonicalize(subset)
    return create_detached_jws(canonical, private_key, kid=signer_kid)


def verify_harness_attestation(
    payload: dict[str, Any],
    signature: str,
    *,
    public_key: PublicKeyTypes | None = None,
    key_data: bytes | None = None,
) -> bool:
    """Verify a harness_attestation JWS detached signature.

    Reconstructs the 9-field subset from ``payload`` per
    :data:`HARNESS_ATTESTATION_SIGNED_FIELDS`, JCS-canonicalizes it,
    and verifies ``signature`` against those bytes.

    Algorithm whitelist enforcement:

    - Headers whose ``alg`` is not in :data:`_ALLOWED_ALGORITHMS`
      raise ``ACEFSigningError(code="ACEF-013")``. This includes
      ``"HS256"``, ``"EdDSA"``, ``"none"``, etc.
    - This raise propagates *out* of this function — it is not
      swallowed into a ``False`` return — because callers MUST be
      able to distinguish a tampered-payload (cryptographic
      verification failure → ``False``) from a malformed-or-forbidden
      signature (structural failure → exception with diagnostic).

    Cryptographic verification failure returns ``False`` without
    raising, so callers can branch cleanly on tamper detection.

    Args:
        payload: The full harness_attestation payload. Only the 9
            normative fields participate in verification; outside
            fields are ignored.
        signature: JWS compact serialization
            ``"<header_b64>..<signature_b64>"``.
        public_key: Verification key. If omitted, the JWS header's
            embedded ``jwk`` or ``x5c`` is used by
            :func:`verify_detached_jws`.
        key_data: Optional PEM-encoded public key (alternative to
            ``public_key``).

    Returns:
        ``True`` on successful verification; ``False`` on
        cryptographic failure (signature does not match payload subset).

    Raises:
        ACEFSigningError: With code ``ACEF-013`` for non-whitelisted
            ``alg`` headers. With code ``ACEF-012`` for malformed JWS
            structure (wrong segment count, undecodable header, etc.).
    """
    from acef.integrity import canonicalize

    subset = _project_harness_attestation_subset(payload)
    canonical = canonicalize(subset)

    try:
        verify_detached_jws(
            signature,
            canonical,
            public_key,
            key_data=key_data,
        )
    except ACEFSigningError as exc:
        # ACEF-013 (unsupported alg, missing kid, key-type mismatch) and
        # ACEF-012 structural failures (malformed JWS, missing header
        # fields) propagate. Only the post-structural cryptographic
        # verification failure (also ACEF-012 — re-raised by
        # verify_detached_jws's except-clause around the
        # cryptography-lib verify call) is converted to a False return
        # so callers can branch cleanly on tamper detection.
        if exc.code == "ACEF-013":
            raise
        # Distinguish the "signature did not match" path from other
        # structural ACEF-012 cases. verify_detached_jws raises a
        # message starting with "Signature verification failed:" only
        # for the cryptographic verify-call failure (see signing.py
        # near `raise ACEFSigningError(f"Signature verification
        # failed: {e}", code="ACEF-012")`). All other ACEF-012 sites
        # carry distinct prefixes (e.g., "Invalid JWS format", "Invalid
        # JWS header", "Public key is not RSA for RS256
        # verification"). Matching by prefix keeps the tamper-vs-
        # malformed-JWS distinction crisp.
        if str(exc).startswith("[ACEF-012] Signature verification failed"):
            return False
        # Any other ACEF-012 (structurally malformed JWS, wrong key
        # type for declared alg, etc.) propagates as a real error so
        # callers see the diagnostic.
        raise
    return True


def sign_bundle(bundle_dir: Path, key_path: str, *, kid: str = "provider-key") -> str:
    """Sign an exported bundle's content-hashes.json.

    Per spec Section 3.1.3: the JWS signature is over the raw bytes of
    content-hashes.json after RFC 8785 canonicalization. This function
    re-canonicalizes the file to ensure correctness even if the file was
    modified or reformatted after initial export.

    Creates a JWS file in signatures/ using the kid for the filename.

    Args:
        bundle_dir: Path to the bundle directory.
        key_path: Path to the PEM private key file.
        kid: Key identifier.

    Returns:
        Path to the created signature file.
    """
    from acef.integrity import canonicalize_json_str

    content_hashes_path = bundle_dir / "hashes" / "content-hashes.json"
    if not content_hashes_path.exists():
        raise ACEFSigningError("content-hashes.json not found — export first", code="ACEF-014")

    # Re-canonicalize to ensure the payload matches RFC 8785 regardless of
    # whether the file was modified after export (e.g., pretty-printed by
    # an external JSON tool). The spec requires signing over the canonicalized
    # bytes of content-hashes.json.
    raw_content = content_hashes_path.read_text(encoding="utf-8")
    payload = canonicalize_json_str(raw_content)

    private_key = _load_private_key(key_path)
    jws = create_detached_jws(payload, private_key, kid=kid)

    sig_dir = bundle_dir / "signatures"
    sig_dir.mkdir(exist_ok=True)
    # Sanitize kid for filesystem use: keep only safe characters
    safe_kid = re.sub(r"[^A-Za-z0-9_\-.]", "-", kid)
    sig_filename = f"{safe_kid}.jws"
    sig_path = sig_dir / sig_filename
    sig_path.write_text(jws, encoding="utf-8")

    return str(sig_path)


def sign_assessment(
    assessment_data: dict[str, Any],
    key_path: str,
) -> dict[str, Any]:
    """Sign an Assessment Bundle.

    Per spec: set integrity to null, canonicalize, sign, then populate integrity.

    Creates a shallow copy of the input dict to avoid mutating the caller's
    data (m5 Scout R2).

    Args:
        assessment_data: The Assessment Bundle dict.
        key_path: Path to the PEM private key file.

    Returns:
        A new Assessment Bundle dict with populated integrity block.
    """
    from acef.integrity import canonicalize

    # m5 (Scout R2): Shallow copy to avoid mutating caller's dict
    assessment_data = dict(assessment_data)

    # Set integrity to null for signing
    assessment_data["integrity"] = None
    canonical = canonicalize(assessment_data)

    private_key = _load_private_key(key_path)
    jws = create_detached_jws(canonical, private_key, kid="assessor-key")

    assessment_data["integrity"] = {
        "signature": {
            "method": "jws",
            "signer": "",
            "value": jws,
        }
    }

    return assessment_data


def verify_assessment(
    assessment_data: dict[str, Any],
    public_key: PublicKeyTypes | None = None,
    *,
    key_data: bytes | None = None,
    manifest_timestamp: str | None = None,
    trust_anchors: list[Certificate] | None = None,
) -> bool:
    """Verify an Assessment Bundle's detached JWS signature.

    Reverses :func:`sign_assessment`: sets the ``integrity`` block to
    ``None``, re-canonicalizes via RFC 8785, and verifies the JWS over
    the resulting bytes. The supplied ``assessment_data`` is NOT mutated.

    Args:
        assessment_data: The Assessment Bundle dict, including a
            populated ``integrity.signature.value``.
        public_key: Optional public key (skips x5c/jwk extraction).
        key_data: Optional PEM-encoded public key or certificate (used
            when neither x5c nor jwk is embedded and ``public_key`` is
            None).
        manifest_timestamp: Forwarded to :func:`verify_detached_jws` for
            x5c expiry checks.
        trust_anchors: Forwarded to :func:`verify_detached_jws` for chain
            anchoring.

    Returns:
        True on successful verification.

    Raises:
        ACEFSigningError: If the assessment lacks a signature, the JWS is
            malformed, or verification fails.
    """
    from acef.integrity import canonicalize

    if not isinstance(assessment_data, dict):
        raise ACEFSigningError(
            "Assessment data must be a dict",
            code="ACEF-012",
        )

    integrity = assessment_data.get("integrity")
    if not integrity or not isinstance(integrity, dict):
        raise ACEFSigningError(
            "Assessment Bundle has no integrity block — nothing to verify",
            code="ACEF-012",
        )
    signature_block = integrity.get("signature")
    if not signature_block or not isinstance(signature_block, dict):
        raise ACEFSigningError(
            "Assessment Bundle integrity block has no signature",
            code="ACEF-012",
        )
    jws = signature_block.get("value")
    if not isinstance(jws, str) or not jws:
        raise ACEFSigningError(
            "Assessment Bundle signature value is missing or non-string",
            code="ACEF-012",
        )

    # Shallow-copy so the caller's dict is not mutated when we null out
    # integrity for canonicalization.
    pre_sign = dict(assessment_data)
    pre_sign["integrity"] = None
    canonical = canonicalize(pre_sign)

    verify_detached_jws(
        jws,
        canonical,
        public_key,
        key_data=key_data,
        manifest_timestamp=manifest_timestamp,
        trust_anchors=trust_anchors,
    )
    return True
