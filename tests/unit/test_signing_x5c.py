"""Unit tests for x5c certificate-chain verification (VAL-FIX-SIGNING-001).

Covers the spec §3.1.3 "Signature trust model (normative)" MUSTs that
``signing.verify_x5c_chain`` implements but which had ZERO covering tests
(audit finding signing-jws-1):

- "If x5c is present, verifiers MUST validate the full certificate chain
  against a locally configured set of trust anchors."
- "Certificate expiry is checked against the metadata.timestamp value from
  the manifest, NOT wall-clock time (this ensures reproducible
  verification)."

Test matrix (real 2-3 cert chains built with ``cryptography``):
(a) anchored chain verifies (terminates AT an anchor, and chain-signed-BY
    an anchor);
(b) chain NOT terminating at any configured anchor raises ACEF-012;
(c) broken chain link raises ACEF-012;
(d) cert validity window not covering manifest_timestamp raises while
    wall-clock "now" would NOT (reproducible-expiry, both directions);
(e) absent anchors -> self-attested pass (backward compatibility per the
    trust model: "If jwk is present without x5c, the signature proves data
    integrity but not organizational identity" — and an x5c chain without
    locally configured anchors is likewise self-attested).

Plus the ``verify_detached_jws(..., trust_anchors=...)`` passthrough that
the bundle-validation pipeline (F-M1-X5C-ANCHOR) relies on.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acef.errors import ACEFSigningError
from acef.signing import create_detached_jws, verify_detached_jws, verify_x5c_chain

# Manifest timestamp used by default in these tests. Deterministic — no
# wall-clock dependence except in the tests that deliberately PROVE
# wall-clock independence.
MANIFEST_TS = "2026-01-01T00:00:00Z"

# Default validity window comfortably covering MANIFEST_TS.
DEFAULT_NOT_BEFORE = datetime(2020, 1, 1, tzinfo=UTC)
DEFAULT_NOT_AFTER = datetime(2036, 1, 1, tzinfo=UTC)


def _make_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _ca_key_usage(*, key_cert_sign: bool = True, digital_signature: bool = False) -> x509.KeyUsage:
    """A KeyUsage extension value; defaults to the CA shape (keyCertSign)."""
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=key_cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def _make_cert(
    subject_cn: str,
    *,
    public_key: ec.EllipticCurvePublicKey,
    signing_key: ec.EllipticCurvePrivateKey,
    issuer_cn: str | None = None,
    not_before: datetime = DEFAULT_NOT_BEFORE,
    not_after: datetime = DEFAULT_NOT_AFTER,
    basic_constraints: x509.BasicConstraints | None = None,
    key_usage: x509.KeyUsage | None = None,
) -> x509.Certificate:
    """Build an X.509 cert for ``public_key`` signed by ``signing_key``.

    When ``issuer_cn`` is None the cert is self-issued (subject == issuer),
    which combined with ``signing_key`` being the subject's own key yields a
    self-SIGNED certificate. ``basic_constraints`` / ``key_usage`` are added
    as critical extensions when provided; ``None`` omits the extension
    entirely (the pre-CA-enforcement cert shape).
    """
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or subject_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if basic_constraints is not None:
        builder = builder.add_extension(basic_constraints, critical=True)
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    return builder.sign(signing_key, hashes.SHA256())


def _b64(cert: x509.Certificate) -> str:
    """x5c entries are standard base64 (NOT base64url) DER."""
    from cryptography.hazmat.primitives import serialization

    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")


def _build_chain(
    *,
    not_before: datetime = DEFAULT_NOT_BEFORE,
    not_after: datetime = DEFAULT_NOT_AFTER,
) -> tuple[ec.EllipticCurvePrivateKey, list[x509.Certificate]]:
    """Build a real 3-cert chain: leaf <- intermediate <- root.

    The intermediate and root are PROPER CA certificates (BasicConstraints
    ca=True + KeyUsage keyCertSign) — verify_x5c_chain enforces RFC 5280
    issuer path constraints, so a constraint-less 'intermediate' would be
    rejected as an end-entity cert.

    Returns (leaf_private_key, [leaf, intermediate, root]).
    """
    root_key = _make_key()
    inter_key = _make_key()
    leaf_key = _make_key()
    root = _make_cert(
        "acef-test-root",
        public_key=root_key.public_key(),
        signing_key=root_key,
        not_before=not_before,
        not_after=not_after,
        basic_constraints=x509.BasicConstraints(ca=True, path_length=None),
        key_usage=_ca_key_usage(),
    )
    inter = _make_cert(
        "acef-test-intermediate",
        public_key=inter_key.public_key(),
        signing_key=root_key,
        issuer_cn="acef-test-root",
        not_before=not_before,
        not_after=not_after,
        basic_constraints=x509.BasicConstraints(ca=True, path_length=0),
        key_usage=_ca_key_usage(),
    )
    leaf = _make_cert(
        "acef-test-leaf",
        public_key=leaf_key.public_key(),
        signing_key=inter_key,
        issuer_cn="acef-test-intermediate",
        not_before=not_before,
        not_after=not_after,
    )
    return leaf_key, [leaf, inter, root]


def _unrelated_root() -> x509.Certificate:
    key = _make_key()
    return _make_cert("acef-unrelated-root", public_key=key.public_key(), signing_key=key)


# --------------------------------------------------------------------------
# (a) Anchored chain verifies.
# --------------------------------------------------------------------------


class TestAnchoredChain:
    def test_full_chain_terminating_at_anchor_verifies(self) -> None:
        """leaf <- intermediate <- root with trust_anchors=[root] verifies and
        returns the LEAF public key (the JWS verification key)."""
        leaf_key, chain = _build_chain()
        x5c = [_b64(c) for c in chain]
        result = verify_x5c_chain(x5c, manifest_timestamp=MANIFEST_TS, trust_anchors=[chain[-1]])
        assert isinstance(result, ec.EllipticCurvePublicKey)
        assert result.public_numbers() == leaf_key.public_key().public_numbers()

    def test_chain_signed_by_anchor_verifies(self) -> None:
        """A chain whose FINAL cert is signed BY a configured anchor (root
        not shipped in x5c) is anchored per the 'OR signed by one of these'
        rule in verify_x5c_chain."""
        leaf_key, chain = _build_chain()
        leaf, inter, root = chain
        x5c = [_b64(leaf), _b64(inter)]  # root omitted from the wire chain
        result = verify_x5c_chain(x5c, manifest_timestamp=MANIFEST_TS, trust_anchors=[root])
        assert isinstance(result, ec.EllipticCurvePublicKey)
        assert result.public_numbers() == leaf_key.public_key().public_numbers()


# --------------------------------------------------------------------------
# (b) Chain NOT terminating at any configured anchor raises ACEF-012.
# --------------------------------------------------------------------------


class TestAnchorTermination:
    def test_unanchored_chain_raises_acef_012(self) -> None:
        """An internally-consistent chain that does NOT terminate at any
        configured trust anchor MUST be rejected (spec §3.1.3 trust model)."""
        _, chain = _build_chain()
        x5c = [_b64(c) for c in chain]
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain(x5c, manifest_timestamp=MANIFEST_TS, trust_anchors=[_unrelated_root()])
        assert excinfo.value.code == "ACEF-012"
        assert "trust anchor" in str(excinfo.value)

    def test_self_signed_cert_not_in_anchor_set_raises(self) -> None:
        """A self-issued single-cert chain (forgeable by anyone) MUST NOT
        anchor unless that exact cert is locally configured."""
        key = _make_key()
        self_signed = _make_cert("acef-self-issued", public_key=key.public_key(), signing_key=key)
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain(
                [_b64(self_signed)],
                manifest_timestamp=MANIFEST_TS,
                trust_anchors=[_unrelated_root()],
            )
        assert excinfo.value.code == "ACEF-012"
        assert "trust anchor" in str(excinfo.value)

    def test_empty_trust_anchor_list_raises(self) -> None:
        """trust_anchors=[] is a configuration error: anchoring was requested
        but no anchor can ever match. MUST reject, never silently pass."""
        _, chain = _build_chain()
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain(
                [_b64(c) for c in chain],
                manifest_timestamp=MANIFEST_TS,
                trust_anchors=[],
            )
        assert excinfo.value.code == "ACEF-012"


# --------------------------------------------------------------------------
# (c) Broken chain link raises ACEF-012.
# --------------------------------------------------------------------------


class TestChainLinks:
    def test_broken_link_raises_acef_012(self) -> None:
        """If x5c[0] is not signed by x5c[1], the chain MUST be rejected even
        when the tail IS a configured anchor (full-chain validation, not just
        anchor membership)."""
        _, chain = _build_chain()
        leaf, _inter, root = chain
        # Splice out the intermediate: leaf was signed by the INTERMEDIATE
        # key, so root does not verify it -> broken link.
        x5c = [_b64(leaf), _b64(root)]
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain(x5c, manifest_timestamp=MANIFEST_TS, trust_anchors=[root])
        assert excinfo.value.code == "ACEF-012"
        assert "broken chain" in str(excinfo.value)

    def test_broken_link_raises_even_without_anchors(self) -> None:
        """Chain-link verification is unconditional — it applies even in the
        anchor-less (self-attested) mode."""
        _, chain = _build_chain()
        leaf, _inter, root = chain
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain([_b64(leaf), _b64(root)], manifest_timestamp=MANIFEST_TS)
        assert excinfo.value.code == "ACEF-012"
        assert "broken chain" in str(excinfo.value)

    def test_empty_x5c_raises(self) -> None:
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain([], manifest_timestamp=MANIFEST_TS)
        assert excinfo.value.code == "ACEF-012"


# --------------------------------------------------------------------------
# (d) Expiry against manifest_timestamp, NOT wall-clock (reproducible).
# --------------------------------------------------------------------------


class TestManifestTimestampExpiry:
    def test_cert_valid_now_but_not_at_manifest_timestamp_raises(self) -> None:
        """A cert whose window covers wall-clock NOW but NOT the manifest
        timestamp MUST be rejected — proving the check reads
        manifest_timestamp, not the wall clock."""
        now = datetime.now(UTC)
        not_before = now - timedelta(days=30)
        not_after = now + timedelta(days=30)
        _, chain = _build_chain(not_before=not_before, not_after=not_after)
        # Sanity: wall-clock now IS inside the window, so a wall-clock-based
        # check would have passed.
        assert not_before < now < not_after
        past_ts = "2019-01-01T00:00:00Z"
        assert datetime(2019, 1, 1, tzinfo=UTC) < not_before
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain(
                [_b64(c) for c in chain],
                manifest_timestamp=past_ts,
                trust_anchors=[chain[-1]],
            )
        assert excinfo.value.code == "ACEF-012"
        assert "not yet valid" in str(excinfo.value)
        assert past_ts in str(excinfo.value)

    def test_cert_expired_at_wall_clock_passes_with_covering_manifest_timestamp(self) -> None:
        """Reproducible verification (spec §3.1.3): a bundle signed before its
        cert expired still verifies after the cert has rolled over. The cert
        window is entirely in the past — a wall-clock check would fail — but
        the manifest timestamp falls inside the window, so verification
        succeeds."""
        not_before = datetime(2020, 1, 1, tzinfo=UTC)
        not_after = datetime(2021, 1, 1, tzinfo=UTC)
        leaf_key, chain = _build_chain(not_before=not_before, not_after=not_after)
        # Sanity: the chain IS expired in wall-clock terms.
        assert datetime.now(UTC) > not_after
        result = verify_x5c_chain(
            [_b64(c) for c in chain],
            manifest_timestamp="2020-06-01T00:00:00Z",
            trust_anchors=[chain[-1]],
        )
        assert result.public_numbers() == leaf_key.public_key().public_numbers()  # type: ignore[union-attr]

    def test_cert_expired_relative_to_manifest_timestamp_raises(self) -> None:
        """manifest_timestamp AFTER not_valid_after -> 'certificate expired'."""
        not_before = datetime(2020, 1, 1, tzinfo=UTC)
        not_after = datetime(2021, 1, 1, tzinfo=UTC)
        _, chain = _build_chain(not_before=not_before, not_after=not_after)
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain(
                [_b64(c) for c in chain],
                manifest_timestamp="2022-01-01T00:00:00Z",
                trust_anchors=[chain[-1]],
            )
        assert excinfo.value.code == "ACEF-012"
        assert "expired" in str(excinfo.value)

    def test_malformed_manifest_timestamp_raises(self) -> None:
        _, chain = _build_chain()
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain([_b64(c) for c in chain], manifest_timestamp="NOT-A-TIMESTAMP")
        assert excinfo.value.code == "ACEF-012"


# --------------------------------------------------------------------------
# (e) Absent anchors -> self-attested pass (backward compatibility).
# --------------------------------------------------------------------------


class TestSelfAttestedMode:
    def test_absent_anchors_chain_links_verified_no_anchor_enforcement(self) -> None:
        """trust_anchors=None: chain links and expiry are still verified, but
        no external root anchoring is enforced — 'self-attested' trust per the
        spec trust model. This pins today's default behavior so the pipeline
        threading (default None) is behavior-neutral."""
        leaf_key, chain = _build_chain()
        result = verify_x5c_chain([_b64(c) for c in chain], manifest_timestamp=MANIFEST_TS)
        assert result.public_numbers() == leaf_key.public_key().public_numbers()  # type: ignore[union-attr]

    def test_absent_anchors_self_signed_single_cert_passes(self) -> None:
        """A self-issued single-cert chain passes in self-attested mode (no
        anchors configured). Attribution honesty: without locally configured
        anchors this proves data integrity only, NOT organizational identity."""
        key = _make_key()
        self_signed = _make_cert("acef-self-issued", public_key=key.public_key(), signing_key=key)
        result = verify_x5c_chain([_b64(self_signed)], manifest_timestamp=MANIFEST_TS)
        assert result.public_numbers() == key.public_key().public_numbers()  # type: ignore[union-attr]


# --------------------------------------------------------------------------
# X.509 path constraints on ISSUERS (roborev High finding on d80198be):
# every cert that signs another cert in the path MUST be a real CA.
# Without this, a CA-issued END-ENTITY cert (BasicConstraints ca=False,
# no keyCertSign) can act as an intermediate and sign a forged leaf that
# is then accepted as anchored. The LEAF is exempt — it never issues.
# --------------------------------------------------------------------------

_CA = x509.BasicConstraints(ca=True, path_length=None)
_NOT_CA = x509.BasicConstraints(ca=False, path_length=None)


def _build_constrained_chain(
    *,
    intermediate_bc: x509.BasicConstraints | None,
    intermediate_ku: x509.KeyUsage | None,
    leaf_issuer_cn: str = "constrained-intermediate",
    root_path_length: int | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, list[x509.Certificate]]:
    """leaf <- intermediate <- root where the ROOT is always a proper CA and
    the INTERMEDIATE's constraints are caller-controlled.

    Returns (leaf_private_key, [leaf, intermediate, root]).
    """
    root_key = _make_key()
    inter_key = _make_key()
    leaf_key = _make_key()
    root = _make_cert(
        "constrained-root",
        public_key=root_key.public_key(),
        signing_key=root_key,
        basic_constraints=x509.BasicConstraints(ca=True, path_length=root_path_length),
        key_usage=_ca_key_usage(),
    )
    inter = _make_cert(
        "constrained-intermediate",
        public_key=inter_key.public_key(),
        signing_key=root_key,
        issuer_cn="constrained-root",
        basic_constraints=intermediate_bc,
        key_usage=intermediate_ku,
    )
    leaf = _make_cert(
        "constrained-leaf",
        public_key=leaf_key.public_key(),
        signing_key=inter_key,
        issuer_cn=leaf_issuer_cn,
    )
    return leaf_key, [leaf, inter, root]


class TestIssuerPathConstraints:
    def test_ca_false_intermediate_rejected_when_anchored(self) -> None:
        """THE exploit (RED-first): a CA-issued END-ENTITY cert (ca=False)
        acting as intermediate signs a forged leaf. Before the fix this chain
        VERIFIED as anchored; it MUST raise ACEF-012."""
        _, chain = _build_constrained_chain(
            intermediate_bc=_NOT_CA,
            intermediate_ku=_ca_key_usage(key_cert_sign=False, digital_signature=True),
        )
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain(
                [_b64(c) for c in chain],
                manifest_timestamp=MANIFEST_TS,
                trust_anchors=[chain[-1]],
            )
        assert excinfo.value.code == "ACEF-012"
        assert "cannot act as an issuer" in str(excinfo.value)

    def test_ca_false_intermediate_rejected_without_anchors(self) -> None:
        """A non-CA issuer is an invalid X.509 path REGARDLESS of anchoring —
        the constraint applies in self-attested (no-anchors) mode too."""
        _, chain = _build_constrained_chain(intermediate_bc=_NOT_CA, intermediate_ku=None)
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain([_b64(c) for c in chain], manifest_timestamp=MANIFEST_TS)
        assert excinfo.value.code == "ACEF-012"
        assert "not a CA" in str(excinfo.value)

    def test_issuer_missing_basic_constraints_rejected(self) -> None:
        """An issuer WITHOUT a BasicConstraints extension is not a CA and
        MUST be rejected (fail closed)."""
        _, chain = _build_constrained_chain(intermediate_bc=None, intermediate_ku=None)
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain([_b64(c) for c in chain], manifest_timestamp=MANIFEST_TS)
        assert excinfo.value.code == "ACEF-012"
        assert "no BasicConstraints" in str(excinfo.value)

    def test_issuer_key_usage_without_key_cert_sign_rejected(self) -> None:
        """ca=True but a KeyUsage extension lacking keyCertSign — the issuer
        is not authorized to sign certificates. MUST be rejected."""
        _, chain = _build_constrained_chain(
            intermediate_bc=_CA,
            intermediate_ku=_ca_key_usage(key_cert_sign=False, digital_signature=True),
        )
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain([_b64(c) for c in chain], manifest_timestamp=MANIFEST_TS)
        assert excinfo.value.code == "ACEF-012"
        assert "keyCertSign" in str(excinfo.value)

    def test_issuer_subject_name_mismatch_rejected(self) -> None:
        """The leaf's issuer NAME does not match the intermediate's subject
        even though the SIGNATURE verifies (signed by the intermediate's
        key) — broken name chaining MUST be rejected."""
        _, chain = _build_constrained_chain(
            intermediate_bc=_CA,
            intermediate_ku=_ca_key_usage(),
            leaf_issuer_cn="somebody-else-entirely",
        )
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain([_b64(c) for c in chain], manifest_timestamp=MANIFEST_TS)
        assert excinfo.value.code == "ACEF-012"
        assert "name" in str(excinfo.value)

    def test_path_length_zero_root_above_intermediate_rejected(self) -> None:
        """A root with pathLenConstraint=0 may issue only end-entity certs;
        an intermediate CA below it violates the constraint."""
        _, chain = _build_constrained_chain(
            intermediate_bc=_CA,
            intermediate_ku=_ca_key_usage(),
            root_path_length=0,
        )
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain([_b64(c) for c in chain], manifest_timestamp=MANIFEST_TS)
        assert excinfo.value.code == "ACEF-012"
        assert "path_length" in str(excinfo.value)

    def test_non_ca_anchor_cannot_anchor_via_signed_by_rule(self) -> None:
        """An anchor used via the 'chain signed BY an anchor' rule acts as an
        ISSUER and must satisfy the same CA constraints. An end-entity cert
        configured as anchor must NOT anchor a chain it signed."""
        ee_key = _make_key()
        ee_cert = _make_cert(
            "ee-as-anchor",
            public_key=ee_key.public_key(),
            signing_key=ee_key,
            basic_constraints=_NOT_CA,
        )
        leaf_key = _make_key()
        leaf = _make_cert(
            "leaf-under-ee",
            public_key=leaf_key.public_key(),
            signing_key=ee_key,
            issuer_cn="ee-as-anchor",
        )
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_x5c_chain(
                [_b64(leaf)],
                manifest_timestamp=MANIFEST_TS,
                trust_anchors=[ee_cert],
            )
        assert excinfo.value.code == "ACEF-012"
        assert "trust anchor" in str(excinfo.value)

    # ---- positive cases: proper CA paths remain valid ----

    def test_proper_ca_chain_with_path_lengths_verifies(self) -> None:
        """root(pl=1) <- inter(pl=0, keyCertSign) <- leaf is a fully
        constraint-compliant path and MUST verify."""
        root_key = _make_key()
        inter_key = _make_key()
        leaf_key = _make_key()
        root = _make_cert(
            "pl-root",
            public_key=root_key.public_key(),
            signing_key=root_key,
            basic_constraints=x509.BasicConstraints(ca=True, path_length=1),
            key_usage=_ca_key_usage(),
        )
        inter = _make_cert(
            "pl-inter",
            public_key=inter_key.public_key(),
            signing_key=root_key,
            issuer_cn="pl-root",
            basic_constraints=x509.BasicConstraints(ca=True, path_length=0),
            key_usage=_ca_key_usage(),
        )
        leaf = _make_cert(
            "pl-leaf",
            public_key=leaf_key.public_key(),
            signing_key=inter_key,
            issuer_cn="pl-inter",
        )
        result = verify_x5c_chain(
            [_b64(leaf), _b64(inter), _b64(root)],
            manifest_timestamp=MANIFEST_TS,
            trust_anchors=[root],
        )
        assert result.public_numbers() == leaf_key.public_key().public_numbers()  # type: ignore[union-attr]

    def test_issuer_without_key_usage_extension_accepted(self) -> None:
        """KeyUsage is OPTIONAL: an issuer carrying only BasicConstraints
        ca=True (no KeyUsage extension at all) is a valid CA."""
        leaf_key, chain = _build_constrained_chain(intermediate_bc=_CA, intermediate_ku=None)
        result = verify_x5c_chain(
            [_b64(c) for c in chain],
            manifest_timestamp=MANIFEST_TS,
            trust_anchors=[chain[-1]],
        )
        assert result.public_numbers() == leaf_key.public_key().public_numbers()  # type: ignore[union-attr]

    def test_leaf_with_ca_false_basic_constraints_accepted(self) -> None:
        """The LEAF is exempt from CA requirements — a typical end-entity
        leaf (BasicConstraints ca=False, digitalSignature-only KeyUsage)
        under a proper CA verifies."""
        ca_key = _make_key()
        ca_cert = _make_cert(
            "leaf-exempt-ca",
            public_key=ca_key.public_key(),
            signing_key=ca_key,
            basic_constraints=_CA,
            key_usage=_ca_key_usage(),
        )
        leaf_key = _make_key()
        leaf = _make_cert(
            "leaf-exempt-leaf",
            public_key=leaf_key.public_key(),
            signing_key=ca_key,
            issuer_cn="leaf-exempt-ca",
            basic_constraints=_NOT_CA,
            key_usage=_ca_key_usage(key_cert_sign=False, digital_signature=True),
        )
        result = verify_x5c_chain(
            [_b64(leaf), _b64(ca_cert)],
            manifest_timestamp=MANIFEST_TS,
            trust_anchors=[ca_cert],
        )
        assert result.public_numbers() == leaf_key.public_key().public_numbers()  # type: ignore[union-attr]


# --------------------------------------------------------------------------
# verify_detached_jws threads trust_anchors into verify_x5c_chain.
# --------------------------------------------------------------------------


class TestVerifyDetachedJwsTrustAnchors:
    def test_anchored_jws_verifies(self) -> None:
        leaf_key, chain = _build_chain()
        payload = b'{"records/test.jsonl":"abc123"}'
        jws = create_detached_jws(payload, leaf_key, kid="x5c-unit-key", x5c=[_b64(c) for c in chain])
        header = verify_detached_jws(
            jws,
            payload,
            manifest_timestamp=MANIFEST_TS,
            trust_anchors=[chain[-1]],
        )
        assert header["alg"] == "ES256"
        assert header["kid"] == "x5c-unit-key"

    def test_unanchored_jws_rejected_when_anchors_configured(self) -> None:
        """An internally-consistent JWS over an x5c chain that does not
        terminate at any configured anchor MUST fail verification with the
        existing ACEF-012 signature-failure code."""
        leaf_key, chain = _build_chain()
        payload = b'{"records/test.jsonl":"abc123"}'
        jws = create_detached_jws(payload, leaf_key, kid="x5c-unit-key", x5c=[_b64(c) for c in chain])
        with pytest.raises(ACEFSigningError) as excinfo:
            verify_detached_jws(
                jws,
                payload,
                manifest_timestamp=MANIFEST_TS,
                trust_anchors=[_unrelated_root()],
            )
        assert excinfo.value.code == "ACEF-012"
        assert "trust anchor" in str(excinfo.value)

    def test_jws_without_anchors_self_attested_pass(self) -> None:
        """Default (no anchors): the same x5c JWS verifies — backward compat
        with every existing caller of verify_detached_jws."""
        leaf_key, chain = _build_chain()
        payload = b'{"records/test.jsonl":"abc123"}'
        jws = create_detached_jws(payload, leaf_key, kid="x5c-unit-key", x5c=[_b64(c) for c in chain])
        header = verify_detached_jws(jws, payload, manifest_timestamp=MANIFEST_TS)
        assert header["alg"] == "ES256"
