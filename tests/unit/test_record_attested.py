"""record_attested JWS verification tests (VAL-FIX-DSL-001 / VAL-FIX-DSL-002).

Spec §3.5 record_attested row: "At least min_count records of the given type
have a non-null attestation block with a valid JWS signature ... Verification:
extract the fields listed in signed_fields, canonicalize via RFC 8785, verify
the detached JWS." The attestation block (spec §3.1) further mandates
method == "jws" for v1 and that signed_fields MUST include "/payload".

RED-first reproduction of audit finding validation-engine-dsl-1: the
presence-only implementation counted attestation={method: anything,
signature: "abc"} as attested. Every negative vector here FAILS against that
implementation and passes only when the operator actually verifies the JWS.
"""

from __future__ import annotations

import base64
import datetime

import jsonpointer  # type: ignore[import-untyped]  # no published stubs / py.typed
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from acef.integrity import canonicalize
from acef.models.enums import RuleOutcome
from acef.models.records import Attestation, RecordEnvelope
from acef.signing import create_detached_jws
from acef.templates.models import EvaluationRule, Provision
from acef.validation.operators import op_record_attested
from acef.validation.rule_engine import evaluate_rules_for_subject


def _make_record(
    record_type: str = "risk_register",
    payload: dict | None = None,
) -> RecordEnvelope:
    return RecordEnvelope(
        record_type=record_type,
        provisions_addressed=["article-9"],
        payload=payload if payload is not None else {"description": "Identified risk", "score": 42},
        timestamp="2025-06-01T00:00:00Z",
    )


def _sign_attestation(
    record: RecordEnvelope,
    private_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey,
    signed_fields: list[str] | None = None,
    kid: str = "attestor-key",
) -> str:
    """Mirror the normative recipe: extract signed_fields subtrees from the
    record's serialized form, RFC 8785-canonicalize the {pointer: value}
    object, and create the detached JWS over those bytes."""
    fields = signed_fields if signed_fields is not None else ["/payload"]
    record_dict = record.to_jsonl_dict()
    subset = {ptr: jsonpointer.resolve_pointer(record_dict, ptr) for ptr in fields}
    return create_detached_jws(canonicalize(subset), private_key, kid=kid)


def _es256_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _rs256_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class TestForgedSignaturesNotCounted:
    """Negative vectors: forged/garbage signatures MUST NOT count (RED-first)."""

    def test_forged_garbage_signature_not_counted(self) -> None:
        """The exact audit repro: attestation={method:'jws', signature:'abc'}."""
        rec = _make_record()
        rec.attestation = Attestation(method="jws", signer="attacker", signature="abc")
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [rec])
        assert passed is False
        assert refs == []

    def test_structurally_jwslike_fake_signature_not_counted(self) -> None:
        """The old conformance fixture: a JWS-shaped string with no real signature."""
        rec = _make_record()
        rec.attestation = Attestation(
            method="jws",
            signer="attacker",
            signature="eyJhbGciOiJSUzI1NiJ9..fake",
        )
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [rec])
        assert passed is False
        assert refs == []

    def test_arbitrary_method_with_garbage_signature_not_counted(self) -> None:
        """The audit's full repro: method='anything' + any non-empty string.

        ``Attestation.method`` is now typed ``Literal["jws"]`` (mirroring the
        frozen schema's ``const: "jws"``), so a non-jws method can no longer be
        VALIDATED into the model — load() and validated construction reject it.
        ``model_construct`` bypasses validation to forge an in-memory model that
        still carries ``method="anything"``, proving the OPERATOR's own
        ``att.method != "jws"`` defense-in-depth (operators.py) independently
        refuses to count it even if such an object were fabricated.
        """
        rec = _make_record()
        rec.attestation = Attestation.model_construct(
            method="anything",  # type: ignore[arg-type]  # deliberately invalid: operator-guard repro
            signer="attacker",
            signed_fields=["/payload"],
            signature="abc",
        )
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [rec])
        assert passed is False
        assert refs == []

    def test_unsupported_alg_jws_not_counted_and_does_not_crash(self) -> None:
        """A JWS declaring alg outside RS256/ES256 is a non-match, not a crash."""
        import base64
        import json

        header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "none", "kid": "k"}).encode("utf-8"))
            .rstrip(b"=")
            .decode("ascii")
        )
        rec = _make_record()
        rec.attestation = Attestation(method="jws", signer="attacker", signature=f"{header}..AAAA")
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [rec])
        assert passed is False
        assert refs == []


class TestTamperingNotCounted:
    """Negative vectors: valid signature over different content MUST NOT count."""

    def test_tampered_payload_after_signing_not_counted(self) -> None:
        rec = _make_record()
        key = _es256_key()
        signature = _sign_attestation(rec, key)
        rec.attestation = Attestation(method="jws", signer="provider", signature=signature)
        # Tamper AFTER signing.
        rec.payload["score"] = 99
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [rec])
        assert passed is False
        assert refs == []

    def test_signature_transplanted_from_other_record_not_counted(self) -> None:
        """A valid signature over a DIFFERENT record's payload does not transfer."""
        key = _es256_key()
        donor = _make_record(payload={"description": "Benign donor record", "score": 1})
        donor_sig = _sign_attestation(donor, key)
        target = _make_record(payload={"description": "Different content", "score": 2})
        target.attestation = Attestation(method="jws", signer="provider", signature=donor_sig)
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [target])
        assert passed is False
        assert refs == []


class TestMethodRestriction:
    """v1 restricts attestation to JWS only — any other method does NOT count."""

    def test_non_jws_method_with_valid_signature_not_counted(self) -> None:
        """Even a CRYPTOGRAPHICALLY VALID signature does not count when the
        method is non-jws. ``Attestation.method`` is now ``Literal["jws"]``
        (frozen schema ``const: "jws"``), so a non-jws method cannot be validated
        into the model; ``model_construct`` forges one to prove the operator's
        own ``att.method != "jws"`` guard rejects it independently of the model
        constraint (defense-in-depth)."""
        rec = _make_record()
        key = _es256_key()
        signature = _sign_attestation(rec, key)  # cryptographically valid
        rec.attestation = Attestation.model_construct(
            method="c2pa",  # type: ignore[arg-type]  # deliberately invalid: operator-guard repro
            signer="provider",
            signed_fields=["/payload"],
            signature=signature,
        )
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [rec])
        assert passed is False
        assert refs == []


class TestSignedFieldsScope:
    """signed_fields drives extraction and MUST include /payload (spec §3.1)."""

    def test_signed_fields_excluding_payload_not_counted(self) -> None:
        """A scope that omits /payload attests nothing about the evidence."""
        rec = _make_record()
        key = _es256_key()
        signature = _sign_attestation(rec, key, signed_fields=["/record_type"])
        rec.attestation = Attestation(
            method="jws",
            signer="provider",
            signed_fields=["/record_type"],
            signature=signature,
        )
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [rec])
        assert passed is False
        assert refs == []

    def test_unresolvable_signed_fields_pointer_not_counted(self) -> None:
        """A pointer that does not resolve in the record fails closed (no crash)."""
        rec = _make_record()
        key = _es256_key()
        # Signature over a subset the record cannot reproduce (claimed field absent).
        subset = {"/payload": rec.to_jsonl_dict()["payload"], "/missing_field": "x"}
        signature = create_detached_jws(canonicalize(subset), key, kid="attestor-key")
        rec.attestation = Attestation(
            method="jws",
            signer="provider",
            signed_fields=["/payload", "/missing_field"],
            signature=signature,
        )
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [rec])
        assert passed is False
        assert refs == []

    def test_multiple_signed_fields_valid_counted(self) -> None:
        rec = _make_record()
        key = _es256_key()
        fields = ["/payload", "/record_type"]
        signature = _sign_attestation(rec, key, signed_fields=fields)
        rec.attestation = Attestation(
            method="jws",
            signer="provider",
            signed_fields=fields,
            signature=signature,
        )
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [rec])
        assert passed is True
        assert refs == [rec.record_id]


class TestValidSignaturesCounted:
    """Positive vectors: real RS256/ES256 detached JWS over the recipe bytes."""

    def test_valid_es256_signature_counted(self) -> None:
        rec = _make_record()
        signature = _sign_attestation(rec, _es256_key())
        rec.attestation = Attestation(method="jws", signer="provider", signature=signature)
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [rec])
        assert passed is True
        assert refs == [rec.record_id]

    def test_valid_rs256_signature_counted(self) -> None:
        rec = _make_record()
        signature = _sign_attestation(rec, _rs256_key())
        rec.attestation = Attestation(method="jws", signer="provider", signature=signature)
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [rec])
        assert passed is True
        assert refs == [rec.record_id]


class TestExistentialSemanticsPreserved:
    """min_count counting + empty-set FAIL semantics survive the fix."""

    def test_one_valid_one_forged_min_count_two_fails(self) -> None:
        key = _es256_key()
        valid = _make_record(payload={"description": "Real risk", "score": 7})
        valid.attestation = Attestation(method="jws", signer="provider", signature=_sign_attestation(valid, key))
        forged = _make_record(payload={"description": "Forged risk", "score": 8})
        forged.attestation = Attestation(method="jws", signer="attacker", signature="abc")
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 2}, [valid, forged])
        assert passed is False
        assert refs == [valid.record_id]

    def test_one_valid_one_forged_min_count_one_passes(self) -> None:
        key = _es256_key()
        valid = _make_record(payload={"description": "Real risk", "score": 7})
        valid.attestation = Attestation(method="jws", signer="provider", signature=_sign_attestation(valid, key))
        forged = _make_record(payload={"description": "Forged risk", "score": 8})
        forged.attestation = Attestation(method="jws", signer="attacker", signature="abc")
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [valid, forged])
        assert passed is True
        assert refs == [valid.record_id]

    def test_no_attestation_not_counted(self) -> None:
        rec = _make_record()
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [rec])
        assert passed is False
        assert refs == []

    def test_empty_signature_not_counted(self) -> None:
        rec = _make_record()
        rec.attestation = Attestation(method="jws", signer="provider", signature="")
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [rec])
        assert passed is False
        assert refs == []

    def test_empty_record_set_fails(self) -> None:
        passed, refs = op_record_attested({"record_type": "risk_register", "min_count": 1}, [])
        assert passed is False
        assert refs == []


def _x5c_entry_and_key(
    not_valid_before: datetime.datetime,
    not_valid_after: datetime.datetime,
) -> tuple[str, ec.EllipticCurvePrivateKey]:
    """Self-signed P-256 cert with an EXPLICIT validity window, as a base64-DER
    x5c entry (standard base64, NOT base64url) plus its private key.

    Mirrors tests/integration/test_validate_bundle_malformed_input.py — the
    x5c header (as opposed to an embedded jwk) is what forces
    verify_detached_jws onto the verify_x5c_chain path, the ONLY consumer of
    manifest_timestamp.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "acef-test-attestor")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .sign(private_key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(cert_der).decode("ascii"), private_key


def _x5c_attested_record(
    not_valid_before: datetime.datetime,
    not_valid_after: datetime.datetime,
) -> RecordEnvelope:
    """A risk_register record whose attestation JWS carries an x5c chain with
    the given validity window, signed per the normative recipe."""
    x5c_entry, private_key = _x5c_entry_and_key(not_valid_before, not_valid_after)
    rec = _make_record()
    record_dict = rec.to_jsonl_dict()
    subset = {"/payload": jsonpointer.resolve_pointer(record_dict, "/payload")}
    signature = create_detached_jws(
        canonicalize(subset),
        private_key,
        kid="x5c-attestor-key",
        x5c=[x5c_entry],
    )
    rec.attestation = Attestation(method="jws", signer="provider", signature=signature)
    return rec


def _attestation_provision() -> Provision:
    return Provision(
        provision_id="att-prov-1",
        evaluation=[
            EvaluationRule(
                rule_id="att-prov-1-attested",
                rule="record_attested",
                params={"record_type": "risk_register", "min_count": 1},
                severity="fail",
                message="risk_register must carry a verified attestation",
            )
        ],
    )


# Cert validity window used throughout: 2024-01-01 .. 2026-01-01 UTC.
_WINDOW_START = datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC)
_WINDOW_END = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
_TS_INSIDE_WINDOW = "2025-06-01T00:00:00Z"
_TS_AFTER_EXPIRY = "2027-06-01T00:00:00Z"
_TS_BEFORE_VALIDITY = "2023-06-01T00:00:00Z"


class TestX5cCertValidityAnchoredToManifestTimestamp:
    """x5c-backed attestation cert validity MUST be checked against the
    bundle's metadata.timestamp (spec §3.1.3: anchored to the manifest
    timestamp, NOT wall-clock).

    RED-first reproduction of roborev finding on cbc3bd33:
    _attestation_verifies called verify_detached_jws WITHOUT
    manifest_timestamp, so an expired or not-yet-valid x5c chain still made
    record_attested pass.
    """

    def test_expired_x5c_cert_at_manifest_timestamp_not_counted(self) -> None:
        rec = _x5c_attested_record(_WINDOW_START, _WINDOW_END)
        passed, refs = op_record_attested(
            {"record_type": "risk_register", "min_count": 1},
            [rec],
            manifest_timestamp=_TS_AFTER_EXPIRY,
        )
        assert passed is False
        assert refs == []

    def test_not_yet_valid_x5c_cert_at_manifest_timestamp_not_counted(self) -> None:
        rec = _x5c_attested_record(_WINDOW_START, _WINDOW_END)
        passed, refs = op_record_attested(
            {"record_type": "risk_register", "min_count": 1},
            [rec],
            manifest_timestamp=_TS_BEFORE_VALIDITY,
        )
        assert passed is False
        assert refs == []

    def test_valid_window_x5c_cert_at_manifest_timestamp_counted(self) -> None:
        rec = _x5c_attested_record(_WINDOW_START, _WINDOW_END)
        passed, refs = op_record_attested(
            {"record_type": "risk_register", "min_count": 1},
            [rec],
            manifest_timestamp=_TS_INSIDE_WINDOW,
        )
        assert passed is True
        assert refs == [rec.record_id]

    def test_omitted_manifest_timestamp_skips_validity_check(self) -> None:
        """Backward compatibility: with no manifest timestamp anchor the
        signing layer documents the validity check is skipped (signing.py
        verify_x5c_chain: 'or skip if not provided'). Direct operator calls
        without the kwarg keep their pre-fix behavior."""
        rec = _x5c_attested_record(_WINDOW_START, _WINDOW_END)
        passed, refs = op_record_attested(
            {"record_type": "risk_register", "min_count": 1},
            [rec],
        )
        assert passed is True
        assert refs == [rec.record_id]


class TestRuleEngineThreadsManifestTimestamp:
    """The rule engine must hand the bundle's metadata.timestamp
    (package_timestamp) to record_attested the same way bundle_signed gets
    signature context — otherwise the operator can never enforce cert
    validity during bundle validation."""

    def test_expired_cert_at_package_timestamp_rule_fails(self) -> None:
        """RED proof of the roborev finding: before the fix this rule PASSED
        because the operator never saw the manifest timestamp."""
        rec = _x5c_attested_record(_WINDOW_START, _WINDOW_END)
        results = evaluate_rules_for_subject(
            [_attestation_provision()],
            [rec],
            profile_id="test-profile",
            package_timestamp=_TS_AFTER_EXPIRY,
        )
        assert len(results) == 1
        assert results[0].outcome == RuleOutcome.FAILED
        assert results[0].evidence_refs == []

    def test_valid_window_cert_at_package_timestamp_rule_passes(self) -> None:
        rec = _x5c_attested_record(_WINDOW_START, _WINDOW_END)
        results = evaluate_rules_for_subject(
            [_attestation_provision()],
            [rec],
            profile_id="test-profile",
            package_timestamp=_TS_INSIDE_WINDOW,
        )
        assert len(results) == 1
        assert results[0].outcome == RuleOutcome.PASSED
        assert results[0].evidence_refs == [rec.record_id]

    def test_empty_package_timestamp_skips_validity_check(self) -> None:
        """A bundle whose metadata.timestamp is missing/malformed is coerced
        to '' by the engine (engine.py _resolve_package_scalars). The rule
        engine maps '' -> None so the signing layer's documented
        skip-if-not-provided semantics apply instead of fail-closed crashes
        on every x5c attestation."""
        rec = _x5c_attested_record(_WINDOW_START, _WINDOW_END)
        results = evaluate_rules_for_subject(
            [_attestation_provision()],
            [rec],
            profile_id="test-profile",
            package_timestamp="",
        )
        assert len(results) == 1
        assert results[0].outcome == RuleOutcome.PASSED


# --- PhD re-review (adversarial-impl W1): record_attested x5c attestation
# anchoring. trust_anchors was absent from the whole rule-evaluation path, so a
# self-issued x5c that FAILS as a bundle signature (ACEF-012 under configured
# anchors) still satisfied record_attested — a trust-posture drift within one
# anchored run. Threading trust_anchors closes it. ---


def _ca_cert_and_key(
    cn: str,
    nvb: datetime.datetime,
    nva: datetime.datetime,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """A self-signed CA cert (BasicConstraints ca=True + keyCertSign), usable as a
    trust anchor — verify_x5c_chain enforces RFC 5280 issuer path constraints."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
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
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _anchored_x5c_attested_record(
    nvb: datetime.datetime,
    nva: datetime.datetime,
) -> tuple[RecordEnvelope, x509.Certificate]:
    """A record whose attestation x5c is a proper root->leaf chain; returns
    ``(rec, root_cert)`` so the test can configure the root as the trust anchor."""
    root_cert, root_key = _ca_cert_and_key("att-root", nvb, nva)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "att-leaf")]))
        .issuer_name(root_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nvb)
        .not_valid_after(nva)
        .sign(root_key, hashes.SHA256())
    )
    leaf_b64 = base64.b64encode(leaf_cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
    root_b64 = base64.b64encode(root_cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
    rec = _make_record()
    subset = {"/payload": jsonpointer.resolve_pointer(rec.to_jsonl_dict(), "/payload")}
    signature = create_detached_jws(canonicalize(subset), leaf_key, kid="att-leaf-key", x5c=[leaf_b64, root_b64])
    rec.attestation = Attestation(method="jws", signer="provider", signature=signature)
    return rec, root_cert


class TestX5cAttestationTrustAnchoring:
    def test_self_issued_x5c_attestation_not_counted_when_anchors_configured(self) -> None:
        """A self-issued x5c attestation does NOT chain to a configured anchor, so
        it must NOT count — consistent with the bundle-signature trust posture."""
        rec = _x5c_attested_record(_WINDOW_START, _WINDOW_END)
        unrelated, _ = _ca_cert_and_key("unrelated-anchor", _WINDOW_START, _WINDOW_END)
        passed, refs = op_record_attested(
            {"record_type": "risk_register", "min_count": 1},
            [rec],
            manifest_timestamp=_TS_INSIDE_WINDOW,
            trust_anchors=[unrelated],
        )
        assert passed is False
        assert refs == []

    def test_self_issued_x5c_attestation_counted_without_anchors(self) -> None:
        """Backward compatibility: WITHOUT anchors a self-issued x5c attestation is
        self-attested and still counts (unchanged behavior)."""
        rec = _x5c_attested_record(_WINDOW_START, _WINDOW_END)
        passed, refs = op_record_attested(
            {"record_type": "risk_register", "min_count": 1},
            [rec],
            manifest_timestamp=_TS_INSIDE_WINDOW,
        )
        assert passed is True
        assert refs == [rec.record_id]

    def test_anchored_x5c_attestation_counted_when_chains_to_anchor(self) -> None:
        """An x5c attestation whose chain terminates at a configured anchor counts."""
        rec, root = _anchored_x5c_attested_record(_WINDOW_START, _WINDOW_END)
        passed, refs = op_record_attested(
            {"record_type": "risk_register", "min_count": 1},
            [rec],
            manifest_timestamp=_TS_INSIDE_WINDOW,
            trust_anchors=[root],
        )
        assert passed is True
        assert refs == [rec.record_id]

    def test_trust_anchors_threaded_through_rule_engine(self) -> None:
        """The whole eval path threads trust_anchors (evaluate_rules_for_subject ->
        operator): a self-issued x5c attestation FAILS record_attested under
        configured anchors."""
        rec = _x5c_attested_record(_WINDOW_START, _WINDOW_END)
        unrelated, _ = _ca_cert_and_key("unrelated-anchor", _WINDOW_START, _WINDOW_END)
        results = evaluate_rules_for_subject(
            [_attestation_provision()],
            [rec],
            profile_id="eu-ai-act",
            package_timestamp=_TS_INSIDE_WINDOW,
            trust_anchors=[unrelated],
        )
        assert len(results) == 1
        assert results[0].outcome == RuleOutcome.FAILED
