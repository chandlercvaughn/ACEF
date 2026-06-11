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

import jsonpointer  # type: ignore[import-untyped]  # no published stubs / py.typed
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from acef.integrity import canonicalize
from acef.models.records import Attestation, RecordEnvelope
from acef.signing import create_detached_jws
from acef.validation.operators import op_record_attested


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
        """The audit's full repro: method='anything' + any non-empty string."""
        rec = _make_record()
        rec.attestation = Attestation(method="anything", signer="attacker", signature="abc")
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
        rec = _make_record()
        key = _es256_key()
        signature = _sign_attestation(rec, key)  # cryptographically valid
        rec.attestation = Attestation(method="c2pa", signer="provider", signature=signature)
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
