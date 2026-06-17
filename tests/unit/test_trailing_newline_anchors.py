"""Trailing-newline anchor hardening across the v1.1 validators (roborev on ae5f0e2).

The Finding-2 class: a ``$``-anchored regex matched with ``re.match`` / ``re.search``
ACCEPTS a value with a trailing ``\\n`` because Python's ``$`` matches BEFORE a final
newline. Every grammar check below is a FULL-STRING check, so a trailing newline (or any
trailing garbage) MUST be rejected — the fix is ``re.fullmatch`` (whole string must
match) or an absolute end anchor ``(?![\\s\\S])`` for the schema-mirrored id patterns.

These tests reproduce the bypass at each call site; each FAILS before the hardening (the
malformed value is accepted) and passes after.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from acef.domain_control import (
    DomainControlVerdict,
    _is_allowed_well_known_host,
    challenge_token_for,
    verify_domain_control,
)
from acef.package import mint_incident_id, validate_namespaces
from acef.redaction import RedactionPolicy
from acef.signing import _derive_jwk
from acef.validation.incident_rules import _is_record_urn
from acef.validation.schema_validator import _commitment_shape_problems

_VALID_SUFFIX = "0123456789ABCDEFGHJKMNPQRS"  # 26 Crockford-base32 chars (>=128 bits)
_VALID_ID = f"AIIC-OPENAI-2026-{_VALID_SUFFIX}"
_VALID_REC_URN = "urn:acef:rec:00000000-0000-0000-0000-000000000000"
_VALID_HEX = "a" * 64


def test_registrable_domain_rejects_trailing_newline_label() -> None:
    """A DNS label with a trailing newline must NOT pass the LDH/TLD registrable-host
    guard (``_LDH_LABEL`` / ``_VALID_TLD`` were ``$``-anchored + ``.match``)."""
    assert _is_allowed_well_known_host("openai.com") is True
    assert _is_allowed_well_known_host("openai\n.com") is False
    assert _is_allowed_well_known_host("openai.com\n") is False


def test_record_urn_shape_rejects_trailing_newline() -> None:
    """A record-URN ref with a trailing newline must NOT be accepted as a §5.8 edge
    endpoint (``_REC_URN_SHAPE`` was ``$``-anchored + ``.match``)."""
    assert _is_record_urn(_VALID_REC_URN) is True
    assert _is_record_urn(f"{_VALID_REC_URN}\n") is False


def test_commitment_shape_rejects_trailing_newline_hash() -> None:
    """A ``redacted_payload_hash`` with a trailing newline must be flagged by the
    commitment-shape validator (``_SHA256_BARE_HEX_RE`` was ``$``-anchored + ``.match``)."""
    clean = {
        "redaction_method": "sha256-hash-commitment",
        "redacted_payload_hash": _VALID_HEX,
        "redaction_policy_version": "1.0.0",
    }
    assert _commitment_shape_problems(clean) == []
    malformed = dict(clean, redacted_payload_hash=f"{_VALID_HEX}\n")
    problems = _commitment_shape_problems(malformed)
    assert any(pointer == "/redacted_payload_hash" for _msg, pointer in problems), (
        "a trailing-newline redacted_payload_hash must be flagged"
    )


def test_redaction_policy_version_rejects_trailing_newline() -> None:
    """RedactionPolicy.version with a trailing newline must raise (``_SEMVER_PATTERN``
    was ``$``-anchored + ``.match``)."""
    RedactionPolicy(version="1.0.0", method="sha256-hash-commitment")  # clean
    with pytest.raises(ValueError):
        RedactionPolicy(version="1.0.0\n", method="sha256-hash-commitment")


def test_validate_namespaces_rejects_trailing_newline_key() -> None:
    """An X6 namespace key with a trailing newline must be rejected by the strict-key
    validator (``_NAMESPACE_KEY_PATTERN`` was ``$``-anchored + ``.match``)."""
    validate_namespaces({"x-vendor": {"a": 1}})  # clean
    with pytest.raises(Exception):  # ACEFSchemaError (ACEF-002)
        validate_namespaces({"x-vendor\n": {"a": 1}})


def test_mint_incident_id_rejects_trailing_newline_domain() -> None:
    """mint_incident_id must reject a domain whose label carries a trailing newline
    rather than mint a newline-corrupted ``AIIC-...`` id (``_ASSIGNER_LABEL_PATTERN`` /
    ``_LDH_LABEL`` were ``$``-anchored + ``.match``)."""
    key = ec.generate_private_key(ec.SECP256R1())
    mint_incident_id("openai.com", key)  # clean
    with pytest.raises(ValueError):
        mint_incident_id("openai\n.com", key)


def test_verify_domain_control_trailing_newline_id_is_unverified() -> None:
    """The OPTIONAL online verifier must treat a trailing-newline public_incident_id as
    UNVERIFIED (no attribution attempted), NOT parse it and return VERIFIED/REJECT
    (``domain_control._PUBLIC_INCIDENT_ID_PATTERN`` was ``$``-anchored + ``.match``).
    A matching DNS proof is supplied so the ONLY thing preventing a VERIFIED verdict is
    the id parse rejecting the newline."""
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = _derive_jwk(key)
    expected = challenge_token_for("OPENAI", jwk)

    def dns_resolver(_name: str) -> list[str]:
        return [expected]

    def no_http(_url: str) -> object:
        raise AssertionError("HTTP channel must not be consulted for an unparseable id")

    result = verify_domain_control(
        f"{_VALID_ID}\n",
        jwk,
        dns_resolver=dns_resolver,
        http_fetcher=no_http,  # type: ignore[arg-type]
    )
    assert result.verdict is DomainControlVerdict.UNVERIFIED, (
        f"a trailing-newline public_incident_id must be UNVERIFIED, got {result.verdict}"
    )
