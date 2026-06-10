"""Unit tests for the OPTIONAL online domain-control verifier (F-M3-DOMAIN-CONTROL).

These tests cover the two primaryFulfills assertions of F-M3-DOMAIN-CONTROL:

- **VAL-DOMAIN-001 (offline never attributes).** The OFFLINE-deterministic id-trust
  class (``acef.validation.incident_rules.check_public_incident_id_offline``, owned by
  F-M3-VALIDATOR-RULES — exercised here, never modified) checks ONLY the
  ``public_incident_id`` pattern + (optional) bundled-snapshot membership and NEVER
  attributes the id to the assigner domain. A FORGED card — a valid-pattern assigner
  (``AIIC-OPENAI-2026-<>=26 Crockford>``) signed with an ATTACKER key whose JWS is
  internally consistent — MUST PASS the offline class, and the offline path performs
  NO network call (proven with a poisoned ``socket`` that raises if touched).

- **VAL-DOMAIN-002 (online verifier).** The NEW module ``acef.domain_control`` implements
  the OPTIONAL online check (DNS-01 TXT and/or ``.well-known`` HTTP challenge, reusing
  ``acef.signing`` for the RFC-7638 JWK thumbprint) returning a tri-valued verdict with
  NO double-mapping:
    * ``verified``   — a proof was presented and validates as current at check time;
    * ``unverified`` — NO proof presented at all, OR the DNS/HTTP lookup could not
                       complete (timeout / SERVFAIL); an explicit non-result that
                       NEVER raises ACEF-083 and is never a silent pass-as-verified;
    * ``reject``     — a proof WAS presented but FAILS validation (wrong challenge /
                       wrong thumbprint / malformed); raises ACEF-083
                       ``class: online-conformance``.

Determinism: every fixture is a static literal or an in-memory generated key; the DNS
resolver and HTTP fetcher are injected stubs (no real network); the freshness clock is
injected (no wall-clock). Generated EC P-256 keys are EXPECTED test fixtures, not
secrets.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from acef.domain_control import (
    DomainControlResult,
    DomainControlVerdict,
    HttpResponse,
    challenge_token_for,
    jwk_thumbprint,
    verify_domain_control,
)
from acef.signing import _derive_jwk, create_detached_jws, verify_detached_jws

# A 26-char Crockford-base32 suffix (>=128 bits — the pattern minimum, §5.3).
_SUFFIX = "0123456789ABCDEFGHJKMNPQRS"
# The corrected LABEL form of the assigner token (label "OPENAI", not the dotted
# "OPENAI.COM" — the dotted form contains a '.' and exceeds 8 chars and can never
# match the pattern; §5.3 Revision-10 correction).
_FORGED_ID = f"AIIC-OPENAI-2026-{_SUFFIX}"
_FORGED_ASSIGNER = "OPENAI"
_FORGED_DOMAIN = "openai.com"


def _gen_ec_key() -> ec.EllipticCurvePrivateKey:
    """Generate an in-memory EC P-256 key (an ES256 signer). Test fixture only."""
    return ec.generate_private_key(ec.SECP256R1())


def _incident_card_record(public_incident_id: str) -> dict[str, Any]:
    """A minimal incident_card record carrying a public_incident_id."""
    return {
        "record_id": "rec-forged-1",
        "record_type": "incident_card",
        "payload": {
            "public_incident_id": public_incident_id,
            "id_grade": "self-asserted",
            "harm_core": {"realization": "harm_event", "harm_class": "physical_health"},
        },
    }


# ===========================================================================
# VAL-DOMAIN-001 — the OFFLINE class never attributes (forged card passes,
# no network). Exercises the EXISTING offline path; does NOT modify it.
# ===========================================================================


class TestOfflineNeverAttributes:
    def test_forged_but_self_consistent_card_passes_offline(self) -> None:
        """A forged AIIC-OPENAI card signed with an ATTACKER key whose JWS is
        internally consistent MUST PASS the offline class (no ACEF-083): the
        offline class checks pattern + JWS self-consistency only, NEVER attribution.
        """
        from acef.validation.incident_rules import check_public_incident_id_offline

        # The attacker mints a valid-pattern OPENAI id and signs it with their OWN
        # key. The JWS is internally consistent (it verifies against the attacker's
        # embedded JWK) — but it proves nothing about control of openai.com.
        attacker_key = _gen_ec_key()
        card = _incident_card_record(_FORGED_ID)
        payload_bytes = b'{"public_incident_id":"%s"}' % _FORGED_ID.encode("ascii")
        jws = create_detached_jws(payload_bytes, attacker_key, kid="attacker-kid")
        # The JWS self-verifies (internal consistency) — confirm the forgery is
        # internally consistent, which is exactly the case that must PASS offline.
        verify_detached_jws(jws, payload_bytes)

        diags = check_public_incident_id_offline([card], manifest={})

        # No ACEF-083 (or any) diagnostic — the forged-but-self-consistent card is
        # accepted by the offline class BY DESIGN; attribution is out of scope offline.
        assert [d.code for d in diags] == [], "offline class must NOT attribute the forged AIIC-OPENAI id to openai.com"

    def test_offline_validation_performs_no_network_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The offline class MUST perform NO network call. Poison every socket
        entry point so that any DNS/HTTP/connect attempt raises immediately.
        """

        def _poison(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("offline validation attempted a network call")

        # Poison the common network entry points. If the offline path touches any
        # of these, the test fails loudly rather than silently passing.
        monkeypatch.setattr(socket, "socket", _poison)
        monkeypatch.setattr(socket, "create_connection", _poison)
        monkeypatch.setattr(socket, "getaddrinfo", _poison)
        monkeypatch.setattr(socket, "gethostbyname", _poison)

        from acef.validation.incident_rules import check_public_incident_id_offline

        card = _incident_card_record(_FORGED_ID)
        # Must not raise (no network touched) and must accept the forged card.
        diags = check_public_incident_id_offline([card], manifest={})
        assert [d.code for d in diags] == []

    def test_offline_rejects_malformed_pattern_without_network(self) -> None:
        """An offline ACEF-083 is a PATTERN failure (still no attribution, no
        network) — the dotted pre-correction form AIIC-OPENAI.COM cannot match."""
        from acef.validation.incident_rules import check_public_incident_id_offline

        bad = _incident_card_record(f"AIIC-OPENAI.COM-2026-{_SUFFIX}")
        diags = check_public_incident_id_offline([bad], manifest={})
        assert [d.code for d in diags] == ["ACEF-083"]


# ===========================================================================
# Helpers — RFC-7638 thumbprint + challenge token.
# ===========================================================================


class TestThumbprintAndChallenge:
    def test_jwk_thumbprint_is_deterministic_and_key_bound(self) -> None:
        key_a = _gen_ec_key()
        key_b = _gen_ec_key()
        jwk_a = _derive_jwk(key_a)
        tp_a1 = jwk_thumbprint(jwk_a)
        tp_a2 = jwk_thumbprint(dict(jwk_a))
        tp_b = jwk_thumbprint(_derive_jwk(key_b))
        assert tp_a1 == tp_a2  # deterministic for the same key
        assert tp_a1 != tp_b  # distinct keys -> distinct thumbprints
        assert isinstance(tp_a1, str) and tp_a1  # non-empty base64url string

    def test_challenge_token_binds_assigner_and_key(self) -> None:
        key = _gen_ec_key()
        jwk = _derive_jwk(key)
        token = challenge_token_for(_FORGED_ASSIGNER, jwk)
        # The challenge carries the RFC-7638 thumbprint so a different key cannot
        # satisfy a challenge minted for this key.
        assert jwk_thumbprint(jwk) in token
        other = challenge_token_for(_FORGED_ASSIGNER, _derive_jwk(_gen_ec_key()))
        assert token != other


# ===========================================================================
# VAL-DOMAIN-002 — the OPTIONAL online verifier: verified / unverified / reject.
# ===========================================================================


def _registrant_jwk() -> tuple[ec.EllipticCurvePrivateKey, dict[str, str]]:
    key = _gen_ec_key()
    return key, _derive_jwk(key)


_FIXED_NOW = datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)


class TestVerifiedVerdict:
    def test_dns_txt_proof_matching_thumbprint_is_verified(self) -> None:
        """A DNS TXT record at the assigner's registrable domain carrying the
        expected challenge (bound to the card's JWK thumbprint) -> verified."""
        _key, jwk = _registrant_jwk()
        expected = challenge_token_for(_FORGED_ASSIGNER, jwk)

        def dns_resolver(name: str) -> list[str]:
            # Records under the registrable domain. Returns the correct challenge.
            return [expected]

        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=dns_resolver,
            http_fetcher=_no_http,
            now=_FIXED_NOW,
        )
        assert result.verdict is DomainControlVerdict.VERIFIED
        assert result.diagnostic is None

    def test_well_known_http_proof_matching_thumbprint_is_verified(self) -> None:
        """A .well-known HTTP document carrying the expected challenge -> verified."""
        _key, jwk = _registrant_jwk()
        expected = challenge_token_for(_FORGED_ASSIGNER, jwk)

        def http_fetcher(url: str) -> HttpResponse:
            return HttpResponse(status=200, content_type="text/plain", body=expected)

        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=_no_dns,
            http_fetcher=http_fetcher,
            now=_FIXED_NOW,
        )
        assert result.verdict is DomainControlVerdict.VERIFIED
        assert result.diagnostic is None


class TestRejectVerdict:
    def test_wrong_challenge_token_is_reject_acef083(self) -> None:
        """A DNS TXT record present but carrying a WRONG/forged challenge -> reject
        with ACEF-083 class: online-conformance."""
        _key, jwk = _registrant_jwk()

        def dns_resolver(name: str) -> list[str]:
            return ["acef-domain-control=totally-wrong-not-the-thumbprint"]

        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=dns_resolver,
            http_fetcher=_no_http,
            now=_FIXED_NOW,
        )
        assert result.verdict is DomainControlVerdict.REJECT
        assert result.diagnostic is not None
        assert result.diagnostic.code == "ACEF-083"
        assert result.diagnostic.details.get("class") == "online-conformance"

    def test_proof_for_a_different_key_is_reject(self) -> None:
        """A presented proof whose thumbprint is for a DIFFERENT key (attacker
        cannot satisfy the card's key) -> reject (presented-but-invalid)."""
        _key, jwk = _registrant_jwk()
        # Proof minted for a DIFFERENT (attacker) key.
        attacker_jwk = _derive_jwk(_gen_ec_key())
        wrong_proof = challenge_token_for(_FORGED_ASSIGNER, attacker_jwk)

        def dns_resolver(name: str) -> list[str]:
            return [wrong_proof]

        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=dns_resolver,
            http_fetcher=_no_http,
            now=_FIXED_NOW,
        )
        assert result.verdict is DomainControlVerdict.REJECT
        assert result.diagnostic is not None
        assert result.diagnostic.code == "ACEF-083"
        assert result.diagnostic.details.get("class") == "online-conformance"

    def test_malformed_http_proof_wrong_content_type_is_reject(self) -> None:
        """A .well-known challenge document PRESENTED (the correct challenge body)
        but served with the WRONG content-type -> reject (a malformed required
        subcomponent of an otherwise-presented proof, §5.3). The proof WAS presented
        (it is challenge-shaped and carries the right token), so the wrong
        content-type is a presence-but-invalid failure, not absence."""
        _key, jwk = _registrant_jwk()
        correct_body = challenge_token_for(_FORGED_ASSIGNER, jwk)

        def http_fetcher(url: str) -> HttpResponse:
            # Right challenge value, but served as text/html instead of text/plain:
            # a malformed required subcomponent of an otherwise-presented proof.
            return HttpResponse(status=200, content_type="text/html", body=correct_body)

        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=_no_dns,
            http_fetcher=http_fetcher,
            now=_FIXED_NOW,
        )
        assert result.verdict is DomainControlVerdict.REJECT
        assert result.diagnostic is not None
        assert result.diagnostic.code == "ACEF-083"


class TestUnverifiedVerdict:
    def test_no_proof_present_is_unverified_not_reject(self) -> None:
        """NO proof presented at all (empty DNS, 404 .well-known) -> unverified,
        NEVER ACEF-083, NEVER verified."""
        _key, jwk = _registrant_jwk()

        def dns_resolver(name: str) -> list[str]:
            return []  # no TXT records at all

        def http_fetcher(url: str) -> HttpResponse:
            return HttpResponse(status=404, content_type="text/plain", body="")

        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=dns_resolver,
            http_fetcher=http_fetcher,
            now=_FIXED_NOW,
        )
        assert result.verdict is DomainControlVerdict.UNVERIFIED
        assert result.diagnostic is None  # an explicit non-result, not an error

    def test_dns_timeout_is_unverified_not_reject(self) -> None:
        """A DNS lookup that cannot complete (timeout) -> unverified (cannot-
        complete), NEVER reject, NEVER verified, NEVER a silent pass."""
        _key, jwk = _registrant_jwk()

        def dns_resolver(name: str) -> list[str]:
            raise TimeoutError("DNS lookup timed out")

        def http_fetcher(url: str) -> HttpResponse:
            raise TimeoutError("HTTP fetch timed out")

        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=dns_resolver,
            http_fetcher=http_fetcher,
            now=_FIXED_NOW,
        )
        assert result.verdict is DomainControlVerdict.UNVERIFIED
        assert result.diagnostic is None

    def test_servfail_oserror_is_unverified_not_reject(self) -> None:
        """A SERVFAIL-class OSError (cannot complete) -> unverified, never reject."""
        _key, jwk = _registrant_jwk()

        def dns_resolver(name: str) -> list[str]:
            raise OSError("SERVFAIL")

        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=dns_resolver,
            http_fetcher=_no_http_404,
            now=_FIXED_NOW,
        )
        assert result.verdict is DomainControlVerdict.UNVERIFIED
        assert result.diagnostic is None

    def test_no_resolvers_supplied_defaults_to_unverified_when_offline(self) -> None:
        """When the default real resolvers cannot complete (no network in the test
        sandbox), the verdict is unverified — never a crash, never reject."""
        _key, jwk = _registrant_jwk()
        # Both injected resolvers raise cannot-complete -> unverified.
        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=_dns_timeout,
            http_fetcher=_http_timeout,
            now=_FIXED_NOW,
        )
        assert result.verdict is DomainControlVerdict.UNVERIFIED


class TestNoDoubleMapping:
    def test_absence_and_timeout_both_map_to_unverified_distinct_from_reject(self) -> None:
        """The invariant: presence-but-invalid -> reject; total absence OR
        cannot-complete -> unverified. Absence != reject; timeout != reject."""
        _key, jwk = _registrant_jwk()

        absent = verify_domain_control(
            _FORGED_ID, jwk, dns_resolver=lambda n: [], http_fetcher=_no_http_404, now=_FIXED_NOW
        )
        timeout = verify_domain_control(
            _FORGED_ID, jwk, dns_resolver=_dns_timeout, http_fetcher=_http_timeout, now=_FIXED_NOW
        )
        presented_invalid = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=lambda n: ["acef-domain-control=wrong"],
            http_fetcher=_no_http,
            now=_FIXED_NOW,
        )
        assert absent.verdict is DomainControlVerdict.UNVERIFIED
        assert timeout.verdict is DomainControlVerdict.UNVERIFIED
        assert presented_invalid.verdict is DomainControlVerdict.REJECT
        # No outcome is double-mapped: the three observations land on exactly two
        # distinct verdicts, and absence/timeout are NEVER reject.
        assert absent.verdict is timeout.verdict
        assert absent.verdict is not presented_invalid.verdict

    def test_result_is_a_dataclass_with_verdict_and_optional_diagnostic(self) -> None:
        _key, jwk = _registrant_jwk()
        result = verify_domain_control(
            _FORGED_ID, jwk, dns_resolver=lambda n: [], http_fetcher=_no_http_404, now=_FIXED_NOW
        )
        assert isinstance(result, DomainControlResult)
        assert isinstance(result.verdict, DomainControlVerdict)
        assert result.assigner == _FORGED_ASSIGNER
        assert result.domain == _FORGED_DOMAIN


class TestMalformedIdInput:
    def test_unparseable_public_incident_id_is_unverified_no_attribution(self) -> None:
        """A public_incident_id that does not parse cannot anchor an online check;
        the verifier returns unverified (it does not invent an attribution and does
        not raise ACEF-083 for a *missing* online proof). Offline pattern failure is
        the offline class's job (ACEF-083 class: offline-deterministic)."""
        _key, jwk = _registrant_jwk()
        result = verify_domain_control(
            f"AIIC-OPENAI.COM-2026-{_SUFFIX}",  # dotted pre-correction form, unparseable
            jwk,
            dns_resolver=lambda n: ["whatever"],
            http_fetcher=_no_http,
            now=_FIXED_NOW,
        )
        assert result.verdict is DomainControlVerdict.UNVERIFIED


# ---------------------------------------------------------------------------
# Stub resolvers/fetchers used across tests.
# ---------------------------------------------------------------------------


def _no_dns(name: str) -> list[str]:
    return []


def _no_http(url: str) -> HttpResponse:
    return HttpResponse(status=404, content_type="text/plain", body="")


def _no_http_404(url: str) -> HttpResponse:
    return HttpResponse(status=404, content_type="text/plain", body="")


def _dns_timeout(name: str) -> list[str]:
    raise TimeoutError("dns timeout")


def _http_timeout(url: str) -> HttpResponse:
    raise TimeoutError("http timeout")
