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

import io
import socket
import urllib.error
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from acef.domain_control import (
    WELL_KNOWN_MAX_BYTES,
    DomainControlResult,
    DomainControlVerdict,
    HttpResponse,
    _default_http_fetcher,
    _NoFollowRedirectHandler,
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


# ===========================================================================
# Default .well-known fetcher hardening (roborev security findings on 1815d235):
#   F1 (High)   — SSRF via redirects: urlopen follows redirects by default,
#                 contradicting the "no cross-origin redirect" contract. An
#                 attacker-controlled assigner domain could 3xx-redirect the
#                 verifier to an internal/arbitrary origin and serve off-origin
#                 challenge content. A 3xx to a DIFFERENT origin must NEVER be
#                 followed; documented verdict for a 3xx = "no valid proof" ->
#                 a non-200 HttpResponse -> ABSENT -> unverified.
#   F2 (Medium) — unbounded response read (DoS): response.read() from an
#                 input-derived domain can exhaust memory. A .well-known
#                 challenge is tiny; enforce WELL_KNOWN_MAX_BYTES (8 KiB),
#                 reject an over-limit Content-Length, and do a BOUNDED read.
#                 An over-limit body = "no valid proof" -> non-200 -> unverified.
# These tests drive _default_http_fetcher's policy directly with a stubbed
# urllib opener (no real network).
# ===========================================================================


class _StubHeaders:
    """A minimal case-insensitive header bag mimicking ``http.client.HTTPMessage``."""

    def __init__(self, headers: dict[str, str]) -> None:
        self._headers = {k.lower(): v for k, v in headers.items()}

    def get(self, name: str, default: str = "") -> str:
        return self._headers.get(name.lower(), default)


class _RecordingBody(io.BytesIO):
    """A BytesIO that records the largest ``read`` size requested.

    Used to PROVE the fetcher does a BOUNDED read (``read(MAX + 1)``) and never
    an unbounded ``read()`` (which on a real socket would stream the whole body).
    """

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.max_read_arg: int | None = None
        self.unbounded_read_called = False

    def read(self, size: int = -1, /) -> bytes:  # type: ignore[override]
        if size is None or size < 0:
            self.unbounded_read_called = True
        else:
            self.max_read_arg = size if self.max_read_arg is None else max(self.max_read_arg, size)
        return super().read(size)


class _StubResponse:
    """A minimal stand-in for the object yielded by ``urlopen`` (context manager)."""

    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = _StubHeaders(headers)
        self.body = _RecordingBody(body)

    # urlopen returns an object that is both a context manager and file-like.
    def __enter__(self) -> _StubResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self, size: int = -1, /) -> bytes:
        return self.body.read(size)


class _CapturingOpener:
    """A stub ``OpenerDirector`` capturing the URLs the fetcher attempts to open.

    The first opened URL yields ``first_response``; if the fetcher were to FOLLOW
    a redirect it would open a second URL — which this stub records so the test can
    assert the redirect target was NEVER fetched.
    """

    def __init__(self, first_response: _StubResponse | BaseException) -> None:
        self._first = first_response
        self.opened: list[str] = []

    def open(self, fullurl: Any, data: Any = None, timeout: Any = None) -> _StubResponse:
        url = fullurl.full_url if hasattr(fullurl, "full_url") else str(fullurl)
        self.opened.append(url)
        if isinstance(self._first, BaseException):
            raise self._first
        return self._first


class TestDefaultFetcherHardening:
    """Direct policy tests for ``_default_http_fetcher`` (F1 SSRF, F2 DoS)."""

    def test_off_origin_redirect_is_not_followed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """F1: an off-origin 3xx redirect MUST NOT be followed. The no-follow
        redirect handler converts the 3xx into an HTTPError, which the fetcher maps
        to a non-200 HttpResponse (no valid proof). The redirect TARGET is never
        fetched. Verdict downstream: ABSENT -> unverified (never verified-off-origin).
        """
        import urllib.request

        # The attacker domain answers the .well-known GET with a 302 to an internal
        # host. With urlopen's default behavior this WOULD be followed (SSRF). With
        # the no-follow handler installed, the 302 raises HTTPError at fetch time.
        redirect_error = urllib.error.HTTPError(
            url="https://attacker.com/.well-known/acef-incident-challenge",
            code=302,
            msg="Found",
            hdrs=_StubHeaders({"Location": "http://169.254.169.254/latest/meta-data/"}),  # type: ignore[arg-type]
            fp=None,
        )
        opener = _CapturingOpener(redirect_error)
        monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener)

        resp = _default_http_fetcher("https://attacker.com/.well-known/acef-incident-challenge")

        # The fetcher attempted exactly ONE open (the original https origin) and did
        # NOT open the redirect target — the SSRF target host never appears.
        assert opener.opened == ["https://attacker.com/.well-known/acef-incident-challenge"]
        assert all("169.254.169.254" not in u for u in opener.opened)
        # A 3xx becomes a non-200 response -> no valid proof (downstream unverified).
        assert resp.status != 200
        assert resp.body == ""

    def test_no_follow_redirect_handler_rejects_cross_origin_redirect(self) -> None:
        """F1 unit: the redirect handler MUST reject (raise) a cross-origin / non-https
        redirect rather than returning a new Request to follow."""
        handler = _NoFollowRedirectHandler()
        req = _StubRequest("https://good.example.com/.well-known/acef-incident-challenge")
        with pytest.raises(urllib.error.HTTPError):
            handler.redirect_request(
                req,  # type: ignore[arg-type]
                fp=io.BytesIO(b""),
                code=302,
                msg="Found",
                headers=_StubHeaders({}),  # type: ignore[arg-type]
                newurl="http://169.254.169.254/internal",
            )

    def test_same_origin_200_with_valid_challenge_is_verified(self) -> None:
        """F1 regression: a same-origin, non-redirect 200 with the correct challenge
        body STILL yields a verified verdict end-to-end (hardening did not break the
        happy path)."""
        _key, jwk = _registrant_jwk()
        expected = challenge_token_for(_FORGED_ASSIGNER, jwk)

        def http_fetcher(url: str) -> HttpResponse:
            # A direct 200 at the expected https origin (no redirect).
            assert url == f"https://{_FORGED_DOMAIN}/.well-known/acef-incident-challenge"
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

    def test_default_fetcher_real_200_returns_bounded_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A normal small 200 through the default fetcher returns the body and reads
        it with a BOUNDED size (read(MAX + 1)), never an unbounded read()."""
        import urllib.request

        body = b"acef-domain-control=OPENAI:thumbprint"
        stub = _StubResponse(200, {"Content-Type": "text/plain", "Content-Length": str(len(body))}, body)
        opener = _CapturingOpener(stub)
        monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener)

        resp = _default_http_fetcher("https://openai.com/.well-known/acef-incident-challenge")

        assert resp.status == 200
        assert resp.body == body.decode("ascii")
        # The read was BOUNDED, never unbounded.
        assert stub.body.unbounded_read_called is False
        assert stub.body.max_read_arg == WELL_KNOWN_MAX_BYTES + 1

    def test_oversized_content_length_is_rejected_without_reading_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """F2: a Content-Length exceeding WELL_KNOWN_MAX_BYTES is rejected as
        not-a-valid-proof (non-200 HttpResponse) and the (huge) body is NOT read."""
        import urllib.request

        huge = b"x" * (WELL_KNOWN_MAX_BYTES * 4)
        stub = _StubResponse(
            200,
            {"Content-Type": "text/plain", "Content-Length": str(WELL_KNOWN_MAX_BYTES + 1)},
            huge,
        )
        opener = _CapturingOpener(stub)
        monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener)

        resp = _default_http_fetcher("https://attacker.com/.well-known/acef-incident-challenge")

        # Rejected via the Content-Length check before any body read -> no valid proof.
        assert resp.status != 200
        assert resp.body == ""
        assert stub.body.unbounded_read_called is False
        # The oversized body was never streamed (read never advanced past 0 bytes).
        assert stub.body.tell() == 0

    def test_oversized_body_without_content_length_is_bounded_and_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F2: when no Content-Length is sent, the read is STILL bounded
        (read(MAX + 1)); an over-limit body is rejected as not-a-valid-proof and the
        full body is never loaded."""
        import urllib.request

        huge = b"x" * (WELL_KNOWN_MAX_BYTES * 4)
        # No Content-Length header -> the bound must come from the read itself.
        stub = _StubResponse(200, {"Content-Type": "text/plain"}, huge)
        opener = _CapturingOpener(stub)
        monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener)

        resp = _default_http_fetcher("https://attacker.com/.well-known/acef-incident-challenge")

        assert resp.status != 200  # over-limit body -> no valid proof
        assert resp.body == ""
        assert stub.body.unbounded_read_called is False
        # At most MAX + 1 bytes were ever pulled off the (4x-MAX) body.
        assert stub.body.tell() <= WELL_KNOWN_MAX_BYTES + 1

    def test_non_https_or_ip_literal_url_is_rejected_without_fetch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """F1 default-deny: an ``http://`` URL or an IP-literal host is rejected
        (no valid proof) WITHOUT performing any open() — the verifier always builds
        an https registrable-domain URL, so a non-https/IP target is anomalous."""
        import urllib.request

        opener = _CapturingOpener(_StubResponse(200, {"Content-Type": "text/plain"}, b"x"))
        monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener)

        http_resp = _default_http_fetcher("http://openai.com/.well-known/acef-incident-challenge")
        assert http_resp.status != 200
        ip_resp = _default_http_fetcher("https://169.254.169.254/.well-known/acef-incident-challenge")
        assert ip_resp.status != 200
        # Neither anomalous URL was ever opened.
        assert opener.opened == []


class _StubRequest:
    """A minimal ``urllib.request.Request`` stand-in for the redirect-handler test."""

    def __init__(self, url: str) -> None:
        self.full_url = url

    def get_full_url(self) -> str:
        return self.full_url


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
