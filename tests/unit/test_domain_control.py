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
    _is_allowed_well_known_host,
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

    @pytest.fixture(autouse=True)
    def _stub_public_dns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Stub getaddrinfo to a PUBLIC IP so these policy tests never perform
        real DNS (F33 added a resolve-and-pin step before the mocked opener is
        reached; roborev on 6be6ff9 — keep these unit tests network-independent)."""

        def _fake_getaddrinfo(host: object, port: object, *a: object, **k: object) -> list[tuple]:
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))]

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

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

    @pytest.mark.parametrize(
        "url",
        [
            # IPv4 dotted-quad literal (already covered by the legacy check, kept here
            # so the parametrized regression locks ALL IP-literal forms in one place).
            "https://169.254.169.254/.well-known/acef-incident-challenge",
            # Bracketed IPv6 loopback. urlsplit STRIPS the brackets, so the host that
            # reaches the guard is the bare "::1" — the residual SSRF that this fix closes.
            "https://[::1]/.well-known/acef-incident-challenge",
            # Bracketed IPv6 link-local.
            "https://[fe80::1]/.well-known/acef-incident-challenge",
            # IPv4-mapped IPv6 literal targeting the cloud metadata endpoint — the
            # nastiest SSRF pivot (it resolves to 169.254.169.254 at the IP layer).
            "https://[::ffff:169.254.169.254]/.well-known/acef-incident-challenge",
            # Full/compressed IPv6 forms.
            "https://[2001:db8::1]/.well-known/acef-incident-challenge",
            "https://[0:0:0:0:0:0:0:1]/.well-known/acef-incident-challenge",
        ],
    )
    def test_ip_literal_host_is_rejected_without_fetch(self, url: str, monkeypatch: pytest.MonkeyPatch) -> None:
        """SSRF residual (roborev Medium): EVERY IP-literal host — IPv4 dotted-quad
        AND bracketed/compressed/IPv4-mapped IPv6 — MUST be rejected as not-a-valid-proof
        (non-200 HttpResponse) WITHOUT performing any open(). ``urlsplit`` strips the
        ``[...]`` brackets before the host reaches the guard, so a bracketed IPv6 host
        must be detected by parsing the bare host as an IP address, not by a string check.
        """
        import urllib.request

        opener = _CapturingOpener(_StubResponse(200, {"Content-Type": "text/plain"}, b"x"))
        monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener)

        resp = _default_http_fetcher(url)
        # No valid proof, and the IP target was NEVER opened (no SSRF request issued).
        assert resp.status != 200
        assert resp.body == ""
        assert opener.opened == []

    def test_ip_literal_host_guard_rejects_all_forms_directly(self) -> None:
        """Unit the host guard directly: after ``urlsplit`` strips IPv6 brackets the
        bare host string reaches ``_is_allowed_well_known_host``. The guard MUST reject
        every parseable IP literal (the bracket-stripped IPv6 forms AND IPv4) and MUST
        accept a real DNS hostname."""
        from urllib.parse import urlsplit

        for url in (
            "https://[::1]/x",
            "https://[fe80::1]/x",
            "https://[::ffff:169.254.169.254]/x",
            "https://[2001:db8::1]/x",
            "https://169.254.169.254/x",
        ):
            host = urlsplit(url).hostname or ""
            assert _is_allowed_well_known_host(host) is False, f"IP literal host must be denied: {host!r}"
        # A genuine registrable domain (and an uppercase/idna-ish label) still passes.
        assert _is_allowed_well_known_host("openai.com") is True
        assert _is_allowed_well_known_host("sub.example.co.uk") is True

    @pytest.mark.parametrize(
        "host",
        [
            # Leading-zero dotted quad: ipaddress.ip_address() REJECTS this as a
            # ValueError (it forbids ambiguous octal-looking octets), so it slipped
            # past the bare ip_address() check and fell through to the "hostname"
            # allow path — yet an OS resolver / inet_aton may normalize it to the
            # loopback 127.0.0.1 (classic SSRF). The new numeric-dotted-quad guard
            # closes this.
            "127.000.000.001",
            "010.000.000.001",
            # Out-of-range dotted quad — also rejected by ipaddress but is four
            # all-numeric labels, so a resolver might still interpret it.
            "999.999.999.999",
            # Bare integer = 127.0.0.1 in 32-bit decimal form (inet_aton accepts it).
            "2130706433",
            # Bare integer = 169.254.169.254 (cloud metadata) in decimal.
            "2852039166",
            # Single bare integer zero.
            "0",
        ],
    )
    def test_ambiguous_ip_ish_host_is_rejected_directly(self, host: str) -> None:
        """SSRF class (roborev a9ccd0e): an AMBIGUOUS IPv4 textual form that
        ``ipaddress.ip_address()`` rejects as a ValueError — a leading-zero / octal-
        looking / out-of-range dotted quad, or a single bare integer (e.g.
        ``2130706433`` == 127.0.0.1) — MUST still be denied by the host guard, because
        an OS resolver may normalize it to a loopback/private IP. The guard rejects ALL
        IP-ish forms (numeric dotted-quad + bare integer), not just clean IP literals."""
        assert _is_allowed_well_known_host(host) is False, f"ambiguous IP-ish host must be denied: {host!r}"

    @pytest.mark.parametrize(
        "host",
        [
            # Numeric final label (TLD): a real DNS hostname always has a non-numeric
            # TLD, so an all-numeric last label is never a registrable domain — and is
            # a common way to smuggle a partly-numeric IP-ish target.
            "example.123",
            "127.0.0.999",
            "1.2.3.4.5",
            # Hex-ish first label with a numeric tail: inet_aton accepts 0x-prefixed
            # octets; the host contains no plausible non-numeric TLD.
            "0x7f.0.0.1",
        ],
    )
    def test_numeric_tld_or_no_alpha_host_is_rejected_directly(self, host: str) -> None:
        """Defense-in-depth: a host whose FINAL label (TLD) is all-numeric, or that
        contains no alphabetic character at all, is not a syntactically plausible DNS
        hostname (a real hostname has a non-numeric TLD). Such forms — including
        hex-ish octet smuggling like ``0x7f.0.0.1`` — are denied."""
        assert _is_allowed_well_known_host(host) is False, f"numeric-TLD / no-alpha host must be denied: {host!r}"

    @pytest.mark.parametrize(
        "host",
        [
            # Hex-COMPONENT IPv4 textual forms (roborev a-class residual). A label such
            # as ``0x1`` / ``0x7f`` looks like a DNS label to a denylist (it is NOT all
            # digits — ``isdigit()`` is False — and it carries the alphabetic char ``x``),
            # so the old denylist's "all-numeric TLD / no-alpha" checks LET THEM THROUGH.
            # But ``inet_aton`` / ``getaddrinfo`` parses 0x-prefixed octets as HEX: the OS
            # resolver normalizes EVERY one of these to the loopback 127.0.0.1 — a genuine
            # SSRF pivot. The allowlist closes the whole class at once because ``0x1`` is
            # not a valid TLD (a TLD must be purely alphabetic or a ``xn--`` punycode
            # A-label), so the host is not a syntactically valid DNS hostname.
            "127.0x1",  # getaddrinfo -> 127.0.0.1
            "0x7f.0x1",  # getaddrinfo -> 127.0.0.1
            "0x7f.0.0x1",  # getaddrinfo -> 127.0.0.1
            "0x7f.0x0.0x0.0x1",  # fully-hex dotted quad -> 127.0.0.1
            "0xA.0xB.0xC.0xD",  # uppercase-hex octets
        ],
    )
    def test_hex_component_ip_ish_host_is_rejected_directly(self, host: str) -> None:
        """SSRF residual (roborev hex-component class): an IPv4 textual form using
        0x-prefixed HEX octets — ``127.0x1``, ``0x7f.0x1``, ``0x7f.0.0x1`` — slips a
        denylist (the labels are not all-numeric and carry the alpha char ``x``) yet the
        OS resolver normalizes it to 127.0.0.1. The ALLOWLIST rejects it: ``0x1`` is not
        a valid alphabetic/punycode TLD, so the host is not a valid DNS hostname."""
        assert _is_allowed_well_known_host(host) is False, f"hex-component IP-ish host must be denied: {host!r}"

    @pytest.mark.parametrize(
        "host",
        [
            # Clean / bracket-stripped IP literals (ip_address parses these).
            "169.254.169.254",
            "::1",
            "::ffff:169.254.169.254",
            # Ambiguous IPv4 textual forms (leading-zero / out-of-range / bare-int).
            "127.000.000.001",
            "2130706433",
            "999.999.999.999",
            # Numeric / hex final label.
            "example.123",
            "0x7f.0.0x1",
            # Bare single-label hosts (no dot at all → not a registrable domain).
            "0",
            "localhost",
            # Trailing-dot / empty-label degeneracies.
            "openai.com.",
            ".com",
            "openai..com",
        ],
    )
    def test_allowlist_rejects_every_non_hostname_form(self, host: str) -> None:
        """The ALLOWLIST converges the whole IP-textual class: a host is accepted ONLY if
        it is a syntactically valid DNS hostname (≥1 dot, every label LDH, an alphabetic
        or ``xn--`` punycode final TLD label, ≤253 total). EVERY IPv4/IPv6 textual form —
        decimal/octal/hex/dotted-quad/bare-int/mixed — and every bare/degenerate label is
        rejected by the same rule, not by a growing denylist."""
        assert _is_allowed_well_known_host(host) is False, f"non-hostname form must be denied: {host!r}"

    @pytest.mark.parametrize(
        "host",
        [
            "openai.com",
            "sub.example.co.uk",
            "a.io",
            "xn--80ak6aa92e.com",  # punycode A-label — alphabetic chars present, non-numeric TLD
            "host123.example.org",  # digits in labels are fine; the TLD is alphabetic
        ],
    )
    def test_plausible_dns_hostnames_are_accepted(self, host: str) -> None:
        """A syntactically plausible DNS hostname — at least one dot, a non-numeric
        final label, and not flagged by the IP-literal / numeric-dotted-quad / bare-int
        checks — MUST be accepted (the guard does not over-reject real hostnames)."""
        assert _is_allowed_well_known_host(host) is True, f"plausible DNS hostname must be allowed: {host!r}"

    @pytest.mark.parametrize(
        "url",
        [
            # Leading-zero dotted quad → resolver may normalize to loopback (SSRF).
            "https://127.000.000.001/.well-known/acef-incident-challenge",
            # Decimal-integer loopback (inet_aton: 2130706433 == 127.0.0.1).
            "https://2130706433/.well-known/acef-incident-challenge",
            # Hex-ish octet smuggling.
            "https://0x7f.0.0.1/.well-known/acef-incident-challenge",
            # Hex-COMPONENT forms (roborev residual): getaddrinfo normalizes each to
            # 127.0.0.1. The allowlist rejects them (``0x1`` is not a valid TLD) so the
            # SSRF request is never issued.
            "https://127.0x1/.well-known/acef-incident-challenge",
            "https://0x7f.0x1/.well-known/acef-incident-challenge",
            "https://0x7f.0.0x1/.well-known/acef-incident-challenge",
        ],
    )
    def test_ambiguous_ip_ish_url_is_rejected_without_fetch(self, url: str, monkeypatch: pytest.MonkeyPatch) -> None:
        """End-to-end through the default fetcher: an ambiguous IP-ish host URL is
        rejected as not-a-valid-proof (non-200 HttpResponse) WITHOUT performing any
        open() — the SSRF request is never issued."""
        import urllib.request

        opener = _CapturingOpener(_StubResponse(200, {"Content-Type": "text/plain"}, b"x"))
        monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener)

        resp = _default_http_fetcher(url)
        assert resp.status != 200
        assert resp.body == ""
        assert opener.opened == []

    def test_normal_hostname_still_passes_guard_and_verifies_end_to_end(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Regression: a normal hostname target is STILL fetched (the guard did not
        over-reject), and a valid challenge body yields a ``verified`` verdict
        end-to-end (hardening preserves the happy path)."""
        import urllib.request

        _key, jwk = _registrant_jwk()
        expected = challenge_token_for(_FORGED_ASSIGNER, jwk)
        body = expected.encode("ascii")
        stub = _StubResponse(200, {"Content-Type": "text/plain", "Content-Length": str(len(body))}, body)
        opener = _CapturingOpener(stub)
        monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener)

        # The default fetcher accepts the hostname URL and issues exactly one open().
        resp = _default_http_fetcher(f"https://{_FORGED_DOMAIN}/.well-known/acef-incident-challenge")
        assert resp.status == 200
        assert resp.body == expected
        assert opener.opened == [f"https://{_FORGED_DOMAIN}/.well-known/acef-incident-challenge"]

        # And the same fetcher drives a full verified verdict end-to-end.
        opener2 = _CapturingOpener(
            _StubResponse(200, {"Content-Type": "text/plain", "Content-Length": str(len(body))}, body)
        )
        monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener2)
        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=_no_dns,
            now=_FIXED_NOW,
        )
        assert result.verdict is DomainControlVerdict.VERIFIED
        assert result.diagnostic is None


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


class TestWellKnownFetcherDnsRebindingGuard:
    """F33: _default_http_fetcher resolves the host and refuses to fetch when the
    resolved IP is private/loopback/link-local/reserved/multicast/unspecified —
    closing the DNS-rebinding SSRF residual where a public-looking hostname's
    A/AAAA record points at an internal address (incl. 169.254.169.254 metadata)."""

    _URL = "https://attacker.example/.well-known/acef-incident-challenge"

    @staticmethod
    def _stub_resolution(monkeypatch: pytest.MonkeyPatch, ip: str) -> None:
        def _fake_getaddrinfo(host: object, port: object, *a: object, **k: object) -> list[tuple]:
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))]

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    @pytest.mark.parametrize("internal_ip", ["127.0.0.1", "169.254.169.254", "10.0.0.5", "192.168.1.1", "0.0.0.0"])
    def test_internal_resolution_is_refused_without_a_fetch(
        self, monkeypatch: pytest.MonkeyPatch, internal_ip: str
    ) -> None:
        self._stub_resolution(monkeypatch, internal_ip)

        def _poison(*a: object, **k: object) -> object:
            raise AssertionError(f"fetch issued despite internal resolution {internal_ip!r} (SSRF)")

        monkeypatch.setattr("acef.domain_control._urllib_request.build_opener", _poison)
        resp = _default_http_fetcher(self._URL)
        assert resp.status == 0 and resp.body == ""

    def test_public_resolution_proceeds_past_the_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._stub_resolution(monkeypatch, "93.184.216.34")  # public (example.com range)

        class _FakeResp:
            status = 200
            headers = {"Content-Type": "text/plain", "Content-Length": "5"}

            def read(self, _n: int) -> bytes:
                return b"proof"

            def __enter__(self) -> _FakeResp:
                return self

            def __exit__(self, *a: object) -> bool:
                return False

        class _FakeOpener:
            def open(self, _request: object, timeout: int = 5) -> _FakeResp:
                return _FakeResp()

        monkeypatch.setattr("acef.domain_control._urllib_request.build_opener", lambda *a, **k: _FakeOpener())
        resp = _default_http_fetcher(self._URL)
        assert resp.status == 200 and resp.body == "proof"


class TestIPPinnedHTTPSConnection:
    """F33 (roborev on 6be6ff9): the connection is PINNED to the validated IP, so
    urllib cannot re-resolve to a different (internal) IP at connect time — the
    DNS-rebinding TOCTOU. The cert is still validated against the original
    hostname (SNI/server_hostname), only the IP is pinned."""

    def test_connect_targets_the_pinned_ip_not_a_reresolution(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from acef.domain_control import _IPPinnedHTTPSConnection

        captured: dict[str, object] = {}

        def _fake_create_connection(address: tuple, timeout: object = None) -> object:
            captured["address"] = address
            raise OSError("sentinel — no real connect in the test")

        monkeypatch.setattr(socket, "create_connection", _fake_create_connection)
        conn = _IPPinnedHTTPSConnection("example.com", _pinned_ips=["93.184.216.34"])
        with pytest.raises(OSError):
            conn.connect()
        # It connected to the PINNED public IP — never re-resolved the hostname.
        assert captured["address"] == ("93.184.216.34", 443)

    def test_connect_refuses_an_internal_pinned_ip_defense_in_depth(self) -> None:
        from acef.domain_control import _IPPinnedHTTPSConnection

        for internal in ("127.0.0.1", "169.254.169.254", "10.0.0.1"):
            conn = _IPPinnedHTTPSConnection("example.com", _pinned_ips=[internal])
            with pytest.raises(OSError):
                conn.connect()

    def test_connect_tries_all_validated_ips_in_order(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """roborev Low on e6d4bd8: if the first validated IP is transiently
        unreachable, the next validated one is tried (not a hard failure)."""
        from acef.domain_control import _IPPinnedHTTPSConnection

        attempts: list[str] = []

        def _fake_create_connection(address: tuple, timeout: object = None) -> object:
            attempts.append(address[0])
            if address[0] == "93.184.216.34":
                raise OSError("first address unreachable")
            raise OSError("sentinel — reached the second address")

        monkeypatch.setattr(socket, "create_connection", _fake_create_connection)
        conn = _IPPinnedHTTPSConnection("example.com", _pinned_ips=["93.184.216.34", "93.184.216.35"])
        with pytest.raises(OSError):
            conn.connect()
        assert attempts == ["93.184.216.34", "93.184.216.35"], "should try all validated IPs in order"

    def test_connect_fails_closed_under_proxy_tunnel(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """roborev High on 59cb4bb: deferring to the proxy-aware super().connect()
        under a tunnel let the PROXY resolve the origin, bypassing the pre-validated
        public-IP pin and reopening the DNS-rebinding / internal-network SSRF case in
        proxy environments. Proxies are DISABLED for this verifier, so a configured
        tunnel host must FAIL CLOSED — never delegate to the proxy, never connect."""
        from acef.domain_control import _IPPinnedHTTPSConnection

        called = {"super": False, "create_connection": False}

        def _fake_super_connect(self: object) -> None:
            called["super"] = True

        def _fake_create_connection(address: tuple, timeout: object = None) -> object:
            called["create_connection"] = True
            raise OSError("pinned path must not run under a proxy")

        monkeypatch.setattr(socket, "create_connection", _fake_create_connection)
        import http.client

        monkeypatch.setattr(http.client.HTTPSConnection, "connect", _fake_super_connect)
        conn = _IPPinnedHTTPSConnection("example.com", _pinned_ips=["93.184.216.34"])
        conn._tunnel_host = "example.com"  # simulate a configured proxy
        with pytest.raises(OSError, match="proxy tunneling is disabled"):
            conn.connect()
        assert called["super"] is False, "must NOT delegate to the proxy-aware connect (SSRF)"
        assert called["create_connection"] is False, "must NOT connect under a proxy tunnel"

    def test_connect_enforces_a_global_deadline_across_blackholed_ips(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """roborev Medium on 59cb4bb: a domain returning many blackholed addresses
        must not amplify one verification to len(ips)×timeout. A single global
        deadline bounds the TOTAL attempts; with a fake clock that each attempt
        advances by 0.2 s and a 0.5 s budget, exactly 3 attempts fit (0.0/0.2/0.4),
        not all 20 — the pre-fix loop would have tried every address."""
        from acef.domain_control import _IPPinnedHTTPSConnection

        clock = {"t": 0.0}
        attempts: list[str] = []

        def _fake_monotonic() -> float:
            return clock["t"]

        def _fake_create_connection(address: tuple, timeout: object = None) -> object:
            attempts.append(address[0])
            clock["t"] += 0.2  # each attempt "consumes" 0.2 s of the budget
            raise OSError("blackholed")

        monkeypatch.setattr("acef.domain_control._time.monotonic", _fake_monotonic)
        monkeypatch.setattr(socket, "create_connection", _fake_create_connection)
        conn = _IPPinnedHTTPSConnection("example.com", _pinned_ips=[f"93.184.216.{i}" for i in range(1, 21)])
        conn.timeout = 0.5
        with pytest.raises(OSError):
            conn.connect()
        assert len(attempts) == 3, f"global deadline must bound attempts, got {len(attempts)}"


class TestWellKnownFetcherProxyAndAmplificationGuards:
    """roborev on 59cb4bb: the fetcher DISABLES environment proxies (a proxy would
    resolve the origin and bypass the IP pin — SSRF), and DEDUPES + CAPS the resolved
    address set it pins (so a long blackholed A/AAAA set cannot amplify connect
    timeouts)."""

    _URL = "https://attacker.example/.well-known/acef-incident-challenge"

    @staticmethod
    def _stub_addrs(monkeypatch: pytest.MonkeyPatch, ips: list[str]) -> None:
        def _fake_getaddrinfo(host: object, port: object, *a: object, **k: object) -> list[tuple]:
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443)) for ip in ips]

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    class _FakeResp:
        status = 200
        headers = {"Content-Type": "text/plain", "Content-Length": "5"}

        def read(self, _n: int) -> bytes:
            return b"proof"

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *a: object) -> bool:
            return False

    class _FakeOpener:
        def open(self, _request: object, timeout: int = 5) -> Any:
            return TestWellKnownFetcherProxyAndAmplificationGuards._FakeResp()

    def test_fetcher_disables_environment_proxies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import urllib.request

        self._stub_addrs(monkeypatch, ["93.184.216.34"])
        captured: dict[str, tuple] = {}

        def _fake_build_opener(*handlers: object) -> object:
            captured["handlers"] = handlers
            return self._FakeOpener()

        monkeypatch.setattr("acef.domain_control._urllib_request.build_opener", _fake_build_opener)
        # An attacker-set environment proxy must NOT be honored by this security verifier.
        monkeypatch.setenv("HTTPS_PROXY", "http://attacker-proxy.example:8080")
        monkeypatch.setenv("https_proxy", "http://attacker-proxy.example:8080")
        self._default_fetch()
        proxy_handlers = [h for h in captured["handlers"] if isinstance(h, urllib.request.ProxyHandler)]
        assert proxy_handlers, "fetcher must install an explicit ProxyHandler to disable env proxies"
        assert all(h.proxies == {} for h in proxy_handlers), "the ProxyHandler must carry NO proxies"

    def test_fetcher_dedupes_and_caps_pinned_ips(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from acef.domain_control import _MAX_PINNED_IPS, _IPPinnedHTTPSHandler

        # 20 distinct public IPs + duplicates — the pre-fix code pinned all 21.
        ips = [f"93.184.216.{i}" for i in range(1, 21)] + ["93.184.216.1", "93.184.216.2"]
        self._stub_addrs(monkeypatch, ips)
        captured: dict[str, list[str]] = {}

        def _fake_build_opener(*handlers: object) -> object:
            for h in handlers:
                if isinstance(h, _IPPinnedHTTPSHandler):
                    captured["pinned"] = list(h._pinned_ips)
            return self._FakeOpener()

        monkeypatch.setattr("acef.domain_control._urllib_request.build_opener", _fake_build_opener)
        self._default_fetch()
        pinned = captured["pinned"]
        assert len(pinned) <= _MAX_PINNED_IPS, f"pinned set must be capped at {_MAX_PINNED_IPS}, got {len(pinned)}"
        assert len(pinned) == len(set(pinned)), "pinned set must be deduplicated"

    def _default_fetch(self) -> None:
        resp = _default_http_fetcher(self._URL)
        # The fake opener returns a 200 "proof"; we only assert the guard wiring above.
        assert resp.status in (0, 200)
