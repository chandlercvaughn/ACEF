"""Unit tests for the F-M8-INCIDENT-BUILDER domain-control fixes.

Covers the two domain-control assertions of F-M8-INCIDENT-BUILDER:

- **VAL-FIX-DOMCTL-001 (freshness expiry is recorded on the result).** ``now`` and
  ``freshness`` are accepted and stored (``checked_at``,
  ``details['freshness_seconds']``) but, before this fix, a ``verified``
  :class:`DomainControlResult` carried NO explicit expiry, so a caller that
  persists/caches the verdict had nothing in the result that names when it goes
  stale. The fix adds ``valid_until = checked_at + freshness`` on the result so a
  persisted verdict's expiry is unambiguous. The module RECORDS expiry; v1.1
  ENFORCEMENT remains the caller's responsibility (cache-TTL is profile-pinnable /
  non-normative in v1.1 — RFC-0002 §5.3 domain-proof underspec list). The verdict
  logic itself is unchanged.

- **VAL-FIX-DOMCTL-002 (`_combine` returns only the verdict).** ``_combine`` used to
  return a ``(verdict, method_tag)`` tuple whose second element was ALWAYS ``""``
  (the caller discarded it via ``verdict, _ = _combine(...)`` then recomputed the
  method tag itself). The dead/misleading second element is dropped: ``_combine``
  now returns a single :class:`DomainControlVerdict`, and the caller's correct,
  already-tested method-tag recomputation is preserved (the ``result.method``
  attribution stays identical).

Determinism: in-memory generated EC P-256 keys (test fixtures, not secrets); the
freshness clock and resolvers/fetchers are injected (no wall-clock, no real network).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import ec

from acef.domain_control import (
    DEFAULT_FRESHNESS,
    DomainControlResult,
    DomainControlVerdict,
    HttpResponse,
    _ChannelOutcome,
    _combine,
    challenge_token_for,
    verify_domain_control,
)
from acef.signing import _derive_jwk

# A 26-char Crockford-base32 suffix (>=128 bits — the §5.3 pattern minimum).
_SUFFIX = "0123456789ABCDEFGHJKMNPQRS"
_FORGED_ID = f"AIIC-OPENAI-2026-{_SUFFIX}"
_FORGED_ASSIGNER = "OPENAI"
_FIXED_NOW = datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)


def _gen_ec_key() -> ec.EllipticCurvePrivateKey:
    """Generate an in-memory EC P-256 (ES256) key. Test fixture only."""
    return ec.generate_private_key(ec.SECP256R1())


def _registrant_jwk() -> dict[str, str]:
    return _derive_jwk(_gen_ec_key())


def _no_dns(name: str) -> list[str]:
    return []


def _no_http(url: str) -> HttpResponse:
    return HttpResponse(status=404, content_type="text/plain", body="")


# ===========================================================================
# VAL-FIX-DOMCTL-001 — the result records its expiry (valid_until).
# ===========================================================================


class TestDomainControlValidUntil:
    def test_verified_result_exposes_valid_until_equal_to_checked_at_plus_freshness(self) -> None:
        """A ``verified`` result MUST carry ``valid_until == checked_at + freshness``
        so a persisted verdict's expiry is unambiguous to a caching caller."""
        jwk = _registrant_jwk()
        expected = challenge_token_for(_FORGED_ASSIGNER, jwk)

        def dns_resolver(name: str) -> list[str]:
            return [expected]

        freshness = timedelta(hours=6)
        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=dns_resolver,
            http_fetcher=_no_http,
            now=_FIXED_NOW,
            freshness=freshness,
        )
        assert result.verdict is DomainControlVerdict.VERIFIED
        # The fix: the result exposes its expiry explicitly.
        assert result.checked_at == _FIXED_NOW
        assert result.valid_until == _FIXED_NOW + freshness

    def test_valid_until_uses_default_freshness_when_unspecified(self) -> None:
        """When ``freshness`` is omitted, ``valid_until`` reflects DEFAULT_FRESHNESS."""
        jwk = _registrant_jwk()
        expected = challenge_token_for(_FORGED_ASSIGNER, jwk)

        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=lambda name: [expected],
            http_fetcher=_no_http,
            now=_FIXED_NOW,
        )
        assert result.valid_until == _FIXED_NOW + DEFAULT_FRESHNESS

    def test_unverified_result_also_carries_valid_until(self) -> None:
        """``valid_until`` is recorded on every result that carries a checked_at —
        an unverified (no-proof) result also exposes the expiry window so callers
        treat the absence-of-proof observation with the same TTL bound."""
        jwk = _registrant_jwk()
        freshness = timedelta(hours=2)
        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=_no_dns,
            http_fetcher=_no_http,
            now=_FIXED_NOW,
            freshness=freshness,
        )
        assert result.verdict is DomainControlVerdict.UNVERIFIED
        assert result.valid_until == _FIXED_NOW + freshness

    def test_valid_until_is_none_when_checked_at_is_absent(self) -> None:
        """A bare :class:`DomainControlResult` without ``checked_at`` has no
        derivable expiry, so ``valid_until`` is ``None`` (never a synthesized
        wall-clock value)."""
        result = DomainControlResult(
            verdict=DomainControlVerdict.UNVERIFIED,
            public_incident_id="x",
            assigner="",
            domain="",
        )
        assert result.valid_until is None

    def test_freshness_does_not_change_the_verdict(self) -> None:
        """The fix is record-only: freshness still does NOT gate the verdict. A
        live, matching proof is ``verified`` regardless of the freshness window
        (enforcement of expiry is the caller's responsibility in v1.1)."""
        jwk = _registrant_jwk()
        expected = challenge_token_for(_FORGED_ASSIGNER, jwk)
        # A tiny freshness window does not turn a live match into unverified/reject.
        result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=lambda name: [expected],
            http_fetcher=_no_http,
            now=_FIXED_NOW,
            freshness=timedelta(seconds=1),
        )
        assert result.verdict is DomainControlVerdict.VERIFIED


# ===========================================================================
# VAL-FIX-DOMCTL-002 — _combine returns only the verdict (no dead method tag).
# ===========================================================================


class TestCombineReturnsOnlyVerdict:
    def test_combine_returns_a_bare_verdict_not_a_tuple(self) -> None:
        """``_combine`` returns a single :class:`DomainControlVerdict`, not a
        ``(verdict, tag)`` tuple whose second element was always empty."""
        out = _combine([_ChannelOutcome.MATCH])
        assert isinstance(out, DomainControlVerdict)
        assert out is DomainControlVerdict.VERIFIED

    def test_combine_precedence_match_then_present_invalid_then_absent(self) -> None:
        """The precedence is unchanged: MATCH -> verified; else PRESENT_INVALID ->
        reject; else (absence/cannot-complete) -> unverified."""
        assert _combine([_ChannelOutcome.MATCH, _ChannelOutcome.PRESENT_INVALID]) is DomainControlVerdict.VERIFIED
        assert _combine([_ChannelOutcome.PRESENT_INVALID, _ChannelOutcome.ABSENT]) is DomainControlVerdict.REJECT
        assert _combine([_ChannelOutcome.ABSENT, _ChannelOutcome.CANNOT_COMPLETE]) is DomainControlVerdict.UNVERIFIED

    def test_method_tag_recomputation_at_call_site_is_unchanged(self) -> None:
        """The caller's method-tag attribution is preserved: a DNS-channel match
        still reports method ``dns-01`` and a well-known-channel match ``well-known``."""
        jwk = _registrant_jwk()
        expected = challenge_token_for(_FORGED_ASSIGNER, jwk)

        dns_result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=lambda name: [expected],
            http_fetcher=_no_http,
            now=_FIXED_NOW,
        )
        assert dns_result.verdict is DomainControlVerdict.VERIFIED
        assert dns_result.method == "dns-01"

        http_result = verify_domain_control(
            _FORGED_ID,
            jwk,
            dns_resolver=_no_dns,
            http_fetcher=lambda url: HttpResponse(status=200, content_type="text/plain", body=expected),
            now=_FIXED_NOW,
        )
        assert http_result.verdict is DomainControlVerdict.VERIFIED
        assert http_result.method == "well-known"
