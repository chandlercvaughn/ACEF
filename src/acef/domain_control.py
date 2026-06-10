"""ACEF RFC-0002 OPTIONAL online domain-control verifier (v1.1 online-conformance).

This is the **OPTIONAL online-conformance** id-trust class of RFC-0002 §5.3 — a
SEPARATE module from the OFFLINE-deterministic incident rules in
:mod:`acef.validation.engine` / :mod:`acef.validation.incident_rules`. The offline
class checks the ``public_incident_id`` pattern + JWS self-consistency + optional
local bundled-snapshot membership and **NEVER attributes** the id to its assigner
domain; this module is where *attribution* lives, and only ever **at check time**.

What this module proves (and does not prove)
=============================================
A ``verified`` verdict means *the registrant demonstrated control of the assigner
domain at the moment of the check* (in the style of ACME DNS-01 / ``.well-known``
HTTP challenges), reusing the card's JWS signing key via its RFC-7638 JWK
thumbprint (:rfc:`7638`). It NEVER means the id is attributable without a network
check, never that the verdict persists after the check, and never that the
self-asserted handle alone resists impersonation. The ``public_incident_id`` is a
**self-asserted handle** (``id_grade: self-asserted`` in v1.1), not a
forgery-resistant credential.

Tri-valued verdict — NO double-mapping (§5.3 invariant)
=======================================================
A given observation maps to exactly ONE verdict:

* :attr:`DomainControlVerdict.VERIFIED` — a proof was presented and validates as
  current: the DNS TXT record (or ``.well-known`` document) at the assigner's
  registrable domain carries the expected challenge bound to the card's JWS key
  (RFC-7638 thumbprint), and is fresh within the configured cache-TTL window.
* :attr:`DomainControlVerdict.UNVERIFIED` — EITHER **no proof was presented at all**
  (empty/absent DNS records, 404 ``.well-known``), OR the DNS/HTTP lookup **could
  not complete** (timeout / SERVFAIL). An explicit non-result: it NEVER raises
  ACEF-083, is never a silent pass-as-verified, and never a forgery verdict.
* :attr:`DomainControlVerdict.REJECT` — a proof **was presented but FAILS
  validation** (a wrong/forged challenge token, a thumbprint for a different key, a
  malformed or absent *required subcomponent of an otherwise-presented proof*, a
  positively-invalid — not merely absent/timed-out — response). This raises
  ACEF-083 ``class: online-conformance`` (carried on
  :attr:`DomainControlResult.diagnostic`).

The invariant, stated exactly: **presence-but-invalid → reject; total absence OR
cannot-complete → unverified.** Total proof absence is ``unverified``, never
``reject``; "absent" appears in the reject branch ONLY in the narrow sense of a
missing required subcomponent of a proof that WAS otherwise presented.

Injectable dependencies (deterministic, no real network in tests)
=================================================================
:func:`verify_domain_control` accepts an injectable ``dns_resolver`` callable and
``http_fetcher`` callable (defaulting to real, stdlib-only implementations) plus an
injectable ``now`` clock, so callers and tests can supply stubs to exercise
``verified`` / ``unverified`` / ``reject`` WITHOUT real network or wall-clock. A
resolver/fetcher that raises a cannot-complete error (``TimeoutError`` / ``OSError``
/ :class:`DomainControlLookupError`) maps to ``unverified`` — never ``reject``.

Profile-pinnable parameters (§5.3 domain-proof underspec list)
==============================================================
The §5.3 domain-proof wire parameters are deliberately UNDERSPECIFIED in v1.1 and
MUST be pinned in the implementing profile / [NR-1] before the online class is
interoperable. This module implements a concrete, reasonable v1.1 default for each
and exposes it as a parameter on :func:`verify_domain_control` so a profile can pin
it without forking the module:

* **IDNA / punycode normalization** — the assigner↔domain mapping. This module's
  default :func:`assigner_to_registrable_domain` maps the uppercased 2–8-char
  ``{assigner}`` LABEL to ``"<label>.com"`` (A-label, lowercased). A profile that
  pins a different eTLD or U-label canonicalization supplies its own ``label_to_domain``.
* **eTLD+1 / subdomain-delegation policy** — keyed to the Public Suffix List; this
  module queries the registrable domain itself (no subdomain delegation by default).
* **TXT-record canonicalization + multiple-record handling** — the DNS lookup name
  is :data:`DNS_CHALLENGE_LABEL` + the registrable domain; ANY returned TXT value
  that equals the expected challenge satisfies ``verified`` (multiple records are
  searched; non-matching records are ignored, not treated as reject).
* **DNSSEC stance** — not enforced by the default resolver; a profile MAY supply a
  validating resolver.
* **HTTP-redirect / TLS rules for ``.well-known``** — the default fetcher follows NO
  redirect at all (an off-origin / non-``https`` 3xx is never followed — SSRF guard),
  requires an ``https://`` URL to a non-IP registrable-domain host (default deny),
  caps the response at :data:`WELL_KNOWN_MAX_BYTES` with a bounded read (DoS guard),
  and requires ``status == 200``. A 3xx, an over-limit body, or a disallowed URL is
  treated as "no valid proof" (non-200 → ``unverified``), never ``verified``.
* **content-type** — the default requires the challenge document's content-type to
  start with :data:`WELL_KNOWN_CONTENT_TYPE` (``text/plain``).
* **cache-TTL / clock semantics** — the freshness window a ``verified`` verdict is
  valid for is :data:`DEFAULT_FRESHNESS`; ``now`` bounds "at check time".
* **JWK-thumbprint canonicalization** — RFC 7638 over the required JWK members in
  lexicographic order, SHA-256, base64url (:func:`jwk_thumbprint`).

Determinism: this module reads no wall-clock except through the injected ``now``
(default :func:`datetime.now` is only used when the caller omits it), performs no
network except through the injected resolver/fetcher, and contains no randomness.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.error as _urllib_error
import urllib.parse as _urllib_parse
import urllib.request as _urllib_request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from acef.errors import ValidationDiagnostic, incident_error_detail

# ---------------------------------------------------------------------------
# Public type aliases for the injectable dependencies.
# ---------------------------------------------------------------------------

#: A DNS TXT resolver: given a fully-qualified name, return the list of TXT
#: record string values found at that name. An empty list means "no records"
#: (a no-proof → unverified case). Raising ``TimeoutError`` / ``OSError`` /
#: :class:`DomainControlLookupError` means "cannot complete" (also unverified).
DnsResolver = Callable[[str], list[str]]

#: A ``.well-known`` HTTP fetcher: given a URL, return an :class:`HttpResponse`.
#: A non-200 status (e.g. 404) means "no proof at that location" (unverified).
#: Raising ``TimeoutError`` / ``OSError`` / :class:`DomainControlLookupError`
#: means "cannot complete" (unverified).
HttpFetcher = Callable[[str], "HttpResponse"]

#: Maps a 2–8-char uppercase assigner LABEL to a registrable domain (profile-pinnable).
LabelToDomain = Callable[[str], str]


# ---------------------------------------------------------------------------
# Profile-pinnable defaults (§5.3 underspec list).
# ---------------------------------------------------------------------------

#: DNS TXT lookup label prefixed onto the registrable domain (ACME DNS-01 style).
DNS_CHALLENGE_LABEL = "_acef-incident-challenge."

#: ``.well-known`` path for the HTTP challenge document.
WELL_KNOWN_PATH = "/.well-known/acef-incident-challenge"

#: Required content-type prefix for the ``.well-known`` challenge document.
WELL_KNOWN_CONTENT_TYPE = "text/plain"

#: Maximum size (bytes) the default ``.well-known`` fetcher will read from an
#: input-derived assigner domain. A valid ACME-style ``.well-known`` challenge
#: document is tiny (a single ``key=value`` token), so 8 KiB is a generous bound.
#: The fetcher (a) rejects a ``Content-Length`` that exceeds this bound and (b)
#: does a BOUNDED ``read(WELL_KNOWN_MAX_BYTES + 1)`` and treats an over-limit body
#: as not-a-valid-proof — it NEVER reads an unbounded body (DoS hardening, roborev
#: F2). An over-limit document becomes a non-200 :class:`HttpResponse` → ABSENT →
#: ``unverified`` downstream (never ``verified``, never a crash).
WELL_KNOWN_MAX_BYTES = 8 * 1024

#: The challenge-token key. The full token is ``"<key>=<thumbprint>"``.
CHALLENGE_PREFIX = "acef-domain-control"

#: Default freshness window a ``verified`` verdict is valid for (cache-TTL).
DEFAULT_FRESHNESS = timedelta(hours=24)

# The public_incident_id assigner/domain grammar (§5.3): AIIC-{assigner}-{year}-{suffix},
# assigner = 2–8 uppercase alphanumerics, year = 4 digits, suffix >=26 Crockford-base32.
import re as _re  # noqa: E402  (kept local to this grammar concern)

_PUBLIC_INCIDENT_ID_PATTERN = _re.compile(r"^AIIC-([A-Z0-9]{2,8})-([0-9]{4})-[0-9A-HJKMNP-TV-Z]{26,}$")


class DomainControlLookupError(Exception):
    """A DNS/HTTP lookup could not complete (timeout / SERVFAIL class).

    Raising this from an injected resolver/fetcher is equivalent to raising a
    ``TimeoutError`` / ``OSError``: it maps to :attr:`DomainControlVerdict.UNVERIFIED`
    (cannot-complete), NEVER to ``reject``. It exists so a resolver can signal a
    cannot-complete condition without conflating it with a programming error.
    """


# Exception classes treated as "the lookup could not complete" → unverified
# (never reject). A genuine programming error (TypeError, AttributeError, …) is
# NOT caught here and propagates, so a stub bug is never masked as unverified.
_CANNOT_COMPLETE: tuple[type[BaseException], ...] = (
    TimeoutError,
    ConnectionError,
    OSError,
    DomainControlLookupError,
)


# ---------------------------------------------------------------------------
# HTTP response shape for the ``.well-known`` fetcher.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HttpResponse:
    """A minimal HTTP response for the ``.well-known`` challenge fetcher.

    Only the fields the verifier needs: ``status`` (HTTP status code),
    ``content_type`` (the ``Content-Type`` header value, possibly with parameters
    like ``"; charset=utf-8"``), and ``body`` (the decoded text body).
    """

    status: int
    content_type: str
    body: str


# ---------------------------------------------------------------------------
# Verdict + result.
# ---------------------------------------------------------------------------


class DomainControlVerdict(str, Enum):
    """The tri-valued online domain-control verdict (§5.3). NO double-mapping."""

    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    REJECT = "reject"


@dataclass(frozen=True)
class DomainControlResult:
    """The outcome of an online domain-control check.

    ``diagnostic`` is populated ONLY for :attr:`DomainControlVerdict.REJECT` (an
    ACEF-083 ``class: online-conformance`` :class:`ValidationDiagnostic`). For
    ``verified`` and ``unverified`` it is ``None`` — ``unverified`` is an explicit
    non-result, never an error. ``method`` records which proof channel produced the
    verdict (``"dns-01"`` / ``"well-known"`` / ``""`` when no proof was found).
    """

    verdict: DomainControlVerdict
    public_incident_id: str
    assigner: str
    domain: str
    method: str = ""
    checked_at: datetime | None = None
    diagnostic: ValidationDiagnostic | None = None
    details: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# RFC 7638 JWK thumbprint + challenge token.
# ---------------------------------------------------------------------------


def _b64url_no_pad(data: bytes) -> str:
    """Base64url without padding (RFC 7638 §3 step 4 / JWS base64url)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """Compute the RFC 7638 SHA-256 JWK thumbprint of a public JWK.

    Per :rfc:`7638`: construct a JSON object containing ONLY the REQUIRED members
    for the key type, with NO whitespace and keys in lexicographic (code-point)
    order, hash its UTF-8 bytes with SHA-256, and base64url-encode (no padding).

    Required members (RFC 7638 §3.2):

    * ``EC`` → ``crv``, ``kty``, ``x``, ``y``
    * ``RSA`` → ``e``, ``kty``, ``n``
    * ``oct`` → ``k``, ``kty`` (symmetric — not used for ACEF signing keys)

    This binds the domain-control challenge to the card's exact signing key: a
    challenge minted for one key cannot be satisfied by any other key.

    Raises:
        ValueError: if ``kty`` is unsupported or a required member is missing.
    """
    kty = jwk.get("kty")
    required: tuple[str, ...]
    if kty == "EC":
        required = ("crv", "kty", "x", "y")
    elif kty == "RSA":
        required = ("e", "kty", "n")
    elif kty == "oct":
        required = ("k", "kty")
    else:
        raise ValueError(f"unsupported JWK kty for thumbprint: {kty!r}")

    canonical: dict[str, Any] = {}
    for member in required:
        value = jwk.get(member)
        if not isinstance(value, str) or not value:
            raise ValueError(f"JWK missing required member {member!r} for kty={kty!r}")
        canonical[member] = value

    # json.dumps with sorted keys + the compact separators yields the RFC 7638
    # canonical form (lexicographic order, no whitespace). The members are all
    # ASCII base64url/curve strings, so ensure_ascii is irrelevant; we set it
    # False to be explicit that no escaping changes the bytes.
    serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(serialized.encode("utf-8")).digest()
    return _b64url_no_pad(digest)


def challenge_token_for(assigner: str, jwk: dict[str, Any]) -> str:
    """Return the expected challenge token binding ``assigner`` to ``jwk``'s key.

    The token is ``"<CHALLENGE_PREFIX>=<assigner>:<rfc7638-thumbprint>"``. Embedding
    BOTH the assigner token AND the key thumbprint means a proof published at a
    domain is only accepted for the specific assigner/key pair it was minted for —
    a record copied to a different key (a forged proof) will not match.
    """
    thumbprint = jwk_thumbprint(jwk)
    return f"{CHALLENGE_PREFIX}={assigner}:{thumbprint}"


# ---------------------------------------------------------------------------
# Assigner → registrable-domain mapping (profile-pinnable).
# ---------------------------------------------------------------------------


def assigner_to_registrable_domain(assigner: str) -> str:
    """Default IDNA/eTLD+1 mapping: a 2–8-char uppercase LABEL → ``"<label>.com"``.

    This is the v1.1 DEFAULT for the first item on the §5.3 domain-proof underspec
    list (IDNA/punycode normalization of the assigner↔domain mapping). It lowercases
    the A-label and appends the ``.com`` eTLD. The assigner LABEL is NOT injective
    across registrable domains (``example.com`` and ``example.ai`` both normalize to
    the label ``EXAMPLE``), so this default is a reasonable, profile-PINNABLE choice;
    a profile that needs a different eTLD or U-label canonicalization supplies its own
    ``label_to_domain`` to :func:`verify_domain_control`.
    """
    return f"{assigner.lower()}.com"


# ---------------------------------------------------------------------------
# Default real resolver / fetcher (stdlib-only; profile may replace).
# ---------------------------------------------------------------------------


def _default_dns_resolver(name: str) -> list[str]:
    """Default DNS TXT resolver using stdlib only.

    Python's stdlib has no TXT-record API, so the default resolver cannot perform
    a real TXT lookup; it signals cannot-complete (→ ``unverified``) rather than
    pretending. A deployment that wants the online check supplies a real resolver
    (e.g. a ``dnspython`` wrapper) as ``dns_resolver=``. This keeps the default
    behavior honest: no network dependency is silently introduced, and the absence
    of a real resolver lands on the explicit non-result, never a forgery verdict.
    """
    raise DomainControlLookupError("no DNS TXT resolver configured — supply dns_resolver= to run the DNS-01 channel")


class _NoFollowRedirectHandler(_urllib_request.HTTPRedirectHandler):
    """A redirect handler that NEVER follows a ``.well-known`` redirect.

    The default :class:`urllib.request.HTTPRedirectHandler` silently FOLLOWS 3xx
    responses, which would let an attacker-controlled assigner domain redirect the
    verifier to an internal/arbitrary origin (SSRF) and serve off-origin challenge
    content — directly contradicting this module's "no cross-origin redirect"
    contract (roborev F1). This subclass instead REJECTS every redirect by
    re-raising it as an :class:`urllib.error.HTTPError` (its default ``http_error_3xx``
    handlers surface the raised error to the caller). A rejected 3xx therefore never
    triggers a follow-up fetch; :func:`_default_http_fetcher` maps the resulting
    HTTPError to a non-200 :class:`HttpResponse` → ABSENT → ``unverified`` downstream.

    We reject ALL redirects (not only off-origin ones): a valid ``.well-known``
    challenge is served directly with ``200`` at the registrable-domain origin, so a
    3xx is, by the profile's default ``.well-known`` rule, "no valid proof". A 3xx to
    a DIFFERENT origin or a non-``https`` scheme is thus NEVER followed.
    """

    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        # Returning a Request here would make urllib FOLLOW the redirect. We must
        # never do that for an input-derived domain. Raise so the 3xx surfaces as an
        # HTTPError the fetcher converts to a non-200 (no valid proof) response.
        origin = req.get_full_url() if hasattr(req, "get_full_url") else getattr(req, "full_url", "")
        raise _urllib_error.HTTPError(
            origin,
            code,
            f"redirect not followed for .well-known challenge (off-origin SSRF guard): {origin!r} -> {newurl!r}",
            headers,
            fp,
        )


def _is_allowed_well_known_host(host: str) -> bool:
    """True iff ``host`` is an allowed registrable-domain host (default deny).

    The verifier always builds ``https://{registrable-domain}/.well-known/...``, so a
    legitimate host is a DNS name (e.g. ``openai.com``). An IP-literal host (IPv4 or
    bracketed IPv6) is anomalous and is denied by default (an IP target is a classic
    SSRF pivot and is never a registrable domain). A profile that needs IP-literal or
    other hosts supplies its own ``http_fetcher``.
    """
    if not host:
        return False
    # Bracketed IPv6 literal, e.g. "[::1]" or "[fd00::1]".
    if host.startswith("["):
        return False
    # IPv4 dotted-quad literal, e.g. "169.254.169.254".
    labels = host.split(".")
    if len(labels) == 4 and all(label.isdigit() for label in labels):
        return False
    return True


def _default_http_fetcher(url: str, *, max_bytes: int = WELL_KNOWN_MAX_BYTES) -> HttpResponse:
    """Default ``.well-known`` HTTP fetcher using stdlib ``urllib`` (hardened).

    Performs a single GET with a short timeout and **NO redirect-following** (an
    off-origin 3xx is never followed — SSRF guard, roborev F1) and a **bounded read**
    capped at ``max_bytes`` (an unbounded body from an input-derived domain is never
    loaded — DoS guard, roborev F2). The request MUST be ``https://`` to a non-IP
    registrable-domain host (default deny); a non-``https``/IP-literal target is
    treated as "no valid proof" (a non-200 :class:`HttpResponse`) WITHOUT a fetch.

    Verdict mapping (documented choices for the two hardening cases):

    * an off-origin / non-``https`` 3xx redirect → not followed → non-200 response →
      ABSENT → ``unverified`` (NEVER ``verified`` from an off-origin body);
    * an over-limit ``Content-Length`` OR an over-limit BODY → non-200 response →
      ABSENT → ``unverified`` (the body is never fully read).

    Any network failure (timeout / connection error / DNS failure) raises a
    cannot-complete error caught by :func:`verify_domain_control` → ``unverified``. A
    non-200 status is RETURNED as an :class:`HttpResponse` (a no-proof case), not raised.
    """
    parsed = _urllib_parse.urlsplit(url)
    if parsed.scheme != "https" or not _is_allowed_well_known_host(parsed.hostname or ""):
        # Default deny: the verifier only ever constructs https://{registrable-domain}.
        # A non-https scheme or an IP-literal host is anomalous → no valid proof,
        # and we do NOT issue the request at all.
        return HttpResponse(status=0, content_type="", body="")

    # Build a dedicated opener that NEVER follows redirects (SSRF guard). Using a
    # bespoke opener (not the global urlopen) keeps the no-follow policy local.
    opener = _urllib_request.build_opener(_NoFollowRedirectHandler())
    request = _urllib_request.Request(url, method="GET")  # noqa: S310 — https + host validated above
    try:
        with opener.open(request, timeout=5) as response:  # noqa: S310
            status = int(getattr(response, "status", 0) or 0)
            content_type = response.headers.get("Content-Type", "")
            # F2: reject an advertised Content-Length over the cap BEFORE reading the
            # body, so a malicious domain cannot make us stream a huge payload.
            declared = response.headers.get("Content-Length", "")
            if declared:
                try:
                    declared_len = int(declared)
                except ValueError:
                    declared_len = -1
                if declared_len > max_bytes:
                    return HttpResponse(status=0, content_type="", body="")
            # F2: BOUNDED read — pull at most max_bytes + 1. If we got more than
            # max_bytes the body is over-limit → not a valid proof (never the full body).
            raw = response.read(max_bytes + 1)
            if isinstance(raw, bytes | bytearray) and len(raw) > max_bytes:
                return HttpResponse(status=0, content_type="", body="")
            body = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes | bytearray) else str(raw)
            return HttpResponse(status=status, content_type=content_type, body=body)
    except _urllib_error.HTTPError as exc:
        # An HTTP error status (404, 500, …) OR a rejected redirect (the no-follow
        # handler raises HTTPError) is a "no proof here" non-result, not a
        # cannot-complete: return it as a non-200 response so the caller treats it as
        # absence (→ unverified), never as verified and never as a crash.
        return HttpResponse(status=int(getattr(exc, "code", 0) or 0), content_type="", body="")
    except (_urllib_error.URLError, TimeoutError, OSError) as exc:
        raise DomainControlLookupError(f".well-known fetch could not complete: {exc}") from exc


# ---------------------------------------------------------------------------
# Internal proof-channel evaluation.
# ---------------------------------------------------------------------------


class _ChannelOutcome(str, Enum):
    """Per-channel evaluation outcome before combination into a final verdict."""

    MATCH = "match"  # a valid, current proof was presented (→ verified)
    PRESENT_INVALID = "present_invalid"  # a proof was presented but FAILS (→ reject)
    ABSENT = "absent"  # no proof presented at all (→ unverified)
    CANNOT_COMPLETE = "cannot_complete"  # lookup timed out / SERVFAIL (→ unverified)


def _looks_like_challenge(value: str) -> bool:
    """True iff ``value`` is structurally a presented challenge for our scheme.

    A record/document that does not even start with the challenge prefix is treated
    as ABSENT (an unrelated TXT record / wrong document), NOT as a presented-invalid
    proof — only a record that claims to be our challenge but fails validation is a
    reject (presence-but-invalid).
    """
    return value.strip().startswith(f"{CHALLENGE_PREFIX}=")


def _eval_dns_channel(
    dns_resolver: DnsResolver,
    domain: str,
    expected: str,
) -> _ChannelOutcome:
    """Evaluate the DNS-01 TXT channel for ``domain`` against ``expected``."""
    lookup_name = f"{DNS_CHALLENGE_LABEL}{domain}"
    try:
        records = dns_resolver(lookup_name)
    except _CANNOT_COMPLETE:
        return _ChannelOutcome.CANNOT_COMPLETE
    if not isinstance(records, list):
        records = []

    presented = [r.strip() for r in records if isinstance(r, str) and _looks_like_challenge(r)]
    if not presented:
        return _ChannelOutcome.ABSENT  # no challenge-shaped record → no proof presented
    # A challenge-shaped record WAS presented. If any matches exactly → verified;
    # otherwise the presented proof is invalid → reject.
    if any(record == expected for record in presented):
        return _ChannelOutcome.MATCH
    return _ChannelOutcome.PRESENT_INVALID


def _eval_http_channel(
    http_fetcher: HttpFetcher,
    domain: str,
    expected: str,
) -> _ChannelOutcome:
    """Evaluate the ``.well-known`` HTTP channel for ``domain`` against ``expected``."""
    url = f"https://{domain}{WELL_KNOWN_PATH}"
    try:
        response = http_fetcher(url)
    except _CANNOT_COMPLETE:
        return _ChannelOutcome.CANNOT_COMPLETE
    if not isinstance(response, HttpResponse):
        # A stub that returns the wrong shape is a programming error, not a
        # domain-control signal — surface it rather than mask it as unverified.
        raise TypeError(f"http_fetcher must return HttpResponse, got {type(response).__name__}")

    if response.status != 200:
        return _ChannelOutcome.ABSENT  # 404 / non-200 → no proof at that location

    body = response.body.strip()
    if not _looks_like_challenge(body):
        # A 200 document that is not even a challenge document → no proof presented.
        return _ChannelOutcome.ABSENT
    # A challenge document WAS presented. Now the required subcomponents (content-type
    # + exact challenge value) MUST be correct, else it is presented-invalid → reject.
    content_type_ok = response.content_type.split(";", 1)[0].strip().lower() == WELL_KNOWN_CONTENT_TYPE
    if content_type_ok and body == expected:
        return _ChannelOutcome.MATCH
    return _ChannelOutcome.PRESENT_INVALID


def _combine(outcomes: list[_ChannelOutcome]) -> tuple[DomainControlVerdict, str]:
    """Combine per-channel outcomes into a final verdict (§5.3 invariant).

    Precedence:
    1. ANY channel ``MATCH`` → ``verified`` (one demonstrated control proof suffices).
    2. Else ANY channel ``PRESENT_INVALID`` → ``reject`` (a proof was presented but
       fails — presence-but-invalid; ACEF-083 ``class: online-conformance``).
    3. Else → ``unverified`` (total absence and/or cannot-complete — an explicit
       non-result, never an error).

    Returns the verdict and the winning channel ``method`` tag (or ``""``).
    """
    # 1. A current, valid proof on ANY channel.
    if _ChannelOutcome.MATCH in outcomes:
        return DomainControlVerdict.VERIFIED, ""  # method tag set by caller
    # 2. A presented-but-invalid proof on ANY channel → reject (never masked by an
    #    absent/cannot-complete sibling channel; presence-but-invalid is positive).
    if _ChannelOutcome.PRESENT_INVALID in outcomes:
        return DomainControlVerdict.REJECT, ""
    # 3. Total absence and/or cannot-complete → unverified.
    return DomainControlVerdict.UNVERIFIED, ""


# ---------------------------------------------------------------------------
# Public entrypoint.
# ---------------------------------------------------------------------------


def verify_domain_control(
    public_incident_id: str,
    card_jwk: dict[str, Any],
    *,
    dns_resolver: DnsResolver | None = None,
    http_fetcher: HttpFetcher | None = None,
    label_to_domain: LabelToDomain | None = None,
    now: datetime | None = None,
    freshness: timedelta = DEFAULT_FRESHNESS,
) -> DomainControlResult:
    """Run the OPTIONAL online domain-control check for ``public_incident_id``.

    Proves the registrant controls the assigner domain AT CHECK TIME by looking for
    a challenge — bound to ``card_jwk`` via its RFC-7638 thumbprint — published at the
    assigner's registrable domain over the DNS-01 TXT channel and/or the
    ``.well-known`` HTTP channel. Returns a tri-valued :class:`DomainControlResult`
    with NO double-mapping (see module docstring for the exact invariant).

    Args:
        public_incident_id: the card's ``AIIC-{assigner}-{year}-{suffix}`` id. Its
            assigner LABEL is mapped to a registrable domain via ``label_to_domain``.
            An id that does not PARSE cannot anchor an online attribution → the
            verdict is ``unverified`` (the malformed-pattern failure is the OFFLINE
            class's ACEF-083 ``class: offline-deterministic``, not this online class).
        card_jwk: the card's public signing JWK (e.g. from the JWS header ``jwk`` or
            derived from the signing key via :func:`acef.signing._derive_jwk`). The
            challenge is bound to THIS key's thumbprint.
        dns_resolver: injectable DNS TXT resolver (``name -> [txt, ...]``). Defaults
            to a stdlib resolver that signals cannot-complete (no real TXT API in the
            stdlib) — supply a real one to run the DNS-01 channel.
        http_fetcher: injectable ``.well-known`` HTTP fetcher (``url -> HttpResponse``).
            Defaults to a stdlib ``urllib`` GET.
        label_to_domain: injectable assigner-LABEL → registrable-domain mapping
            (profile-pinnable; default :func:`assigner_to_registrable_domain`).
        now: the check-time instant (injectable clock). Defaults to ``datetime.now(UTC)``
            ONLY when omitted; tests should pass an explicit ``now`` for determinism.
        freshness: the cache-TTL window a ``verified`` verdict is valid for. Recorded
            on the result for the caller; the proof itself is observed live, so a
            successful observation is fresh by construction at ``now``.

    Returns:
        A :class:`DomainControlResult`. ``diagnostic`` is an ACEF-083
        ``class: online-conformance`` :class:`ValidationDiagnostic` ONLY for
        ``reject``; ``None`` for ``verified`` / ``unverified``.
    """
    checked_at = now if now is not None else datetime.now(UTC)
    dns = dns_resolver if dns_resolver is not None else _default_dns_resolver
    http = http_fetcher if http_fetcher is not None else _default_http_fetcher
    mapper = label_to_domain if label_to_domain is not None else assigner_to_registrable_domain

    match = _PUBLIC_INCIDENT_ID_PATTERN.match(public_incident_id) if isinstance(public_incident_id, str) else None
    if match is None:
        # A malformed id cannot anchor an online attribution. This is NOT an
        # online-conformance reject (no proof was presented-and-invalid) — it is an
        # unverified non-result; the offline class diagnoses the pattern failure.
        return DomainControlResult(
            verdict=DomainControlVerdict.UNVERIFIED,
            public_incident_id=public_incident_id if isinstance(public_incident_id, str) else "",
            assigner="",
            domain="",
            method="",
            checked_at=checked_at,
            diagnostic=None,
            details={"reason": "public_incident_id does not parse — no online attribution attempted"},
        )

    assigner = match.group(1)
    domain = mapper(assigner)

    try:
        expected = challenge_token_for(assigner, card_jwk)
    except ValueError:
        # The card's JWK is unusable for thumbprint binding (missing members / bad
        # kty). We cannot construct the expected challenge, so we cannot attribute —
        # an explicit unverified non-result, never a forgery verdict.
        return DomainControlResult(
            verdict=DomainControlVerdict.UNVERIFIED,
            public_incident_id=public_incident_id,
            assigner=assigner,
            domain=domain,
            method="",
            checked_at=checked_at,
            diagnostic=None,
            details={"reason": "card_jwk is not a usable public JWK for RFC-7638 thumbprint binding"},
        )

    dns_outcome = _eval_dns_channel(dns, domain, expected)
    http_outcome = _eval_http_channel(http, domain, expected)

    verdict, _ = _combine([dns_outcome, http_outcome])

    # Resolve the winning channel method tag for the result (DNS preferred when both
    # match; whichever produced the reject when rejecting).
    method = ""
    if verdict is DomainControlVerdict.VERIFIED:
        method = "dns-01" if dns_outcome is _ChannelOutcome.MATCH else "well-known"
    elif verdict is DomainControlVerdict.REJECT:
        method = "dns-01" if dns_outcome is _ChannelOutcome.PRESENT_INVALID else "well-known"

    details: dict[str, Any] = {
        "assigner": assigner,
        "domain": domain,
        "dns_outcome": dns_outcome.value,
        "well_known_outcome": http_outcome.value,
        "freshness_seconds": int(freshness.total_seconds()),
    }

    diagnostic: ValidationDiagnostic | None = None
    if verdict is DomainControlVerdict.REJECT:
        diagnostic = _reject_diagnostic(public_incident_id, assigner, domain, method, details)

    return DomainControlResult(
        verdict=verdict,
        public_incident_id=public_incident_id,
        assigner=assigner,
        domain=domain,
        method=method,
        checked_at=checked_at,
        diagnostic=diagnostic,
        details=details,
    )


def _reject_diagnostic(
    public_incident_id: str,
    assigner: str,
    domain: str,
    method: str,
    details: dict[str, Any],
) -> ValidationDiagnostic:
    """Build the ACEF-083 ``class: online-conformance`` reject diagnostic.

    The fix-hint text is sourced from the registered ACEF-083 incident error detail
    (:func:`acef.errors.incident_error_detail`) so the reject surfaces the same
    problem + cause + fix the offline branch and the SDK rendering use, tagged with
    ``class: online-conformance`` to distinguish it from the offline-deterministic
    branch of the SAME single code (§5.3 / §7).
    """
    detail = incident_error_detail("ACEF-083")
    fix = detail.fix if detail is not None else ""
    message = (
        f"public_incident_id {public_incident_id!r}: online domain-control proof was PRESENTED "
        f"but FAILS validation for assigner {assigner!r} at domain {domain!r} "
        f"(class: online-conformance) — a forged/incorrect challenge token, a thumbprint for a "
        f"different key, or a malformed required subcomponent of an otherwise-presented proof "
        f"(§5.3). This is the reject verdict (presence-but-invalid), distinct from the unverified "
        f"non-result (no proof OR a lookup that could not complete). {fix}"
    )
    diag_details = dict(details)
    diag_details["class"] = "online-conformance"
    return ValidationDiagnostic(
        "ACEF-083",
        message,
        path=f"/{assigner}/domain-control",
        details=diag_details,
    )
