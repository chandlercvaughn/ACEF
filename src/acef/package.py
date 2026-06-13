"""ACEF Package — core evidence package builder.

The primary API for creating ACEF Evidence Bundles.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from acef.errors import ACEFError, ACEFSchemaError
from acef.integrity import canonicalize, path_nfc_utf8_problem, sha256_hex
from acef.models.agent_reliability import (
    AuthorizedTestScopePayload,
    DeliveryVerdictPayload,
    FindingRecordPayload,
    HarnessAttestationPayload,
    ScopeBoundaryEventPayload,
)
from acef.models.entities import Actor, Component, Dataset, EntitiesBlock, Relationship
from acef.models.enums import (
    RECORD_TYPES,
    ActorRole,
    AuditEventType,
    ComponentType,
    Confidentiality,
    DatasetModality,
    DatasetSourceType,
    LifecyclePhase,
    ObligationRole,
    RelationshipType,
    RiskClassification,
    SubjectType,
    TrustLevel,
)
from acef.models.manifest import AuditTrailEntry, Manifest, ProfileEntry, RecordFileEntry
from acef.models.metadata import PackageMetadata, ProducerInfo, RetentionPolicy, Versioning
from acef.models.records import (
    AttachmentRef,
    Attestation,
    CollectorInfo,
    EntityRefs,
    RecordEnvelope,
    RecordRetention,
)
from acef.models.subjects import LifecycleEntry, Subject
from acef.models.urns import URNType, generate_urn
from acef.schemas.registry import (
    list_record_type_schemas,
    parse_core_version_minor,
)

# Spec §3.1 timestamp format — ISO 8601 with explicit ``Z`` suffix and no
# sub-second precision. Both the model default factories and the injected-
# clock path MUST format identically so v0.3 behavior is preserved.
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Spec §3.1 (line 419): obligation_role is "REQUIRED for transparency_marking,
# disclosure_labeling, and event_log records (EU AI Act and CAC split
# obligations by role)." For these role-split record types the builder must NOT
# silently invent ``provider`` when the caller omits the role — a
# deployer-side disclosure_labeling defaulted to ``provider`` is semantically
# wrong split-obligation evidence with no caller signal (audit
# envelope-manifest-5). All OTHER record types keep the convenience default.
_ROLE_SPLIT_RECORD_TYPES: frozenset[str] = frozenset({"transparency_marking", "disclosure_labeling", "event_log"})

# ``coverage_cell`` is registered in ``RECORD_TYPES`` (so cross-cutting
# type-name inventories treat it uniformly), but it is an Assessment-Bundle
# inventory concept that has NO standalone ``coverage_cell.schema.json`` — it
# is defined inline in assessment-bundle.schema.json#/properties/coverage_cells.
# It is therefore NOT a records/ record_type: ``Package.record()`` rejects it up
# front (audit records-payloads-3) rather than authoring a record the SDK's own
# validator later rejects ACEF-003.
_ASSESSMENT_ONLY_RECORD_TYPES: frozenset[str] = frozenset({"coverage_cell"})


# ---------------------------------------------------------------------------
# RFC-0002 §5.5 — the canonical cross-database incident_dedupe_key.
#
# The dedupe spine is ACEF's own ``incident_dedupe_key``, built like RFC-0001's
# ``finding_record.dedupe_key``: an RFC 8785 (JCS) canonicalization of a 4-key
# OBJECT (NOT a delimiter-joined string), SHA-256, ``"sha256:"`` prefix. The
# preimage and primitives REUSE :func:`acef.integrity.canonicalize` + SHA-256,
# the same path :meth:`Package.record_finding` uses for RFC-0001's key, so the
# two key families share one deterministic computation.
# ---------------------------------------------------------------------------


def _normalize_subject_identity(provider: str, name: str, version: str) -> str:
    """NFC-normalize then case-fold the ``provider|name|version`` triple (§5.5).

    The subject_identity is the cross-DB stable spelling of the affected subject
    — NOT the per-bundle subject UUID (which never matches across databases). It
    is the ``"provider|name|version"`` triple, UTF-8 **NFC-normalized** and
    **case-folded**, so two databases that spell the same provider with different
    Unicode composition or letter case derive the SAME key (the interop property
    the whole spine depends on).
    """
    triple = f"{provider}|{name}|{version}"
    return unicodedata.normalize("NFC", triple).casefold()


def _occurrence_date_utc(occurrence_date: str | None, detection_date: str | None) -> str | None:
    """Project the incident date to a UTC ``YYYY-MM-DD`` calendar date (§5.5).

    Uses ``occurrence_date`` when present, else ``detection_date``. The value is
    an ISO-8601 instant (Zulu or offset); it is converted to UTC and reduced to
    the calendar date so the key keys on the UTC day, not a local day. Returns
    ``None`` when neither date is supplied or the supplied value is unparseable
    (the key is then simply not emitted — it is never computed from a partial
    preimage).
    """
    raw = occurrence_date if occurrence_date else detection_date
    if not isinstance(raw, str) or not raw:
        return None
    candidate = raw.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%d")


def _coerce_subject_identity_parts(
    subject_identity: tuple[str, str, str] | list[str] | dict[str, str] | Subject | None,
) -> tuple[str, str, str] | None:
    """Coerce a subject_identity input to a ``(provider, name, version)`` triple.

    Accepts a ``(provider, name, version)`` tuple/list, a ``{provider, name,
    version}`` mapping, or a :class:`~acef.models.subjects.Subject` (whose
    ``provider``/``name``/``version`` fields back the triple). Returns ``None``
    when the input is absent or does not yield all three string parts (the key is
    then omitted rather than computed from a partial identity).
    """
    if subject_identity is None:
        return None
    if isinstance(subject_identity, Subject):
        return (subject_identity.provider, subject_identity.name, subject_identity.version)
    if isinstance(subject_identity, dict):
        provider = subject_identity.get("provider")
        name = subject_identity.get("name")
        version = subject_identity.get("version")
        if isinstance(provider, str) and isinstance(name, str) and isinstance(version, str):
            return (provider, name, version)
        return None
    if isinstance(subject_identity, (tuple, list)) and len(subject_identity) == 3:
        provider, name, version = subject_identity
        if isinstance(provider, str) and isinstance(name, str) and isinstance(version, str):
            return (provider, name, version)
        return None
    return None


def _incident_dedupe_preimage(
    *,
    value_chain_role: str,
    subject_identity: str,
    harm_class: str,
    occurrence_date_utc: str,
) -> dict[str, str]:
    """The 4-key §5.5 dedupe preimage OBJECT (the JCS input)."""
    return {
        "value_chain_role": value_chain_role,
        "subject_identity": subject_identity,
        "harm_class": harm_class,
        "occurrence_date_utc": occurrence_date_utc,
    }


def compute_incident_dedupe_key(
    *,
    value_chain_role: str | None,
    subject_identity: tuple[str, str, str] | list[str] | dict[str, str] | Subject | None,
    harm_class: str | None,
    occurrence_date: str | None,
    detection_date: str | None = None,
) -> str | None:
    """Compute the §5.5 ``incident_dedupe_key``, or ``None`` if not derivable.

    ``incident_dedupe_key = "sha256:" + hex(SHA-256(JCS({value_chain_role,
    subject_identity, harm_class, occurrence_date_utc})))``. All four inputs are
    REQUIRED; when any is absent/underivable the function returns ``None`` (the
    caller omits the field rather than emit a key over a partial preimage). The
    SHA-256 over the RFC 8785-canonicalized object is the ONLY computation — no
    entropy, no wall-clock — so identical inputs yield a byte-equal key.
    """
    if not isinstance(value_chain_role, str) or not value_chain_role:
        return None
    if not isinstance(harm_class, str) or not harm_class:
        return None
    parts = _coerce_subject_identity_parts(subject_identity)
    if parts is None:
        return None
    date_utc = _occurrence_date_utc(occurrence_date, detection_date)
    if date_utc is None:
        return None
    preimage = _incident_dedupe_preimage(
        value_chain_role=value_chain_role,
        subject_identity=_normalize_subject_identity(*parts),
        harm_class=harm_class,
        occurrence_date_utc=date_utc,
    )
    return "sha256:" + hashlib.sha256(canonicalize(preimage)).hexdigest()


def compute_incident_dedupe_key_hmac(
    *,
    pepper: bytes | str,
    value_chain_role: str | None,
    subject_identity: tuple[str, str, str] | list[str] | dict[str, str] | Subject | None,
    harm_class: str | None,
    occurrence_date: str | None,
    detection_date: str | None = None,
) -> str | None:
    """Compute the §5.5 keyed ``incident_dedupe_key_hmac``, or ``None``.

    ``incident_dedupe_key_hmac = "hmac-sha256:" + hex(HMAC-SHA-256(pepper,
    JCS(K)))`` over the SAME 4-key preimage ``K`` as the plaintext key. The
    ``pepper`` is the §5.3 resolver secret (held only by the central id/dedupe
    resolver); a ``str`` pepper is UTF-8 encoded. Returns ``None`` when the
    preimage is not derivable. Absent a pepper the keyed variant degrades to
    link-only and the caller emits nothing.
    """
    if not isinstance(value_chain_role, str) or not value_chain_role:
        return None
    if not isinstance(harm_class, str) or not harm_class:
        return None
    parts = _coerce_subject_identity_parts(subject_identity)
    if parts is None:
        return None
    date_utc = _occurrence_date_utc(occurrence_date, detection_date)
    if date_utc is None:
        return None
    key_bytes = pepper.encode("utf-8") if isinstance(pepper, str) else pepper
    preimage = _incident_dedupe_preimage(
        value_chain_role=value_chain_role,
        subject_identity=_normalize_subject_identity(*parts),
        harm_class=harm_class,
        occurrence_date_utc=date_utc,
    )
    mac = hmac.new(key_bytes, canonicalize(preimage), hashlib.sha256).hexdigest()
    return "hmac-sha256:" + mac


@lru_cache(maxsize=1)
def _v1_1_only_record_types() -> frozenset[str]:
    """Record types in ``RECORD_TYPES`` that exist ONLY in the v1.1 schema set.

    A v1.1-only type (e.g. ``incident_card`` or an agent-reliability primitive)
    is present in ``list_record_type_schemas('v1.1')`` but absent from
    ``list_record_type_schemas('v1')``. Recording one on a v1.0-declared package
    MUST bump ``core_version`` to 1.1.0 so the validator resolves the v1.1
    allowlist (audit records-payloads-2). ``_ASSESSMENT_ONLY_RECORD_TYPES``
    (coverage_cell) is excluded — it has no schema in EITHER set and is rejected
    up front, so it never reaches the version-bump path.

    ``list_record_type_schemas`` globs the on-disk schema dirs (it is not itself
    cached) and the schema set is fixed for the process lifetime, so this result
    is memoized with ``lru_cache(maxsize=1)`` — every ``Package.record()`` call
    consults it without re-globbing (the schema files are frozen on disk, so the
    cached value cannot go stale within a process).
    """
    v1_types = set(list_record_type_schemas("v1"))
    v1_1_types = set(list_record_type_schemas("v1.1"))
    return frozenset((v1_1_types - v1_types) - _ASSESSMENT_ONLY_RECORD_TYPES)


# Open-core v1.1 manifest-field (X5/X6) builder authoring constraints. These
# mirror the FROZEN v1.1 manifest schema EXACTLY so the builder cannot author a
# manifest the schema rejects (the same guard discipline as add_profile):
#   - analysis_mode is the Manifest model's Literal domain (models/manifest.py).
#   - the namespaces top-level key pattern is the v1.1 manifest schema's
#     patternProperties regex (acef-conventions/v1.1/manifest.schema.json:97).
_ANALYSIS_MODES: frozenset[str] = frozenset({"subscriber", "public_artifact", "canary", "unattributed_artifact"})
_NAMESPACE_KEY_PATTERN = re.compile(r"^x-[a-z0-9-]+/?$")


def _default_clock() -> datetime:
    """Wall-clock default; replaced by the injected ``clock`` callable."""
    return datetime.now(UTC)


def _format_timestamp(dt: datetime) -> str:
    """Format a datetime per spec §3.1 — ISO 8601 with ``Z`` suffix.

    Naive datetimes are treated as UTC. Sub-second precision is dropped.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    return dt.strftime(_TIMESTAMP_FORMAT)


# Brief §3.6 / VAL-LOAD-001/002 — persona and LLM verifiers lack the
# determinism required to attest state transitions; they are rejected at
# SDK build time AND at load time AND mirrored by validate_bundle.
_BANNED_VERIFIER_CLASSES: frozenset[str] = frozenset({"persona", "llm"})

# Brief Q3 / VAL-SCHEMA-009 — the seven hard-coded state classes.
_STATE_CLASS_TAXONOMY: frozenset[str] = frozenset(
    {
        "step",
        "finding",
        "coverage_cell",
        "regression",
        "delivery",
        "badge",
        "attestation",
    }
)

# Brief §3.1 — ownership proof methods that prove genuine *ownership* of
# the underlying system (as opposed to mere *control of an account*).
# Production-capable authorization requires one of these methods.
_OWNERSHIP_PROVING_METHODS: frozenset[str] = frozenset({"dns_txt", "well_known_file", "sso_assertion"})


# ---------------------------------------------------------------------------
# RFC-0002 v1.1 incident DX — mint_incident_id (VAL-DX-002) + builder helpers.
# ---------------------------------------------------------------------------

if TYPE_CHECKING:  # pragma: no cover — type-only import to avoid a runtime cost
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

# §5.3 self-asserted public_incident_id grammar:
#   AIIC-{assigner}-{year}-{suffix}
#   assigner = 2-8 uppercase alphanumerics; year = 4 digits;
#   suffix    = >=26 Crockford-base32 chars `[0-9A-HJKMNP-TV-Z]` (>=128 bits).
_ASSIGNER_LABEL_PATTERN = re.compile(r"^[A-Z0-9]{2,8}$")
_PUBLIC_INCIDENT_ID_PATTERN = re.compile(r"^AIIC-([A-Z0-9]{2,8})-([0-9]{4})-[0-9A-HJKMNP-TV-Z]{26,}$")

# Crockford base32 alphabet (RFC-0002 §5.3 / Crockford spec): 0-9 then A-Z
# EXCLUDING I, L, O, U (the ambiguous letters), giving 32 symbols. The suffix
# encodes >=128 bits of CSPRNG entropy; 26 symbols carry 26 * 5 = 130 bits.
_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_SUFFIX_ENTROPY_BITS = 128
# 26 symbols * 5 bits = 130 bits >= 128 (the >=128-bit floor with >=26 chars).
_SUFFIX_SYMBOLS = 26

# The Art.73 / crosswalk edition pins (schema consts; §5.5 / §5.7). The eu_ai_act
# member + facts are pinned to Regulation (EU) 2024/1689 ("reg-2024-1689"); the
# NIST AI 600-1 projection is pinned to its 2024-07-final edition.
_EU_AI_ACT_EDITION = "reg-2024-1689"
_NIST_AI_600_1_EDITION = "2024-07-final"

# The Art.73 crosswalk profile id + regulatory_timeline framework tag the builder
# declares + emits (must match acef.validation.incident_rules so the delegated
# ACEF-084 checks run and the framework-match rule is satisfied, §5.7).
_ART73_PROFILE_ID = "eu-ai-act-art73-2026"
_ART73_TIMELINE_FRAMEWORK = "eu-ai-act-art73"


def _parse_iso_instant(value: str) -> datetime:
    """Parse an ISO-8601 instant (Zulu or offset) into a UTC :class:`datetime`.

    Mirrors the validator's instant parser (acef.validation.incident_rules) so the
    builder's awareness/deadline arithmetic stays consistent with the ACEF-084
    shortest-clock check. Raises ``ValueError`` on an unparseable value.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"awareness_date must be a non-empty ISO-8601 instant, got {value!r}")
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    parsed = datetime.fromisoformat(candidate)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _format_iso_instant(dt: datetime) -> str:
    """Format a UTC instant as ``YYYY-MM-DDTHH:MM:SSZ`` (byte-stable, no sub-second).

    Matches the ``...Z`` form the conformance vectors + the validator's parser use,
    so a builder-minted deadline is byte-deterministic and round-trips through the
    Art.73 clock check.
    """
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def band(severity_vector: str) -> str | None:
    """Project an ``ACEF-SEV:1.0`` vector to the coarse ``severity`` enum (§5.4).

    A thin re-export of the NORMATIVE
    :func:`acef.validation.incident_rules.band` so the SDK builder and the
    validator share ONE band() grammar (never a reimplementation). Returns the
    coarse band (``critical`` / ``major`` / ``minor`` / ``informational``) or
    ``None`` when the vector does not parse / is not bandable.
    """
    from acef.validation.incident_rules import band as _band

    return _band(severity_vector)


@dataclass(frozen=True)
class MintedIncidentId:
    """The one-call result of :func:`mint_incident_id` (RFC-0002 §5.3, VAL-DX-002).

    Carries everything a filer needs from a SINGLE call so id minting is not an
    "ACME spelunk":

    * :attr:`public_incident_id` — the ``AIIC-{LABEL}-{year}-{suffix}`` handle, with
      a >=128-bit CSPRNG Crockford-base32 suffix and an explicit
      :attr:`id_grade` of ``"self-asserted"`` (the only value emitted on the v1.1
      surface; ``registry-canonical`` is reserved for v1.2, §11).
    * :attr:`assigner` — the uppercased assigner LABEL embedded in the id (the
      registrable domain's leftmost label).
    * :attr:`jwk` — the card's public RFC-7517 JWK, derived from the signing key,
      to which the challenge token is bound (RFC-7638 thumbprint).
    * :attr:`challenge_token` — the DNS-01 / ``.well-known`` challenge token the
      registrant publishes to PROVE control at check time
      (``acef-domain-control=<assigner>:<thumbprint>``), reused verbatim from
      :func:`acef.domain_control.challenge_token_for`.
    * :attr:`dns_record_name` / :attr:`well_known_url` — the exact DNS TXT name and
      ``.well-known`` URL the token is published at, so the filer can publish it
      without re-deriving the wire locations.

    HONESTY DISCIPLINE: the id is a SELF-ASSERTED handle, not a forgery-resistant
    credential. The token does not attribute the id offline; it only lets the
    OPTIONAL online :func:`acef.domain_control.verify_domain_control` prove control
    AT CHECK TIME. A minted id round-trips to ``verified`` ONLY when the registrant
    actually publishes :attr:`challenge_token` at :attr:`dns_record_name` /
    :attr:`well_known_url`.
    """

    public_incident_id: str
    assigner: str
    year: int
    jwk: dict[str, str]
    challenge_token: str
    dns_record_name: str
    well_known_url: str
    id_grade: str = "self-asserted"


def _registrable_label_from_domain(domain: str) -> str:
    """Derive the assigner LABEL from ``domain``, RESTRICTED to domains that
    genuinely round-trip through the default
    :func:`acef.domain_control.assigner_to_registrable_domain`
    (``LABEL -> "<label>.com"``).

    The v1.1 default mapper has NO public-suffix list in scope, so it cannot
    correctly split a multi-label eTLD (``co.uk``, ``com.au``) or a non-``.com``
    eTLD (``.ai``). Naively taking ``labels[-2]`` would misparse
    ``service.example.co.uk`` to the label ``CO`` and emit a challenge location for
    ``co.com`` — a WRONG, silently-attributed challenge. To stay honest (roborev F2)
    this helper:

    1. derives the candidate registrable LABEL from the host's leftmost
       registrable label (the label immediately left of the eTLD for a multi-label
       host: ``api.openai.com`` -> ``openai`` -> ``OPENAI``; the sole label
       otherwise), validated against the ``[A-Z0-9]{2,8}`` assigner grammar (§5.3);
       then
    2. VERIFIES the derived LABEL round-trips:
       ``assigner_to_registrable_domain(LABEL)`` MUST equal the host's REGISTRABLE
       domain (its last two labels, or the bare host for a single label). If it does
       not — a multi-label public suffix, a non-``.com`` eTLD, etc. — it raises a
       clear :class:`ValueError` telling the caller to pass a ``<label>.com`` domain
       or supply a custom mapping for v1.1, rather than emitting a wrong challenge.

    Accepted (round-trips): ``openai.com``, ``api.openai.com`` (-> ``OPENAI``).
    Rejected (no round-trip): ``example.ai``, ``example.co.uk``,
    ``service.example.co.uk``.

    Raises:
        ValueError: if ``domain`` is empty, has no DNS labels, its leftmost
            registrable label cannot satisfy the ``[A-Z0-9]{2,8}`` assigner grammar,
            or the derived LABEL does not round-trip to the host's registrable domain
            under the default ``<label>.com`` mapper.
    """
    from acef.domain_control import assigner_to_registrable_domain

    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("mint_incident_id: domain must be a non-empty string (e.g. 'openai.com')")
    host = domain.strip().lower().rstrip(".")
    # Strip a scheme if a full URL was passed.
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    labels = [label for label in host.split(".") if label]
    if not labels:
        raise ValueError(f"mint_incident_id: domain {domain!r} has no DNS labels")
    # The registrable label is the leftmost label of the registrable domain. For
    # the .com-default round-trip we take the label immediately left of the eTLD
    # when a multi-label host is given (api.openai.com -> openai), else the sole
    # label (openai.com -> openai; bare 'openai' -> openai). The registrable DOMAIN
    # is the host's last two labels (eTLD+1) for a multi-label host, else the host.
    if len(labels) >= 2:
        registrable_label = labels[-2]
        registrable_domain = ".".join(labels[-2:])
    else:
        registrable_label = labels[0]
        registrable_domain = labels[0]
    label = registrable_label.upper()
    if not _ASSIGNER_LABEL_PATTERN.match(label):
        raise ValueError(
            f"mint_incident_id: cannot derive an assigner LABEL from domain {domain!r} — the "
            f"registrable label {registrable_label!r} -> {label!r} does not satisfy the §5.3 "
            f"assigner grammar [A-Z0-9]{{2,8}} (2-8 uppercase alphanumerics). Use a domain whose "
            f"leftmost registrable label is 2-8 alphanumeric characters."
        )
    # Honesty round-trip (roborev F2): the v1.1 default mapper is <label>.com with NO
    # PSL, so it only correctly handles .com registrable domains. If the derived LABEL
    # does not map back to the host's registrable domain, the challenge location would
    # be wrong (e.g. service.example.co.uk -> CO -> co.com). Refuse rather than emit it.
    if assigner_to_registrable_domain(label) != registrable_domain:
        raise ValueError(
            f"mint_incident_id: domain {domain!r} does not round-trip under the v1.1 default "
            f"assigner mapping — its registrable domain {registrable_domain!r} is not "
            f"'<label>.com' (derived LABEL {label!r} maps back to "
            f"{assigner_to_registrable_domain(label)!r}). The default mapper has no public-suffix "
            f"list, so a multi-label public suffix (e.g. 'co.uk') or non-'.com' eTLD (e.g. '.ai') "
            f"cannot be parsed without silently emitting a wrong challenge location. Pass a "
            f"'<label>.com' domain, or supply a custom domain mapping for v1.1."
        )
    return label


def _mint_suffix() -> str:
    """Return a >=26-char Crockford-base32 suffix carrying >=128 bits of CSPRNG
    entropy (RFC-0002 §5.3). Uses :mod:`secrets` (CSPRNG); never wall-clock or a
    weak RNG. 26 Crockford symbols * 5 bits = 130 bits >= the 128-bit floor."""
    # Draw enough random bytes to cover the symbol count, then map each 5-bit
    # group to a Crockford symbol. 26 symbols need 130 bits = ceil(130/8)=17 bytes.
    needed_bits = _SUFFIX_SYMBOLS * 5
    needed_bytes = (needed_bits + 7) // 8
    raw = secrets.token_bytes(needed_bytes)
    value = int.from_bytes(raw, "big")
    # Take the top needed_bits so we use exactly _SUFFIX_SYMBOLS * 5 bits.
    value >>= needed_bytes * 8 - needed_bits
    symbols: list[str] = []
    for _ in range(_SUFFIX_SYMBOLS):
        symbols.append(_CROCKFORD_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(symbols))


def mint_incident_id(
    domain: str,
    key: PrivateKeyTypes,
    *,
    year: int | None = None,
    now: datetime | None = None,
) -> MintedIncidentId:
    """Mint a self-asserted ``public_incident_id`` + its domain-control challenge
    token in ONE call (RFC-0002 §5.3, VAL-DX-002).

    Returns a :class:`MintedIncidentId` carrying the
    ``AIIC-{LABEL}-{year}-{suffix}`` id (``id_grade: self-asserted``, >=128-bit
    CSPRNG Crockford-base32 suffix), the card's public JWK derived from ``key``,
    and the DNS-01 / ``.well-known`` challenge token the registrant publishes to
    prove control at check time. The minted token round-trips through
    :func:`acef.domain_control.verify_domain_control` to ``verified`` when the
    registrant publishes it at the returned DNS name / ``.well-known`` URL.

    Args:
        domain: the registrant's domain (e.g. ``"openai.com"`` or
            ``"api.openai.com"``). The assigner LABEL is derived from the
            registrable domain's leftmost label, uppercased, so it ROUND-TRIPS
            through the default ``LABEL -> "<label>.com"`` mapper (the .com-default
            round-trip constraint — see :func:`_registrable_label_from_domain`).
        key: the card's PRIVATE signing key (RSA or EC P-256). The public JWK is
            derived from it via :func:`acef.signing._derive_jwk` (the established
            route the signing path and the verifier already use) and the challenge
            token is bound to its RFC-7638 thumbprint.
        year: the 4-digit year embedded in the id. NO wall-clock default is baked
            into the hash domain — when omitted it is derived from ``now`` (or, as a
            last resort, the current UTC year); tests pass an explicit ``year`` for
            determinism.
        now: an injectable clock used ONLY to derive ``year`` when ``year`` is
            omitted; never read otherwise. Defaults to ``datetime.now(UTC)`` when
            both ``year`` and ``now`` are omitted.

    Returns:
        A :class:`MintedIncidentId`.

    Raises:
        ValueError: if ``domain``'s registrable label cannot satisfy the §5.3
            assigner grammar ``[A-Z0-9]{2,8}``.
    """
    # Lazy import to avoid any import cost / cycle at package module load.
    from acef.domain_control import (
        DNS_CHALLENGE_LABEL,
        WELL_KNOWN_PATH,
        assigner_to_registrable_domain,
        challenge_token_for,
    )
    from acef.signing import _derive_jwk

    label = _registrable_label_from_domain(domain)

    if year is None:
        clock_now = now if now is not None else datetime.now(UTC)
        year = clock_now.year
    if not (1000 <= int(year) <= 9999):
        raise ValueError(f"mint_incident_id: year must be a 4-digit year, got {year!r}")

    suffix = _mint_suffix()
    public_incident_id = f"AIIC-{label}-{int(year):04d}-{suffix}"

    jwk = _derive_jwk(key)
    challenge_token = challenge_token_for(label, jwk)

    registrable_domain = assigner_to_registrable_domain(label)
    dns_record_name = f"{DNS_CHALLENGE_LABEL}{registrable_domain}"
    well_known_url = f"https://{registrable_domain}{WELL_KNOWN_PATH}"

    return MintedIncidentId(
        public_incident_id=public_incident_id,
        assigner=label,
        year=int(year),
        jwk=jwk,
        challenge_token=challenge_token,
        dns_record_name=dns_record_name,
        well_known_url=well_known_url,
        id_grade="self-asserted",
    )


class Package:
    """ACEF Evidence Package builder.

    Usage:
        pkg = Package(producer={"name": "my-tool", "version": "1.0"})
        system = pkg.add_subject(subject_type="ai_system", name="My System")
        pkg.record("risk_register", provisions=["article-9"], payload={...})
        pkg.export("output.acef/")
    """

    def __init__(
        self,
        producer: dict[str, str] | ProducerInfo | None = None,
        *,
        retention_policy: dict[str, Any] | RetentionPolicy | None = None,
        prior_package_ref: str | None = None,
        clock: Callable[[], datetime] | None = None,
        urn_generator: Callable[[URNType], str] | None = None,
        redaction_policy: Any = None,
    ) -> None:
        """Build an empty Package.

        Args:
            producer: Tool/organization metadata.
            retention_policy: Package-level retention requirements.
            prior_package_ref: URN of a prior version of this package.
            clock: Optional callable returning the current
                :class:`datetime` (timezone-aware). When provided, replaces
                the default ``datetime.now(timezone.utc)`` for all
                timestamps minted by this builder (record envelopes,
                audit-trail entries, package metadata). Enables byte-
                deterministic export per VAL-SDK-007.
            urn_generator: Optional callable taking a
                :class:`acef.models.urns.URNType` and returning a URN
                string. When provided, replaces the default
                :func:`acef.models.urns.generate_urn` for all URN minting
                by this builder (``package_id``, ``record_id``, and the
                payload identifiers minted by the v1.1 typed builders).
                Enables byte-deterministic export per VAL-SDK-007.
            redaction_policy: Optional
                :class:`acef.redaction.RedactionPolicy` attached to this
                package. When attached, :meth:`record` auto-populates the
                X1 envelope field (``redaction_policy_version``) and the
                X2 field (``redaction_attestation_ref``) for any record
                whose ``confidentiality`` is not ``public``, also
                appending a Core ``event_log`` attestation record (per
                VAL-REDACTION-003 / 004 — no vendor namespace introduced).
                Typed as ``Any`` here to avoid an import cycle with
                ``acef.redaction``; the runtime check at use-time
                enforces the actual class.
        """
        # Stash injection callables BEFORE building metadata so the
        # metadata's timestamp / package_id come from the injected
        # implementations rather than the model's default factories.
        self._clock: Callable[[], datetime] = clock or _default_clock
        self._urn_generator: Callable[[URNType], str] = urn_generator or generate_urn

        if producer is None:
            producer = ProducerInfo(name="acef-sdk", version="0.1.0")
        elif isinstance(producer, dict):
            producer = ProducerInfo(**producer)

        retention = None
        if retention_policy is not None:
            if isinstance(retention_policy, dict):
                retention = RetentionPolicy(**retention_policy)
            else:
                retention = retention_policy

        self._metadata = PackageMetadata(
            package_id=self._urn_generator(URNType.PACKAGE),
            timestamp=_format_timestamp(self._clock()),
            producer=producer,
            prior_package_ref=prior_package_ref,
            retention_policy=retention,
        )
        self._versioning = Versioning()
        self._subjects: list[Subject] = []
        self._entities = EntitiesBlock()
        self._profiles: list[ProfileEntry] = []
        self._records: list[RecordEnvelope] = []
        self._audit_trail: list[AuditTrailEntry] = []
        self._attachments: dict[str, bytes] = {}  # path -> content
        # Open-core v1.1 manifest fields (X5 analysis_mode, X6 namespaces)
        # and any top-level manifest extras (vendor x-*). A freshly-built
        # Package leaves these unset (None/empty); the loader populates them
        # from an inbound manifest so build_manifest() re-emits them on
        # export, preserving the §6.4/§6.5 lossless round-trip MUST.
        self._analysis_mode: str | None = None
        self._namespaces: dict[str, dict[str, Any]] | None = None
        self._manifest_extras: dict[str, Any] = {}
        self._signed = False
        self._signature_key: str | None = None
        self._signature_method: str | None = None
        # Stash any attached RedactionPolicy so Package.record() can
        # auto-populate the X1/X2 envelope fields (VAL-REDACTION-003).
        # Typed as ``Any`` to avoid an import cycle with acef.redaction.
        self._redaction_policy: Any = redaction_policy

        # Add creation audit entry
        self._audit_trail.append(
            AuditTrailEntry(
                event_type=AuditEventType.CREATED,
                timestamp=self._metadata.timestamp,
                description="Initial package creation",
            )
        )

    # ------------------------------------------------------------------
    # Injection helpers (private)
    # ------------------------------------------------------------------

    def _now_iso(self) -> str:
        """Return ``self._clock()`` formatted per spec §3.1."""
        return _format_timestamp(self._clock())

    def _mint_record_urn(self) -> str:
        """Mint a record URN via the injected URN generator."""
        return self._urn_generator(URNType.RECORD)

    @property
    def metadata(self) -> PackageMetadata:
        return self._metadata

    @property
    def versioning(self) -> Versioning:
        """Public read-only access to versioning info."""
        return self._versioning

    @property
    def subjects(self) -> list[Subject]:
        return list(self._subjects)

    @property
    def entities(self) -> EntitiesBlock:
        return self._entities

    @property
    def records(self) -> list[RecordEnvelope]:
        return list(self._records)

    @property
    def profiles(self) -> list[ProfileEntry]:
        return list(self._profiles)

    @property
    def audit_trail(self) -> list[AuditTrailEntry]:
        """Public read-only access to audit trail entries."""
        return list(self._audit_trail)

    @property
    def attachments(self) -> dict[str, bytes]:
        """Public read-only access to attachment content."""
        return dict(self._attachments)

    @property
    def is_signed(self) -> bool:
        """Whether this package is marked for signing during export."""
        return self._signed

    @property
    def signing_key(self) -> str | None:
        """Path to the signing key, if signing is enabled."""
        return self._signature_key

    def add_subject(
        self,
        subject_type: str | SubjectType,
        name: str,
        *,
        version: str = "1.0.0",
        provider: str = "",
        risk_classification: str | RiskClassification = RiskClassification.MINIMAL_RISK,
        modalities: list[str] | None = None,
        lifecycle_phase: str | LifecyclePhase = LifecyclePhase.DEVELOPMENT,
        lifecycle_timeline: list[dict[str, str]] | None = None,
    ) -> Subject:
        """Add a subject (AI system or model) to the package.

        Returns:
            The created Subject with generated URN.
        """
        if isinstance(subject_type, str):
            subject_type = SubjectType(subject_type)
        if isinstance(risk_classification, str):
            risk_classification = RiskClassification(risk_classification)
        if isinstance(lifecycle_phase, str):
            lifecycle_phase = LifecyclePhase(lifecycle_phase)

        timeline = []
        if lifecycle_timeline:
            timeline = [LifecycleEntry.model_validate(entry) for entry in lifecycle_timeline]

        subject = Subject(
            subject_id=self._urn_generator(URNType.SUBJECT),
            subject_type=subject_type,
            name=name,
            version=version,
            provider=provider,
            risk_classification=risk_classification,
            modalities=modalities or [],
            lifecycle_phase=lifecycle_phase,
            lifecycle_timeline=timeline,
        )
        self._subjects.append(subject)
        return subject

    def add_component(
        self,
        name: str,
        type: str | ComponentType,
        *,
        version: str = "1.0.0",
        subject_refs: list[str] | None = None,
        provider: str = "",
    ) -> Component:
        """Add a component entity to the package.

        Returns:
            The created Component with generated URN.
        """
        if isinstance(type, str):
            type = ComponentType(type)

        component = Component(
            component_id=self._urn_generator(URNType.COMPONENT),
            name=name,
            type=type,
            version=version,
            subject_refs=subject_refs or [],
            provider=provider,
        )
        self._entities.components.append(component)
        return component

    def add_dataset(
        self,
        name: str,
        *,
        version: str = "1.0.0",
        source_type: str | DatasetSourceType = DatasetSourceType.LICENSED,
        modality: str | DatasetModality = DatasetModality.TEXT,
        size: dict[str, Any] | None = None,
        subject_refs: list[str] | None = None,
    ) -> Dataset:
        """Add a dataset entity to the package.

        Returns:
            The created Dataset with generated URN.
        """
        if isinstance(source_type, str):
            source_type = DatasetSourceType(source_type)
        if isinstance(modality, str):
            modality = DatasetModality(modality)

        dataset = Dataset(
            dataset_id=self._urn_generator(URNType.DATASET),
            name=name,
            version=version,
            source_type=source_type,
            modality=modality,
            size=size or {"records": 0, "size_gb": 0.0},
            subject_refs=subject_refs or [],
        )
        self._entities.datasets.append(dataset)
        return dataset

    def add_actor(
        self,
        name: str = "",
        *,
        role: str | ActorRole = ActorRole.PROVIDER,
        organization: str = "",
    ) -> Actor:
        """Add an actor entity to the package.

        Returns:
            The created Actor with generated URN.
        """
        if isinstance(role, str):
            role = ActorRole(role)

        actor = Actor(
            actor_id=self._urn_generator(URNType.ACTOR),
            name=name,
            role=role,
            organization=organization,
        )
        self._entities.actors.append(actor)
        return actor

    def add_relationship(
        self,
        source_ref: str,
        target_ref: str,
        relationship_type: str | RelationshipType,
        *,
        description: str = "",
    ) -> Relationship:
        """Add a relationship between entities.

        Returns:
            The created Relationship.
        """
        if isinstance(relationship_type, str):
            relationship_type = RelationshipType(relationship_type)

        rel = Relationship(
            source_ref=source_ref,
            target_ref=target_ref,
            relationship_type=relationship_type,
            description=description,
        )
        self._entities.relationships.append(rel)
        return rel

    def add_profile(
        self,
        profile_id: str,
        *,
        provisions: list[str] | tuple[str, ...],
        template_version: str = "1.0.0",
    ) -> ProfileEntry:
        """Declare a regulation profile for this package.

        Args:
            profile_id: The profile identifier (e.g. ``"eu-ai-act-2024"``).
            provisions: A ``list`` or ``tuple`` of the applicable provision ids
                this profile covers — both are concrete, ordered sequences and
                are accepted; element order is preserved verbatim into
                ``applicable_provisions`` (a tuple is normalized to a list).
                MUST be non-empty: the frozen manifest schema pins
                ``profiles[].applicable_provisions`` to ``minItems: 1``, so a
                profile with no provisions produces a manifest the spec's
                §3.1.3 step-(a) schema gate rejects (ACEF-002). The builder
                refuses up front rather than letting export-time validation
                surface a structurally-invalid bundle (audit envelope-manifest-3).
            template_version: The mapping-template version this declaration
                pins to.

        Returns:
            The created ProfileEntry.

        Raises:
            ACEFSchemaError: If ``provisions`` is not a concrete, ordered
                ``list``/``tuple`` of provision strings (ACEF-002). The type is
                checked up front, BEFORE any iteration, so only a ``list`` or
                ``tuple`` is accepted. Every other shape is rejected, including:
                a bare ``str``/``bytes`` (``list("article-9")`` would shred it
                into ``["a", "r", ...]``); a ``dict`` (iterating yields KEYS,
                silently authoring a profile from keys); a ``set`` (unordered —
                accepting it would make ``applicable_provisions`` order
                non-deterministic, breaking byte-stable bundle output); and a
                generator/other lazy iterable (an EMPTY generator is truthy, so
                it would bypass the emptiness gate and author an invalid empty
                profile; it is also single-use). A single provision MUST be
                passed as a list (``["article-9"]``). An empty sequence, a
                non-string element, or an empty-string element is likewise
                rejected (audit envelope-manifest-3, roborev
                builder-input-validation).
        """
        # Type gate BEFORE any iteration: accept ONLY a concrete, ordered
        # sequence (list/tuple). str/bytes/dict/set/generator/other iterables
        # and non-iterables are all rejected here — iterating them would shred,
        # reorder non-deterministically, or (empty generator) bypass the
        # emptiness check below and author a schema-invalid empty profile.
        if not isinstance(provisions, (list, tuple)):
            raise ACEFSchemaError(
                f"Profile {profile_id!r} provisions must be a list or tuple of "
                f"provision strings, not a {type(provisions).__name__}: a single "
                'provision must be passed as a list (e.g. ["article-9"]). A '
                "str/bytes would be shredded into characters, a dict would be "
                "iterated as keys, a set would have non-deterministic order, and "
                "a generator/other iterable is not a concrete ordered sequence.",
                code="ACEF-002",
            )
        if not provisions:
            raise ACEFSchemaError(
                f"Profile {profile_id!r} must declare at least one applicable "
                "provision: the manifest schema requires "
                "profiles[].applicable_provisions to be non-empty (minItems:1).",
                code="ACEF-002",
            )
        normalized: list[str] = []
        for provision in provisions:
            if not isinstance(provision, str) or not provision:
                raise ACEFSchemaError(
                    f"Profile {profile_id!r} provision {provision!r} must be a "
                    "non-empty string: the manifest schema pins "
                    "profiles[].applicable_provisions items to non-empty strings.",
                    code="ACEF-002",
                )
            normalized.append(provision)
        entry = ProfileEntry(
            profile_id=profile_id,
            template_version=template_version,
            applicable_provisions=normalized,
        )
        self._profiles.append(entry)
        return entry

    def set_analysis_mode(self, mode: str) -> None:
        """Declare the v1.1 ``analysis_mode`` (X5) manifest field.

        ``analysis_mode`` is an open-core v1.1 manifest-level field that gates
        which conditional-required envelope fields and mode-gated record-type
        rules the validator applies (spec §8.1). The standard Package builder
        previously had no path to author it — the model + schema supported the
        field, but ``build_manifest`` never carried a builder-set value (audit
        envelope-manifest-6). This setter closes that gap.

        Declaring a v1.1-only manifest field bumps ``core_version`` to ``1.1.0``
        so the validator resolves the v1.1 schema set (the field is rejected by
        the v1.0 schema), matching the typed incident builders' version gate.

        Args:
            mode: One of ``subscriber``, ``public_artifact``, ``canary``,
                ``unattributed_artifact``.

        Raises:
            ACEFSchemaError: If ``mode`` is not a recognized analysis_mode
                (ACEF-002).
        """
        if mode not in _ANALYSIS_MODES:
            allowed = ", ".join(sorted(_ANALYSIS_MODES))
            raise ACEFSchemaError(
                f"Unknown analysis_mode {mode!r}: must be one of {allowed}.",
                code="ACEF-002",
            )
        self._analysis_mode = mode
        self._ensure_v1_1()

    def add_namespace(self, key: str, value: dict[str, Any]) -> None:
        """Register a v1.1 vendor-extension ``namespaces`` (X6) entry.

        ``namespaces`` is the open-core v1.1 vendor-extension container (spec
        §6.4). Each top-level key MUST be x-vendor-prefixed, matching the FROZEN
        v1.1 manifest schema pattern ``^x-[a-z0-9-]+/?$`` — the builder rejects
        a non-conformant key up front so it cannot author a manifest the schema
        rejects (the same guard discipline as ``add_profile``; audit
        envelope-manifest-6). The standard builder previously had no path to
        author this field (the loader could only round-trip it on the load
        path); this setter lets the builder ORIGINATE it.

        Declaring a v1.1-only manifest field bumps ``core_version`` to ``1.1.0``
        so the v1.1 schema set resolves.

        Args:
            key: The x-vendor-prefixed namespace key (e.g. ``x-vendor`` or
                ``x-vendor-ns``).
            value: The namespace's arbitrary object payload.

        Raises:
            ACEFSchemaError: If ``key`` does not match the frozen schema's
                x-vendor pattern, or if ``value`` is not an object/dict
                (ACEF-002). The v1.1 manifest schema pins each namespace
                value to ``"type": "object"`` — a non-dict value is rejected
                here, at the setter, so the builder cannot store invalid
                package state that would otherwise surface only as a raw
                Pydantic error at ``build_manifest``/export time (roborev
                builder-input-validation).
        """
        if not _NAMESPACE_KEY_PATTERN.match(key):
            raise ACEFSchemaError(
                f"Invalid namespace key {key!r}: top-level namespace keys MUST "
                "be x-vendor-prefixed, matching the manifest schema pattern "
                f"'{_NAMESPACE_KEY_PATTERN.pattern}'.",
                code="ACEF-002",
            )
        if not isinstance(value, dict):
            raise ACEFSchemaError(
                f"Invalid namespace value for {key!r}: namespace values MUST be "
                f"an object/dict, not {type(value).__name__}. The v1.1 manifest "
                "schema pins each namespaces value to 'type: object'.",
                code="ACEF-002",
            )
        if self._namespaces is None:
            self._namespaces = {}
        self._namespaces[key] = value
        self._ensure_v1_1()

    def record(
        self,
        record_type: str,
        *,
        provisions: list[str] | None = None,
        payload: dict[str, Any] | None = None,
        obligation_role: str | ObligationRole | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        redaction_method: str | None = None,
        access_policy: dict[str, Any] | None = None,
        trust_level: str | TrustLevel = TrustLevel.SELF_ATTESTED,
        lifecycle_phase: str | LifecyclePhase | None = None,
        collector: dict[str, str] | CollectorInfo | None = None,
        attachments: list[dict[str, Any] | AttachmentRef] | None = None,
        attestation: dict[str, Any] | Attestation | None = None,
        retention: dict[str, Any] | RecordRetention | None = None,
        timestamp: str | None = None,
        record_id: str | None = None,
        redaction_policy_version: str | None = None,
        redaction_attestation_ref: str | None = None,
    ) -> RecordEnvelope:
        """Record an evidence record.

        Args:
            record_type: One of the 16 ACEF v1 record types.
            provisions: Regulatory provisions this evidence supports.
            payload: The type-specific evidence payload. For v1.1 packages
                with confidentiality ``redacted`` / ``hash-committed`` on
                the auto-attestation path, the STORED payload is the
                redacted hash-commitment produced by
                :func:`acef.redaction.apply_redaction` — the source
                cleartext is never persisted (VAL-FIX-REDACT-001). Callers
                who pass ``redaction_attestation_ref`` explicitly own
                their own pre-redaction and their payload is stored
                verbatim.
            obligation_role: Who produced this evidence.
            entity_refs: Links to subjects, components, datasets, actors.
            confidentiality: Evidence confidentiality level. ``redacted``
                and ``hash-committed`` are redaction transforms (payload
                replaced, see ``payload`` above); ``regulator-only`` and
                ``under-nda`` are access-class restrictions (payload
                retained for the privileged consumer).
            trust_level: Evidence trust provenance.
            lifecycle_phase: Which lifecycle phase this relates to.
            collector: Tool/person that collected this evidence.
            attachments: File references in artifacts/.
            attestation: Cryptographic attestation.
            retention: Per-record retention requirements.
            timestamp: Override timestamp (ISO 8601). When ``None``, the
                envelope timestamp is minted by the package's injected
                ``clock`` (or the default wall clock if no injection).
            record_id: Override record_id URN. When ``None``, the
                envelope record_id is minted by the package's injected
                ``urn_generator`` (or the default ``generate_urn`` if no
                injection). Caller-supplied IDs win.

        Returns:
            The created RecordEnvelope.

        Raises:
            ACEFSchemaError: If record_type is not recognized.
            ACEFError: If timestamp is not valid ISO 8601.
        """
        # Validate record type - allow extension types with x- prefix
        if record_type not in RECORD_TYPES and not record_type.startswith("x-"):
            raise ACEFSchemaError(
                f"Unknown record_type: {record_type!r}",
                code="ACEF-003",
            )

        # ``coverage_cell`` is an Assessment-Bundle inventory concept with no
        # ``coverage_cell.schema.json`` — it is NOT a records/ record_type.
        # Reject it up front with an assessment-bundle hint (audit
        # records-payloads-3) rather than authoring a record the SDK's own
        # validator later rejects ACEF-003. This guard fires BEFORE any version
        # mutation below, so a rejected coverage_cell leaves package state
        # (including core_version) unchanged.
        if record_type in _ASSESSMENT_ONLY_RECORD_TYPES:
            raise ACEFSchemaError(
                f"record_type {record_type!r} is an Assessment-Bundle inventory "
                "concept, not an Evidence-Bundle records/ record_type: it has no "
                f"standalone {record_type}.schema.json (it is defined inline in "
                "assessment-bundle.schema.json#/properties/coverage_cells). "
                "Recording it would produce a record the validator rejects "
                "ACEF-003. Build coverage cells via the Assessment Bundle path "
                "instead.",
                code="ACEF-003",
            )

        # v1.1-only record types (incident_card + the agent-reliability
        # primitives) have schemas ONLY under acef-conventions/v1.1/. A default
        # Package declares core_version 1.0.0, whose validator allowlist
        # (list_record_type_schemas('v1')) excludes these types and would reject
        # the record ACEF-003 — the SDK producing a bundle its own validator
        # rejects (audit records-payloads-2). Bump to 1.1.0 here so the v1.1
        # schema set resolves, exactly as the typed incident/agent-reliability
        # builders do via _ensure_v1_1().
        if record_type in _v1_1_only_record_types():
            self._ensure_v1_1()

        # Resolve the schema-required envelope fields when callers omit
        # them, so SDK-produced records carry concrete values rather than
        # relying on to_jsonl_dict's emit-time defaults (which exist as a
        # safety net for direct RecordEnvelope construction).
        #
        # For the role-split record types the caller MUST choose the role
        # explicitly: providers vs deployers carry distinct EU AI Act Art.
        # 16/26/50 (and CAC) obligations, so silently defaulting to
        # ``provider`` would mislabel deployer-side evidence (spec §3.1 line
        # 419 / audit envelope-manifest-5). Every other record type keeps the
        # convenience ``provider`` default.
        if obligation_role is None:
            if record_type in _ROLE_SPLIT_RECORD_TYPES:
                raise ACEFSchemaError(
                    f"record_type {record_type!r} requires an explicit "
                    "obligation_role: providers and deployers carry distinct "
                    "EU AI Act / CAC split obligations (spec §3.1), so the SDK "
                    "will not default to 'provider'. Pass "
                    "obligation_role='provider' or 'deployer' (or another "
                    "ObligationRole).",
                    code="ACEF-002",
                )
            obligation_role = ObligationRole.PROVIDER
        elif isinstance(obligation_role, str):
            obligation_role = ObligationRole(obligation_role)
        if isinstance(confidentiality, str):
            confidentiality = Confidentiality(confidentiality)
        if isinstance(trust_level, str):
            trust_level = TrustLevel(trust_level)
        if lifecycle_phase is None:
            lifecycle_phase = LifecyclePhase.DEVELOPMENT
        elif isinstance(lifecycle_phase, str):
            lifecycle_phase = LifecyclePhase(lifecycle_phase)

        if isinstance(entity_refs, dict):
            entity_refs = EntityRefs(**entity_refs)
        elif entity_refs is None:
            entity_refs = EntityRefs()

        if collector is None:
            # Default collector to the package's producer info if available.
            producer_name = self.metadata.producer.name if self.metadata and self.metadata.producer else "unknown"
            producer_version = self.metadata.producer.version if self.metadata and self.metadata.producer else ""
            collector = CollectorInfo(name=producer_name, version=producer_version)
        elif isinstance(collector, dict):
            collector = CollectorInfo(**collector)

        parsed_attachments: list[AttachmentRef] = []
        if attachments:
            for att in attachments:
                if isinstance(att, dict):
                    parsed_attachments.append(AttachmentRef(**att))
                else:
                    parsed_attachments.append(att)

        if isinstance(attestation, dict):
            attestation = Attestation(**attestation)
        if isinstance(retention, dict):
            retention = RecordRetention(**retention)

        # Resolve record_id + timestamp BEFORE RecordEnvelope construction
        # so the injected clock/URN generator are honored instead of the
        # model's default factories (which would otherwise mint random
        # uuid4-based URNs + wall-clock timestamps).
        if timestamp is not None:
            try:
                datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except (ValueError, AttributeError) as e:
                raise ACEFError(
                    f"Invalid ISO 8601 timestamp: {timestamp!r}",
                    code="ACEF-050",
                ) from e
            resolved_timestamp = timestamp
        else:
            resolved_timestamp = self._now_iso()

        resolved_record_id = record_id if record_id is not None else self._mint_record_urn()

        # The payload that will actually be stored in the envelope. For
        # redaction-transform confidentiality levels (redacted /
        # hash-committed) on the auto-attestation path below, this is
        # REPLACED with the redacted commitment payload (VAL-FIX-REDACT-001).
        resolved_payload: dict[str, Any] = payload or {}

        # ------------------------------------------------------------------
        # VAL-REDACTION-003 — auto-populate X1/X2 on non-public records.
        #
        # When the caller flags this record as non-public (anything other
        # than Confidentiality.PUBLIC), the v1.1 validator's
        # cross_record.enforce_redaction_policy_version /
        # enforce_redaction_attestation_ref will demand the X1
        # (redaction_policy_version) and X2 (redaction_attestation_ref)
        # envelope fields. We auto-populate them here so SDK callers do
        # not have to remember the wiring:
        #
        #   1. X1 resolves from an explicit kwarg OR the package's
        #      attached RedactionPolicy.version. If neither is available
        #      we raise ValueError immediately — the SDK refuses to mint
        #      a record the validator will then reject.
        #
        #   2. X2 resolves from an explicit kwarg OR from a freshly-
        #      generated event_log attestation record (via
        #      acef.redaction.apply_redaction). The attestation record
        #      reuses the Core event_log record_type — no vendor
        #      namespace is introduced (VAL-REDACTION-004).
        #
        #   3. VAL-FIX-REDACT-001 (audit finding redaction-1): when the
        #      confidentiality level is a redaction TRANSFORM (redacted /
        #      hash-committed) and the SDK mints the attestation itself,
        #      the STORED payload is the redacted commitment returned by
        #      apply_redaction — never the source cleartext — so the
        #      stored bytes hash to the attestation's
        #      redacted_payload_hash. Access-CLASS levels (regulator-only
        #      / under-nda) retain the full payload: they are distribution
        #      restrictions, not content transforms (the RFC-0002 incident
        #      machinery reads incident_report.card_source from
        #      regulator-only records). Callers who supply X2 explicitly
        #      own their own pre-redaction: the payload is stored verbatim
        #      in that flow.
        # ------------------------------------------------------------------
        resolved_policy_version: str | None = redaction_policy_version
        resolved_attestation_ref: str | None = redaction_attestation_ref
        # The auto-minted event_log attestation (if any) is HELD here and
        # only appended together with the primary record once the
        # RecordEnvelope construction below succeeds — a failing
        # construction must leave the package unmutated (no orphan
        # attestation; roborev finding on bba166b4).
        pending_attestation: RecordEnvelope | None = None

        is_non_public = confidentiality != Confidentiality.PUBLIC

        # Version-gating: X1/X2 are v1.1 additions (spec §8.1
        # conditional-required keyed on manifest.versioning.core_version).
        # v1.0 bundles have no schema for these fields and the v1.1
        # cross-record validator does not run against them — auto-
        # populating would emit fields v1.0 readers must ignore. Skip the
        # entire block unless the package declares v1.1+. Caller-supplied
        # X1/X2 kwargs still flow through to RecordEnvelope below; the
        # gate only suppresses *auto*-population.
        #
        # The gate parses ``(major, minor)`` numerically via
        # :func:`parse_core_version_minor` (audit redaction-5) rather than a
        # lexicographic ``core_v >= "1.1"`` comparison, which is not
        # semver-correct (e.g. it would treat ``"1.1abc"`` as v1.1). X1/X2 are
        # v1.1 (major-1) additions, so a bundle is v1.1+ ONLY when it declares
        # ``major == 1`` AND a numeric ``minor >= 1``. A malformed minor
        # (``(1, None)`` for "1.1abc"), an unsupported major (``(2, None)`` for
        # "2.x", or ``(2, 0)`` for "2.0"), or a fully-unparseable version
        # (``None``) is NOT v1.1+ — suppress auto-population. (Comparing
        # ``parsed_core >= (1, 1)`` directly is wrong on both counts: it raises
        # ``TypeError`` on a ``None`` minor AND a non-1 major like ``(2, None)``
        # would short-circuit as "True" and wrongly auto-populate X1/X2 on an
        # unsupported-major bundle; roborev finding 1.)
        try:
            parsed_core = parse_core_version_minor(self._versioning.core_version)
        except AttributeError:
            parsed_core = None
        v1_1_or_later = (
            parsed_core is not None and parsed_core[0] == 1 and parsed_core[1] is not None and parsed_core[1] >= 1
        )

        if is_non_public and v1_1_or_later:
            policy = self._redaction_policy
            # ---- X1: redaction_policy_version ----
            if resolved_policy_version is None:
                if policy is None:
                    raise ValueError(
                        "Package.record(confidentiality="
                        f"{confidentiality.value!r}) requires "
                        "redaction_policy_version. Either pass it "
                        "explicitly as a kwarg, or attach a "
                        "RedactionPolicy to the Package via "
                        "Package(redaction_policy=...) — non-public "
                        "records without X1 fail validator ACEF-074."
                    )
                policy_version_attr = getattr(policy, "version", None)
                if not isinstance(policy_version_attr, str) or not policy_version_attr:
                    raise ValueError(
                        "Package.record: attached redaction_policy does "
                        "not expose a non-empty .version string; cannot "
                        "auto-populate redaction_policy_version."
                    )
                resolved_policy_version = policy_version_attr

            # ---- X2: redaction_attestation_ref ----
            if resolved_attestation_ref is None:
                if policy is None:
                    # We already raised above when policy is None and
                    # resolved_policy_version was None. But if the caller
                    # supplied X1 explicitly we still need a way to
                    # produce X2 — without a policy we cannot mint the
                    # event_log attestation. Caller must supply X2 too.
                    raise ValueError(
                        "Package.record(confidentiality="
                        f"{confidentiality.value!r}) requires "
                        "redaction_attestation_ref. Either pass it "
                        "explicitly as a kwarg, or attach a "
                        "RedactionPolicy to the Package via "
                        "Package(redaction_policy=...) so the SDK can "
                        "mint a Core event_log attestation record."
                    )
                # Lazy import — acef.redaction imports Package, so we
                # must not import at module load time.
                from acef.redaction import apply_redaction

                redacted_payload, attestation_record = apply_redaction(
                    resolved_payload,
                    policy,
                    clock=self._clock,
                    urn_generator=self._urn_generator,
                )
                # Held locally; appended only AFTER the primary envelope
                # constructs successfully (atomic append below). Appending
                # here left an ORPHAN attestation in self._records whenever
                # RecordEnvelope construction raised (roborev partial-
                # mutation finding on bba166b4).
                pending_attestation = attestation_record
                resolved_attestation_ref = attestation_record.record_id

                if confidentiality in (
                    Confidentiality.REDACTED,
                    Confidentiality.HASH_COMMITTED,
                ):
                    # VAL-FIX-REDACT-001/-004 (audit finding redaction-1):
                    # store the redacted commitment, never the cleartext.
                    # The attestation's redacted_payload_hash describes
                    # exactly these bytes; its original_payload_hash
                    # commits to the (unstored) source payload.
                    resolved_payload = redacted_payload
                    if redaction_method is None:
                        original_hash = attestation_record.payload["original_payload_hash"]
                        redaction_method = f"{policy.method}:{original_hash}"

        envelope = RecordEnvelope(
            record_id=resolved_record_id,
            record_type=record_type,
            provisions_addressed=provisions or [],
            payload=resolved_payload,
            obligation_role=obligation_role,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            redaction_method=redaction_method,
            access_policy=access_policy,
            trust_level=trust_level,
            lifecycle_phase=lifecycle_phase,
            collector=collector,
            attachments=parsed_attachments,
            attestation=attestation,
            retention=retention,
            timestamp=resolved_timestamp,
            redaction_policy_version=resolved_policy_version,
            redaction_attestation_ref=resolved_attestation_ref,
        )

        # Atomic append: nothing is added to the package unless the primary
        # envelope constructed successfully. The attestation precedes the
        # primary record, preserving the pre-existing success-path ordering
        # (and therefore export/audit semantics).
        if pending_attestation is not None:
            self._records.append(pending_attestation)
        self._records.append(envelope)
        return envelope

    # ------------------------------------------------------------------
    # v1.1 typed builders (F-M1-SDK-BUILDERS)
    #
    # These five methods wrap :meth:`record` with Pydantic-validated
    # payloads and SDK-side pre-flight checks for the brief §3 cross-
    # field rules. Each method:
    #   1. Runs the brief-specified cross-field rule check (which Pydantic
    #      cannot express) — raises ValueError BEFORE any state mutation.
    #   2. Runs the relevant Pydantic payload model — raises ValueError
    #      (via :class:`pydantic.ValidationError`, which subclasses
    #      :class:`ValueError`) for shape/enum violations.
    #   3. Delegates to :meth:`record` with ``record_type`` set, the
    #      validated payload, and any envelope-level kwargs forwarded.
    # ------------------------------------------------------------------

    def authorize_test_scope(
        self,
        *,
        scope_id: str,
        scope_version: str,
        subject_ref: str,
        authorized_surfaces: list[dict[str, Any]],
        authorized_identities: list[dict[str, Any]],
        side_effect_policy: dict[str, Any],
        sandbox_boundary: dict[str, Any],
        ownership_proof: dict[str, Any],
        effective_from: str,
        authorizing_actor_ref: str,
        effective_until: str | None = None,
        kill_switch_ref: str | None = None,
        provisions: list[str] | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        obligation_role: str | ObligationRole | None = None,
        timestamp: str | None = None,
    ) -> RecordEnvelope:
        """Add an ``authorized_test_scope`` record (brief §3.1).

        Enforces the brief §3.1 cross-field rules BEFORE the record is
        appended to the bundle:

        - If any ``authorized_surfaces[*].authorization_level`` is
          ``production_capable_owner_authorized``, then
          ``ownership_proof.proof_method`` MUST be one of
          ``dns_txt``, ``well_known_file``, or ``sso_assertion`` (the
          three methods that prove genuine ownership; ``github_oauth``
          and ``http_header`` prove account control but not system
          ownership) — TC-FRD-001-N1.
        - If any surface is production-capable, ``kill_switch_ref``
          MUST be a non-empty string — TC-FRD-001-N2.

        Raises:
            ValueError: If either cross-field rule fails, or if the
                payload fails Pydantic validation. The record is NOT
                appended to ``self._records`` in either case.
        """
        # ---- Cross-field rules (brief §3.1) — run BEFORE Pydantic ----
        has_production_capable = any(
            isinstance(s, dict) and s.get("authorization_level") == "production_capable_owner_authorized"
            for s in authorized_surfaces
        )
        if has_production_capable:
            method = ownership_proof.get("proof_method") if isinstance(ownership_proof, dict) else None
            if method not in _OWNERSHIP_PROVING_METHODS:
                raise ValueError(
                    "authorized_test_scope rejected: "
                    "authorization_level='production_capable_owner_authorized' "
                    f"requires ownership_proof.proof_method in {sorted(_OWNERSHIP_PROVING_METHODS)!r}; "
                    f"got {method!r} (brief §3.1 TC-FRD-001-N1)."
                )
            if not (isinstance(kill_switch_ref, str) and kill_switch_ref):
                raise ValueError(
                    "authorized_test_scope rejected: "
                    "authorization_level='production_capable_owner_authorized' "
                    "requires kill_switch_ref (non-empty URN) "
                    "(brief §3.1 TC-FRD-001-N2)."
                )

        # ---- Pydantic validation ----
        payload_dict: dict[str, Any] = {
            "scope_id": scope_id,
            "scope_version": scope_version,
            "subject_ref": subject_ref,
            "authorized_surfaces": authorized_surfaces,
            "authorized_identities": authorized_identities,
            "side_effect_policy": side_effect_policy,
            "sandbox_boundary": sandbox_boundary,
            "ownership_proof": ownership_proof,
            "effective_from": effective_from,
            "authorizing_actor_ref": authorizing_actor_ref,
        }
        if effective_until is not None:
            payload_dict["effective_until"] = effective_until
        if kill_switch_ref is not None:
            payload_dict["kill_switch_ref"] = kill_switch_ref

        try:
            validated = AuthorizedTestScopePayload.model_validate(payload_dict)
        except ValidationError as e:
            raise ValueError(f"authorized_test_scope payload failed validation: {e}") from e

        return self.record(
            record_type="authorized_test_scope",
            payload=validated.model_dump(mode="json", exclude_none=True),
            provisions=provisions,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            obligation_role=obligation_role,
            timestamp=timestamp,
        )

    def record_scope_boundary_event(
        self,
        *,
        scope_ref: str,
        attempted_action: dict[str, Any],
        authorized_scope_snapshot: dict[str, Any],
        classification: str,
        hard_stop_triggered: bool,
        detected_at: str,
        detector: dict[str, Any],
        event_id: str | None = None,
        hard_stop_attestation_ref: str | None = None,
        provisions: list[str] | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        obligation_role: str | ObligationRole | None = None,
        timestamp: str | None = None,
    ) -> RecordEnvelope:
        """Add a ``scope_boundary_event`` record (brief §3.2).

        Enforces the brief §3.2 conditional rule BEFORE the record is
        appended: when ``hard_stop_triggered=True``,
        ``hard_stop_attestation_ref`` MUST be a non-empty URN.

        Raises:
            ValueError: If the conditional rule fails, or if the payload
                fails Pydantic validation. The record is NOT appended.
        """
        # ---- Cross-field rule (brief §3.2) ----
        if hard_stop_triggered and not (isinstance(hard_stop_attestation_ref, str) and hard_stop_attestation_ref):
            raise ValueError(
                "scope_boundary_event rejected: hard_stop_triggered=True "
                "requires a non-empty hard_stop_attestation_ref URN "
                "(brief §3.2)."
            )

        if event_id is None:
            event_id = self._mint_record_urn()

        payload_dict: dict[str, Any] = {
            "event_id": event_id,
            "scope_ref": scope_ref,
            "attempted_action": attempted_action,
            "authorized_scope_snapshot": authorized_scope_snapshot,
            "classification": classification,
            "hard_stop_triggered": hard_stop_triggered,
            "detected_at": detected_at,
            "detector": detector,
        }
        if hard_stop_attestation_ref is not None:
            payload_dict["hard_stop_attestation_ref"] = hard_stop_attestation_ref

        try:
            validated = ScopeBoundaryEventPayload.model_validate(payload_dict)
        except ValidationError as e:
            raise ValueError(f"scope_boundary_event payload failed validation: {e}") from e

        return self.record(
            record_type="scope_boundary_event",
            payload=validated.model_dump(mode="json", exclude_none=True),
            provisions=provisions,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            obligation_role=obligation_role,
            timestamp=timestamp,
        )

    def record_finding(
        self,
        *,
        class_: str,
        subject_ref: str,
        expected_behavior: str,
        reproduction_steps_ref_content_hash: str,
        severity: dict[str, Any],
        reproduction: dict[str, Any],
        attribution: dict[str, Any],
        discovered_at: str,
        discovered_in_run_ref: str,
        finding_id: str | None = None,
        variant_group_id: str | None = None,
        regulation_impact: list[str] | None = None,
        disposition_history: list[str] | None = None,
        accepted_risk_ref: str | None = None,
        regression_ref: str | None = None,
        provisions: list[str] | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        obligation_role: str | ObligationRole | None = None,
        timestamp: str | None = None,
    ) -> RecordEnvelope:
        """Add a ``finding_record`` (brief §3.3) with auto-computed
        ``dedupe_key``.

        The dedupe_key recipe is normative per brief Q5 / design
        decision D5::

            dedupe_key = "sha256:" + hex(SHA-256(JCS-canonicalize({
                "class": class_,
                "subject_ref": subject_ref,
                "expected_behavior": expected_behavior,
                "reproduction_steps_ref_content_hash":
                    reproduction_steps_ref_content_hash,
            })))

        The computation uses :func:`acef.integrity.canonicalize` (RFC
        8785 JCS) and has no entropy source — two identical-input calls
        produce byte-equal ``dedupe_key``.

        Note: ``class_`` is the Python parameter name (``class`` is
        reserved). The Pydantic model field is ``finding_class``; the
        dedupe_key recipe per brief uses the JSON key ``class``.
        """
        # Compute dedupe_key BEFORE Pydantic validation — the payload
        # model requires the field to be present and matching the
        # ^sha256:[0-9a-f]{64}$ pattern.
        recipe = {
            "class": class_,
            "subject_ref": subject_ref,
            "expected_behavior": expected_behavior,
            "reproduction_steps_ref_content_hash": reproduction_steps_ref_content_hash,
        }
        canonical = canonicalize(recipe)
        dedupe_key = "sha256:" + hashlib.sha256(canonical).hexdigest()

        if finding_id is None:
            finding_id = self._mint_record_urn()

        payload_dict: dict[str, Any] = {
            "finding_id": finding_id,
            "finding_class": class_,
            "subject_ref": subject_ref,
            "severity": severity,
            "dedupe_key": dedupe_key,
            "reproduction": reproduction,
            "attribution": attribution,
            "discovered_at": discovered_at,
            "discovered_in_run_ref": discovered_in_run_ref,
        }
        if variant_group_id is not None:
            payload_dict["variant_group_id"] = variant_group_id
        if regulation_impact is not None:
            payload_dict["regulation_impact"] = regulation_impact
        if disposition_history is not None:
            payload_dict["disposition_history"] = disposition_history
        if accepted_risk_ref is not None:
            payload_dict["accepted_risk_ref"] = accepted_risk_ref
        if regression_ref is not None:
            payload_dict["regression_ref"] = regression_ref

        try:
            validated = FindingRecordPayload.model_validate(payload_dict)
        except ValidationError as e:
            raise ValueError(f"finding_record payload failed validation: {e}") from e

        return self.record(
            record_type="finding_record",
            payload=validated.model_dump(mode="json", exclude_none=True),
            provisions=provisions,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            obligation_role=obligation_role,
            timestamp=timestamp,
        )

    def record_delivery_verdict(
        self,
        *,
        finding_ref: str,
        destination: dict[str, Any],
        write_attempt: dict[str, Any],
        delivery_state: str,
        verdict_id: str | None = None,
        read_back: dict[str, Any] | None = None,
        harness_attestation_ref: str | None = None,
        drift_classification: str | None = None,
        retry_history: list[dict[str, Any]] | None = None,
        provisions: list[str] | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        obligation_role: str | ObligationRole | None = None,
        timestamp: str | None = None,
    ) -> RecordEnvelope:
        """Add a ``delivery_verdict`` record (brief §3.4).

        Enforces two cross-field rules BEFORE the record is appended:

        1. If ``read_back`` is provided, ``read_back.read_back_digest``
           MUST equal ``write_attempt.request_digest``. A mismatch
           raises immediately so the bundle never contains a
           self-inconsistent verdict.
        2. If ``delivery_state == "verified_delivered"``, ALL of the
           following MUST hold per brief §3.4:
           - ``read_back`` is provided (not None)
           - ``read_back.digest_match`` is exactly True
           - ``harness_attestation_ref`` is a non-empty URN

        Raises:
            ValueError: For either rule above, or for Pydantic shape
                violations. The record is NOT appended in any failure
                case.
        """
        # Rule 1: read-back digest equality — applies whenever a
        # read_back block is present, regardless of delivery_state.
        if isinstance(read_back, dict):
            req_digest = write_attempt.get("request_digest") if isinstance(write_attempt, dict) else None
            rb_digest = read_back.get("read_back_digest")
            if req_digest is not None and rb_digest is not None and req_digest != rb_digest:
                raise ValueError(
                    "delivery_verdict rejected: read-back digest mismatch — "
                    f"write_attempt.request_digest={req_digest!r} but "
                    f"read_back.read_back_digest={rb_digest!r}. A delivery "
                    "verdict with self-inconsistent digests MUST NOT enter "
                    "the bundle (brief §3.4)."
                )

        # Rule 2: verified_delivered triple-requirement (brief §3.4).
        if delivery_state == "verified_delivered":
            problems: list[str] = []
            if not isinstance(read_back, dict):
                problems.append("read_back is missing")
            elif read_back.get("digest_match") is not True:
                problems.append(f"read_back.digest_match must be exactly True (got {read_back.get('digest_match')!r})")
            if not (isinstance(harness_attestation_ref, str) and harness_attestation_ref):
                problems.append("harness_attestation_ref is missing or empty")
            if problems:
                raise ValueError(
                    "delivery_verdict rejected: delivery_state='verified_delivered' "
                    "requires read_back + read_back.digest_match=True + "
                    f"harness_attestation_ref; problems: {problems!r} "
                    "(brief §3.4)."
                )

        if verdict_id is None:
            verdict_id = self._mint_record_urn()

        payload_dict: dict[str, Any] = {
            "verdict_id": verdict_id,
            "finding_ref": finding_ref,
            "destination": destination,
            "write_attempt": write_attempt,
            "delivery_state": delivery_state,
        }
        if read_back is not None:
            payload_dict["read_back"] = read_back
        if drift_classification is not None:
            payload_dict["drift_classification"] = drift_classification
        if retry_history is not None:
            payload_dict["retry_history"] = retry_history
        if harness_attestation_ref is not None:
            payload_dict["harness_attestation_ref"] = harness_attestation_ref

        try:
            validated = DeliveryVerdictPayload.model_validate(payload_dict)
        except ValidationError as e:
            raise ValueError(f"delivery_verdict payload failed validation: {e}") from e

        return self.record(
            record_type="delivery_verdict",
            payload=validated.model_dump(mode="json", exclude_none=True),
            provisions=provisions,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            obligation_role=obligation_role,
            timestamp=timestamp,
        )

    def attest(
        self,
        *,
        state_class: str,
        state_transition: dict[str, Any],
        bound_evidence_refs: list[str],
        verifier: dict[str, Any],
        claim: str,
        fake_green_test_ref: str | None,
        attestation_signature: dict[str, Any],
        signed_at: str,
        signer_kid: str,
        attestation_id: str | None = None,
        provisions: list[str] | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        obligation_role: str | ObligationRole | None = None,
        timestamp: str | None = None,
    ) -> RecordEnvelope:
        """Add a ``harness_attestation`` record (brief §3.6).

        Enforces the following SDK-side pre-flight checks BEFORE the
        record is appended:

        - ``state_class`` MUST be one of the seven values in the brief
          Q3 taxonomy (VAL-SCHEMA-009). Mirrors validator ACEF-076.
        - ``verifier.verifier_class`` MUST NOT be ``persona`` or ``llm``
          (brief §3.6, VAL-LOAD-001/002). Mirrors loader's ACEF-070
          LoadRejection at SDK build time.
        - ``bound_evidence_refs`` MUST be a non-empty list (VAL-SDK-005,
          brief TC8 — state-class records require >=1 binding).
        - ``fake_green_test_ref`` MUST be a non-empty string for any
          state_class (VAL-SDK-006).

        Raises:
            ValueError: For any of the above, or for Pydantic shape
                violations. The record is NOT appended.
        """
        # Pre-flight checks ordered so the most informative error
        # surfaces first.
        if state_class not in _STATE_CLASS_TAXONOMY:
            raise ValueError(
                f"harness_attestation rejected: state_class={state_class!r} "
                f"is not in the brief Q3 taxonomy {sorted(_STATE_CLASS_TAXONOMY)!r} "
                "(VAL-SCHEMA-009)."
            )

        verifier_class = verifier.get("verifier_class") if isinstance(verifier, dict) else None
        if verifier_class in _BANNED_VERIFIER_CLASSES:
            raise ValueError(
                f"harness_attestation rejected: verifier_class={verifier_class!r} "
                "is banned — persona and LLM verifiers lack the determinism "
                "required to attest state transitions (brief §3.6, "
                "VAL-LOAD-001/002)."
            )

        # VAL-SDK-005 — state-class records require >=1 ref.
        if not bound_evidence_refs:
            raise ValueError(
                f"harness_attestation rejected: state_class={state_class!r} "
                "record requires bound_evidence_refs with at least one entry "
                "(VAL-SDK-005, brief TC8)."
            )

        # VAL-SDK-006 — fake_green_test_ref required for any state_class.
        if not (isinstance(fake_green_test_ref, str) and fake_green_test_ref):
            raise ValueError(
                f"harness_attestation rejected: state_class={state_class!r} "
                "record requires a non-empty fake_green_test_ref "
                "(VAL-SDK-006)."
            )

        if attestation_id is None:
            attestation_id = self._mint_record_urn()

        payload_dict: dict[str, Any] = {
            "attestation_id": attestation_id,
            "state_class": state_class,
            "state_transition": state_transition,
            "bound_evidence_refs": bound_evidence_refs,
            "verifier": verifier,
            "claim": claim,
            "fake_green_test_ref": fake_green_test_ref,
            "attestation_signature": attestation_signature,
            "signed_at": signed_at,
            "signer_kid": signer_kid,
        }

        try:
            validated = HarnessAttestationPayload.model_validate(payload_dict)
        except ValidationError as e:
            raise ValueError(f"harness_attestation payload failed validation: {e}") from e

        return self.record(
            record_type="harness_attestation",
            payload=validated.model_dump(mode="json", exclude_none=True),
            provisions=provisions,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            obligation_role=obligation_role,
            timestamp=timestamp,
        )

    def add_attachment(self, path: str, content: bytes) -> None:
        """Add an attachment file to be included in artifacts/.

        Args:
            path: Relative path within artifacts/ (e.g., 'eval-report-v3.pdf').
            content: Raw file content.

        Raises:
            ACEFError: If the path contains traversal sequences, backslashes, or is absolute.
        """
        # Validate raw input path BEFORE prefix — catch absolute paths and traversal
        # on the raw caller-supplied value
        _validate_raw_attachment_path(path)

        if not path.startswith("artifacts/"):
            path = f"artifacts/{path}"

        # Validate final path — defense in depth
        _validate_attachment_path(path)

        self._attachments[path] = content

    # ------------------------------------------------------------------
    # RFC-0002 v1.1 incident builders (F-M5-BUILDER, VAL-DX-001)
    #
    # report_incident() emits the SOURCE-BACKED incident_report (the Art.73
    # regulatory-filing critical path, carrying the private card_source block);
    # incident_card() emits the PUBLIC incident_card (the publishability-projected
    # public surface). Both:
    #   - auto-derive harm_core -> taxonomy_crosswalk by REUSING the §5.5
    #     derivation rows materialized in acef-conventions/v1.1/
    #     harm-core-taxonomy.json (via acef.validation.incident_rules — never a
    #     hardcoded crosswalk);
    #   - compute the ACEF-SEV band() by REUSING acef.validation.incident_rules.band
    #     (never a reimplemented grammar);
    #   - assemble the eu_ai_act_facts + the Art.73 regulatory_timeline entry whose
    #     deadline = awareness_date + shortest_art73_clock_days(facts) (REUSING
    #     acef.validation.incident_rules.shortest_art73_clock_days);
    #   - emit id_grade: self-asserted, set core_version 1.1.0, and declare the
    #     eu-ai-act-art73-2026 profile so the delegated ACEF-084 checks run.
    # One builder call emits a valid, signable bundle that PASSES the offline
    # engine (proved end-to-end in tests/integration/test_report_incident_e2e.py).
    # ------------------------------------------------------------------

    def _ensure_v1_1(self) -> None:
        """Bump core_version to 1.1.0 (the incident record types are gated on it).

        v1.1 is a minor release; a bundle already declaring 1.1.x (or any future
        v1.y, y > 1) is left as-is. Calling an incident builder on a fresh
        Package (default 1.0.0) upgrades it so the v1.1 schema set + incident
        validation rules apply.

        The gate parses ``(major, minor)`` numerically via
        :func:`parse_core_version_minor` (audit records-payloads-6) instead of a
        lexicographic ``current >= "1.1"`` string comparison, which is not
        semver-correct: an unparseable/odd MAJOR-1 value (e.g. ``"1.1abc"``) is
        treated as not-yet-v1.1 and repaired to the canonical ``"1.1.0"`` rather
        than being mistaken for a valid v1.1 declaration.

        An UNSUPPORTED-MAJOR version (e.g. ``"2.x"``, ``"2.abc"``, ``"2.0"``) is
        left UNTOUCHED — it must NOT be silently clobbered to ``"1.1.0"``
        (roborev finding 1). The parse preserves the major even when the minor
        is malformed, so a non-1 major is detected and skipped here; the
        validator surfaces the unsupported major as ACEF-001 downstream
        (:func:`acef.schemas.registry.schema_version_for_core_version`).
        """
        parsed = parse_core_version_minor(self._versioning.core_version)
        if parsed is None:
            # No parseable major (legacy/odd/absent) — default a fresh bundle to
            # the v1.1 floor so the incident schema set + rules apply.
            self._versioning.core_version = "1.1.0"
            return
        major, minor = parsed
        if major != 1:
            # Unsupported major (2.x, 2.0, …) — do NOT rewrite; leave the
            # declared version so the validator rejects it (ACEF-001) instead of
            # masking a forged/typo'd major as a self-inconsistent v1.1 bundle.
            return
        if minor is None or minor < 1:
            # major == 1 with a malformed minor ("1.1abc") or below the v1.1
            # floor (1.0.x) — repair to the canonical v1.1.0.
            self._versioning.core_version = "1.1.0"

    def _declare_art73_profile(self) -> None:
        """Declare the eu-ai-act-art73-2026 profile once (idempotent)."""
        if not any(p.profile_id == _ART73_PROFILE_ID for p in self._profiles):
            self.add_profile(_ART73_PROFILE_ID, provisions=["art-73"])

    @staticmethod
    def _merged_eu_facts(
        harm_core: dict[str, Any],
        eu_ai_act_facts: dict[str, Any],
    ) -> dict[str, Any]:
        """Return the SINGLE merged Art.73 EU fact block (roborev F1).

        Both builders derive Art.3(49) ``serious_incident_triggers`` from
        ``harm_core.harm_class`` (a ``critical_infrastructure`` card DERIVES
        ``3.49.b`` even when the caller supplies no triggers) and merge them with
        any caller-supplied compound triggers, deterministically sorted (§5.10).
        This is the ONE fact block the builder must use consistently for:

        - the persisted ``card_source.eu_ai_act_facts`` (confidential path) /
          ``taxonomy_crosswalk.eu_ai_act`` (public path) the validator reads, AND
        - the Art.73 ``regulatory_timeline`` deadline computation.

        Computing the deadline from the PRE-derivation caller facts (without the
        derived ``3.49.b``) while persisting the DERIVED triggers would make the
        builder's deadline disagree with the validator's clock (derived from the
        persisted triggers) — exactly the ACEF-084 mismatch roborev F1 found. The
        ``edition`` pin is included so this block is reusable verbatim as the
        confidential ``card_source.eu_ai_act_facts``.
        """
        from acef.validation.incident_rules import _class_to_triggers

        harm_class = harm_core.get("harm_class")
        derived_triggers: set[str] = set()
        if isinstance(harm_class, str):
            derived_triggers = set(_class_to_triggers().get(harm_class, frozenset()))
        supplied = {t for t in eu_ai_act_facts.get("serious_incident_triggers", []) if isinstance(t, str)}
        return {
            "edition": _EU_AI_ACT_EDITION,
            "serious_incident_triggers": sorted(derived_triggers | supplied),
            "widespread": bool(eu_ai_act_facts.get("widespread", False)),
            "death_involved": bool(eu_ai_act_facts.get("death_involved", False)),
        }

    @staticmethod
    def _derive_taxonomy_crosswalk(
        harm_core: dict[str, Any],
        eu_ai_act_facts: dict[str, Any],
    ) -> dict[str, Any]:
        """Auto-derive ``taxonomy_crosswalk`` from ``harm_core`` (§5.5).

        REUSES the one-directional core->scheme derivation ROWS materialized in
        ``acef-conventions/v1.1/harm-core-taxonomy.json`` (loaded via
        :mod:`acef.validation.incident_rules`) rather than hardcoding a crosswalk.
        For the card's ``harm_class`` it emits:

        - ``eu_ai_act`` — the version-pinned member carrying the Art.3(49)
          ``serious_incident_triggers`` (the trigger derived from ``harm_class`` is
          always included; any caller-supplied compound triggers are merged in,
          deterministically sorted §5.10) plus the ``widespread`` / ``death_involved``
          booleans. This is the SAME merged block (:meth:`_merged_eu_facts`) the
          Art.73 deadline is computed from, so the public crosswalk the validator
          reads and the builder's deadline agree (roborev F1, no ACEF-084).
        - ``nist_ai_600_1`` — the closed NIST category projection for the row (the one
          external enum already transcribed/closed), present only when non-empty.

        The result is CONSISTENT with the validator's ACEF-085 derivation check by
        construction (it is derived from the same rows). An unmappable harm_class
        (empty members) leaves the corresponding member legitimately absent.
        """
        from acef.validation.incident_rules import _derivation_rows_by_class

        harm_class = harm_core.get("harm_class")
        crosswalk: dict[str, Any] = {}
        if not isinstance(harm_class, str):
            return crosswalk

        rows = _derivation_rows_by_class()
        row = rows.get(harm_class, {})

        # --- eu_ai_act member (always emitted; it anchors the Art.73 facts) ---
        # REUSE the merged (derived ∪ supplied) fact block so the public crosswalk
        # the validator reads carries the same triggers the deadline is clocked from.
        crosswalk["eu_ai_act"] = Package._merged_eu_facts(harm_core, eu_ai_act_facts)

        # --- nist_ai_600_1 member (only when the row has a non-empty projection) ---
        nist_row = row.get("nist_ai_600_1", {}) if isinstance(row, dict) else {}
        nist_members = [m for m in nist_row.get("members", []) if isinstance(m, str)]
        if nist_members:
            crosswalk["nist_ai_600_1"] = {
                "edition": _NIST_AI_600_1_EDITION,
                "categories": sorted(nist_members),
            }
        return crosswalk

    @staticmethod
    def _art73_timeline_entry(awareness_date: str, eu_ai_act_facts: dict[str, Any]) -> dict[str, Any]:
        """Build the Art.73 ``regulatory_timeline`` entry whose ``deadline`` equals
        the SHORTEST applicable clock (§5.7), REUSING
        :func:`acef.validation.incident_rules.shortest_art73_clock_days`.

        ``deadline = awareness_date + shortest_clock_days``. The awareness instant is
        parsed as ISO 8601 (Zulu / offset) and the deadline is re-emitted in the same
        ``...Z`` form so it is byte-stable and matches the validator's instant parser.
        """
        from acef.validation.incident_rules import shortest_art73_clock_days

        clock_days = shortest_art73_clock_days(eu_ai_act_facts)
        awareness = _parse_iso_instant(awareness_date)
        deadline = awareness + timedelta(days=clock_days)
        return {
            "framework": _ART73_TIMELINE_FRAMEWORK,
            "clock_model": "awareness_days",
            "awareness_date": _format_iso_instant(awareness),
            "deadline": _format_iso_instant(deadline),
        }

    def report_incident(
        self,
        *,
        public_incident_id: str,
        harm_core: dict[str, Any],
        incident_type: str,
        description: str,
        awareness_date: str,
        eu_ai_act_facts: dict[str, Any],
        severity: str = "major",
        severity_vector: str | None = None,
        id_state: str = "RESERVED",
        value_chain_role: str | None = None,
        subject_identity: tuple[str, str, str] | list[str] | dict[str, str] | Subject | None = None,
        occurrence_date: str | None = None,
        detection_date: str | None = None,
        pepper: bytes | str | None = None,
        publishability_map: dict[str, str] | None = None,
        root_cause_analysis: str | None = None,
        disclosure_status: str = "coordinated",
        reporter_role: str | None = None,
        extra_card_source: dict[str, Any] | None = None,
        confidentiality: str | Confidentiality = Confidentiality.REGULATOR_ONLY,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        obligation_role: str | ObligationRole | None = None,
        timestamp: str | None = None,
        record_id: str | None = None,
    ) -> RecordEnvelope:
        """Build a SOURCE-BACKED ``incident_report`` carrying the private
        ``card_source`` block (RFC-0002 §5.1/§5.7, VAL-DX-001).

        This is the EU Art. 73 regulatory-filing critical path: the confidential
        report validates from ``card_source.eu_ai_act_facts`` BEFORE any public card
        exists (a RESERVED id, no public projection). The builder:

        - auto-derives ``card_source.harm_core -> taxonomy-aware eu_ai_act_facts``
          (the supplied facts are pinned to the ``reg-2024-1689`` edition);
        - assembles ``card_source.coordinated_disclosure.regulatory_timeline`` with
          the ``eu-ai-act-art73`` entry whose ``deadline`` equals the shortest
          applicable clock derived from ``eu_ai_act_facts`` (death -> 10d; 3.49.b /
          widespread -> 2d; else 15d);
        - computes the coarse ``severity`` from ``severity_vector`` via ``band()``
          when a vector is supplied (so the public ``severity`` and the private
          ``severity_vector`` never disagree — ACEF-088);
        - emits ``id_grade: self-asserted`` + the requested ``id_state`` (default
          ``RESERVED``), sets ``core_version 1.1.0``, and declares the
          ``eu-ai-act-art73-2026`` profile.

        The record is emitted ``regulator-only`` by default, so the package's
        attached :class:`~acef.redaction.RedactionPolicy` (if any) auto-populates the
        X1/X2 redaction envelope fields the v1.1 cross-record validator requires.

        Raises:
            ValueError: if ``awareness_date`` is not a parseable ISO-8601 instant.
        """
        self._ensure_v1_1()
        self._declare_art73_profile()

        # ONE merged Art.73 fact block (harm_core-derived ∪ caller-supplied triggers).
        # The SAME block backs card_source.eu_ai_act_facts AND the deadline below, so
        # the persisted facts the validator reads and the builder's clock agree —
        # roborev F1 (a critical_infrastructure report deriving 3.49.b without an
        # explicit supplied trigger now yields a 2-day deadline, not 15-day → no ACEF-084).
        facts = self._merged_eu_facts(harm_core, eu_ai_act_facts)

        timeline_entry = self._art73_timeline_entry(awareness_date, facts)

        disclosure: dict[str, Any] = {
            "status": disclosure_status,
            "regulatory_timeline": [timeline_entry],
        }
        if reporter_role is not None:
            disclosure["reporter_role"] = reporter_role

        card_source: dict[str, Any] = {
            "public_incident_id": public_incident_id,
            "id_grade": "self-asserted",
            "id_state": id_state,
            "harm_core": dict(harm_core),
            "publishability_map": dict(publishability_map) if publishability_map else {},
            "eu_ai_act_facts": facts,
            "coordinated_disclosure": disclosure,
        }
        if severity_vector is not None:
            card_source["severity_vector"] = severity_vector
        if extra_card_source:
            for key, value in extra_card_source.items():
                card_source.setdefault(key, value)

        # The coarse severity. When a vector is supplied, band() WINS so the public
        # root severity and the private vector never disagree (ACEF-088); otherwise
        # the explicit `severity` (default "major") is used. incident_report
        # structurally requires `severity`, so it is always present.
        resolved_severity = severity
        if severity_vector is not None:
            band_value = band(severity_vector)
            if band_value is not None:
                resolved_severity = band_value

        payload: dict[str, Any] = {
            "incident_type": incident_type,
            "description": description,
            "severity": resolved_severity,
            "card_source": card_source,
        }
        if root_cause_analysis is not None:
            payload["root_cause_analysis"] = root_cause_analysis
        if occurrence_date is not None:
            payload["occurrence_date"] = occurrence_date
        if detection_date is not None:
            payload["detection_date"] = detection_date

        # §5.5 incident_dedupe_key. report_incident is the CONFIDENTIAL Art.73
        # path (regulator-only by default), so the subject-bearing plaintext key
        # is OMITTED unless the record is explicitly emitted public (the §5.5 Q20
        # confidentiality MUST — the same public-only gate the public card applies).
        # The keyed HMAC variant (pepper supplied) is the redacted-subject dedupe
        # path and is emitted regardless of confidentiality (it is pepper-keyed).
        resolved_confidentiality = (
            Confidentiality(confidentiality) if isinstance(confidentiality, str) else confidentiality
        )
        harm_class = harm_core.get("harm_class") if isinstance(harm_core, dict) else None
        if resolved_confidentiality == Confidentiality.PUBLIC:
            dedupe_key = compute_incident_dedupe_key(
                value_chain_role=value_chain_role,
                subject_identity=subject_identity,
                harm_class=harm_class,
                occurrence_date=occurrence_date,
                detection_date=detection_date,
            )
            if dedupe_key is not None:
                payload["incident_dedupe_key"] = dedupe_key
        if pepper is not None:
            dedupe_hmac = compute_incident_dedupe_key_hmac(
                pepper=pepper,
                value_chain_role=value_chain_role,
                subject_identity=subject_identity,
                harm_class=harm_class,
                occurrence_date=occurrence_date,
                detection_date=detection_date,
            )
            if dedupe_hmac is not None:
                payload["incident_dedupe_key_hmac"] = dedupe_hmac

        return self.record(
            record_type="incident_report",
            payload=payload,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            obligation_role=obligation_role,
            timestamp=timestamp,
            record_id=record_id,
        )

    def incident_card(
        self,
        *,
        public_incident_id: str,
        harm_core: dict[str, Any],
        severity_vector: str,
        awareness_date: str,
        eu_ai_act_facts: dict[str, Any],
        autonomy_level: str | None = None,
        value_chain_role: str | None = None,
        subject_identity: tuple[str, str, str] | list[str] | dict[str, str] | Subject | None = None,
        occurrence_date: str | None = None,
        detection_date: str | None = None,
        pepper: bytes | str | None = None,
        harm_distribution_basis: list[str] | None = None,
        declared_publication_basis: dict[str, Any] | None = None,
        commitments: dict[str, Any] | None = None,
        disclosure_status: str = "coordinated",
        reporter_role: str | None = None,
        extra_payload: dict[str, Any] | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        obligation_role: str | ObligationRole | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        timestamp: str | None = None,
        record_id: str | None = None,
    ) -> RecordEnvelope:
        """Build a PUBLIC ``incident_card`` (RFC-0002 §5.4/§5.5/§5.11, VAL-DX-001).

        The publishability-projected public surface. The builder:

        - auto-derives ``harm_core -> taxonomy_crosswalk`` from the §5.5 derivation
          rows (consistent with the ACEF-085 check by construction);
        - computes the coarse ``severity`` from ``severity_vector`` via ``band()`` so
          the two never disagree (ACEF-088);
        - assembles ``coordinated_disclosure.regulatory_timeline`` with the
          ``eu-ai-act-art73`` shortest-clock entry (§5.7);
        - applies the §5.11 publishability projection: when a special-category field
          (``harm_distribution_basis``) is projected public, a satisfying
          ``declared_publication_basis`` (Art.6 basis + Art.9 condition, or a declared
          anonymization method) MUST be threaded through (else the validator raises
          ACEF-086); ``commitments`` are emitted as ``<field>_commitment`` =
          ``"sha256:" + hex(SHA-256(JCS(value)))`` whole-value hash commitments
          (REUSING the same RFC-8785 + SHA-256 primitive
          :func:`acef.redaction.apply_redaction` uses), so a privileged field can be
          hash-committed instead of disclosed;
        - emits the §5.5 cross-database ``incident_dedupe_key`` =
          ``"sha256:" + hex(SHA-256(JCS({value_chain_role, subject_identity,
          harm_class, occurrence_date_utc})))`` — but ONLY on a PUBLIC card
          (``confidentiality == public``), and only when all four recipe inputs
          (``value_chain_role`` + ``subject_identity`` + ``harm_core.harm_class``
          + ``occurrence_date`` or ``detection_date``) are supplied. The
          subject-bearing key is OMITTED on any non-public record (§5.5 Q20: the
          triple is low-entropy/enumerable, so a published unsalted key would be
          offline-enumerable). When a ``pepper`` is supplied the keyed
          ``incident_dedupe_key_hmac`` = ``"hmac-sha256:" + hex(HMAC-SHA-256(
          pepper, JCS(K)))`` is ALSO emitted (the redacted-subject dedupe path);
          absent a pepper the keyed variant degrades to link-only and nothing is
          emitted for it. ``subject_identity`` is the cross-DB-stable
          ``provider|name|version`` triple (NFC-normalized + case-folded), NOT
          the per-bundle subject UUID;
        - emits ``id_grade: self-asserted``, sets ``core_version 1.1.0``, and declares
          the ``eu-ai-act-art73-2026`` profile.

        Raises:
            ValueError: if ``awareness_date`` is not a parseable ISO-8601 instant.
        """
        self._ensure_v1_1()
        self._declare_art73_profile()

        # ONE merged Art.73 fact block (harm_core-derived ∪ caller-supplied triggers).
        # It backs taxonomy_crosswalk.eu_ai_act (via _derive_taxonomy_crosswalk, which
        # re-derives the same merged block) AND the deadline below, so the public
        # crosswalk the validator reads and the builder's clock agree — roborev F1
        # (a critical_infrastructure card deriving 3.49.b without an explicit supplied
        # trigger now yields a 2-day deadline, not 15-day → no ACEF-084).
        facts = self._merged_eu_facts(harm_core, eu_ai_act_facts)

        crosswalk = self._derive_taxonomy_crosswalk(harm_core, eu_ai_act_facts)
        timeline_entry = self._art73_timeline_entry(awareness_date, facts)
        band_value = band(severity_vector)

        disclosure: dict[str, Any] = {
            "status": disclosure_status,
            "regulatory_timeline": [timeline_entry],
        }
        if reporter_role is not None:
            disclosure["reporter_role"] = reporter_role

        payload: dict[str, Any] = {
            "public_incident_id": public_incident_id,
            "id_grade": "self-asserted",
            "harm_core": dict(harm_core),
            "severity_vector": severity_vector,
            "taxonomy_crosswalk": crosswalk,
            "coordinated_disclosure": disclosure,
        }
        if band_value is not None:
            payload["severity"] = band_value
        if autonomy_level is not None:
            payload["autonomy_level"] = autonomy_level
        if value_chain_role is not None:
            payload["value_chain_role"] = value_chain_role
        if harm_distribution_basis is not None:
            payload["harm_distribution_basis"] = sorted(harm_distribution_basis)
        if declared_publication_basis is not None:
            payload["declared_publication_basis"] = dict(declared_publication_basis)
        # §5.11 whole-value hash commitments — REUSE the RFC-8785 + SHA-256 primitive.
        if commitments:
            for field_name, value in commitments.items():
                payload[f"{field_name}_commitment"] = "sha256:" + sha256_hex(canonicalize(value))

        # §5.5 cross-database incident_dedupe_key. The subject-bearing key is
        # emitted ONLY on a PUBLIC card (the confidentiality MUST, §5.5 Q20); on
        # any non-public record it is OMITTED. harm_class comes from harm_core;
        # occurrence_date (else detection_date) is normalized to a UTC YYYY-MM-DD
        # calendar date; subject_identity is the NFC+case-folded provider|name|
        # version triple. The keyed HMAC variant (when a pepper is supplied) is
        # the redacted-subject dedupe path and is emitted regardless of
        # confidentiality because it is pepper-keyed (not enumerable).
        resolved_confidentiality = (
            Confidentiality(confidentiality) if isinstance(confidentiality, str) else confidentiality
        )
        harm_class = harm_core.get("harm_class") if isinstance(harm_core, dict) else None
        if resolved_confidentiality == Confidentiality.PUBLIC:
            dedupe_key = compute_incident_dedupe_key(
                value_chain_role=value_chain_role,
                subject_identity=subject_identity,
                harm_class=harm_class,
                occurrence_date=occurrence_date,
                detection_date=detection_date,
            )
            if dedupe_key is not None:
                payload["incident_dedupe_key"] = dedupe_key
        if pepper is not None:
            dedupe_hmac = compute_incident_dedupe_key_hmac(
                pepper=pepper,
                value_chain_role=value_chain_role,
                subject_identity=subject_identity,
                harm_class=harm_class,
                occurrence_date=occurrence_date,
                detection_date=detection_date,
            )
            if dedupe_hmac is not None:
                payload["incident_dedupe_key_hmac"] = dedupe_hmac

        if extra_payload:
            for key, value in extra_payload.items():
                payload.setdefault(key, value)

        return self.record(
            record_type="incident_card",
            payload=payload,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            obligation_role=obligation_role,
            timestamp=timestamp,
            record_id=record_id,
        )

    def sign(self, key: str, *, method: str = "jws") -> None:
        """Mark this package for signing during export.

        The actual signing happens during export() when the content hashes
        are computed.

        Args:
            key: Path to the private key file (PEM format).
            method: Signing method ('jws' only for v1).
        """
        self._signed = True
        self._signature_key = key
        self._signature_method = method

    def build_manifest(self) -> Manifest:
        """Build the Manifest object from current package state.

        Uses the same deterministic sharding algorithm as the export module
        to ensure manifest record_files paths match actual file layout.

        Returns:
            A Manifest ready for serialization.
        """
        from acef.records_util import compute_shard_boundaries, sort_records

        # Build record_files index by grouping records by type
        records_by_type: dict[str, list[RecordEnvelope]] = {}
        for rec in self._records:
            records_by_type.setdefault(rec.record_type, []).append(rec)

        record_files: list[RecordFileEntry] = []
        for record_type, recs in sorted(records_by_type.items()):
            sorted_recs = sort_records(recs)
            shards = compute_shard_boundaries(sorted_recs)

            if len(shards) == 1:
                path = f"records/{record_type}.jsonl"
                record_files.append(RecordFileEntry(path=path, record_type=record_type, count=len(shards[0])))
            else:
                for i, shard in enumerate(shards):
                    shard_num = str(i + 1).zfill(4)
                    path = f"records/{record_type}/{record_type}.{shard_num}.jsonl"
                    record_files.append(RecordFileEntry(path=path, record_type=record_type, count=len(shard)))

        # Re-emit open-core v1.1 manifest fields (X5 analysis_mode, X6
        # namespaces) and any top-level manifest extras (vendor x-*) that a
        # loaded bundle carried, so a load→export round-trip is lossless to
        # the open core (spec §6.4 rule 5 / §6.5). These are passed as
        # constructor kwargs: analysis_mode/namespaces are declared Manifest
        # fields; the extras land via Manifest's extra='allow' config and
        # emit unchanged. A freshly-built Package leaves all of these empty,
        # so v1.0 manifests are byte-unchanged.
        manifest_kwargs: dict[str, Any] = dict(self._manifest_extras)
        if self._analysis_mode is not None:
            manifest_kwargs["analysis_mode"] = self._analysis_mode
        if self._namespaces is not None:
            manifest_kwargs["namespaces"] = self._namespaces

        return Manifest(
            metadata=self._metadata,
            versioning=self._versioning,
            subjects=self._subjects,
            entities=self._entities,
            profiles=self._profiles,
            record_files=record_files,
            audit_trail=self._audit_trail,
            **manifest_kwargs,
        )

    def export(self, path: str) -> None:
        """Export the package to a directory or archive.

        If path ends with .tar.gz, exports as an archive.
        Otherwise, exports as a directory bundle.

        Args:
            path: Output path (directory or .acef.tar.gz).
        """
        from acef.export import export_archive, export_directory

        if path.endswith(".tar.gz"):
            export_archive(self, path)
        else:
            export_directory(self, path)

    @classmethod
    def _init_from_parts(
        cls,
        *,
        metadata: PackageMetadata,
        versioning: Versioning,
        subjects: list[Subject],
        entities: EntitiesBlock,
        profiles: list[ProfileEntry],
        records: list[RecordEnvelope],
        audit_trail: list[AuditTrailEntry],
        attachments: dict[str, bytes] | None = None,
        analysis_mode: str | None = None,
        namespaces: dict[str, dict[str, Any]] | None = None,
        manifest_extras: dict[str, Any] | None = None,
    ) -> Package:
        """Create a Package from pre-parsed parts (deserialization path).

        This is the approved way for loader.py, merge.py, and redaction.py
        to construct Package instances without reaching into private attributes.

        Args:
            metadata: Fully constructed PackageMetadata.
            versioning: Versioning info.
            subjects: List of Subject instances.
            entities: EntitiesBlock with all entity types.
            profiles: List of ProfileEntry instances.
            records: List of RecordEnvelope instances.
            audit_trail: List of AuditTrailEntry instances.
            attachments: Dict mapping artifact paths to bytes content.
            analysis_mode: Open-core v1.1 manifest field (X5) carried from
                an inbound manifest, re-emitted by build_manifest() so the
                load→export round-trip is lossless (spec §6.4/§6.5).
            namespaces: Open-core v1.1 manifest field (X6) carried from an
                inbound manifest, re-emitted by build_manifest().
            manifest_extras: Top-level manifest keys outside the known
                sections (vendor x-* extensions, future fields) carried from
                an inbound manifest, re-emitted by build_manifest() so they
                survive round-trip. Defaults to an empty mapping.

        Returns:
            A fully constructed Package.
        """
        pkg = cls.__new__(cls)
        # Seed injection callables with their defaults so post-load
        # callers can still invoke record() / typed builders without
        # AttributeError. Loaded packages are not expected to be
        # extended in deterministic-output workflows; callers wanting
        # deterministic post-load edits should construct a fresh
        # Package(clock=, urn_generator=) and re-add records.
        pkg._clock = _default_clock
        pkg._urn_generator = generate_urn
        pkg._metadata = metadata
        pkg._versioning = versioning
        pkg._subjects = list(subjects)
        pkg._entities = entities
        pkg._profiles = list(profiles)
        pkg._records = list(records)
        pkg._audit_trail = list(audit_trail)
        pkg._attachments = dict(attachments) if attachments else {}
        pkg._signed = False
        pkg._signature_key = None
        pkg._signature_method = None
        # _init_from_parts is the deserialization path — loaded packages
        # do not carry the source-side RedactionPolicy. Seed to None so
        # Package.record() can read the attribute without AttributeError.
        pkg._redaction_policy = None
        # Open-core v1.1 manifest fields + top-level extras carried from an
        # inbound manifest so build_manifest() re-emits them losslessly
        # (spec §6.4/§6.5). Default to empty for callers that don't pass them
        # (merge.py / redaction.py), keeping their output byte-unchanged.
        pkg._analysis_mode = analysis_mode
        pkg._namespaces = namespaces
        pkg._manifest_extras = dict(manifest_extras) if manifest_extras else {}
        return pkg


def _validate_raw_attachment_path(path: str) -> None:
    """Validate raw caller-supplied attachment path before prefix is applied.

    Rejects:
    - Absolute paths (starting with '/')
    - Path traversal sequences ('..' segments)
    - Current-directory segments ('.' segments)
    - Backslash separators (spec 3.1.1: forward slashes only)

    Args:
        path: The raw caller-supplied path.

    Raises:
        ACEFError: If the path is unsafe.
    """
    # M4 (Implementer R2): Reject backslash separators per spec 3.1.1
    if "\\" in path:
        raise ACEFError(
            f"Backslash separators not allowed in attachment path (use forward slashes): {path!r}",
            code="ACEF-052",
        )

    if path.startswith("/"):
        raise ACEFError(
            f"Absolute attachment path not allowed: {path!r}",
            code="ACEF-052",
        )

    # Spec §3.1.1: paths in the manifest and hashes MUST be UTF-8 with NFC
    # normalization. Reject non-UTF-8 (surrogate-bearing) or non-NFC (e.g. an
    # HFS+ NFD-decomposed name) paths via the shared rule so the determinism
    # contract holds: a conformant NFC-normalizing exporter and this one must
    # produce identical content-hashes.json keys and tar members.
    problem = path_nfc_utf8_problem(path)
    if problem is not None:
        raise ACEFError(
            f"Attachment path violates spec §3.1.1 ({problem}): {path!r}",
            code="ACEF-052",
        )

    segments = path.split("/")
    for segment in segments:
        if segment == "..":
            raise ACEFError(
                f"Path traversal detected in attachment path: {path!r}",
                code="ACEF-052",
            )
        if segment == ".":
            raise ACEFError(
                f"Current-directory segment (.) not allowed in attachment path: {path!r}",
                code="ACEF-052",
            )


def _validate_attachment_path(path: str) -> None:
    """Validate a final attachment path for safety.

    Rejects:
    - Absolute paths (starting with '/')
    - Path traversal sequences ('..' segments)
    - Current-directory segments ('.' segments)
    - Paths not under artifacts/
    - Backslash separators (spec 3.1.1: forward slashes only)

    Args:
        path: The attachment path to validate (with artifacts/ prefix).

    Raises:
        ACEFError: If the path is unsafe.
    """
    # M4 (Implementer R2): Reject backslash separators per spec 3.1.1
    if "\\" in path:
        raise ACEFError(
            f"Backslash separators not allowed in attachment path (use forward slashes): {path!r}",
            code="ACEF-052",
        )

    if path.startswith("/"):
        raise ACEFError(
            f"Absolute attachment path not allowed: {path!r}",
            code="ACEF-052",
        )

    # Spec §3.1.1: paths in the manifest and hashes MUST be UTF-8 with NFC
    # normalization. Reject non-UTF-8 (surrogate-bearing) or non-NFC paths here
    # too (defense in depth alongside the raw-path check) via the shared rule so
    # such an artifact key can never reach the hash domain.
    problem = path_nfc_utf8_problem(path)
    if problem is not None:
        raise ACEFError(
            f"Attachment path violates spec §3.1.1 ({problem}): {path!r}",
            code="ACEF-052",
        )

    segments = path.split("/")
    for segment in segments:
        if segment == "..":
            raise ACEFError(
                f"Path traversal detected in attachment path: {path!r}",
                code="ACEF-052",
            )
        if segment == ".":
            raise ACEFError(
                f"Current-directory segment (.) not allowed in attachment path: {path!r}",
                code="ACEF-052",
            )

    if not path.startswith("artifacts/"):
        raise ACEFError(
            f"Attachment path must be under artifacts/: {path!r}",
            code="ACEF-052",
        )
