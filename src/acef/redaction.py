"""ACEF redaction module — privacy-preserving redaction with hash commitments.

Supports:
- Hash-commitment redaction (replace payload with hash)
- Access policies (roles and organizations)
- Redacted package verification
- :class:`RedactionPolicy` — versioned policy required for non-public
  records (X1 envelope field) per VAL-REDACTION-001.
- :func:`apply_redaction` — produces a ``(redacted_payload, event_log)``
  pair; the event_log attestation record uses the existing Core
  ``event_log`` record type (NOT a new vendor namespace) per
  VAL-REDACTION-002 and the codex scope-creep removal (VAL-REDACTION-004).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import Field, field_validator

from acef.errors import ACEFFormatError
from acef.integrity import canonicalize, sha256_hex
from acef.models.base import ACEFBaseModel
from acef.models.enums import Confidentiality
from acef.models.records import RecordEnvelope
from acef.models.urns import URNType, generate_urn
from acef.package import Package

# The v1 SDK only documents and supports one redaction method. New methods
# (e.g., zero-knowledge proofs per spec §7 Q6) require an explicit
# whitelist update so untested methods cannot silently produce records
# that downstream tooling will not understand.
_SUPPORTED_REDACTION_METHODS = frozenset({"sha256-hash-commitment"})

# Semver shape per https://semver.org — MAJOR.MINOR.PATCH plus optional
# pre-release / build metadata segment introduced by '-' or '+'. We do not
# pull in a full semver parser because the validator only needs the shape,
# not the comparison semantics.
_SEMVER_PATTERN: re.Pattern[str] = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")


class RedactionPolicy(ACEFBaseModel):
    """Versioned redaction policy (VAL-REDACTION-001).

    A :class:`RedactionPolicy` is the X1 source-of-truth for the
    ``redaction_policy_version`` envelope field. When a non-public record
    is emitted via :meth:`acef.package.Package.record`, the package's
    attached policy supplies the semver written to X1.

    Fields:
        version: Semver-shaped policy version (e.g., ``"1.0.0"``). The
            shape is validated via the
            :data:`_SEMVER_PATTERN` regex; non-semver strings raise.
        method: Redaction method used by :func:`apply_redaction` when
            building the redacted payload. Currently only
            ``"sha256-hash-commitment"`` is implemented; the field is
            here so future policies (e.g., zero-knowledge proofs per
            spec §7 Q6) can be declared without a model change.
        description: Free-form human-readable description of the policy
            (what fields are redacted, what guarantees the method
            provides).
    """

    version: str = Field(
        ...,
        description="Semver-shaped policy version, e.g. '1.0.0'.",
    )
    method: str = Field(
        default="sha256-hash-commitment",
        description="Redaction method; must be in _SUPPORTED_REDACTION_METHODS.",
    )
    description: str = Field(default="")

    @field_validator("version")
    @classmethod
    def _validate_semver(cls, v: str) -> str:
        if not isinstance(v, str) or not _SEMVER_PATTERN.match(v):
            raise ValueError(
                f"RedactionPolicy.version must be semver-shaped (MAJOR.MINOR.PATCH[-pre|+build]); got {v!r}."
            )
        return v

    @field_validator("method")
    @classmethod
    def _validate_method(cls, v: str) -> str:
        if v not in _SUPPORTED_REDACTION_METHODS:
            raise ValueError(
                f"RedactionPolicy.method={v!r} is not in the supported set {sorted(_SUPPORTED_REDACTION_METHODS)!r}."
            )
        return v


def apply_redaction(
    payload: dict[str, Any],
    policy: RedactionPolicy,
    *,
    redacting_actor_ref: str | None = None,
    clock: Any | None = None,
    urn_generator: Any | None = None,
    access_policy: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], RecordEnvelope]:
    """Apply a redaction policy to a payload (VAL-REDACTION-002).

    Returns a tuple ``(redacted_payload, attestation_record)`` where the
    attestation record is a Core ``event_log`` (NOT a vendor namespace —
    see VAL-REDACTION-004) carrying ``event_type: "redaction"`` plus the
    policy version and SHA-256 hashes of the original and redacted
    payloads.

    The hash-commitment method replaces the payload with::

        {
            "redaction_method": "sha256-hash-commitment",
            "redacted_payload_hash": "<sha256 of original>",
            "redaction_policy_version": "<policy.version>",
            "access_policy": {...}  # only if caller supplied one
        }

    Args:
        payload: The original (sensitive) payload to redact.
        policy: The :class:`RedactionPolicy` to apply.
        redacting_actor_ref: Optional URN of the actor performing the
            redaction. When supplied, recorded in
            ``attestation.payload.redacting_actor_ref``.
        clock: REQUIRED zero-arg callable returning a timezone-aware
            ``datetime``. Mints the attestation record's timestamp. The
            attestation event_log is a hash-domain record — it enters the
            bundle and the Merkle tree — so its timestamp MUST be supplied
            deterministically by the caller; a ``None``/non-callable clock
            raises :class:`ValueError` instead of silently leaking the wall
            clock into the hash domain (audit finding redaction-6).
            ``Package.record`` passes the package clock automatically;
            ``redact_record``/``redact_package`` derive a clock from the
            source record's timestamp.
        urn_generator: Optional callable ``(URNType) -> str`` used to mint
            the attestation record's ``record_id``. Defaults to
            :func:`acef.models.urns.generate_urn`.
        access_policy: Optional access policy carried into the redacted
            payload's ``access_policy`` field.

    Returns:
        ``(redacted_payload, attestation_record)``.

    Raises:
        ValueError: If ``clock`` is not a callable.
        ACEFFormatError: If ``policy.method`` is not supported.
    """
    if not callable(clock):
        raise ValueError(
            "apply_redaction requires an explicit 'clock' callable (zero-arg, "
            "returning a timezone-aware datetime). The attestation event_log "
            "is a hash-domain record — it enters the bundle and the Merkle "
            "tree — so its timestamp must be injected deterministically by "
            "the caller, never read from the wall clock. Pass e.g. "
            "clock=lambda: datetime(2026, 1, 1, tzinfo=UTC)."
        )

    if policy.method not in _SUPPORTED_REDACTION_METHODS:
        raise ACEFFormatError(
            f"Unsupported redaction method on policy: {policy.method!r}. "
            f"Supported: {sorted(_SUPPORTED_REDACTION_METHODS)!r}",
            code="ACEF-004",
        )

    # 1. Hash the original payload (RFC 8785 canonicalized).
    original_canonical = canonicalize(payload)
    original_hash = sha256_hex(original_canonical)

    # 2. Build the redacted payload per method. Only one method is
    # supported today (sha256-hash-commitment).
    redacted_payload: dict[str, Any] = {
        "redaction_method": "sha256-hash-commitment",
        "redacted_payload_hash": original_hash,
        "redaction_policy_version": policy.version,
    }
    if access_policy is not None:
        redacted_payload["access_policy"] = access_policy
    elif isinstance(payload.get("access_policy"), dict):
        # Preserve any existing access_policy in the source payload so
        # callers don't lose it when redacting in-place.
        redacted_payload["access_policy"] = payload["access_policy"]

    # 3. Hash the redacted payload too — the attestation needs both
    # hashes so verifiers can independently confirm the transformation.
    redacted_hash = sha256_hex(canonicalize(redacted_payload))

    # 4. Build the attestation event_log record. We deliberately use the
    # Core ``event_log`` record_type (VAL-REDACTION-004) — no vendor
    # namespace is introduced.
    gen_urn = urn_generator if callable(urn_generator) else generate_urn
    attestation_payload: dict[str, Any] = {
        "event_type": "redaction",
        "policy_version": policy.version,
        "policy_method": policy.method,
        "original_payload_hash": original_hash,
        "redacted_payload_hash": redacted_hash,
    }
    if redacting_actor_ref is not None and redacting_actor_ref:
        attestation_payload["redacting_actor_ref"] = redacting_actor_ref
    if policy.description:
        attestation_payload["policy_description"] = policy.description

    # The clock is guaranteed callable by the guard at the top of this
    # function — the attestation timestamp is ALWAYS injected; the
    # RecordEnvelope wall-clock default factory is unreachable here.
    ts_dt = clock()
    if ts_dt.tzinfo is None:
        ts_dt = ts_dt.replace(tzinfo=UTC)
    else:
        ts_dt = ts_dt.astimezone(UTC)

    attestation_record = RecordEnvelope(
        record_id=gen_urn(URNType.RECORD),
        record_type="event_log",
        payload=attestation_payload,
        timestamp=ts_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    return redacted_payload, attestation_record


def _core_version_is_v1_1_or_later(core_version: Any) -> bool:
    """True when ``core_version`` parses as semver with ``(major, minor) >= (1, 1)``.

    Numeric tuple comparison — deliberately NOT lexicographic string
    comparison (see audit finding redaction-5 for why string compare is a
    latent hazard). Malformed or non-string values return ``False`` (treated
    as v1.0-era, the conservative reading).
    """
    if not isinstance(core_version, str):
        return False
    parts = core_version.split(".")
    if len(parts) < 2:
        return False
    try:
        major = int(parts[0])
        minor = int(parts[1])
    except ValueError:
        return False
    return (major, minor) >= (1, 1)


def _record_timestamp_clock(record: RecordEnvelope) -> Callable[[], datetime]:
    """Build a deterministic clock pinned to ``record.timestamp``.

    The redaction attestation minted for an existing record uses the SOURCE
    record's timestamp as its own — the attestation describes that record's
    content, and deriving the instant from the input keeps standalone
    redaction byte-deterministic (two runs over the same record produce the
    same attestation timestamp; audit finding redaction-6).

    Raises:
        ACEFFormatError: ACEF-050 when the source record carries a
            non-ISO-8601 timestamp.
    """
    raw = record.timestamp
    try:
        instant = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as e:
        raise ACEFFormatError(
            f"Cannot derive a deterministic attestation timestamp: record "
            f"{record.record_id!r} has a non-ISO-8601 timestamp {raw!r}.",
            code="ACEF-050",
        ) from e
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=UTC)

    def _clock() -> datetime:
        return instant

    return _clock


def redact_record(
    record: RecordEnvelope,
    *,
    policy: RedactionPolicy | None = None,
    method: str = "sha256-hash-commitment",
    access_policy: dict[str, Any] | None = None,
    urn_generator: Callable[[URNType], str] | None = None,
) -> tuple[RecordEnvelope, RecordEnvelope | None]:
    """Create a redacted copy of a record.

    Two modes (VAL-FIX-REDACT-002, audit finding redaction-2):

    **Policy mode** (``policy`` supplied) — the v1.1 contract, mirroring
    ``Package.record``'s auto-population: the payload is replaced with the
    canonical :func:`apply_redaction` hash-commitment shape, the X1 envelope
    field (``redaction_policy_version``) is set from ``policy.version``, a
    Core ``event_log`` attestation describing the STORED payload bytes is
    minted, and its URN is wired into X2 (``redaction_attestation_ref``).
    The attestation's timestamp derives deterministically from the source
    record's timestamp. Callers MUST place the returned attestation record
    in the same bundle as the redacted record, otherwise X2 dangles and the
    validator emits ACEF-078 (``redact_package`` does this automatically).

    **Legacy mode** (``policy`` omitted) — the v1.0-era behavior: the payload
    is replaced with ``{"_redacted": True, "_commitment": "sha256:<hash>"}``
    and no X1/X2 fields are emitted (v1.0 schemas predate them). Records
    produced this way fail validator ACEF-074 if placed in a v1.1 bundle —
    v1.1 producers must supply ``policy``.

    In both modes the original payload hash is stored in
    ``redaction_method`` (``"<method>:<hash>"``) so verifiers can recompute
    it against the original payload via :func:`verify_redaction`.

    Args:
        record: The record to redact.
        policy: The :class:`RedactionPolicy` governing the redaction.
            Supplying it enables policy mode (X1/X2 + attestation); its
            ``method`` field selects the redaction method.
        method: Redaction method for legacy mode (default:
            ``sha256-hash-commitment``). Must be a documented method in
            :data:`_SUPPORTED_REDACTION_METHODS`; arbitrary strings are
            rejected so misspellings cannot produce records labeled with
            a method downstream tools cannot interpret. In policy mode
            ``policy.method`` governs.
        access_policy: Who can see the full payload. If ``None``, the
            record's existing ``access_policy`` is preserved rather than
            overwritten — passing ``None`` should not strip an existing
            policy.
        urn_generator: Optional callable ``(URNType) -> str`` minting the
            attestation's ``record_id`` (policy mode only). Defaults to
            :func:`acef.models.urns.generate_urn`; inject a deterministic
            generator for byte-stable output.

    Returns:
        ``(redacted_record, attestation_record)``. ``attestation_record``
        is ``None`` in legacy mode.

    Raises:
        ACEFFormatError: If ``method`` is not a documented redaction
            method (ACEF-004), or the source record's timestamp is not
            ISO 8601 (ACEF-050, policy mode).
    """
    if method not in _SUPPORTED_REDACTION_METHODS:
        raise ACEFFormatError(
            f"Unsupported redaction method: {method!r}. Supported methods: {sorted(_SUPPORTED_REDACTION_METHODS)}",
            code="ACEF-004",
        )

    if policy is not None:
        # ---- Policy mode (v1.1): canonical commitment + X1/X2 + attestation.
        redacted_payload, attestation = apply_redaction(
            record.payload,
            policy,
            clock=_record_timestamp_clock(record),
            urn_generator=urn_generator,
        )
        original_hash = attestation.payload["original_payload_hash"]

        redacted = record.model_copy(deep=True)
        redacted.confidentiality = Confidentiality.HASH_COMMITTED
        redacted.redaction_method = f"{policy.method}:{original_hash}"
        # Only overwrite access_policy when the caller actually provides one
        # (same P2 guard as legacy mode below).
        if access_policy is not None:
            redacted.access_policy = access_policy
        # Store the commitment shape computed by apply_redaction — the
        # attestation's redacted_payload_hash describes EXACTLY these bytes.
        redacted.payload = redacted_payload
        redacted.redaction_policy_version = policy.version
        redacted.redaction_attestation_ref = attestation.record_id
        return redacted, attestation

    # ---- Legacy mode (v1.0-era): hash commitment without X1/X2.
    payload_canonical = canonicalize(record.payload)
    payload_hash = sha256_hex(payload_canonical)

    redacted = record.model_copy(deep=True)
    redacted.confidentiality = Confidentiality.HASH_COMMITTED
    redacted.redaction_method = f"{method}:{payload_hash}"
    # Only overwrite access_policy when the caller actually provides one.
    # Passing access_policy=None previously erased any pre-existing policy
    # — a bug that silently removed access controls (P2 from structural
    # review).
    if access_policy is not None:
        redacted.access_policy = access_policy
    redacted.payload = {"_redacted": True, "_commitment": f"sha256:{payload_hash}"}

    return redacted, None


def verify_redaction(
    redacted_record: RecordEnvelope,
    original_payload: dict[str, Any],
) -> bool:
    """Verify that a redacted record's hash commitment matches original payload.

    Args:
        redacted_record: The redacted record.
        original_payload: The original (unredacted) payload.

    Returns:
        True if the commitment matches.
    """
    if not redacted_record.redaction_method:
        return False

    # Extract expected hash from redaction method
    parts = redacted_record.redaction_method.split(":")
    if len(parts) < 2:
        return False
    expected_hash = parts[-1]

    # Compute hash of original payload
    payload_canonical = canonicalize(original_payload)
    actual_hash = sha256_hex(payload_canonical)

    return actual_hash == expected_hash


def redact_package(
    package: Package,
    *,
    record_filter: dict[str, Any] | None = None,
    method: str = "sha256-hash-commitment",
    access_policy: dict[str, Any] | None = None,
    policy: RedactionPolicy | None = None,
) -> Package:
    """Create a redacted copy of a package.

    Uses public properties to read package state and _init_from_parts()
    to construct the new package (M-R2-3).

    Policy resolution (VAL-FIX-REDACT-002) mirrors ``Package.record``:

    1. An explicit ``policy`` argument always wins and engages policy mode
       (X1/X2 + in-bundle attestation per redacted record). If the source
       package declares core_version < 1.1, the OUTPUT package's
       core_version is bumped to ``1.1.0`` — the output carries v1.1
       surface (X1/X2 envelope fields and an ``event_log`` with
       ``event_type: "redaction"``) and would self-reject under v1.0
       schemas otherwise (mirrors ``Package._ensure_v1_1``).
    2. Otherwise, on a v1.1+ package the package's attached
       :class:`RedactionPolicy` (``Package(redaction_policy=...)``) is used.
    3. A v1.1+ package with records to redact and NO resolvable policy
       raises :class:`ValueError` — the SDK refuses to mint records the
       validator will then reject with ACEF-074.
    4. A v1.0 package without an explicit policy redacts in legacy mode
       (no X1/X2, no attestation) — the v1.0-era behavior.

    Args:
        package: The package to redact.
        record_filter: Filter criteria for which records to redact.
                      Keys: record_types (list), confidentiality_levels (list).
        method: Redaction method (legacy mode; ``policy.method`` governs in
                policy mode).
        access_policy: Default access policy for redacted records.
        policy: Optional :class:`RedactionPolicy` enabling policy mode
                explicitly (see resolution order above).

    Returns:
        A new Package with selected records redacted. In policy mode the
        minted ``event_log`` attestation records are included so every
        ``redaction_attestation_ref`` (X2) resolves in-bundle (no ACEF-078).

    Raises:
        ValueError: v1.1+ package with records to redact but no
            resolvable RedactionPolicy (rule 3 above).
    """
    if record_filter is None:
        record_filter = {}

    redact_types = set(record_filter.get("record_types", []))
    redact_levels = set(record_filter.get("confidentiality_levels", []))

    explicit_policy = policy is not None
    v1_1_or_later = _core_version_is_v1_1_or_later(package.versioning.core_version)
    resolved_policy: RedactionPolicy | None = policy
    if resolved_policy is None and v1_1_or_later:
        # Mirror Package.record: the attached policy is only consulted on
        # v1.1+ packages (v1.0 bundles have no schema for X1/X2).
        # _redaction_policy is the same private attribute Package.record
        # reads; this module already couples to Package internals via
        # _init_from_parts below.
        attached = getattr(package, "_redaction_policy", None)
        if isinstance(attached, RedactionPolicy):
            resolved_policy = attached

    # Process records (using public .records property)
    new_records: list[RecordEnvelope] = []
    redacted_any = False
    for record in package.records:
        should_redact = False
        if redact_types and record.record_type in redact_types:
            should_redact = True
        if redact_levels and record.confidentiality.value in redact_levels:
            should_redact = True

        if should_redact:
            if v1_1_or_later and resolved_policy is None:
                raise ValueError(
                    "redact_package on a v1.1+ package requires a "
                    "RedactionPolicy: pass policy=... explicitly or attach "
                    "one via Package(redaction_policy=...). Without it the "
                    "redacted records would lack redaction_policy_version "
                    "(X1) and fail validator ACEF-074."
                )
            redacted, attestation = redact_record(
                record,
                policy=resolved_policy,
                method=method,
                access_policy=access_policy,
                urn_generator=package._urn_generator,
            )
            new_records.append(redacted)
            if attestation is not None:
                # Keep X2 resolvable in-bundle (otherwise ACEF-078).
                new_records.append(attestation)
            redacted_any = True
        else:
            new_records.append(record.model_copy(deep=True))

    new_versioning = package.versioning.model_copy(deep=True)
    if explicit_policy and redacted_any and not v1_1_or_later:
        # Rule 1: explicit policy mode on a v1.0 input — the output now
        # carries v1.1 surface and must declare it (the input package is
        # left untouched; only the deep-copied output versioning changes).
        new_versioning.core_version = "1.1.0"

    # Build new package via _init_from_parts using public properties (M-R2-3)
    return Package._init_from_parts(
        metadata=package.metadata.model_copy(deep=True),
        versioning=new_versioning,
        subjects=[s.model_copy(deep=True) for s in package.subjects],
        entities=package.entities.model_copy(deep=True),
        profiles=[p.model_copy(deep=True) for p in package.profiles],
        records=new_records,
        audit_trail=[a.model_copy(deep=True) for a in package.audit_trail],
        attachments=dict(package.attachments),
    )
