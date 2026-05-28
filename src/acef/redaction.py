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
        clock: Optional zero-arg callable returning a timezone-aware
            ``datetime``. Used to mint the attestation record's timestamp
            for deterministic output (VAL-SDK-007 parity). Defaults to
            the standard :class:`RecordEnvelope` factory which uses
            ``datetime.now(timezone.utc)``.
        urn_generator: Optional callable ``(URNType) -> str`` used to mint
            the attestation record's ``record_id``. Defaults to
            :func:`acef.models.urns.generate_urn`.
        access_policy: Optional access policy carried into the redacted
            payload's ``access_policy`` field.

    Returns:
        ``(redacted_payload, attestation_record)``.

    Raises:
        ACEFFormatError: If ``policy.method`` is not supported.
    """
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

    envelope_kwargs: dict[str, Any] = {
        "record_id": gen_urn(URNType.RECORD),
        "record_type": "event_log",
        "payload": attestation_payload,
    }
    if callable(clock):
        from datetime import UTC

        ts_dt = clock()
        if ts_dt.tzinfo is None:
            ts_dt = ts_dt.replace(tzinfo=UTC)
        else:
            ts_dt = ts_dt.astimezone(UTC)
        envelope_kwargs["timestamp"] = ts_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    attestation_record = RecordEnvelope(**envelope_kwargs)
    return redacted_payload, attestation_record


def redact_record(
    record: RecordEnvelope,
    *,
    method: str = "sha256-hash-commitment",
    access_policy: dict[str, Any] | None = None,
) -> RecordEnvelope:
    """Create a redacted copy of a record.

    The payload is replaced with a hash commitment. The original payload
    hash is stored in ``redaction_method`` so verifiers can recompute it
    against the original payload via :func:`verify_redaction`.

    Args:
        record: The record to redact.
        method: Redaction method (default: ``sha256-hash-commitment``).
            Must be a documented method in
            :data:`_SUPPORTED_REDACTION_METHODS`; arbitrary strings are
            rejected so misspellings cannot produce records labeled with
            a method downstream tools cannot interpret.
        access_policy: Who can see the full payload. If ``None``, the
            record's existing ``access_policy`` is preserved rather than
            overwritten — passing ``None`` should not strip an existing
            policy.

    Returns:
        A new :class:`RecordEnvelope` with redacted payload.

    Raises:
        ACEFFormatError: If ``method`` is not a documented redaction
            method.
    """
    if method not in _SUPPORTED_REDACTION_METHODS:
        raise ACEFFormatError(
            f"Unsupported redaction method: {method!r}. Supported methods: {sorted(_SUPPORTED_REDACTION_METHODS)}",
            code="ACEF-004",
        )

    # Compute hash of canonical payload
    payload_canonical = canonicalize(record.payload)
    payload_hash = sha256_hex(payload_canonical)

    # Create redacted copy
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

    return redacted


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
) -> Package:
    """Create a redacted copy of a package.

    Uses public properties to read package state and _init_from_parts()
    to construct the new package (M-R2-3).

    Args:
        package: The package to redact.
        record_filter: Filter criteria for which records to redact.
                      Keys: record_types (list), confidentiality_levels (list).
        method: Redaction method.
        access_policy: Default access policy for redacted records.

    Returns:
        A new Package with selected records redacted.
    """
    if record_filter is None:
        record_filter = {}

    redact_types = set(record_filter.get("record_types", []))
    redact_levels = set(record_filter.get("confidentiality_levels", []))

    # Process records (using public .records property)
    new_records = []
    for record in package.records:
        should_redact = False
        if redact_types and record.record_type in redact_types:
            should_redact = True
        if redact_levels and record.confidentiality.value in redact_levels:
            should_redact = True

        if should_redact:
            redacted = redact_record(record, method=method, access_policy=access_policy)
            new_records.append(redacted)
        else:
            new_records.append(record.model_copy(deep=True))

    # Build new package via _init_from_parts using public properties (M-R2-3)
    return Package._init_from_parts(
        metadata=package.metadata.model_copy(deep=True),
        versioning=package.versioning.model_copy(deep=True),
        subjects=[s.model_copy(deep=True) for s in package.subjects],
        entities=package.entities.model_copy(deep=True),
        profiles=[p.model_copy(deep=True) for p in package.profiles],
        records=new_records,
        audit_trail=[a.model_copy(deep=True) for a in package.audit_trail],
        attachments=dict(package.attachments),
    )
