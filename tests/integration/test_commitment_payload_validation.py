"""fix-F-M2-REDACTION — commitment-shaped payload validation for redacted records.

Since F-M2-REDACTION, a record whose ``confidentiality`` is ``hash-committed``
or ``redacted`` STORES the commitment shape minted by
:func:`acef.redaction.apply_redaction`::

    {
        "redaction_method": "sha256-hash-commitment",
        "redacted_payload_hash": "<64 lowercase hex chars>",
        "redaction_policy_version": "<policy semver>",
        "access_policy": {...}   # optional
    }

But ``validate_record_schemas`` validated EVERY record's payload against its
per-record-type schema, so a conformant redacted ``risk_register`` (which has
no ``risk_id``/``description``/``category`` BY DESIGN) emitted spurious
ACEF-004s. This file pins the fixed routing:

1. A hash-committed / redacted record carrying X1 (``redaction_policy_version``)
   AND X2 (``redaction_attestation_ref``) on the envelope has its payload
   validated against the COMMITMENT shape — a well-formed commitment is clean.
2. A malformed commitment (bad hash grammar, unknown method, missing keys,
   extra keys, non-object access_policy) emits ACEF-004.
3. FAIL-CLOSED: a record merely LABELED hash-committed/redacted without BOTH
   X1 and X2 still gets per-type payload validation — there is no bypass lane
   for mislabeled records (cleartext or commitment-shaped alike).
4. Access-class levels (``regulator-only`` / ``under-nda``) retain cleartext
   payloads (distribution restriction, not content transform) and keep
   per-type validation even though X1/X2 are populated.
5. Ordinary public-record validation and envelope-level validation are
   unchanged.
"""

from __future__ import annotations

from typing import Any

from acef.validation.schema_validator import validate_record_schemas

# A 64-char lowercase-hex digest, the shape sha256_hex() mints.
_VALID_HASH = "e144bf5311cc15474fc2211de01c951f6e5a8c2f6cdd96fb599750b0f3c36297"

_VALID_RISK_REGISTER_PAYLOAD: dict[str, Any] = {
    "risk_id": "R-001",
    "description": "model drift risk",
    "category": "safety",
}


def _commitment_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "redaction_method": "sha256-hash-commitment",
        "redacted_payload_hash": _VALID_HASH,
        "redaction_policy_version": "1.0.0",
    }
    payload.update(overrides)
    return payload


def _record(
    payload: dict[str, Any],
    *,
    confidentiality: str = "hash-committed",
    x1: str | None = "1.0.0",
    x2: str | None = "urn:acef:rec:05f25c54-eb39-416d-a88e-9d52ab4858e8",
    record_type: str = "risk_register",
) -> dict[str, Any]:
    """A fully envelope-valid v1.1 record wrapper (mirrors Package export)."""
    record: dict[str, Any] = {
        "record_id": "urn:acef:rec:170552ac-5f87-4512-8db7-d8fd65e2f268",
        "record_type": record_type,
        "provisions_addressed": [],
        "timestamp": "2026-01-01T00:00:00Z",
        "lifecycle_phase": "development",
        "collector": {"name": "commitment-validation-test", "version": "1.0.0"},
        "obligation_role": "provider",
        "confidentiality": confidentiality,
        "trust_level": "self-attested",
        "entity_refs": {
            "subject_refs": [],
            "component_refs": [],
            "dataset_refs": [],
            "actor_refs": [],
        },
        "attachments": [],
        "payload": payload,
    }
    if x1 is not None:
        record["redaction_policy_version"] = x1
    if x2 is not None:
        record["redaction_attestation_ref"] = x2
    return record


def _diags(record: dict[str, Any]) -> list[Any]:
    return validate_record_schemas([record], "v1.1")


def _codes(diagnostics: list[Any]) -> list[str]:
    return [d.code for d in diagnostics]


# --------------------------------------------------------------------------- #
# 1. Conformant commitment payloads validate CLEANLY                          #
# --------------------------------------------------------------------------- #


def test_hash_committed_commitment_payload_is_clean() -> None:
    """RED (the defect): a conformant hash-committed record — the exact shape
    apply_redaction mints, X1+X2 on the envelope — must NOT emit ACEF-004."""
    diagnostics = _diags(_record(_commitment_payload()))
    assert diagnostics == [], (
        f"A conformant commitment-shaped redacted record must validate "
        f"cleanly; got {[(d.code, d.message) for d in diagnostics]!r}"
    )


def test_redacted_confidentiality_commitment_payload_is_clean() -> None:
    """confidentiality='redacted' routes to commitment validation too."""
    diagnostics = _diags(_record(_commitment_payload(), confidentiality="redacted"))
    assert diagnostics == [], (
        f"A conformant 'redacted' commitment record must validate cleanly; "
        f"got {[(d.code, d.message) for d in diagnostics]!r}"
    )


def test_commitment_with_access_policy_is_clean() -> None:
    """access_policy is the one OPTIONAL commitment key (an object)."""
    payload = _commitment_payload(access_policy={"roles": ["auditor"]})
    diagnostics = _diags(_record(payload))
    assert diagnostics == [], (
        f"access_policy is an allowed optional commitment key; got {[(d.code, d.message) for d in diagnostics]!r}"
    )


# --------------------------------------------------------------------------- #
# 2. Malformed commitments emit ACEF-004 (fail closed on the shape itself)    #
# --------------------------------------------------------------------------- #


def test_short_commitment_hash_emits_acef_004() -> None:
    payload = _commitment_payload(redacted_payload_hash="0" * 63)
    assert "ACEF-004" in _codes(_diags(_record(payload)))


def test_prefixed_commitment_hash_emits_acef_004() -> None:
    """apply_redaction mints BARE lowercase hex — a 'sha256:'-prefixed value
    is not the producer's shape and must be rejected (fail closed)."""
    payload = _commitment_payload(redacted_payload_hash=f"sha256:{_VALID_HASH}")
    assert "ACEF-004" in _codes(_diags(_record(payload)))


def test_uppercase_commitment_hash_emits_acef_004() -> None:
    payload = _commitment_payload(redacted_payload_hash=_VALID_HASH.upper())
    assert "ACEF-004" in _codes(_diags(_record(payload)))


def test_unknown_redaction_method_emits_acef_004() -> None:
    payload = _commitment_payload(redaction_method="rot13-super-secure")
    assert "ACEF-004" in _codes(_diags(_record(payload)))


def test_missing_redaction_policy_version_key_emits_acef_004() -> None:
    payload = _commitment_payload()
    del payload["redaction_policy_version"]
    assert "ACEF-004" in _codes(_diags(_record(payload)))


def test_non_string_payload_policy_version_emits_acef_004() -> None:
    payload = _commitment_payload(redaction_policy_version=100)
    assert "ACEF-004" in _codes(_diags(_record(payload)))


def test_extra_key_in_commitment_emits_acef_004() -> None:
    """'Exactly the commitment keys': leftover cleartext alongside the
    commitment is a malformed commitment, not a valid redaction."""
    payload = _commitment_payload(description="leaked cleartext field")
    assert "ACEF-004" in _codes(_diags(_record(payload)))


def test_non_object_access_policy_emits_acef_004() -> None:
    payload = _commitment_payload(access_policy="everyone")
    assert "ACEF-004" in _codes(_diags(_record(payload)))


def test_malformed_commitment_collects_all_problems() -> None:
    """Phase-1 discipline: collect ALL commitment-shape problems, not just
    the first one."""
    payload = _commitment_payload(
        redaction_method="rot13",
        redacted_payload_hash="nope",
    )
    del payload["redaction_policy_version"]
    diagnostics = _diags(_record(payload))
    acef_004 = [d for d in diagnostics if d.code == "ACEF-004"]
    assert len(acef_004) >= 3, (
        f"Expected >=3 ACEF-004 diagnostics (method, hash, missing version); "
        f"got {[(d.code, d.message) for d in diagnostics]!r}"
    )


# --------------------------------------------------------------------------- #
# 3. FAIL-CLOSED: no bypass lane without BOTH X1 and X2                       #
# --------------------------------------------------------------------------- #


def test_hash_committed_cleartext_without_x1_x2_fails_per_type() -> None:
    """A record LABELED hash-committed but carrying a cleartext-looking
    payload and NO X1/X2 still gets per-type validation and fails."""
    record = _record({"foo": "cleartext"}, x1=None, x2=None)
    codes = _codes(_diags(record))
    assert "ACEF-004" in codes, (
        "A mislabeled hash-committed record without X1/X2 must NOT bypass per-record-type payload validation."
    )


def test_commitment_shaped_payload_without_x1_x2_no_bypass() -> None:
    """Even a commitment-SHAPED payload does not engage commitment routing
    without the X1+X2 envelope surface — per-type validation applies."""
    record = _record(_commitment_payload(), x1=None, x2=None)
    codes = _codes(_diags(record))
    assert "ACEF-004" in codes, (
        "Commitment routing must require BOTH X1 and X2 on the envelope; "
        "a bare commitment-shaped payload is not a conformant redaction."
    )


def test_hash_committed_with_only_x1_no_bypass() -> None:
    record = _record(_commitment_payload(), x2=None)
    assert "ACEF-004" in _codes(_diags(record))


def test_hash_committed_with_only_x2_no_bypass() -> None:
    record = _record(_commitment_payload(), x1=None)
    assert "ACEF-004" in _codes(_diags(record))


def test_hash_committed_with_empty_string_x1_no_bypass() -> None:
    record = _record(_commitment_payload(), x1="")
    assert "ACEF-004" in _codes(_diags(record))


# --------------------------------------------------------------------------- #
# 4. Access-class levels keep per-type validation (cleartext is retained)     #
# --------------------------------------------------------------------------- #


def test_regulator_only_valid_cleartext_payload_is_clean() -> None:
    """regulator-only retains the full payload (distribution restriction, not
    a content transform) — per-type validation applies and passes."""
    record = _record(
        dict(_VALID_RISK_REGISTER_PAYLOAD),
        confidentiality="regulator-only",
    )
    diagnostics = _diags(record)
    assert diagnostics == [], (
        f"regulator-only cleartext payload must pass per-type validation; "
        f"got {[(d.code, d.message) for d in diagnostics]!r}"
    )


def test_regulator_only_invalid_cleartext_payload_fails_per_type() -> None:
    record = _record({"foo": "bar"}, confidentiality="regulator-only")
    assert "ACEF-004" in _codes(_diags(record))


# --------------------------------------------------------------------------- #
# 5. Public records + envelope validation unchanged                           #
# --------------------------------------------------------------------------- #


def test_public_valid_payload_unchanged() -> None:
    record = _record(
        dict(_VALID_RISK_REGISTER_PAYLOAD),
        confidentiality="public",
        x1=None,
        x2=None,
    )
    assert _diags(record) == []


def test_public_invalid_payload_unchanged() -> None:
    record = _record({"foo": "bar"}, confidentiality="public", x1=None, x2=None)
    assert "ACEF-004" in _codes(_diags(record))


def test_envelope_validation_still_runs_for_commitment_records() -> None:
    """Envelope-level schema validation is unchanged: a commitment record
    missing a required envelope field still emits the envelope ACEF-004."""
    record = _record(_commitment_payload())
    del record["timestamp"]
    diagnostics = _diags(record)
    envelope_violations = [d for d in diagnostics if d.code == "ACEF-004" and "envelope" in d.message]
    assert envelope_violations, (
        f"Missing envelope field must still emit the envelope ACEF-004; "
        f"got {[(d.code, d.message) for d in diagnostics]!r}"
    )


def test_unknown_record_type_still_emits_acef_003_for_commitment_records() -> None:
    """The record-type allowlist gate runs BEFORE commitment routing: an
    unknown type is ACEF-003 regardless of redaction surface."""
    record = _record(_commitment_payload(), record_type="totally_unknown_type")
    codes = _codes(_diags(record))
    assert "ACEF-003" in codes


# --------------------------------------------------------------------------- #
# Drift guard: the validator's supported-method set mirrors redaction's       #
# --------------------------------------------------------------------------- #


def test_supported_method_sets_do_not_drift() -> None:
    """schema_validator keeps a local copy of the supported redaction methods
    (so the validation layer does not import the Package-building redaction
    module). This guard fails the build if the two sets ever diverge."""
    from acef.redaction import _SUPPORTED_REDACTION_METHODS
    from acef.validation.schema_validator import _SUPPORTED_COMMITMENT_METHODS

    assert _SUPPORTED_COMMITMENT_METHODS == _SUPPORTED_REDACTION_METHODS
