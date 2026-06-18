"""Tests for RedactionPolicy + apply_redaction() — VAL-REDACTION-001/002.

Covers:
- VAL-REDACTION-001: ``RedactionPolicy`` Pydantic model with required
  semver-shaped ``version`` field.
- VAL-REDACTION-002: ``apply_redaction(payload, policy)`` returns
  ``(redacted_payload, event_log_record)`` where the event_log record has
  ``event_type: "redaction"`` and an attestation block over policy_version
  + payload hash. The attestation record uses the existing ``event_log``
  record type — NOT a new vendor namespace.
- VAL-FIX-REDACT-006 (audit finding redaction-6): the attestation event_log
  is a hash-domain record, so ``apply_redaction`` REQUIRES an explicit
  ``clock`` callable — a ``None`` clock raises ValueError instead of leaking
  the wall clock into the bundle/Merkle domain.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

import pytest

from acef.integrity import canonicalize, sha256_hex
from acef.models.records import RecordEnvelope
from acef.models.urns import URNType
from acef.redaction import RedactionPolicy, apply_redaction

_FIXED_INSTANT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _fixed_clock() -> datetime:
    return _FIXED_INSTANT


class TestRedactionPolicyModel:
    """VAL-REDACTION-001 — RedactionPolicy model + semver validation."""

    def test_version_required(self) -> None:
        """RedactionPolicy() with no version raises ValidationError."""
        with pytest.raises(Exception) as exc_info:
            RedactionPolicy()  # type: ignore[call-arg]
        # Pydantic v2 ValidationError; do not over-couple to the class
        msg = str(exc_info.value)
        assert "version" in msg

    def test_version_semver_valid(self) -> None:
        """A semver-shaped version is accepted."""
        p = RedactionPolicy(version="1.0.0")
        assert p.version == "1.0.0"

    def test_version_semver_with_prerelease(self) -> None:
        """Semver pre-release suffix is accepted."""
        p = RedactionPolicy(version="2.3.4-rc1")
        assert p.version == "2.3.4-rc1"

    def test_version_non_semver_rejected(self) -> None:
        """A non-semver string is rejected."""
        with pytest.raises(Exception) as exc_info:
            RedactionPolicy(version="abc")
        assert "semver" in str(exc_info.value).lower() or "version" in str(exc_info.value)

    def test_version_two_components_rejected(self) -> None:
        """A two-component version (no patch) is rejected."""
        with pytest.raises(Exception):
            RedactionPolicy(version="1.0")

    def test_default_method(self) -> None:
        """Default method is the hash-commitment one already supported by redact_record."""
        p = RedactionPolicy(version="1.0.0")
        assert p.method == "sha256-hash-commitment"


class TestApplyRedaction:
    """VAL-REDACTION-002 — apply_redaction returns redacted payload + event_log."""

    def test_returns_tuple_of_two(self) -> None:
        policy = RedactionPolicy(version="1.0.0")
        payload = {"description": "sensitive data", "score": 95}
        result = apply_redaction(payload, policy, clock=_fixed_clock)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_second_element_is_event_log_record(self) -> None:
        policy = RedactionPolicy(version="1.0.0")
        payload = {"description": "sensitive data"}
        _, attestation_record = apply_redaction(payload, policy, clock=_fixed_clock)
        assert isinstance(attestation_record, RecordEnvelope)
        assert attestation_record.record_type == "event_log"

    def test_event_log_carries_event_type_redaction(self) -> None:
        """The event_log record payload uses event_type='redaction' — NOT a vendor namespace."""
        policy = RedactionPolicy(version="1.0.0")
        payload = {"k": "v"}
        _, attestation_record = apply_redaction(payload, policy, clock=_fixed_clock)
        assert attestation_record.payload.get("event_type") == "redaction"

    def test_event_log_carries_policy_version(self) -> None:
        policy = RedactionPolicy(version="2.1.0")
        _, attestation_record = apply_redaction({"k": "v"}, policy, clock=_fixed_clock)
        assert attestation_record.payload.get("policy_version") == "2.1.0"

    def test_event_log_carries_payload_hashes(self) -> None:
        """Attestation records original and redacted payload hashes for downstream auditing."""
        policy = RedactionPolicy(version="1.0.0")
        payload = {"x": 1, "y": 2}
        redacted_payload, attestation_record = apply_redaction(payload, policy, clock=_fixed_clock)

        original_hash_expected = sha256_hex(canonicalize(payload))
        redacted_hash_expected = sha256_hex(canonicalize(redacted_payload))

        assert attestation_record.payload.get("original_payload_hash") == original_hash_expected
        assert attestation_record.payload.get("redacted_payload_hash") == redacted_hash_expected

    def test_redacted_payload_strips_secrets(self) -> None:
        """The redacted payload does not contain the original sensitive keys."""
        policy = RedactionPolicy(version="1.0.0")
        payload = {"secret_key": "AKIA...", "score": 99}
        redacted_payload, _ = apply_redaction(payload, policy, clock=_fixed_clock)
        assert "secret_key" not in redacted_payload
        # Should carry the redaction-method marker and hash
        assert redacted_payload.get("redaction_method") == "sha256-hash-commitment"

    def test_redacting_actor_ref_recorded(self) -> None:
        policy = RedactionPolicy(version="1.0.0")
        actor_urn = "urn:acef:actor:11111111-1111-1111-1111-111111111111"
        _, attestation_record = apply_redaction({"k": "v"}, policy, redacting_actor_ref=actor_urn, clock=_fixed_clock)
        assert attestation_record.payload.get("redacting_actor_ref") == actor_urn

    def test_no_vendor_namespace_in_record_type(self) -> None:
        """The attestation record_type must NOT be an x-* vendor namespace.

        VAL-REDACTION-004 codex scope-creep removal: the redaction
        attestation must reuse the Core event_log record type, not invent
        a new vendor record_type like 'x-freddy/redaction-attestation'.
        """
        policy = RedactionPolicy(version="1.0.0")
        _, attestation_record = apply_redaction({"k": "v"}, policy, clock=_fixed_clock)
        assert not attestation_record.record_type.startswith("x-")
        assert attestation_record.record_type == "event_log"


class TestApplyRedactionClockDiscipline:
    """VAL-FIX-REDACT-006 — no wall clock in the hash domain."""

    def test_none_clock_raises_value_error(self) -> None:
        """RED (redaction-6): today a None clock silently mints a wall-clock
        attestation timestamp; it must raise a clear ValueError instead."""
        with pytest.raises(ValueError, match="clock"):
            apply_redaction({"a": 1}, RedactionPolicy(version="1.0.0"))

    def test_non_callable_clock_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="clock"):
            apply_redaction({"a": 1}, RedactionPolicy(version="1.0.0"), clock="2026-01-01T00:00:00Z")

    def test_two_runs_byte_identical_with_injected_clock_and_urns(self) -> None:
        """Determinism: with an injected clock + URN generator, two runs of
        apply_redaction over the same payload produce byte-identical
        attestation records and byte-identical redacted payloads."""

        def make_gen():
            counter = itertools.count()

            def gen(urn_type: URNType) -> str:
                return f"urn:acef:rec:00000000-0000-4000-8000-{next(counter):012d}"

            return gen

        policy = RedactionPolicy(version="1.0.0")
        payload = {"description": "sensitive", "score": 42}

        r1, a1 = apply_redaction(payload, policy, clock=_fixed_clock, urn_generator=make_gen())
        r2, a2 = apply_redaction(payload, policy, clock=_fixed_clock, urn_generator=make_gen())

        assert canonicalize(r1) == canonicalize(r2)
        assert canonicalize(a1.to_jsonl_dict()) == canonicalize(a2.to_jsonl_dict())
        assert a1.timestamp == "2026-01-02T03:04:05Z"


class TestHmacHidingCommitment:
    """PhD-review finding 3: the default sha256-hash-commitment is BINDING but not
    HIDING for low-entropy/enumerable inputs (an attacker brute-forces the preimage
    and confirms it against the published hash). The hmac-sha256-commitment method
    is HIDING when the key is withheld out-of-band (never stored in the bundle)."""

    @staticmethod
    def _clock():
        import datetime as _dt

        return lambda: _dt.datetime(2026, 1, 1, tzinfo=_dt.UTC)

    def test_hmac_commitment_uses_the_key_and_never_stores_it(self) -> None:
        import hashlib
        import hmac as _hmac

        from acef.integrity import canonicalize
        from acef.redaction import RedactionPolicy, apply_redaction

        payload = {"diagnosis": "yes"}  # a low-entropy, enumerable secret
        key = b"out-of-band-secret-key-32-bytes!!"
        policy = RedactionPolicy(version="1.0.0", method="hmac-sha256-commitment")
        redacted, _att = apply_redaction(payload, policy, hmac_key=key, clock=self._clock())

        expected = _hmac.new(key, canonicalize(payload), hashlib.sha256).hexdigest()
        assert redacted["redacted_payload_hash"] == expected
        assert redacted["redaction_method"] == "hmac-sha256-commitment"
        # The key MUST NOT appear anywhere in the stored redacted payload.
        assert key.decode("latin-1") not in str(redacted)
        assert "hmac_key" not in redacted and "key" not in redacted

    def test_hiding_a_brute_force_without_the_key_fails(self) -> None:
        import hashlib

        from acef.integrity import canonicalize
        from acef.redaction import RedactionPolicy, apply_redaction

        payload = {"diagnosis": "yes"}
        key = b"out-of-band-secret-key-32-bytes!!"
        policy = RedactionPolicy(version="1.0.0", method="hmac-sha256-commitment")
        redacted, _att = apply_redaction(payload, policy, hmac_key=key, clock=self._clock())
        # An attacker enumerating the small input space WITHOUT the key computes the
        # plain sha256 of each candidate — which does NOT match the HMAC commitment.
        plain = hashlib.sha256(canonicalize(payload)).hexdigest()
        assert redacted["redacted_payload_hash"] != plain, (
            "HMAC commitment must not equal the (brute-forceable) plain hash"
        )

    def test_hmac_method_requires_a_key(self) -> None:
        from acef.errors import ACEFFormatError
        from acef.redaction import RedactionPolicy, apply_redaction

        policy = RedactionPolicy(version="1.0.0", method="hmac-sha256-commitment")
        try:
            apply_redaction({"x": 1}, policy, clock=self._clock())  # no hmac_key
        except ACEFFormatError as exc:
            assert exc.code == "ACEF-004"
        else:
            raise AssertionError("hmac-sha256-commitment without a key must raise ACEF-004")


class TestHmacFootgunsClosed:
    """roborev on 28df1ec: the keyless convenience paths must NOT produce or accept
    a FALSE hiding commitment (plain sha256 mislabelled as HMAC)."""

    @staticmethod
    def _clock():
        import datetime as _dt

        return lambda: _dt.datetime(2026, 1, 1, tzinfo=_dt.UTC)

    def test_legacy_redact_record_rejects_hmac_method(self) -> None:
        from acef.errors import ACEFFormatError
        from acef.models.records import EntityRefs, RecordEnvelope
        from acef.redaction import redact_record

        rec = RecordEnvelope(
            record_type="risk_register",
            payload={"diagnosis": "yes"},
            entity_refs=EntityRefs(),
            timestamp="2026-01-01T00:00:00Z",
        )
        with pytest.raises(ACEFFormatError) as exc:
            redact_record(rec, method="hmac-sha256-commitment")  # legacy keyless path
        assert exc.value.code == "ACEF-004"
        assert "apply_redaction" in str(exc.value), "the error must point to the key-bearing apply_redaction API"

    def test_verify_redaction_does_not_false_positive_on_mislabelled_hmac(self) -> None:
        from acef.integrity import canonicalize, sha256_hex
        from acef.models.records import EntityRefs, RecordEnvelope
        from acef.redaction import verify_redaction

        payload = {"diagnosis": "yes"}
        plain = sha256_hex(canonicalize(payload))
        # An attacker labels a PLAIN sha256 commitment as HMAC.
        forged = RecordEnvelope(
            record_type="risk_register",
            payload={"_redacted": True},
            entity_refs=EntityRefs(),
            timestamp="2026-01-01T00:00:00Z",
            redaction_method=f"hmac-sha256-commitment:{plain}",
        )
        # WITHOUT a key, an HMAC commitment cannot be verified — must NOT recompute
        # plain sha256 and accept it.
        assert verify_redaction(forged, payload) is False
        assert verify_redaction(forged, payload, hmac_key=b"any-key") is False

    def test_verify_redaction_accepts_real_hmac_with_key(self) -> None:
        import hashlib
        import hmac as _hmac

        from acef.integrity import canonicalize
        from acef.models.records import EntityRefs, RecordEnvelope
        from acef.redaction import verify_redaction

        payload = {"diagnosis": "yes"}
        key = b"out-of-band-secret-key-32-bytes!!"
        commitment = _hmac.new(key, canonicalize(payload), hashlib.sha256).hexdigest()
        rec = RecordEnvelope(
            record_type="risk_register",
            payload={"_redacted": True},
            entity_refs=EntityRefs(),
            timestamp="2026-01-01T00:00:00Z",
            redaction_method=f"hmac-sha256-commitment:{commitment}",
        )
        assert verify_redaction(rec, payload, hmac_key=key) is True
        assert verify_redaction(rec, {"diagnosis": "no"}, hmac_key=key) is False
