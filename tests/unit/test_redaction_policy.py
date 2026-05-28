"""Tests for RedactionPolicy + apply_redaction() — VAL-REDACTION-001/002.

Covers:
- VAL-REDACTION-001: ``RedactionPolicy`` Pydantic model with required
  semver-shaped ``version`` field.
- VAL-REDACTION-002: ``apply_redaction(payload, policy)`` returns
  ``(redacted_payload, event_log_record)`` where the event_log record has
  ``event_type: "redaction"`` and an attestation block over policy_version
  + payload hash. The attestation record uses the existing ``event_log``
  record type — NOT a new vendor namespace.
"""

from __future__ import annotations

import pytest

from acef.integrity import canonicalize, sha256_hex
from acef.models.records import RecordEnvelope
from acef.redaction import RedactionPolicy, apply_redaction


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
        result = apply_redaction(payload, policy)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_second_element_is_event_log_record(self) -> None:
        policy = RedactionPolicy(version="1.0.0")
        payload = {"description": "sensitive data"}
        _, attestation_record = apply_redaction(payload, policy)
        assert isinstance(attestation_record, RecordEnvelope)
        assert attestation_record.record_type == "event_log"

    def test_event_log_carries_event_type_redaction(self) -> None:
        """The event_log record payload uses event_type='redaction' — NOT a vendor namespace."""
        policy = RedactionPolicy(version="1.0.0")
        payload = {"k": "v"}
        _, attestation_record = apply_redaction(payload, policy)
        assert attestation_record.payload.get("event_type") == "redaction"

    def test_event_log_carries_policy_version(self) -> None:
        policy = RedactionPolicy(version="2.1.0")
        _, attestation_record = apply_redaction({"k": "v"}, policy)
        assert attestation_record.payload.get("policy_version") == "2.1.0"

    def test_event_log_carries_payload_hashes(self) -> None:
        """Attestation records original and redacted payload hashes for downstream auditing."""
        policy = RedactionPolicy(version="1.0.0")
        payload = {"x": 1, "y": 2}
        redacted_payload, attestation_record = apply_redaction(payload, policy)

        original_hash_expected = sha256_hex(canonicalize(payload))
        redacted_hash_expected = sha256_hex(canonicalize(redacted_payload))

        assert attestation_record.payload.get("original_payload_hash") == original_hash_expected
        assert attestation_record.payload.get("redacted_payload_hash") == redacted_hash_expected

    def test_redacted_payload_strips_secrets(self) -> None:
        """The redacted payload does not contain the original sensitive keys."""
        policy = RedactionPolicy(version="1.0.0")
        payload = {"secret_key": "AKIA...", "score": 99}
        redacted_payload, _ = apply_redaction(payload, policy)
        assert "secret_key" not in redacted_payload
        # Should carry the redaction-method marker and hash
        assert redacted_payload.get("redaction_method") == "sha256-hash-commitment"

    def test_redacting_actor_ref_recorded(self) -> None:
        policy = RedactionPolicy(version="1.0.0")
        actor_urn = "urn:acef:actor:11111111-1111-1111-1111-111111111111"
        _, attestation_record = apply_redaction({"k": "v"}, policy, redacting_actor_ref=actor_urn)
        assert attestation_record.payload.get("redacting_actor_ref") == actor_urn

    def test_no_vendor_namespace_in_record_type(self) -> None:
        """The attestation record_type must NOT be an x-* vendor namespace.

        VAL-REDACTION-004 codex scope-creep removal: the redaction
        attestation must reuse the Core event_log record type, not invent
        a new vendor record_type like 'x-freddy/redaction-attestation'.
        """
        policy = RedactionPolicy(version="1.0.0")
        _, attestation_record = apply_redaction({"k": "v"}, policy)
        assert not attestation_record.record_type.startswith("x-")
        assert attestation_record.record_type == "event_log"
