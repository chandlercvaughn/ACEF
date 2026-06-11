"""Tests for acef.redaction — privacy-preserving redaction with hash commitments.

Covers the legacy (v1.0-era) hash-commitment path AND the policy mode added
for audit finding redaction-2 (VAL-FIX-REDACT-002): ``redact_record`` /
``redact_package`` accept a :class:`RedactionPolicy`, set the X1
(``redaction_policy_version``) and X2 (``redaction_attestation_ref``)
envelope fields, and mint the Core ``event_log`` attestation describing the
STORED payload bytes — mirroring ``Package.record``.
"""

from __future__ import annotations

import pytest

from acef.integrity import canonicalize, sha256_hex
from acef.models.enums import Confidentiality
from acef.models.records import RecordEnvelope
from acef.package import Package
from acef.redaction import RedactionPolicy, redact_package, redact_record, verify_redaction
from acef.validation.cross_record import enforce_redaction_policy_version


def _make_record(
    record_type: str = "risk_register",
    payload: dict | None = None,
    confidentiality: Confidentiality = Confidentiality.PUBLIC,
) -> RecordEnvelope:
    """Helper to create a record for testing."""
    return RecordEnvelope(
        record_type=record_type,
        payload=payload or {"description": "sensitive data", "score": 95},
        confidentiality=confidentiality,
    )


class TestRedactRecordLegacyMode:
    """Legacy mode (no policy): v1.0-era hash commitment, no X1/X2, no attestation."""

    def test_creates_hash_commitment(self):
        original = _make_record()
        redacted, attestation = redact_record(original)

        assert attestation is None
        assert redacted.confidentiality == Confidentiality.HASH_COMMITTED
        assert redacted.redaction_method is not None
        assert "sha256-hash-commitment:" in redacted.redaction_method
        assert redacted.payload["_redacted"] is True
        assert redacted.payload["_commitment"].startswith("sha256:")

    def test_preserves_envelope_fields(self):
        original = _make_record()
        redacted, _ = redact_record(original)

        assert redacted.record_id == original.record_id
        assert redacted.record_type == original.record_type
        assert redacted.timestamp == original.timestamp

    def test_original_payload_not_in_redacted(self):
        original = _make_record(payload={"secret": "value123"})
        redacted, _ = redact_record(original)

        assert "secret" not in redacted.payload
        assert "value123" not in str(redacted.payload)

    def test_access_policy_set(self):
        original = _make_record()
        policy = {"roles": ["regulator"], "organizations": ["EU Commission"]}
        redacted, _ = redact_record(original, access_policy=policy)

        assert redacted.access_policy == policy

    def test_hash_is_deterministic(self):
        original = _make_record(payload={"key": "value"})
        r1, _ = redact_record(original)
        r2, _ = redact_record(original)

        # Same payload should produce same hash
        assert r1.redaction_method == r2.redaction_method

    def test_no_x1_x2_in_legacy_mode(self):
        """Without a policy the output targets v1.0 bundles: no X1/X2 emitted.

        (Such records fail ACEF-074 if placed in a v1.1 bundle — callers
        targeting v1.1 must pass ``policy=``; ``redact_package`` enforces it.)
        """
        original = _make_record()
        redacted, attestation = redact_record(original)

        assert redacted.redaction_policy_version is None
        assert redacted.redaction_attestation_ref is None
        assert attestation is None


class TestRedactRecordPolicyMode:
    """VAL-FIX-REDACT-002 — policy mode sets X1/X2 + mints the attestation."""

    def test_x1_set_from_policy_version(self):
        original = _make_record()
        redacted, _ = redact_record(original, policy=RedactionPolicy(version="2.0.0"))

        assert redacted.redaction_policy_version == "2.0.0"

    def test_no_acef_074_on_policy_mode_output(self):
        """RED (redaction-2): today this output fires ACEF-074 — after the fix
        the validator's own X1 rule passes on the module's entry point."""
        original = _make_record()
        redacted, _ = redact_record(original, policy=RedactionPolicy(version="1.0.0"))

        diags = enforce_redaction_policy_version([redacted.to_jsonl_dict()])
        assert [d.code for d in diags] == [], (
            f"redact_record output must satisfy the v1.1 X1 rule; got {[d.code for d in diags]!r}"
        )

    def test_attestation_minted_and_wired_to_x2(self):
        original = _make_record()
        redacted, attestation = redact_record(original, policy=RedactionPolicy(version="1.0.0"))

        assert attestation is not None
        assert attestation.record_type == "event_log"
        assert attestation.payload["event_type"] == "redaction"
        assert attestation.payload["policy_version"] == "1.0.0"
        assert redacted.redaction_attestation_ref == attestation.record_id

    def test_stored_payload_hash_matches_attestation(self):
        """The attestation's redacted_payload_hash describes the STORED payload."""
        original = _make_record(payload={"secret": "S3CR3T-token"})
        redacted, attestation = redact_record(original, policy=RedactionPolicy(version="1.0.0"))

        assert attestation is not None
        stored_hash = sha256_hex(canonicalize(redacted.payload))
        assert stored_hash == attestation.payload["redacted_payload_hash"]
        assert "S3CR3T-token" not in str(redacted.payload)

    def test_attestation_timestamp_pinned_to_source_record(self):
        """Determinism: the attestation timestamp derives from the source
        record's timestamp, never from the wall clock."""
        original = RecordEnvelope(
            record_type="risk_register",
            payload={"k": "v"},
            timestamp="2026-01-02T03:04:05Z",
        )
        _, attestation = redact_record(original, policy=RedactionPolicy(version="1.0.0"))

        assert attestation is not None
        assert attestation.timestamp == "2026-01-02T03:04:05Z"

    def test_verify_redaction_works_in_policy_mode(self):
        original_payload = {"description": "sensitive data", "score": 95}
        original = _make_record(payload=dict(original_payload))
        redacted, _ = redact_record(original, policy=RedactionPolicy(version="1.0.0"))

        assert verify_redaction(redacted, original_payload) is True
        assert verify_redaction(redacted, {"description": "other"}) is False

    def test_injected_urn_generator_used_for_attestation(self):
        from acef.models.urns import URNType

        def gen(urn_type: URNType) -> str:
            return "urn:acef:rec:00000000-0000-4000-8000-000000000042"

        original = _make_record()
        redacted, attestation = redact_record(original, policy=RedactionPolicy(version="1.0.0"), urn_generator=gen)
        assert attestation is not None
        assert attestation.record_id == "urn:acef:rec:00000000-0000-4000-8000-000000000042"
        assert redacted.redaction_attestation_ref == attestation.record_id


class TestVerifyRedaction:
    """Test verify_redaction matches original payload."""

    def test_verify_succeeds_with_correct_payload(self):
        original_payload = {"description": "sensitive data", "score": 95}
        original = _make_record(payload=original_payload)
        redacted, _ = redact_record(original)

        assert verify_redaction(redacted, original_payload)

    def test_verify_fails_with_different_payload(self):
        original_payload = {"description": "sensitive data", "score": 95}
        original = _make_record(payload=original_payload)
        redacted, _ = redact_record(original)

        tampered = {"description": "modified data", "score": 50}
        assert not verify_redaction(redacted, tampered)

    def test_verify_fails_without_redaction_method(self):
        record = _make_record()
        assert not verify_redaction(record, {"key": "value"})

    def test_verify_fails_with_bad_redaction_method(self):
        record = _make_record()
        record.redaction_method = "invalid"
        assert not verify_redaction(record, {"key": "value"})


class TestRedactPackage:
    """Test redact_package filters by record_type and confidentiality."""

    def test_redact_by_record_type(self):
        pkg = Package()
        pkg.record("risk_register", payload={"risk": "high"})
        pkg.record("dataset_card", payload={"name": "Data"})

        redacted_pkg = redact_package(
            pkg,
            record_filter={"record_types": ["risk_register"]},
        )

        assert len(redacted_pkg.records) == 2

        rr = next(r for r in redacted_pkg.records if r.record_type == "risk_register")
        dc = next(r for r in redacted_pkg.records if r.record_type == "dataset_card")

        assert rr.confidentiality == Confidentiality.HASH_COMMITTED
        assert rr.payload.get("_redacted") is True

        assert dc.confidentiality == Confidentiality.PUBLIC
        assert dc.payload == {"name": "Data"}

    def test_redact_by_confidentiality_level(self):
        pkg = Package()
        pkg.record("risk_register", payload={"r": 1}, confidentiality="regulator-only")
        pkg.record("dataset_card", payload={"d": 1}, confidentiality="public")

        redacted_pkg = redact_package(
            pkg,
            record_filter={"confidentiality_levels": ["regulator-only"]},
        )

        rr = next(r for r in redacted_pkg.records if r.record_type == "risk_register")
        dc = next(r for r in redacted_pkg.records if r.record_type == "dataset_card")

        assert rr.confidentiality == Confidentiality.HASH_COMMITTED
        assert dc.confidentiality == Confidentiality.PUBLIC

    def test_redacted_package_preserves_metadata(self):
        pkg = Package(producer={"name": "tool", "version": "1.0"})
        pkg.add_subject("ai_system", name="System")
        pkg.record("risk_register", payload={"x": 1})

        redacted_pkg = redact_package(pkg, record_filter={"record_types": ["risk_register"]})

        assert redacted_pkg.metadata.package_id == pkg.metadata.package_id
        assert len(redacted_pkg.subjects) == 1

    def test_empty_filter_no_redaction(self):
        pkg = Package()
        pkg.record("risk_register", payload={"x": 1})

        redacted_pkg = redact_package(pkg)

        rec = redacted_pkg.records[0]
        assert rec.confidentiality == Confidentiality.PUBLIC
        assert rec.payload == {"x": 1}

    def test_v1_0_legacy_mode_appends_no_attestation(self):
        """Pins the v1.0 contract: no policy → no attestation record appended,
        record count unchanged (matches the legacy integration tests)."""
        pkg = Package()
        pkg.record("risk_register", payload={"x": 1})

        redacted_pkg = redact_package(pkg, record_filter={"record_types": ["risk_register"]})

        assert len(redacted_pkg.records) == 1
        rec = redacted_pkg.records[0]
        assert rec.redaction_policy_version is None
        assert rec.redaction_attestation_ref is None


class TestRedactPackagePolicyMode:
    """VAL-FIX-REDACT-002 — v1.1 packages wire X1/X2 + append the attestation."""

    def _v1_1_pkg(self, *, attach_policy: bool = True) -> Package:
        kwargs = {"producer": {"name": "t", "version": "1.0"}}
        if attach_policy:
            kwargs["redaction_policy"] = RedactionPolicy(version="1.0.0")
        pkg = Package(**kwargs)
        pkg.versioning.core_version = "1.1.0"
        pkg.add_subject("ai_system", name="System")
        return pkg

    def test_attached_policy_sets_x1_x2_and_appends_attestation(self):
        pkg = self._v1_1_pkg()
        pkg.record("risk_register", payload={"secret": "S"})

        redacted_pkg = redact_package(pkg, record_filter={"record_types": ["risk_register"]})

        rr = next(r for r in redacted_pkg.records if r.record_type == "risk_register")
        assert rr.redaction_policy_version == "1.0.0"
        assert rr.redaction_attestation_ref is not None

        in_bundle = {r.record_id for r in redacted_pkg.records}
        assert rr.redaction_attestation_ref in in_bundle

        attestations = [
            r
            for r in redacted_pkg.records
            if r.record_type == "event_log" and r.payload.get("event_type") == "redaction"
        ]
        assert len(attestations) == 1

    def test_explicit_policy_param_wins_over_attached(self):
        pkg = self._v1_1_pkg()
        pkg.record("risk_register", payload={"secret": "S"})

        redacted_pkg = redact_package(
            pkg,
            record_filter={"record_types": ["risk_register"]},
            policy=RedactionPolicy(version="3.1.4"),
        )
        rr = next(r for r in redacted_pkg.records if r.record_type == "risk_register")
        assert rr.redaction_policy_version == "3.1.4"

    def test_v1_1_without_policy_raises(self):
        pkg = self._v1_1_pkg(attach_policy=False)
        pkg.record("risk_register", payload={"x": 1})

        with pytest.raises(ValueError, match="RedactionPolicy"):
            redact_package(pkg, record_filter={"record_types": ["risk_register"]})

    def test_v1_1_without_policy_no_matching_records_does_not_raise(self):
        pkg = self._v1_1_pkg(attach_policy=False)
        pkg.record("dataset_card", payload={"name": "open"})

        redacted_pkg = redact_package(pkg, record_filter={"record_types": ["risk_register"]})
        assert len(redacted_pkg.records) == 1
        assert redacted_pkg.records[0].confidentiality == Confidentiality.PUBLIC
