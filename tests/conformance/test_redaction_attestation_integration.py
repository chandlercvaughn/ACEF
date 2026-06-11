"""VAL-REDACTION-003 — Package.record() auto-populates X1 + X2 for non-public.

Integration test against the real validator + model stack (no mocks).
A bundle built with ``Package.record(confidentiality="redacted", ...)``
must:

1. Emit a record envelope with ``redaction_policy_version`` (X1) populated
   to the policy semver.
2. Emit a record envelope with ``redaction_attestation_ref`` (X2) populated
   to an in-bundle URN.
3. The referenced URN must resolve to a real ``event_log`` record in the
   bundle (the auto-generated attestation).
4. The validator (``validate_bundle``) MUST NOT emit ACEF-074 or ACEF-078
   for this bundle — the auto-populated fields satisfy the cross-record
   policy/attestation checks.

VAL-FIX-REDACT-001/003/004 (audit findings redaction-1/-3/-4) extend this
file with strip assertions: a ``hash-committed`` / ``redacted`` record built
through ``Package.record`` MUST persist the redacted (commitment-shaped)
payload, NOT the source cleartext, and the stored payload bytes MUST hash to
the attestation's ``redacted_payload_hash``. Access-class confidentiality
levels (``regulator-only`` / ``under-nda``) retain the full payload — the
RFC-0002 incident machinery reads ``incident_report.card_source`` from
regulator-only records, so those are distribution restrictions, not content
transforms.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from acef.integrity import canonicalize, sha256_hex
from acef.models.enums import Confidentiality
from acef.package import Package
from acef.redaction import RedactionPolicy, verify_redaction
from acef.validation.engine import validate_bundle


def _codes(diagnostics: list[dict]) -> list[str]:
    return [d.get("code") for d in diagnostics if isinstance(d, dict)]


def _build_bundle_with_redacted_record(bundle_dir: Path) -> Package:
    """Build a minimal v1.1 bundle containing one redacted record."""
    policy = RedactionPolicy(version="1.0.0")
    pkg = Package(
        producer={"name": "redaction-integration-test", "version": "1.0.0"},
        redaction_policy=policy,
    )
    # Set core_version to 1.1.0 so the v1.1 cross-record validator runs.
    pkg.versioning.core_version = "1.1.0"
    pkg.add_subject(
        subject_type="ai_system",
        name="TestSystem",
        risk_classification="minimal-risk",
    )
    # Record a non-public record — auto-populates X1 + X2.
    pkg.record(
        "risk_register",
        payload={"description": "sensitive risk content", "score": 87},
        confidentiality=Confidentiality.REDACTED,
    )
    pkg.export(str(bundle_dir))
    return pkg


def test_record_envelope_has_redaction_policy_version(tmp_path: Path) -> None:
    """X1 (redaction_policy_version) is auto-populated on non-public records."""
    bundle_dir = tmp_path / "redacted.acef"
    pkg = _build_bundle_with_redacted_record(bundle_dir)

    # Find the redacted user record (not the auto-generated event_log).
    redacted_records = [r for r in pkg.records if r.record_type == "risk_register"]
    assert len(redacted_records) == 1, f"Expected 1 risk_register; got {len(redacted_records)}"
    rec = redacted_records[0]
    assert rec.confidentiality == Confidentiality.REDACTED
    assert rec.redaction_policy_version == "1.0.0", f"X1 not auto-populated; got {rec.redaction_policy_version!r}"


def test_record_envelope_has_redaction_attestation_ref(tmp_path: Path) -> None:
    """X2 (redaction_attestation_ref) is auto-populated and resolves in-bundle."""
    bundle_dir = tmp_path / "redacted.acef"
    pkg = _build_bundle_with_redacted_record(bundle_dir)

    redacted_records = [r for r in pkg.records if r.record_type == "risk_register"]
    rec = redacted_records[0]
    ref = rec.redaction_attestation_ref
    assert ref is not None and ref, f"X2 not auto-populated; got {ref!r}"

    # Must resolve to an in-bundle record (the auto-generated event_log).
    in_bundle_urns = {r.record_id for r in pkg.records}
    assert ref in in_bundle_urns, (
        f"redaction_attestation_ref {ref!r} does not resolve to an in-bundle record. "
        f"In-bundle URNs: {sorted(in_bundle_urns)!r}"
    )


def test_attestation_record_is_event_log_with_event_type_redaction(tmp_path: Path) -> None:
    """The auto-generated attestation is an event_log record with event_type=redaction."""
    bundle_dir = tmp_path / "redacted.acef"
    pkg = _build_bundle_with_redacted_record(bundle_dir)

    event_logs = [r for r in pkg.records if r.record_type == "event_log"]
    assert len(event_logs) >= 1, "Expected at least one auto-generated event_log attestation"
    redaction_attestations = [r for r in event_logs if r.payload.get("event_type") == "redaction"]
    assert len(redaction_attestations) == 1, (
        f"Expected exactly 1 event_log with event_type='redaction'; found {len(redaction_attestations)}"
    )
    att = redaction_attestations[0]
    assert att.payload.get("policy_version") == "1.0.0"


def test_validator_emits_no_acef_074_or_078(tmp_path: Path) -> None:
    """Real validator stack — no ACEF-074 (missing policy version) and no
    ACEF-078 (unresolvable attestation ref) on a Package-built bundle."""
    bundle_dir = tmp_path / "redacted.acef"
    _build_bundle_with_redacted_record(bundle_dir)

    assessment = validate_bundle(bundle_dir)
    emitted = _codes(assessment.structural_errors)

    assert "ACEF-074" not in emitted, (
        f"ACEF-074 (missing redaction_policy_version) should NOT fire after "
        f"Package.record auto-populates X1. Got diagnostics: {emitted!r}"
    )
    assert "ACEF-078" not in emitted, (
        f"ACEF-078 (unresolvable redaction_attestation_ref) should NOT fire "
        f"after Package.record auto-populates X2 with an in-bundle URN. "
        f"Got diagnostics: {emitted!r}"
    )


def test_validator_emits_no_acef_004_on_conformant_redacted_bundle(tmp_path: Path) -> None:
    """fix-F-M2-REDACTION RED: a CONFORMANT redacted bundle must be clean of
    ACEF-004.

    Since F-M2-REDACTION the stored payload of a hash-committed/redacted
    record is the commitment shape (redaction_method /
    redacted_payload_hash / redaction_policy_version), so validating it
    against the per-record-type schema (risk_register requires
    risk_id/description/category) emitted spurious ACEF-004s. The validator
    must route commitment-shaped payloads of X1+X2-bearing redacted records
    to commitment-shape validation instead.
    """
    bundle_dir = tmp_path / "redacted-clean.acef"
    _build_bundle_with_redacted_record(bundle_dir)

    assessment = validate_bundle(bundle_dir)
    offending = [d for d in assessment.structural_errors if isinstance(d, dict) and d.get("code") == "ACEF-004"]
    assert offending == [], (
        "A conformant redacted bundle (commitment-shaped payload + X1/X2) "
        f"must validate clean of ACEF-004; got: "
        f"{[(d.get('code'), d.get('message')) for d in offending]!r}"
    )


def test_record_without_redaction_policy_raises_when_non_public(tmp_path: Path) -> None:
    """Package without a redaction_policy + non-public record raises ValueError.

    The SDK refuses to silently emit a non-public record that the validator
    would reject — it forces the producer to either supply a policy or
    name the policy_version explicitly.
    """
    import pytest

    pkg = Package(producer={"name": "no-policy", "version": "1.0.0"})
    pkg.versioning.core_version = "1.1.0"
    pkg.add_subject(subject_type="ai_system", name="X", risk_classification="minimal-risk")

    with pytest.raises(ValueError, match="redaction_policy"):
        pkg.record(
            "risk_register",
            payload={"description": "x"},
            confidentiality=Confidentiality.REDACTED,
        )


def test_explicit_redaction_policy_version_overrides_auto(tmp_path: Path) -> None:
    """If the caller passes redaction_policy_version explicitly, it is honored."""
    policy = RedactionPolicy(version="1.0.0")
    pkg = Package(
        producer={"name": "explicit-version", "version": "1.0.0"},
        redaction_policy=policy,
    )
    pkg.versioning.core_version = "1.1.0"
    pkg.add_subject(subject_type="ai_system", name="X", risk_classification="minimal-risk")

    explicit_ref = "urn:acef:rec:caller-supplied-attestation"
    rec = pkg.record(
        "risk_register",
        payload={"description": "x"},
        confidentiality=Confidentiality.REDACTED,
        # Pass via kwargs that Package.record must accept (added by this feature).
        redaction_policy_version="9.9.9",
        redaction_attestation_ref=explicit_ref,
    )
    assert rec.redaction_policy_version == "9.9.9"
    assert rec.redaction_attestation_ref == explicit_ref


# ---------------------------------------------------------------------------
# VAL-FIX-REDACT-001 / -003 / -004 (audit findings redaction-1/-3/-4):
# the stored payload of a hash-committed / redacted Package.record output
# MUST be the redacted commitment, never the source cleartext, and MUST
# hash to the attestation's redacted_payload_hash.
# ---------------------------------------------------------------------------

_SECRET_TOKEN = "TOPSECRET-AUDIT-R1-token"
_SECRET_PAYLOAD = {"description": f"{_SECRET_TOKEN} sensitive risk content", "score": 87}


def _read_records_raw(bundle_dir: Path) -> str:
    """Concatenate the raw on-disk bytes of every records/*.jsonl file."""
    return "".join(f.read_text(encoding="utf-8") for f in sorted((bundle_dir / "records").glob("*.jsonl")))


def _build_secret_bundle(
    bundle_dir: Path,
    confidentiality: Confidentiality,
) -> Package:
    """Build + export a v1.1 bundle with one secret-bearing non-public record."""
    policy = RedactionPolicy(version="1.0.0")
    pkg = Package(
        producer={"name": "strip-assertion-test", "version": "1.0.0"},
        redaction_policy=policy,
    )
    pkg.versioning.core_version = "1.1.0"
    pkg.add_subject(
        subject_type="ai_system",
        name="StripTestSystem",
        risk_classification="minimal-risk",
    )
    pkg.record(
        "risk_register",
        payload=dict(_SECRET_PAYLOAD),
        confidentiality=confidentiality,
    )
    pkg.export(str(bundle_dir))
    return pkg


def _stored_record_and_attestation(raw: str) -> tuple[dict, dict]:
    """Parse exported JSONL; return (risk_register record, redaction attestation)."""
    records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    rr = next(r for r in records if r["record_type"] == "risk_register")
    att = next(r for r in records if r["record_type"] == "event_log" and r["payload"].get("event_type") == "redaction")
    return rr, att


def test_hash_committed_export_does_not_contain_cleartext(tmp_path: Path) -> None:
    """redaction-1 RED: the exported JSONL of a hash-committed record built via
    Package.record must NOT contain the source secret tokens."""
    bundle_dir = tmp_path / "hc.acef"
    _build_secret_bundle(bundle_dir, Confidentiality.HASH_COMMITTED)

    raw = _read_records_raw(bundle_dir)
    assert _SECRET_TOKEN not in raw, (
        "'claimed redacted, actually raw': the source secret survived into the "
        "exported records/*.jsonl of a hash-committed record (audit finding redaction-1)."
    )


def test_redacted_export_does_not_contain_cleartext(tmp_path: Path) -> None:
    """confidentiality='redacted' must also strip per the attached policy."""
    bundle_dir = tmp_path / "red.acef"
    _build_secret_bundle(bundle_dir, Confidentiality.REDACTED)

    raw = _read_records_raw(bundle_dir)
    assert _SECRET_TOKEN not in raw, (
        "'claimed redacted, actually raw': the source secret survived into the "
        "exported records/*.jsonl of a redacted record (audit finding redaction-1)."
    )


def test_stored_payload_hashes_to_attestation_redacted_payload_hash(tmp_path: Path) -> None:
    """redaction-3: stored payload bytes == what the X2 attestation describes.

    sha256(JCS(stored payload)) MUST equal the attestation's
    ``redacted_payload_hash`` — the attestation must describe bytes that are
    actually persisted, not a discarded intermediate.
    """
    bundle_dir = tmp_path / "hc-hash.acef"
    _build_secret_bundle(bundle_dir, Confidentiality.HASH_COMMITTED)

    rr, att = _stored_record_and_attestation(_read_records_raw(bundle_dir))
    stored_hash = sha256_hex(canonicalize(rr["payload"]))
    assert stored_hash == att["payload"]["redacted_payload_hash"], (
        f"Stored payload hashes to {stored_hash!r} but the attestation's "
        f"redacted_payload_hash is {att['payload']['redacted_payload_hash']!r} — "
        "the attestation describes bytes that were never stored."
    )
    # The X2 wiring must point at this attestation.
    assert rr["redaction_attestation_ref"] == att["record_id"]


def test_hash_committed_record_redaction_method_and_verify(tmp_path: Path) -> None:
    """The stored record carries a usable redaction_method commitment:
    verify_redaction(record, original_payload) recomputes and matches."""
    bundle_dir = tmp_path / "hc-verify.acef"
    pkg = _build_secret_bundle(bundle_dir, Confidentiality.HASH_COMMITTED)

    rec = next(r for r in pkg.records if r.record_type == "risk_register")
    assert rec.redaction_method is not None and rec.redaction_method.startswith("sha256-hash-commitment:"), (
        f"redaction_method must carry the method:original-hash commitment; got {rec.redaction_method!r}"
    )
    assert verify_redaction(rec, dict(_SECRET_PAYLOAD)) is True
    wrong = {"description": "completely different", "score": 1}
    assert verify_redaction(rec, wrong) is False


def test_regulator_only_payload_is_retained(tmp_path: Path) -> None:
    """Access-class levels (regulator-only/under-nda) are distribution
    restrictions, NOT content transforms: the payload MUST survive so the
    privileged consumer (e.g. RFC-0002 incident_report.card_source readers)
    can read it. X1/X2 are still populated (ACEF-074 applies to all
    non-public records)."""
    bundle_dir = tmp_path / "reg.acef"
    pkg = _build_secret_bundle(bundle_dir, Confidentiality.REGULATOR_ONLY)

    raw = _read_records_raw(bundle_dir)
    assert _SECRET_TOKEN in raw, "regulator-only payload must be retained for the privileged consumer"
    rec = next(r for r in pkg.records if r.record_type == "risk_register")
    assert rec.redaction_policy_version == "1.0.0"
    assert rec.redaction_attestation_ref is not None


# ---------------------------------------------------------------------------
# roborev follow-up on bba166b4 (finding 1, MEDIUM — partial mutation):
# Package.record appended the minted redaction attestation to pkg.records
# BEFORE constructing the primary RecordEnvelope. If envelope construction
# then raised, the package was left mutated with an ORPHAN attestation whose
# X2 consumer was never added. The append must be atomic: nothing lands in
# pkg.records unless the primary envelope construction succeeds, and on the
# success path the ordering (attestation, then primary) is unchanged.
# ---------------------------------------------------------------------------


def _build_atomicity_package() -> Package:
    """v1.1 package with an attached policy and no records yet."""
    pkg = Package(
        producer={"name": "atomic-append-test", "version": "1.0.0"},
        redaction_policy=RedactionPolicy(version="1.0.0"),
    )
    pkg.versioning.core_version = "1.1.0"
    pkg.add_subject(
        subject_type="ai_system",
        name="AtomicSystem",
        risk_classification="minimal-risk",
    )
    return pkg


def test_failed_envelope_construction_leaves_no_orphan_attestation() -> None:
    """RED (roborev bba166b4 #1): a record_id that passes the redaction block
    untouched (it is only validated by RecordEnvelope construction, which runs
    AFTER the attestation was minted and appended) must not leave the package
    mutated. Before the fix: pkg.records grows by 1 — an orphan event_log
    attestation for a record that was never added."""
    pkg = _build_atomicity_package()
    record_ids_before = [r.record_id for r in pkg.records]

    with pytest.raises(ValidationError):
        pkg.record(
            "risk_register",
            payload={"description": "secret content"},
            confidentiality=Confidentiality.HASH_COMMITTED,
            # Invalid on purpose: an int is rejected by the RecordEnvelope
            # model (pydantic str field, no int→str coercion) but flows
            # through record_id resolution and the redaction block untouched.
            record_id=12345,
        )

    record_ids_after = [r.record_id for r in pkg.records]
    assert record_ids_after == record_ids_before, (
        "Package.record mutated pkg.records despite raising: "
        f"{len(record_ids_before)} record(s) before, {len(record_ids_after)} after. "
        "An orphan redaction attestation was appended for a record that was "
        "never added (roborev bba166b4 finding 1)."
    )
    orphan_attestations = [
        r for r in pkg.records if r.record_type == "event_log" and r.payload.get("event_type") == "redaction"
    ]
    assert orphan_attestations == [], (
        f"Found {len(orphan_attestations)} orphan redaction attestation(s) after a failed Package.record call."
    )


def test_success_path_appends_attestation_then_primary_record() -> None:
    """Ordering/audit-trail lock: on the success path the atomic append keeps
    the pre-fix semantics — the minted attestation precedes the primary
    record in pkg.records, and the primary's X2 points at it."""
    pkg = _build_atomicity_package()
    rec = pkg.record(
        "risk_register",
        payload={"description": "secret content"},
        confidentiality=Confidentiality.HASH_COMMITTED,
    )

    record_ids = [r.record_id for r in pkg.records]
    assert record_ids == [rec.redaction_attestation_ref, rec.record_id], (
        "Expected exactly [attestation, primary] in pkg.records after a "
        f"successful redacted Package.record call; got {record_ids!r}"
    )


def test_explicit_attestation_ref_payload_passthrough(tmp_path: Path) -> None:
    """When the caller supplies X1+X2 explicitly, the SDK does not mint an
    attestation and stores the caller's payload verbatim — the caller owns
    pre-redaction in that flow (documented)."""
    policy = RedactionPolicy(version="1.0.0")
    pkg = Package(
        producer={"name": "explicit-passthrough", "version": "1.0.0"},
        redaction_policy=policy,
    )
    pkg.versioning.core_version = "1.1.0"
    pkg.add_subject(subject_type="ai_system", name="X", risk_classification="minimal-risk")

    pre_redacted = {"redaction_method": "sha256-hash-commitment", "redacted_payload_hash": "0" * 64}
    rec = pkg.record(
        "risk_register",
        payload=dict(pre_redacted),
        confidentiality=Confidentiality.HASH_COMMITTED,
        redaction_policy_version="1.0.0",
        redaction_attestation_ref="urn:acef:rec:caller-supplied-attestation",
    )
    assert rec.payload == pre_redacted
