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
"""

from __future__ import annotations

from pathlib import Path

from acef.models.enums import Confidentiality
from acef.package import Package
from acef.redaction import RedactionPolicy
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
