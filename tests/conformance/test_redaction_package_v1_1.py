"""VAL-FIX-REDACT-002 (audit finding redaction-2) — redact_package v1.1 conformance.

The module-level redaction entry points (``redact_record`` / ``redact_package``)
previously stripped the payload but never set the X1 (``redaction_policy_version``)
or X2 (``redaction_attestation_ref``) envelope fields, so their own output fired
ACEF-074 under v1.1 validation — a self-rejecting redaction feature.

This file proves the fixed end-to-end contract with the real validator stack
(no mocks): a ``redact_package`` output exported at ``core_version`` 1.1.0

1. validates with NO ACEF-074 (X1 present on every non-public record) and
   NO ACEF-078 (X2 resolves to an in-bundle attestation record);
2. actually strips the sensitive payload from the exported bytes;
3. persists a payload whose sha256-of-JCS equals the attestation's
   ``redacted_payload_hash`` (the attestation describes stored bytes).
"""

from __future__ import annotations

import json
from pathlib import Path

from acef.integrity import canonicalize, sha256_hex
from acef.package import Package
from acef.redaction import RedactionPolicy, redact_package
from acef.validation.engine import validate_bundle

_SECRET_TOKEN = "TOPSECRET-AUDIT-R2-token"


def _codes(diagnostics: list[dict]) -> list[str]:
    return [d.get("code") for d in diagnostics if isinstance(d, dict)]


def _build_v1_1_source_package() -> Package:
    """A v1.1 package with an attached RedactionPolicy and two public records."""
    policy = RedactionPolicy(version="1.0.0")
    pkg = Package(
        producer={"name": "redact-package-conformance", "version": "1.0.0"},
        redaction_policy=policy,
    )
    pkg.versioning.core_version = "1.1.0"
    pkg.add_subject(
        subject_type="ai_system",
        name="RedactPackageSystem",
        risk_classification="minimal-risk",
    )
    pkg.record(
        "risk_register",
        payload={"description": f"{_SECRET_TOKEN} sensitive risk content", "score": 87},
    )
    pkg.record("dataset_card", payload={"name": "open-data"})
    return pkg


def _read_records_raw(bundle_dir: Path) -> str:
    return "".join(f.read_text(encoding="utf-8") for f in sorted((bundle_dir / "records").glob("*.jsonl")))


def test_redact_package_v1_1_end_to_end_no_acef_074_or_078(tmp_path: Path) -> None:
    """Exported redact_package output validates with no ACEF-074 / ACEF-078."""
    pkg = _build_v1_1_source_package()
    redacted_pkg = redact_package(pkg, record_filter={"record_types": ["risk_register"]})

    bundle_dir = tmp_path / "redacted-v11.acef"
    redacted_pkg.export(str(bundle_dir))

    assessment = validate_bundle(bundle_dir)
    emitted = _codes(assessment.structural_errors)
    assert "ACEF-074" not in emitted, f"redact_package output still missing X1 (redaction_policy_version): {emitted!r}"
    assert "ACEF-078" not in emitted, (
        f"redact_package output has an unresolvable X2 (redaction_attestation_ref): {emitted!r}"
    )


def test_redact_package_v1_1_payload_stripped_and_hash_matches(tmp_path: Path) -> None:
    """The exported bytes contain no source secret; the stored payload hashes
    to the attestation's redacted_payload_hash; X2 resolves in-bundle."""
    pkg = _build_v1_1_source_package()
    redacted_pkg = redact_package(pkg, record_filter={"record_types": ["risk_register"]})

    bundle_dir = tmp_path / "redacted-v11-strip.acef"
    redacted_pkg.export(str(bundle_dir))

    raw = _read_records_raw(bundle_dir)
    assert _SECRET_TOKEN not in raw, "redact_package left the source secret in the exported JSONL"

    records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    rr = next(r for r in records if r["record_type"] == "risk_register")
    assert rr["confidentiality"] == "hash-committed"
    assert rr["redaction_policy_version"] == "1.0.0"

    ref = rr["redaction_attestation_ref"]
    attestations = [r for r in records if r["record_id"] == ref]
    assert len(attestations) == 1, f"X2 {ref!r} must resolve to exactly one in-bundle record"
    att = attestations[0]
    assert att["record_type"] == "event_log"
    assert att["payload"]["event_type"] == "redaction"

    stored_hash = sha256_hex(canonicalize(rr["payload"]))
    assert stored_hash == att["payload"]["redacted_payload_hash"], (
        "attestation redacted_payload_hash does not describe the stored payload bytes"
    )

    # Untouched records stay public and unmodified.
    dc = next(r for r in records if r["record_type"] == "dataset_card")
    assert dc["confidentiality"] == "public"
    assert dc["payload"] == {"name": "open-data"}


def test_redact_package_v1_1_without_policy_raises(tmp_path: Path) -> None:
    """A v1.1 package with no policy (param or attached) must refuse to mint
    self-rejecting output (mirrors Package.record's ACEF-074 refusal)."""
    import pytest

    pkg = Package(producer={"name": "no-policy", "version": "1.0.0"})
    pkg.versioning.core_version = "1.1.0"
    pkg.add_subject(subject_type="ai_system", name="X", risk_classification="minimal-risk")
    pkg.record("risk_register", payload={"x": 1})

    with pytest.raises(ValueError, match="RedactionPolicy"):
        redact_package(pkg, record_filter={"record_types": ["risk_register"]})


def test_redact_package_explicit_policy_bumps_v1_0_output_to_v1_1(tmp_path: Path) -> None:
    """An explicit policy on a v1.0 package engages policy mode: the OUTPUT
    declares core 1.1.0 (it carries X1/X2 + event_type='redaction', which are
    v1.1 surface) while the input package is left untouched."""
    pkg = Package(producer={"name": "v10-explicit", "version": "1.0.0"})
    pkg.add_subject(subject_type="ai_system", name="X", risk_classification="minimal-risk")
    pkg.record("risk_register", payload={"x": 1})
    assert pkg.versioning.core_version == "1.0.0"

    redacted_pkg = redact_package(
        pkg,
        record_filter={"record_types": ["risk_register"]},
        policy=RedactionPolicy(version="1.0.0"),
    )
    assert redacted_pkg.versioning.core_version == "1.1.0"
    assert pkg.versioning.core_version == "1.0.0"
