"""F1 (doctor coherence) — ``acef doctor`` must NOT call a schema-invalid bundle healthy.

Before the fix, ``doctor`` ran only structure/manifest/integrity/records phases — NO
schema and NO reference phase — yet its docstring claimed it "Checks ... references" and
it printed "Bundle looks healthy" + exit 0 on a bundle that ``acef validate`` rejects
FATAL. ``doctor`` and ``validate`` must not disagree on whether a bundle is valid.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from acef.cli.main import cli
from acef.package import Package


def _schema_invalid_bundle(tmp_path: Path) -> str:
    """A bundle that is structurally well-formed (valid hashes/Merkle) but
    schema-invalid: its subject declares no modalities (schema minItems:1)."""
    pkg = Package(producer={"name": "acef-sdk", "version": "0.1.0"})
    pkg.add_subject("ai_system", name="S", risk_classification="high-risk")  # no modalities
    out = str(tmp_path / "schema-invalid.acef")
    pkg.export(out)
    return out


def test_doctor_fails_on_schema_invalid_bundle_like_validate(tmp_path: Path) -> None:
    """doctor MUST exit non-zero (matching ``validate``) on a schema-invalid bundle and
    must NOT print 'Bundle looks healthy'."""
    bundle = _schema_invalid_bundle(tmp_path)
    runner = CliRunner()
    validate = runner.invoke(cli, ["validate", bundle])
    assert validate.exit_code == 2, "precondition: validate rejects this bundle FATAL"

    doctor = runner.invoke(cli, ["doctor", bundle])
    assert doctor.exit_code != 0, f"doctor must agree with validate (non-zero), got {doctor.exit_code}\n{doctor.output}"
    assert "looks healthy" not in doctor.output.lower(), "doctor must not call a schema-invalid bundle healthy"
    assert "ACEF-002" in doctor.output, "doctor must surface the schema violation"


def test_doctor_agrees_with_validate_on_a_nonfatal_reference_diagnostic(tmp_path: Path) -> None:
    """roborev on 7c29922: ``validate`` fails only on FATAL structural errors (or a
    NOT_SATISFIED provision); a NON-fatal diagnostic (e.g. a dangling subject_ref ->
    non-fatal ACEF-020) is advisory and exits 0. doctor must AGREE — it must not exit
    non-zero on a non-fatal diagnostic — and must file it under its real category
    ('reference'), not mislabel it '[schema]'."""
    pkg = Package(producer={"name": "acef-sdk", "version": "0.1.0"})
    pkg.add_subject(
        "ai_system",
        name="S",
        version="1.0.0",
        provider="P",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )
    pkg.record(
        "risk_register",
        payload={
            "risk_id": "R1",
            "description": "x",
            "category": "safety",
            "likelihood": "possible",
            "severity": "major",
        },
        obligation_role="provider",
        entity_refs={"subject_refs": ["urn:acef:sub:00000000-0000-0000-0000-000000000999"]},  # dangling
    )
    bundle = str(tmp_path / "dangling.acef")
    pkg.export(bundle)
    runner = CliRunner()
    validate = runner.invoke(cli, ["validate", bundle])
    doctor = runner.invoke(cli, ["doctor", bundle])
    assert validate.exit_code == doctor.exit_code == 0, (
        f"doctor must agree with validate on a non-fatal diagnostic; "
        f"validate={validate.exit_code} doctor={doctor.exit_code}"
    )
    assert "ACEF-020" in doctor.output
    assert "[reference]" in doctor.output, "ACEF-020 must be filed under its real 'reference' category"


def test_doctor_passes_a_clean_bundle(tmp_path: Path) -> None:
    """A fully-valid bundle still passes doctor (exit 0)."""
    pkg = Package(producer={"name": "acef-sdk", "version": "0.1.0"})
    pkg.add_subject(
        "ai_system",
        name="S",
        version="1.0.0",
        provider="P",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )
    out = str(tmp_path / "clean.acef")
    pkg.export(out)
    result = CliRunner().invoke(cli, ["doctor", out])
    assert result.exit_code == 0, result.output


def test_doctor_files_integrity_phase_diagnostic_under_its_real_category(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """roborev on 6700802: ACEF-051 (hash-domain canonicalization) is emitted by the
    INTEGRITY phase (so it is excluded from the schema/reference dedup set), but
    ``_check_integrity`` hardcoded the category as ``"integrity"`` — yet ACEF-051 is
    registered ``format`` (not ``integrity``). Each integrity-phase diagnostic must be
    filed under its OWN serialized category, so ACEF-051 surfaces as ``[format]`` not a
    mislabeled ``[integrity]``. The common integrity codes (ACEF-010..014, genuinely
    ``integrity``) are unaffected."""
    from acef.cli import doctor_cmd
    from acef.errors import ValidationDiagnostic

    # ACEF-051's category auto-resolves to ErrorCategory.FORMAT in ValidationDiagnostic.
    monkeypatch.setattr(
        "acef.validation.integrity_checker.check_integrity",
        lambda _bundle: [ValidationDiagnostic("ACEF-051", "non-NFC attachment path", path="/records/x.jsonl")],
    )
    issues: list[tuple[str, str, str]] = []
    doctor_cmd._check_integrity(tmp_path, issues)

    assert issues, "the synthetic ACEF-051 integrity diagnostic must be surfaced"
    _severity, category, message = issues[0]
    assert category == "format", f"ACEF-051 must be filed under its real category 'format', got {category!r}"
    assert "ACEF-051" in message
