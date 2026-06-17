"""F1 (doctor coherence) — ``acef doctor`` must NOT call a schema-invalid bundle healthy.

Before the fix, ``doctor`` ran only structure/manifest/integrity/records phases — NO
schema and NO reference phase — yet its docstring claimed it "Checks ... references" and
it printed "Bundle looks healthy" + exit 0 on a bundle that ``acef validate`` rejects
FATAL. ``doctor`` and ``validate`` must not disagree on whether a bundle is valid.
"""

from __future__ import annotations

from pathlib import Path

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
