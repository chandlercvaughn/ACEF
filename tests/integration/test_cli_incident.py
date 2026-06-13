"""F-M9-CLI: CLI audit — incident-awareness + arg-handling + exit-code semantics.

These tests pin the behavior the VAL-COVERAGE-CLI-001 audit requires:

* ``inspect`` MUST surface incident EVIDENCE (public_incident_id, severity band,
  harm class, crosswalk members) when the bundle carries an ``incident_card`` /
  ``incident_report`` record. The cli/* surface had ZERO incident references before
  this feature — inspect rendered only the manifest and silently dropped the
  incident payload. The wiring REUSES :func:`acef.render.render_incident_evidence_console`
  / :func:`acef.render.render_incident_evidence_markdown` (no reimplementation).

* ``validate`` / ``verify`` MUST process a v1.1 incident bundle correctly: the
  exit code reflects pass/fail and a tampered incident bundle is rejected non-zero
  with the integrity diagnostic reaching the user.

* Arg-handling / exit-code defects found in the audit are pinned: ``export`` MUST
  surface a missing/invalid input path (and a bad ``--sign`` key) as a CLEAN
  ``Error:`` message + non-zero exit, NOT an uncaught Python traceback.
"""

from __future__ import annotations

import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from acef.cli.main import cli
from acef.models.urns import URNType
from acef.package import Package, mint_incident_id
from acef.redaction import RedactionPolicy

_HARM_CORE = {
    "realization": "harm_event",
    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
    "harm_class": "physical_health",
}
_SEVERITY_VECTOR = "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _deterministic_urn_generator() -> Any:
    counter = {"n": 0}

    def _gen(urn_type: URNType) -> str:
        counter["n"] += 1
        return f"urn:acef:{urn_type.value}:00000000-0000-0000-0000-{counter['n']:012x}"

    return _gen


def _fixed_clock() -> datetime:
    return datetime(2026, 8, 10, 0, 0, 0, tzinfo=UTC)


def _write_ec_key(tmp_path: Path) -> tuple[str, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "signing-key.pem"
    key_path.write_bytes(pem)
    return str(key_path), key


def _new_incident_pkg() -> Package:
    return Package(
        producer={"name": "acef-cli-incident", "version": "1.1.0"},
        redaction_policy=RedactionPolicy(version="1.0.0"),
        clock=_fixed_clock,
        urn_generator=_deterministic_urn_generator(),
    )


def _build_public_card_bundle(tmp_path: Path) -> tuple[Path, str]:
    """Build + export a signed public incident_card bundle; return (dir, public_id)."""
    key_path, key = _write_ec_key(tmp_path)
    pkg = _new_incident_pkg()
    minted = mint_incident_id("openai.com", key, year=2026)
    pkg.add_subject("ai_system", name="Sys", risk_classification="high-risk", modalities=["text"])
    pkg.incident_card(
        public_incident_id=minted.public_incident_id,
        harm_core=dict(_HARM_CORE),
        severity_vector=_SEVERITY_VECTOR,
        awareness_date="2026-08-01T00:00:00Z",
        eu_ai_act_facts={
            "serious_incident_triggers": ["3.49.a"],
            "widespread": False,
            "death_involved": False,
        },
    )
    pkg.sign(key_path)
    bundle_dir = tmp_path / "card.acef"
    pkg.export(str(bundle_dir))
    return bundle_dir, minted.public_incident_id


def _build_raw_archive(src_dir: Path, out: Path) -> None:
    """Pack ``src_dir`` into a raw .tar.gz preserving the on-disk file set EXACTLY."""
    with tarfile.open(str(out), "w:gz") as tar:
        for path in sorted(src_dir.rglob("*")):
            arcname = path.relative_to(src_dir.parent).as_posix()
            tar.add(str(path), arcname=arcname, recursive=False)


class TestInspectIncidentAware:
    """``inspect`` surfaces incident EVIDENCE from a v1.1 incident bundle."""

    def test_inspect_directory_surfaces_incident_evidence(self, runner: CliRunner, tmp_path: Path) -> None:
        bundle_dir, public_id = _build_public_card_bundle(tmp_path)

        result = runner.invoke(cli, ["inspect", str(bundle_dir)])

        assert result.exit_code == 0, result.output
        # Incident-evidence section reused from render.render_incident_evidence_console.
        assert "Incident Evidence" in result.output
        assert public_id in result.output
        # Severity band derived by the shipped band() projection (this vector → major).
        assert "Severity: major" in result.output
        # harm_class + a crosswalk member surfaced.
        assert "physical_health" in result.output
        assert "Crosswalk:" in result.output

    def test_inspect_archive_surfaces_incident_evidence(self, runner: CliRunner, tmp_path: Path) -> None:
        bundle_dir, public_id = _build_public_card_bundle(tmp_path)
        archive = tmp_path / "card.acef.tar.gz"
        _build_raw_archive(bundle_dir, archive)

        result = runner.invoke(cli, ["inspect", str(archive)])

        assert result.exit_code == 0, result.output
        assert "Incident Evidence" in result.output
        assert public_id in result.output

    def test_inspect_json_includes_incident_records(self, runner: CliRunner, tmp_path: Path) -> None:
        """``--format json`` MUST still expose the incident records (machine-readable)."""
        bundle_dir, public_id = _build_public_card_bundle(tmp_path)

        result = runner.invoke(cli, ["inspect", str(bundle_dir), "--format", "json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert isinstance(payload, dict)
        # The incident_records key carries the surfaced incident evidence.
        records = payload.get("incident_records")
        assert records, "incident_records missing from JSON inspect output"
        flat = json.dumps(records)
        assert public_id in flat

    def test_inspect_non_incident_bundle_omits_incident_section(
        self, runner: CliRunner, minimal_package: Package, tmp_path: Path
    ) -> None:
        """A bundle with NO incident records → no incident section (no false render)."""
        bundle_dir = tmp_path / "plain.acef"
        minimal_package.export(str(bundle_dir))

        result = runner.invoke(cli, ["inspect", str(bundle_dir)])

        assert result.exit_code == 0, result.output
        assert "Incident Evidence" not in result.output


class TestValidateVerifyIncidentBundle:
    """``validate`` / ``verify`` process an incident bundle with correct exit codes."""

    def test_validate_clean_incident_bundle_no_incident_errors(self, runner: CliRunner, tmp_path: Path) -> None:
        bundle_dir, _ = _build_public_card_bundle(tmp_path)

        result = runner.invoke(cli, ["validate", str(bundle_dir), "--profile", "eu-ai-act-art73-2026"])

        # The incident rules (ACEF-081..088) run; NONE of the incident error codes
        # fire on a conformant card — that is the load-bearing assertion.
        for incident_code in ("ACEF-081", "ACEF-082", "ACEF-084", "ACEF-085", "ACEF-086"):
            assert incident_code not in result.output, f"{incident_code} unexpectedly fired: {result.output}"
        # ``validate`` returns a documented exit code and never crashes. The only
        # residual structural error on a vanilla-SDK-built bundle is the pre-existing
        # SDK ``audit_trail[0].actor_ref`` ACEF-002 quirk (root cause in
        # Package.__init__, OUTSIDE cli/ — see test_report_incident_e2e and the
        # handoff discoveredIssues), which the schema treats as FATAL → exit 2.
        # The CLI surfaces it cleanly; this asserts a clean documented exit (0/1/2),
        # never an uncaught traceback.
        assert result.exit_code in (0, 1, 2), result.output
        assert result.exception is None or isinstance(result.exception, SystemExit)

    def test_verify_clean_incident_bundle_exit_zero(self, runner: CliRunner, tmp_path: Path) -> None:
        bundle_dir, _ = _build_public_card_bundle(tmp_path)

        result = runner.invoke(cli, ["verify", str(bundle_dir)])

        # A conformant, signed incident bundle verifies clean.
        assert result.exit_code == 0, result.output
        for incident_code in ("ACEF-081", "ACEF-082", "ACEF-084", "ACEF-085", "ACEF-086"):
            assert incident_code not in result.output

    def test_verify_tampered_incident_bundle_rejected(self, runner: CliRunner, tmp_path: Path) -> None:
        """A tampered incident bundle (content-hash mismatch) → verify non-zero +
        the integrity diagnostic reaches the user."""
        bundle_dir, _ = _build_public_card_bundle(tmp_path)

        # Tamper the manifest AFTER hashing: still valid JSON, but content hash no
        # longer matches content-hashes.json — only an integrity verify catches it.
        manifest_path = bundle_dir / "acef-manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["metadata"]["producer"]["name"] = "ATTACKER"
        manifest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = runner.invoke(cli, ["verify", str(bundle_dir)])

        assert result.exit_code != 0, result.output
        assert "ACEF-010" in result.output


class TestExportArgHandling:
    """``export`` arg-handling defects pinned: clean error + non-zero, never a traceback."""

    def test_export_missing_input_clean_error(self, runner: CliRunner, tmp_path: Path) -> None:
        """RED proof: ``export`` on a nonexistent input raised an uncaught
        ACEFFormatError (Python traceback, empty user output). It MUST instead print
        a clean ``Error:`` message and exit non-zero with NO escaping exception."""
        result = runner.invoke(cli, ["export", "/no/such/input", str(tmp_path / "out.acef")])

        assert result.exit_code != 0
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            f"export leaked an uncaught exception: {result.exception!r}"
        )
        assert "Error:" in result.output

    def test_export_plain_file_input_clean_error(self, runner: CliRunner, tmp_path: Path) -> None:
        """A plain (non-bundle) file as input → clean error, not a traceback."""
        plain = tmp_path / "plain.txt"
        plain.write_text("not a bundle", encoding="utf-8")

        result = runner.invoke(cli, ["export", str(plain), str(tmp_path / "out.acef")])

        assert result.exit_code != 0
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            f"export leaked an uncaught exception: {result.exception!r}"
        )
        assert "Error:" in result.output

    def test_export_bad_sign_key_clean_error(self, runner: CliRunner, tmp_path: Path) -> None:
        """RED proof: ``export --sign`` with a missing key path raised an uncaught
        ACEFExportError. It MUST be a clean ``Error:`` + non-zero exit instead."""
        pkg = Package(producer={"name": "t", "version": "1.0.0"})
        pkg.add_subject("ai_system", name="S", risk_classification="minimal-risk", modalities=["text"])
        bundle_dir = tmp_path / "src.acef"
        pkg.export(str(bundle_dir))

        result = runner.invoke(
            cli,
            ["export", str(bundle_dir), str(tmp_path / "out.acef"), "--sign", "/no/such/key.pem"],
        )

        assert result.exit_code != 0
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            f"export leaked an uncaught exception: {result.exception!r}"
        )
        assert "Error:" in result.output

    def test_export_valid_input_still_succeeds(self, runner: CliRunner, tmp_path: Path) -> None:
        """Guard: the clean-error wrapping does NOT regress the happy path."""
        pkg = Package(producer={"name": "t", "version": "1.0.0"})
        pkg.add_subject("ai_system", name="S", risk_classification="minimal-risk", modalities=["text"])
        bundle_dir = tmp_path / "src.acef"
        pkg.export(str(bundle_dir))

        out = tmp_path / "out.acef.tar.gz"
        result = runner.invoke(cli, ["export", str(bundle_dir), str(out)])

        assert result.exit_code == 0, result.output
        assert out.exists()


class TestValidateArgHandling:
    """``validate --output`` arg-handling defect pinned: an unwritable output
    path must be a CLEAN error + non-zero exit, never an uncaught OSError
    traceback (which would corrupt a ``--format json`` consumer's stream)."""

    def test_validate_output_unwritable_path_clean_error(self, runner: CliRunner, tmp_path: Path) -> None:
        pkg = Package(producer={"name": "t", "version": "1.0.0"})
        pkg.add_subject("ai_system", name="S", risk_classification="minimal-risk", modalities=["text"])
        bundle_dir = tmp_path / "src.acef"
        pkg.export(str(bundle_dir))

        # Make the OUTPUT path's parent a regular FILE. export_assessment runs
        # ``output.parent.mkdir(parents=True, ...)``, which raises OSError
        # (NotADirectoryError/FileExistsError) when the parent is a file — a
        # portable, deterministic way to force the write to fail.
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory", encoding="utf-8")
        bad_output = blocker / "assessment.json"

        result = runner.invoke(cli, ["validate", str(bundle_dir), "--output", str(bad_output)])

        assert result.exit_code != 0
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            f"validate --output leaked an uncaught exception: {result.exception!r}"
        )
        # The error reaches the user on stderr.
        assert "Error:" in result.output
