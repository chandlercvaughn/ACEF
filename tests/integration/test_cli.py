"""Integration tests for the ACEF CLI."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from acef.cli.main import cli
from acef.package import Package


@pytest.fixture
def runner():
    return CliRunner()


def _build_raw_archive(src_dir: Path, out: Path, *, skip: set[str] | None = None) -> None:
    """Pack ``src_dir`` into a raw .tar.gz at ``out``, preserving the on-disk
    file set EXACTLY (optionally omitting members named in ``skip``).

    This deliberately does NOT go through ``export_archive`` / ``Package.export``:
    those regenerate ``hashes/content-hashes.json`` and ``hashes/merkle-tree.json``
    from the loaded records, which would heal any tampering. To prove doctor
    detects a tampered archive we must ship the tampered bytes verbatim, with
    the bundle nested under its root directory exactly like a real archive.
    """
    skip = skip or set()
    with tarfile.open(str(out), "w:gz") as tar:
        for path in sorted(src_dir.rglob("*")):
            inner = path.relative_to(src_dir).as_posix()
            if inner in skip:
                continue
            arcname = path.relative_to(src_dir.parent).as_posix()
            tar.add(str(path), arcname=arcname, recursive=False)


class TestCLI:
    """CLI command integration tests."""

    def test_version(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_init_creates_bundle(self, runner: CliRunner, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "new-bundle.acef")
        result = runner.invoke(cli, ["init", bundle_path])
        assert result.exit_code == 0
        assert "Created ACEF bundle" in result.output
        assert (tmp_dir / "new-bundle.acef" / "acef-manifest.json").exists()

    def test_init_with_subject(self, runner: CliRunner, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "with-subject.acef")
        result = runner.invoke(
            cli,
            [
                "init",
                bundle_path,
                "--subject-name",
                "Test System",
                "--subject-type",
                "ai_system",
                "--risk-classification",
                "high-risk",
            ],
        )
        assert result.exit_code == 0

    def test_inspect_bundle(self, runner: CliRunner, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "inspect.acef")
        minimal_package.export(bundle_path)

        result = runner.invoke(cli, ["inspect", bundle_path])
        assert result.exit_code == 0

    def test_inspect_json(self, runner: CliRunner, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "inspect-json.acef")
        minimal_package.export(bundle_path)

        result = runner.invoke(cli, ["inspect", bundle_path, "--format", "json"])
        assert result.exit_code == 0

    def test_validate_bundle(self, runner: CliRunner, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "validate.acef")
        minimal_package.export(bundle_path)

        result = runner.invoke(cli, ["validate", bundle_path])
        # Exit code 0 (pass), 1 (not satisfied), or 2 (fatal schema errors) are all valid
        # depending on schema strictness. The command should complete without exceptions.
        assert result.exit_code in (0, 1, 2)

    def test_doctor_healthy_bundle(self, runner: CliRunner, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "doctor.acef")
        minimal_package.export(bundle_path)

        result = runner.invoke(cli, ["doctor", bundle_path])
        assert result.exit_code == 0

    def test_doctor_absent_merkle_tree_is_fatal(
        self, runner: CliRunner, minimal_package: Package, tmp_dir: Path
    ) -> None:
        """doctor must agree with the validator: absent merkle-tree.json (content-hashes.json
        present) is FATAL ACEF-011 with a non-zero exit, NOT a warning + exit 0.

        Finding (roborev Medium on c3d914a1): doctor reported a missing
        ``hashes/merkle-tree.json`` as a WARNING and exited 0, while
        ``check_integrity`` now treats the same condition as FATAL ACEF-011.
        That made doctor exit 0 for a bundle ``validate`` rejects — inconsistent
        severity + exit status. RED proof: before the fix doctor prints
        "No merkle-tree.json found" as a warning and exits 0.
        """
        bundle_path = str(tmp_dir / "doctor-no-merkle.acef")
        minimal_package.export(bundle_path)

        merkle_path = Path(bundle_path) / "hashes" / "merkle-tree.json"
        content_hashes_path = Path(bundle_path) / "hashes" / "content-hashes.json"
        assert merkle_path.exists()
        assert content_hashes_path.exists()
        merkle_path.unlink()
        assert not merkle_path.exists()

        result = runner.invoke(cli, ["doctor", bundle_path])

        assert result.exit_code != 0, "doctor exited 0 for a bundle the validator rejects with FATAL ACEF-011"
        assert "ACEF-011" in result.output
        assert "merkle-tree.json" in result.output
        # It must be reported as an error, not a warning — the summary line
        # counts at least one error and zero false content-hash mismatches.
        assert "0 errors" not in result.output

    def test_doctor_complete_bundle_still_clean(
        self, runner: CliRunner, minimal_package: Package, tmp_dir: Path
    ) -> None:
        """A complete, untouched bundle (merkle-tree.json present) → doctor exits 0.

        Guards that promoting the absent-Merkle branch does not regress the
        healthy-bundle exit path.
        """
        bundle_path = str(tmp_dir / "doctor-complete.acef")
        minimal_package.export(bundle_path)

        assert (Path(bundle_path) / "hashes" / "merkle-tree.json").exists()

        result = runner.invoke(cli, ["doctor", bundle_path])
        assert result.exit_code == 0
        assert "ACEF-011" not in result.output

    def test_doctor_healthy_archive_is_clean(self, runner: CliRunner, minimal_package: Package, tmp_dir: Path) -> None:
        """A healthy .acef.tar.gz archive → doctor exits 0 and verifies integrity.

        Guards the archive happy path: delegating archive integrity to
        ``check_integrity`` must NOT regress a clean archive into an error.
        """
        bundle_dir = tmp_dir / "healthy.acef"
        minimal_package.export(str(bundle_dir))
        archive = tmp_dir / "healthy.acef.tar.gz"
        _build_raw_archive(bundle_dir, archive)

        result = runner.invoke(cli, ["doctor", str(archive)])
        assert result.exit_code == 0, result.output
        assert "ACEF-011" not in result.output
        assert "ACEF-010" not in result.output

    def test_doctor_archive_absent_merkle_tree_is_fatal(
        self, runner: CliRunner, minimal_package: Package, tmp_dir: Path
    ) -> None:
        """ARCHIVE parity with the directory path: an .acef.tar.gz whose
        ``hashes/merkle-tree.json`` is removed (content-hashes.json present) is
        FATAL ACEF-011 with a non-zero exit.

        Finding (roborev Medium on d8a3a4f9): for archive inputs doctor only
        called ``load(path)`` and returned BEFORE any integrity check. ``load()``
        does not verify ``hashes/merkle-tree.json``, so a tampered archive
        (merkle-tree.json stripped) exited 0 — while the equivalent directory
        bundle and ``validate`` both reject it with FATAL ACEF-011. RED proof:
        before the fix doctor prints "Archive loads successfully" and exits 0.
        """
        bundle_dir = tmp_dir / "src-no-merkle.acef"
        minimal_package.export(str(bundle_dir))
        assert (bundle_dir / "hashes" / "merkle-tree.json").exists()
        assert (bundle_dir / "hashes" / "content-hashes.json").exists()

        archive = tmp_dir / "no-merkle.acef.tar.gz"
        _build_raw_archive(bundle_dir, archive, skip={"hashes/merkle-tree.json"})

        result = runner.invoke(cli, ["doctor", str(archive)])
        assert result.exit_code != 0, "doctor exited 0 for a tampered archive the validator rejects with FATAL ACEF-011"
        assert "ACEF-011" in result.output
        assert "merkle-tree.json" in result.output

    def test_doctor_archive_content_hash_mismatch_matches_validate(
        self, runner: CliRunner, minimal_package: Package, tmp_dir: Path
    ) -> None:
        """ARCHIVE content-hash mismatch (valid JSON, tampered field) → doctor
        reports it as an error and exits non-zero, in PARITY with ``validate``.

        RED proof: before the fix the archive branch skipped integrity entirely,
        so doctor printed "Archive loads successfully" and exited 0 even though
        ``validate`` flags the same archive with FATAL ACEF-010.
        """
        bundle_dir = tmp_dir / "src-tamper.acef"
        minimal_package.export(str(bundle_dir))

        # Tamper a field inside the manifest. The result is STILL valid JSON and
        # a structurally valid bundle, but its content hash no longer matches
        # content-hashes.json — only an integrity verify catches it.
        manifest_path = bundle_dir / "acef-manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["metadata"]["producer"]["name"] = "ATTACKER"
        manifest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        archive = tmp_dir / "tampered-field.acef.tar.gz"
        _build_raw_archive(bundle_dir, archive)

        # validate's verdict on the SAME archive (the parity oracle).
        validate_result = runner.invoke(cli, ["validate", str(archive)])

        doctor_result = runner.invoke(cli, ["doctor", str(archive)])
        assert doctor_result.exit_code != 0, (
            "doctor exited 0 for an archive with a content-hash mismatch that validate rejects"
        )
        assert "ACEF-010" in doctor_result.output
        # Parity: validate also fails (fatal) on the tampered archive.
        assert validate_result.exit_code != 0, validate_result.output

    def test_export_to_archive(self, runner: CliRunner, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "export-src.acef")
        minimal_package.export(bundle_path)

        archive_path = str(tmp_dir / "export-out.acef.tar.gz")
        result = runner.invoke(cli, ["export", bundle_path, archive_path])
        assert result.exit_code == 0
        assert Path(archive_path).exists()
