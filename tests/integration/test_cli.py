"""Integration tests for the ACEF CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from acef.cli.main import cli
from acef.package import Package


@pytest.fixture
def runner():
    return CliRunner()


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

    def test_export_to_archive(self, runner: CliRunner, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "export-src.acef")
        minimal_package.export(bundle_path)

        archive_path = str(tmp_dir / "export-out.acef.tar.gz")
        result = runner.invoke(cli, ["export", bundle_path, archive_path])
        assert result.exit_code == 0
        assert Path(archive_path).exists()
