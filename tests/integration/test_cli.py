"""Integration tests for the ACEF CLI."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from acef.cli.main import cli
from acef.errors import ACEFFormatError
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


def _clean_package() -> Package:
    """Build a SCHEMA-VALID minimal package.

    The shared ``minimal_package`` fixture carries a deliberately loose
    risk_register payload (legacy field names) that trips FATAL ACEF-004
    payload-schema errors — fine for asserting on integrity-code PRESENCE, but
    it cannot prove a "healthy bundle → exit 0" path because the schema noise
    keeps the exit code non-zero. ``verify`` exits 0 here because the only
    remaining diagnostic (``ACEF-002`` empty ``audit_trail[0].actor_ref``) is a
    known baseline downgrade.
    """
    pkg = Package(producer={"name": "test-tool", "version": "1.0.0"})
    system = pkg.add_subject(
        "ai_system",
        name="Test System",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )
    pkg.record(
        "risk_register",
        provisions=["article-9"],
        payload={
            "risk_id": "R-1",
            "description": "Test risk",
            "category": "safety",
            "likelihood": "possible",
            "severity": "major",
        },
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    return pkg


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

    def test_validate_archive_missing_merkle_reports_acef011(
        self, runner: CliRunner, minimal_package: Package, tmp_dir: Path
    ) -> None:
        """ARCHIVE with ``hashes/merkle-tree.json`` stripped → ``acef validate``
        MUST surface FATAL ACEF-011 (the integrity verdict), not silently heal it.

        RED proof (roborev Medium on 40b11e4a): ``validate`` resolved an archive
        input by ``load(path)`` then ``pkg.export(...)`` into a temp dir before
        running the validator. That round-trip REGENERATES
        ``hashes/content-hashes.json`` / ``hashes/merkle-tree.json`` from the
        loaded records, so the stripped Merkle tree is rebuilt and the tampering
        is HEALED — ``validate`` ran against the recomputed (clean) integrity
        files and never emitted ACEF-011. (The exit code happened to be non-zero
        only because of unrelated baseline payload-schema errors in the fixture,
        masking the real defect.) The integrity code is the load-bearing signal:
        on the tampered archive it must be PRESENT.
        """
        bundle_dir = tmp_dir / "val-no-merkle.acef"
        minimal_package.export(str(bundle_dir))
        assert (bundle_dir / "hashes" / "merkle-tree.json").exists()
        assert (bundle_dir / "hashes" / "content-hashes.json").exists()

        archive = tmp_dir / "val-no-merkle.acef.tar.gz"
        _build_raw_archive(bundle_dir, archive, skip={"hashes/merkle-tree.json"})

        result = runner.invoke(cli, ["validate", str(archive)])
        assert result.exit_code != 0, result.output
        assert "ACEF-011" in result.output, (
            "validate healed the stripped merkle-tree.json instead of reporting ACEF-011"
        )

    def test_validate_archive_content_hash_mismatch_reports_acef010(
        self, runner: CliRunner, minimal_package: Package, tmp_dir: Path
    ) -> None:
        """ARCHIVE with a content-hash mismatch (a record/manifest byte changed
        after hashing) → ``acef validate`` MUST surface FATAL ACEF-010.

        RED proof: the load→export round-trip recomputes content-hashes.json from
        the tampered bytes, so the recomputed hashes match the tampered content
        and the mismatch is HEALED — ACEF-010 never fires. Validating the raw
        archive bytes as-received catches it.
        """
        bundle_dir = tmp_dir / "val-tamper.acef"
        minimal_package.export(str(bundle_dir))

        # Tamper a manifest field AFTER hashing: still valid JSON and a
        # structurally valid bundle, but its content hash no longer matches the
        # frozen content-hashes.json entry. Only an integrity verify catches it.
        manifest_path = bundle_dir / "acef-manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["metadata"]["producer"]["name"] = "ATTACKER"
        manifest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        archive = tmp_dir / "val-tampered-field.acef.tar.gz"
        _build_raw_archive(bundle_dir, archive)

        result = runner.invoke(cli, ["validate", str(archive)])
        assert result.exit_code != 0, result.output
        assert "ACEF-010" in result.output, "validate healed the content-hash mismatch instead of reporting ACEF-010"

    def test_validate_healthy_archive_no_integrity_errors(
        self, runner: CliRunner, minimal_package: Package, tmp_dir: Path
    ) -> None:
        """A healthy, untampered archive → ``acef validate`` emits NO integrity
        codes (ACEF-010/ACEF-011). Guards that validating the raw archive bytes
        does not regress a clean archive into a false integrity failure.
        """
        bundle_dir = tmp_dir / "val-healthy.acef"
        minimal_package.export(str(bundle_dir))
        archive = tmp_dir / "val-healthy.acef.tar.gz"
        _build_raw_archive(bundle_dir, archive)

        result = runner.invoke(cli, ["validate", str(archive)])
        assert "ACEF-011" not in result.output, result.output
        assert "ACEF-010" not in result.output, result.output

    def test_verify_archive_missing_merkle_rejected(
        self, runner: CliRunner, minimal_package: Package, tmp_dir: Path
    ) -> None:
        """``acef verify`` on an ARCHIVE with ``hashes/merkle-tree.json`` stripped
        → FATAL ACEF-011, non-zero exit.

        RED proof: ``verify`` rejected ANY non-directory path outright
        ("bundle path is not a directory") and so could not verify archive
        integrity at all — a CI gate that silently never inspected archives.
        """
        bundle_dir = tmp_dir / "vfy-no-merkle.acef"
        minimal_package.export(str(bundle_dir))
        archive = tmp_dir / "vfy-no-merkle.acef.tar.gz"
        _build_raw_archive(bundle_dir, archive, skip={"hashes/merkle-tree.json"})

        result = runner.invoke(cli, ["verify", str(archive)])
        assert result.exit_code != 0, result.output
        assert "ACEF-011" in result.output

    def test_verify_archive_content_hash_mismatch_rejected(
        self, runner: CliRunner, minimal_package: Package, tmp_dir: Path
    ) -> None:
        """``acef verify`` on an ARCHIVE with a content-hash mismatch → FATAL
        ACEF-010, non-zero exit (raw archive bytes verified as-received)."""
        bundle_dir = tmp_dir / "vfy-tamper.acef"
        minimal_package.export(str(bundle_dir))

        manifest_path = bundle_dir / "acef-manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["metadata"]["producer"]["name"] = "ATTACKER"
        manifest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        archive = tmp_dir / "vfy-tampered-field.acef.tar.gz"
        _build_raw_archive(bundle_dir, archive)

        result = runner.invoke(cli, ["verify", str(archive)])
        assert result.exit_code != 0, result.output
        assert "ACEF-010" in result.output

    def test_verify_healthy_archive_passes(self, runner: CliRunner, tmp_dir: Path) -> None:
        """A healthy (schema-valid) archive → ``acef verify`` exits 0 with no
        integrity diagnostics. Guards that verifying the raw archive bytes does
        not regress a clean archive into a false failure."""
        bundle_dir = tmp_dir / "vfy-healthy.acef"
        _clean_package().export(str(bundle_dir))
        archive = tmp_dir / "vfy-healthy.acef.tar.gz"
        _build_raw_archive(bundle_dir, archive)

        result = runner.invoke(cli, ["verify", str(archive)])
        assert result.exit_code == 0, result.output
        assert "ACEF-011" not in result.output
        assert "ACEF-010" not in result.output

    def test_verify_directory_input_unchanged(self, runner: CliRunner, tmp_dir: Path) -> None:
        """Directory inputs to ``verify`` are unaffected by the archive fix: a
        healthy directory bundle still verifies clean (exit 0)."""
        bundle_dir = tmp_dir / "vfy-dir.acef"
        _clean_package().export(str(bundle_dir))

        result = runner.invoke(cli, ["verify", str(bundle_dir)])
        assert result.exit_code == 0, result.output

    def test_export_to_archive(self, runner: CliRunner, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "export-src.acef")
        minimal_package.export(bundle_path)

        archive_path = str(tmp_dir / "export-out.acef.tar.gz")
        result = runner.invoke(cli, ["export", bundle_path, archive_path])
        assert result.exit_code == 0
        assert Path(archive_path).exists()


# Non-UTF-8 manifest bytes used by the doctor crash tests below: a UTF-16-LE
# encoded ``{}`` (BOM + braces) that is NOT decodable as UTF-8 — its leading
# 0xff byte makes ``read_text(encoding="utf-8")`` raise ``UnicodeDecodeError``.
_NON_UTF8_MANIFEST = b"\xff\xfe{\x00}\x00"


class TestCLIDoctorNonUtf8Manifest:
    """P2(a): ``acef doctor`` must not crash with an uncaught ``UnicodeDecodeError``
    when ``acef-manifest.json`` contains non-UTF-8 bytes.

    RED proof (before the fix): both a DIRECTORY bundle and a ``.acef.tar.gz``
    archive whose manifest is ``b"\\xff\\xfe{\\x00}\\x00"`` make ``doctor`` read the
    manifest via ``read_text(encoding="utf-8")`` and raise an UNCAUGHT
    ``UnicodeDecodeError`` ("'utf-8' codec can't decode byte 0xff in position 0:
    invalid start byte") — a raw traceback escapes instead of a clean
    ``[ACEF-050]`` error. This is the SAME malformed-manifest class the
    ``inspect`` fix already closed (``inspect`` catches
    ``(json.JSONDecodeError, UnicodeDecodeError)`` → clean ``[ACEF-050]`` +
    ``SystemExit(1)``); ``doctor`` was missed. After the fix doctor emits the same
    clean ``[ACEF-050]`` error and exits non-zero (1) with NO traceback.
    """

    def test_doctor_directory_non_utf8_manifest_acef050_no_traceback(self, runner: CliRunner, tmp_dir: Path) -> None:
        bundle = tmp_dir / "doctor-bad-utf8.acef"
        bundle.mkdir()
        (bundle / "acef-manifest.json").write_bytes(_NON_UTF8_MANIFEST)
        (bundle / "records").mkdir()

        result = runner.invoke(cli, ["doctor", str(bundle)], catch_exceptions=True)

        # No uncaught exception (CliRunner only sets ``.exception`` to a non-exit
        # error when the command crashed — ``SystemExit`` is the clean path).
        assert not isinstance(result.exception, UnicodeDecodeError), result.exception
        assert result.exit_code == 1, result.output
        assert "ACEF-050" in result.output
        assert "Traceback" not in result.output

    def test_doctor_archive_non_utf8_manifest_acef050_no_traceback(self, runner: CliRunner, tmp_dir: Path) -> None:
        # Build a real .acef.tar.gz whose nested manifest is non-UTF-8.
        root = tmp_dir / "arc-src" / "bundle.acef"
        root.mkdir(parents=True)
        (root / "acef-manifest.json").write_bytes(_NON_UTF8_MANIFEST)
        (root / "records").mkdir()
        archive = tmp_dir / "doctor-bad-utf8.acef.tar.gz"
        with tarfile.open(str(archive), "w:gz") as tar:
            tar.add(str(root), arcname="bundle.acef")

        result = runner.invoke(cli, ["doctor", str(archive)], catch_exceptions=True)

        assert not isinstance(result.exception, UnicodeDecodeError), result.exception
        assert result.exit_code == 1, result.output
        assert "ACEF-050" in result.output
        assert "Traceback" not in result.output


class TestCLIValidateArchiveErrorSymmetry:
    """P2(b): ``acef validate`` on a missing / malformed ARCHIVE must emit a clean
    error + the SAME non-zero exit code as the equivalent DIRECTORY failure, for
    both text and ``--format json``.

    RED proof (before the fix): ``validate /no/such/bundle.acef.tar.gz`` and
    ``validate <non-gzip *.tar.gz>`` let the loader's ``ACEFFormatError``
    ("[ACEF-050] Archive not found: ..." / "[ACEF-050] Malformed or corrupt
    archive: ...: not a gzip file") propagate UNCAUGHT out of ``validate_cmd`` —
    a traceback — while a missing/malformed DIRECTORY input returns an
    ``AssessmentBundle`` carrying a FATAL structural error → exit 2 cleanly. The
    archive path was asymmetric. After the fix the archive path is caught and
    surfaced as a clean ``ACEF-050`` error with exit code 2, matching the
    directory case, in text and JSON.
    """

    def test_validate_missing_archive_clean_error_no_traceback(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["validate", "/no/such/bundle.acef.tar.gz"], catch_exceptions=True)
        assert not isinstance(result.exception, ACEFFormatError), result.exception
        assert result.exit_code == 2, result.output
        assert "ACEF-050" in result.output
        assert "Traceback" not in result.output

    def test_validate_non_gzip_archive_clean_error_no_traceback(self, runner: CliRunner, tmp_dir: Path) -> None:
        bad = tmp_dir / "corrupt.tar.gz"
        bad.write_bytes(b"x")
        result = runner.invoke(cli, ["validate", str(bad)], catch_exceptions=True)
        assert not isinstance(result.exception, ACEFFormatError), result.exception
        assert result.exit_code == 2, result.output
        assert "ACEF-050" in result.output
        assert "Traceback" not in result.output

    def test_validate_missing_archive_json_format_emits_structured_error(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            ["validate", "/no/such/bundle.acef.tar.gz", "--format", "json"],
            catch_exceptions=True,
        )
        assert not isinstance(result.exception, ACEFFormatError), result.exception
        assert result.exit_code == 2, result.output
        # --format json must emit parseable JSON carrying the ACEF-050 error, not
        # a traceback, so a `| jq` consumer does not choke.
        payload = json.loads(result.output)
        assert "ACEF-050" in json.dumps(payload)

    def test_validate_archive_and_directory_exit_codes_match(self, runner: CliRunner) -> None:
        """Symmetry assertion: a missing ARCHIVE and a missing DIRECTORY produce
        the SAME non-zero exit code (the established ACEF-050/fatal mapping)."""
        archive_result = runner.invoke(cli, ["validate", "/no/such/bundle.acef.tar.gz"], catch_exceptions=True)
        dir_result = runner.invoke(cli, ["validate", "/no/such/directory"], catch_exceptions=True)
        assert not isinstance(archive_result.exception, ACEFFormatError), archive_result.exception
        assert archive_result.exit_code == dir_result.exit_code
        assert archive_result.exit_code == 2

    def test_validate_missing_archive_json_is_assessment_bundle_shaped(self, runner: CliRunner) -> None:
        """roborev Medium (validate_cmd.py:59): the ``--format json`` archive-error
        branch must emit a NORMAL ``AssessmentBundle`` dict — the SAME top-level
        shape a successful/normal validation emits — not an ad-hoc partial object.

        RED proof (before the fix) the branch emitted only::

            {"structural_errors": [{"code": ..., "severity": "fatal",
                                    "message": ..., "path": ...}]}

        which (a) OMITS every other AssessmentBundle top-level key
        (``assessment_id``, ``versioning``, ``results``, ``provision_summary``,
        ``evaluation_instant``, ...), (b) OMITS the diagnostic ``category``, and
        (c) HARD-CODES ``severity: "fatal"``. A consumer expecting the standard
        validate JSON payload breaks. After the fix the body is a real
        ``AssessmentBundle.to_dict()`` carrying a registry-derived diagnostic.
        """
        result = runner.invoke(
            cli,
            ["validate", "/no/such/bundle.acef.tar.gz", "--format", "json"],
            catch_exceptions=True,
        )
        assert not isinstance(result.exception, ACEFFormatError), result.exception
        assert result.exit_code == 2, result.output
        payload = json.loads(result.output)

        # SAME top-level shape as a normal validate --format json output: a full
        # AssessmentBundle dict, not an object whose only key is structural_errors.
        from acef.models.assessment import AssessmentBundle

        expected_keys = set(AssessmentBundle().to_dict().keys())
        assert set(payload.keys()) == expected_keys, (
            f"archive-error JSON is not AssessmentBundle-shaped; got keys {sorted(payload.keys())}"
        )

        # The diagnostic is carried in structural_errors with the full
        # ValidationDiagnostic shape: code, severity, category, message.
        errors = payload["structural_errors"]
        assert len(errors) == 1, errors
        diag = errors[0]
        assert diag["code"] == "ACEF-050"
        assert "category" in diag, "ValidationDiagnostic category omitted from archive-error JSON"
        assert "severity" in diag

        # severity + category MUST be derived from the error registry for the
        # code, not hard-coded. For ACEF-050 the registry says fatal/format.
        from acef.errors import resolve_error_meta

        sev, cat = resolve_error_meta("ACEF-050")
        assert diag["severity"] == sev.value
        assert diag["category"] == cat.value

    def test_validate_json_non_fatal_format_error_carries_registry_severity(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The JSON archive-error branch must NOT hard-code ``"fatal"``: a
        non-fatal ``ACEFFormatError`` code (e.g. ACEF-052, registry severity
        ``error``) must serialize its TRUE registry severity/category in the
        emitted AssessmentBundle body. The hard-coded ``"severity": "fatal"`` in
        the prior commit MISREPRESENTS such codes — this is the core RED.

        Exit code stays 2 (the directory-input FATAL-exit symmetry the prior
        commit established) — exit code and the diagnostic's registry severity
        are separate concerns.
        """
        from acef.cli import validate_cmd as vc
        from acef.errors import ACEFFormatError, resolve_error_meta

        def _raise_acef052(path: str, profiles: list[str] | None = None, **kwargs: object) -> None:
            # ``**kwargs`` absorbs the ``trust_anchors=`` keyword the CLI now
            # forwards to ``validate`` (F4); the stub still raises before it
            # would be used.
            raise ACEFFormatError("Synthetic non-fatal format error", code="ACEF-052")

        monkeypatch.setattr(vc, "validate", _raise_acef052)

        result = runner.invoke(
            cli,
            ["validate", "/no/such/bundle.acef.tar.gz", "--format", "json"],
            catch_exceptions=True,
        )
        # Exit-code symmetry preserved: still 2 even though the diagnostic
        # registry severity is "error", not "fatal".
        assert result.exit_code == 2, result.output
        payload = json.loads(result.output)
        diag = payload["structural_errors"][0]
        assert diag["code"] == "ACEF-052"

        sev, cat = resolve_error_meta("ACEF-052")
        assert sev.value == "error", "precondition: ACEF-052 registry severity is 'error'"
        assert diag["severity"] == "error", "JSON body hard-coded 'fatal' instead of the registry severity for ACEF-052"
        assert diag["category"] == cat.value

    def test_validate_archive_error_json_message_not_code_prefixed(self, runner: CliRunner) -> None:
        """roborev Low (validate_cmd.py:74): the ``--format json`` archive-error
        ``ValidationDiagnostic`` message must NOT embed the ``[ACEF-050]`` code
        prefix, because the diagnostic already carries the code in its SEPARATE
        ``code`` field. Normal (engine) ``ValidationDiagnostic`` messages read as
        bare text (e.g. ``"acef-manifest.json not found"``) with no embedded
        ``[CODE]`` — duplicating the code (once in ``code``, once inside
        ``message``) breaks that convention and double-shows the code to a
        machine consumer.

        RED proof (before the fix): the branch built ``message = str(exc)`` which
        serializes the exception as ``"[ACEF-050] Archive not found: ..."`` — so
        ``payload["structural_errors"][0]["message"]`` STARTED WITH the literal
        ``"[ACEF-050]"`` prefix while ``["code"] == "ACEF-050"`` — the code
        appeared TWICE. After the fix the JSON message uses ``exc.message`` (the
        un-prefixed text), so ``code`` is the ONLY place the code appears.
        """
        result = runner.invoke(
            cli,
            ["validate", "/no/such/bundle.acef.tar.gz", "--format", "json"],
            catch_exceptions=True,
        )
        assert not isinstance(result.exception, ACEFFormatError), result.exception
        assert result.exit_code == 2, result.output
        payload = json.loads(result.output)
        diag = payload["structural_errors"][0]
        code = diag["code"]
        assert code == "ACEF-050"
        message = diag["message"]
        # The JSON diagnostic message must be the BARE message — no ``[ACEF-050]``
        # prefix and no embedded ``[<code>]`` token anywhere — so the code is not
        # duplicated between ``code`` and ``message``.
        assert not message.startswith(f"[{code}]"), (
            f"JSON diagnostic message embeds the code prefix (duplicated with the 'code' field): {message!r}"
        )
        assert f"[{code}]" not in message, (
            f"JSON diagnostic message embeds the code token (duplicated with the 'code' field): {message!r}"
        )
        # Sanity: the underlying error text is still present (just un-prefixed),
        # matching the bare-message convention of normal engine diagnostics.
        assert message, "JSON diagnostic message is empty"

    def test_validate_archive_error_text_path_still_inline_code(self, runner: CliRunner) -> None:
        """The human-readable text/stderr path MUST keep the inline ``[ACEF-050]``
        prefix (it reads ``Error: [ACEF-050] Archive not found: ...``) — only the
        machine-readable JSON ``message`` field is de-prefixed. This guards
        against a fix that strips the code from BOTH paths.
        """
        result = runner.invoke(
            cli,
            ["validate", "/no/such/bundle.acef.tar.gz"],
            catch_exceptions=True,
        )
        assert not isinstance(result.exception, ACEFFormatError), result.exception
        assert result.exit_code == 2, result.output
        # Text path keeps the inline code prefix for human readers.
        assert "[ACEF-050]" in result.output, f"text path lost the inline [ACEF-050] code prefix: {result.output!r}"
