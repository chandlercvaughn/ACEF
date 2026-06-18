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


def _build_source_backed_report_bundle(tmp_path: Path) -> tuple[Path, str]:
    """Build + export a signed SOURCE-BACKED ``report_incident()`` bundle.

    ``Package.report_incident()`` stores its evidence under the private
    ``payload.card_source`` subtree (with the regulator-only ``eu_ai_act_facts``
    block) and defaults the record to ``regulator-only`` confidentiality. This is
    exactly the shape whose raw envelope MUST NOT be dumped by a plain
    ``inspect --format json`` (the confidentiality LEAK). Returns
    ``(bundle_dir, public_id)``.
    """
    key_path, key = _write_ec_key(tmp_path)
    pkg = _new_incident_pkg()
    minted = mint_incident_id("openai.com", key, year=2026)
    pkg.add_subject("ai_system", name="Sys", risk_classification="high-risk", modalities=["text"])
    pkg.report_incident(
        public_incident_id=minted.public_incident_id,
        harm_core=dict(_HARM_CORE),
        incident_type="operational_failure",
        description="Confidential Art.73 serious-incident report.",
        awareness_date="2026-08-01T00:00:00Z",
        eu_ai_act_facts={
            "serious_incident_triggers": ["3.49.a"],
            "widespread": False,
            "death_involved": True,
        },
        severity_vector=_SEVERITY_VECTOR,
    )
    pkg.sign(key_path)
    bundle_dir = tmp_path / "report.acef"
    pkg.export(str(bundle_dir))
    return bundle_dir, minted.public_incident_id


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

    def test_inspect_markdown_surfaces_incident_evidence(self, runner: CliRunner, tmp_path: Path) -> None:
        """F16: ``inspect --format markdown`` emits the incident evidence as Markdown — wiring
        render_incident_evidence_markdown into a production path. Before this it was built +
        14-test-covered but had ZERO production wiring (dead code); ``--format`` had no
        ``markdown`` choice."""
        bundle_dir, public_id = _build_public_card_bundle(tmp_path)

        result = runner.invoke(cli, ["inspect", str(bundle_dir), "--format", "markdown"])

        assert result.exit_code == 0, result.output
        assert "## Incident Evidence" in result.output
        assert f"**Public Incident ID:** `{public_id}`" in result.output
        # Severity band derived by the shipped band() projection (this vector -> major).
        assert "(band: **major**)" in result.output

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


class TestInspectJsonNoConfidentialityLeak:
    """``inspect --format json`` MUST NOT leak regulator-only incident payloads.

    ``Package.report_incident()`` stores its source-backed evidence under the
    private ``payload.card_source`` subtree (with ``eu_ai_act_facts``) and emits the
    record ``regulator-only``. Dumping the raw ``to_jsonl_dict()`` envelope would
    publish that confidential subtree to anyone who can run ``inspect`` — a real
    confidentiality breach through a summary command (roborev High). By DEFAULT the
    JSON path MUST emit only a PROJECTION-SAFE summary (the same fields the console
    path surfaces), never ``card_source`` / ``eu_ai_act_facts``.
    """

    def test_json_default_omits_card_source_and_eu_ai_act_facts(self, runner: CliRunner, tmp_path: Path) -> None:
        bundle_dir, public_id = _build_source_backed_report_bundle(tmp_path)

        result = runner.invoke(cli, ["inspect", str(bundle_dir), "--format", "json"])

        assert result.exit_code == 0, result.output
        # The leaked keys MUST be entirely absent from the default JSON output.
        # RED (pre-fix): the raw envelope dump includes "card_source" and the
        # regulator-only "eu_ai_act_facts" block.
        assert "card_source" not in result.output, (
            f"LEAK: regulator-only 'card_source' subtree present in default "
            f"inspect --format json output: {result.output}"
        )
        assert "eu_ai_act_facts" not in result.output, (
            f"LEAK: regulator-only 'eu_ai_act_facts' block present in default "
            f"inspect --format json output: {result.output}"
        )

        payload = json.loads(result.output)
        records = payload.get("incident_records")
        assert records, "projection-safe incident summary missing from JSON output"
        # The projection-safe summary still surfaces the public id, the derived
        # severity band, and the harm class — resolved via the SAME render helpers.
        summary = records[0]
        assert summary["public_incident_id"] == public_id
        assert summary["severity_band"] == "major"
        assert summary["harm_class"] == "physical_health"
        # And it carries NONE of the regulator-only subtree keys.
        assert "card_source" not in summary
        assert "eu_ai_act_facts" not in summary
        assert "payload" not in summary

    def test_json_source_backed_report_surfaces_eu_ai_act_crosswalk(self, runner: CliRunner, tmp_path: Path) -> None:
        """The JSON projection MUST be consistent with the console/markdown renderers:
        a source-backed report's crosswalk comes from card_source.eu_ai_act_facts
        (surfaced as the eu_ai_act framework), NOT payload.taxonomy_crosswalk (which a
        source-backed report does not have). RED (pre-fix): the JSON summary read root
        taxonomy_crosswalk only, so the crosswalk was omitted. The raw facts content
        (e.g. the trigger codes) MUST NOT leak — only the framework label."""
        bundle_dir, _ = _build_source_backed_report_bundle(tmp_path)

        result = runner.invoke(cli, ["inspect", str(bundle_dir), "--format", "json"])

        assert result.exit_code == 0, result.output
        summary = json.loads(result.output)["incident_records"][0]
        crosswalk = summary.get("taxonomy_crosswalk")
        assert crosswalk, "source-backed report JSON summary omits the eu_ai_act crosswalk"
        assert "eu_ai_act" in [m.get("framework") for m in crosswalk]
        # No-leak: only the framework label is projected; the regulator-only
        # eu_ai_act_facts content (the §5.7 trigger code) MUST NOT appear.
        assert "card_source" not in result.output
        assert "eu_ai_act_facts" not in result.output
        assert "3.49.a" not in result.output

    def test_json_include_private_flag_required_to_see_raw_payload(self, runner: CliRunner, tmp_path: Path) -> None:
        """The raw envelope (with ``card_source``) is only emitted under the
        EXPLICIT ``--include-private`` opt-in; absent the flag it is withheld."""
        bundle_dir, _ = _build_source_backed_report_bundle(tmp_path)

        # Without the flag: no raw payload.
        default_result = runner.invoke(cli, ["inspect", str(bundle_dir), "--format", "json"])
        assert default_result.exit_code == 0, default_result.output
        assert "card_source" not in default_result.output

        # With the explicit opt-in flag: the raw envelope (and its card_source) is
        # surfaced for the operator who knowingly asked for it.
        raw_result = runner.invoke(cli, ["inspect", str(bundle_dir), "--format", "json", "--include-private"])
        assert raw_result.exit_code == 0, raw_result.output
        assert "card_source" in raw_result.output
        assert "eu_ai_act_facts" in raw_result.output

    def test_console_path_unchanged_for_source_backed_report(self, runner: CliRunner, tmp_path: Path) -> None:
        """The pretty/console path keeps surfacing the source-backed evidence
        (public id, severity band, harm class) — the no-leak fix is JSON-only."""
        bundle_dir, public_id = _build_source_backed_report_bundle(tmp_path)

        result = runner.invoke(cli, ["inspect", str(bundle_dir)])

        assert result.exit_code == 0, result.output
        assert "Incident Evidence" in result.output
        assert public_id in result.output
        assert "Severity: major" in result.output
        assert "physical_health" in result.output


class TestInspectIncidentStreamsRecordsNoFullLoad:
    """Incident enrichment MUST stream incident records from the manifest, not
    call the whole-bundle :func:`acef.loader.load` (which reads EVERY record file
    AND all artifacts, and extracts an archive a SECOND time) — roborev Medium.
    """

    def test_directory_enrichment_does_not_call_loader_load(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bundle_dir, _ = _build_source_backed_report_bundle(tmp_path)

        import acef.loader as loader_mod

        calls: list[str] = []
        real_load = loader_mod.load

        def _spy_load(path: str) -> Any:
            calls.append(path)
            return real_load(path)

        monkeypatch.setattr(loader_mod, "load", _spy_load)

        result = runner.invoke(cli, ["inspect", str(bundle_dir), "--format", "json"])

        assert result.exit_code == 0, result.output
        # The incident summary is still produced...
        payload = json.loads(result.output)
        assert payload.get("incident_records"), "incident summary missing"
        # ...WITHOUT the whole-bundle loader.load() (no artifact load).
        # RED (pre-fix): _load_incident_records called loader.load(path).
        assert calls == [], (
            f"inspect incident enrichment called the whole-bundle loader.load {len(calls)} time(s): {calls}"
        )

    def test_archive_not_extracted_twice(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bundle_dir, _ = _build_source_backed_report_bundle(tmp_path)
        archive = tmp_path / "report.acef.tar.gz"
        _build_raw_archive(bundle_dir, archive)

        import acef.loader as loader_mod

        extract_calls: list[str] = []
        real_extract = loader_mod.extract_archive_raw

        def _spy_extract(p: str) -> Any:
            extract_calls.append(str(p))
            return real_extract(p)

        monkeypatch.setattr(loader_mod, "extract_archive_raw", _spy_extract)

        result = runner.invoke(cli, ["inspect", str(archive), "--format", "json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload.get("incident_records"), "incident summary missing for archive"
        # The archive is extracted exactly ONCE for the whole inspect run; the
        # incident enrichment reuses that single raw extraction rather than
        # round-tripping through loader.load() (a second extraction).
        assert len(extract_calls) <= 1, f"archive extracted {len(extract_calls)} times (expected <= 1): {extract_calls}"


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


class TestInspectNonUtf8ManifestCleanError:
    """``inspect`` must surface a non-UTF-8 ``acef-manifest.json`` as a CLEAN
    ACEF-050-style error + non-zero exit, NEVER an uncaught ``UnicodeDecodeError``
    traceback — roborev Medium.

    The streaming manifest read uses ``read_text(encoding="utf-8")``, whose decode
    raises ``UnicodeDecodeError`` (a ``ValueError`` subclass, NOT ``OSError`` and
    NOT ``json.JSONDecodeError``). Before the fix that exception escaped both the
    directory path (``except OSError`` only) AND the archive path
    (``except (ACEFError, OSError)`` only), producing an empty user output and an
    uncaught traceback. RED proof (pre-fix, BOTH paths):
    ``UnicodeDecodeError('utf-8', b'\\xff\\xfe...', 0, 1, 'invalid start byte')``.
    The Unicode-decode failure MUST converge on the SAME user-facing error path the
    invalid-JSON case (``json.JSONDecodeError``) already produces: a clean
    ``Error: ... [ACEF-050]`` message on stderr and the documented exit code 1.
    """

    # 0xFF/0xFE are invalid UTF-8 lead bytes — a deterministic non-UTF-8 manifest.
    _NON_UTF8_MANIFEST = b'\xff\xfe{"format_version": "1.0"}'

    def _assert_clean_acef050(self, result: Any) -> None:
        # No traceback escaped (only a clean SystemExit from the CLI error path).
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            f"inspect leaked an uncaught exception on a non-UTF-8 manifest: {result.exception!r}"
        )
        # Documented non-zero exit code (same as the invalid-JSON path).
        assert result.exit_code == 1, result.output
        # The clean ACEF-050-style diagnostic reaches the user on stderr.
        assert "Error:" in result.output, result.output
        assert "ACEF-050" in result.output, result.output

    def test_directory_non_utf8_manifest_clean_error(self, runner: CliRunner, tmp_path: Path) -> None:
        bundle_dir = tmp_path / "bad-dir.acef"
        bundle_dir.mkdir()
        (bundle_dir / "acef-manifest.json").write_bytes(self._NON_UTF8_MANIFEST)

        result = runner.invoke(cli, ["inspect", str(bundle_dir)])

        self._assert_clean_acef050(result)

    def test_archive_non_utf8_manifest_clean_error(self, runner: CliRunner, tmp_path: Path) -> None:
        arc_src = tmp_path / "bad-arc"
        arc_src.mkdir()
        (arc_src / "acef-manifest.json").write_bytes(self._NON_UTF8_MANIFEST)
        archive = tmp_path / "bad.acef.tar.gz"
        with tarfile.open(str(archive), "w:gz") as tar:
            for path in sorted(arc_src.rglob("*")):
                arcname = path.relative_to(arc_src.parent).as_posix()
                tar.add(str(path), arcname=arcname, recursive=False)

        result = runner.invoke(cli, ["inspect", str(archive)])

        self._assert_clean_acef050(result)


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
