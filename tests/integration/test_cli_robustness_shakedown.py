"""Stability-shakedown: CLI commands must surface clean errors / tolerant output
(never an uncaught traceback) on malformed input — found by the whole-codebase
opus review.

* ``inspect`` (default --format pretty) on a valid-JSON-object manifest with a
  malformed nested field (non-object metadata/producer, non-array
  subjects/record_files/entities) reached ``.get(...)`` / ``len(...)`` / arithmetic
  in ``cli.formatters.print_bundle_info`` -> raw AttributeError/TypeError.
* ``record`` with a bad ``--type`` (ACEFError ACEF-003) or ``--role`` (ValueError
  from the ObligationRole enum) raised an uncaught traceback at record_cmd:64.
"""

from __future__ import annotations

import glob
import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from acef.cli.main import cli

_GOLDEN = next(p for p in sorted(glob.glob("tests/conformance/golden-bundles/*")) if Path(p).is_dir())


def _clean(result) -> bool:
    return (result.exception is None or isinstance(result.exception, SystemExit)) and (
        "Traceback (most recent call last)" not in result.output
    )


class TestInspectPrettyMalformedManifest:
    @pytest.mark.parametrize(
        "manifest",
        [
            {"metadata": "x", "subjects": []},
            {"metadata": {"producer": "x"}, "subjects": []},
            {"metadata": {"producer": 5}},
            {"subjects": 5},
            {"subjects": [5, "x", {"name": []}]},
            {"entities": "x"},
            {"entities": {"components": "x"}},
            {"record_files": 5},
            {"record_files": [{"count": "lots"}, 5]},
            {"profiles": [5, {"profile_id": []}]},
        ],
    )
    def test_inspect_pretty_never_raises_uncaught(self, tmp_path: Path, manifest: dict) -> None:
        dst = tmp_path / "b"
        shutil.copytree(_GOLDEN, dst)
        (dst / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        result = CliRunner().invoke(cli, ["inspect", str(dst)])
        assert result.exception is None, (
            f"inspect raised {type(result.exception).__name__}: {result.exception}"
        )
        # inspect is a TOLERANT summary: it must still SUCCEED (exit 0) and render
        # the pretty bundle panel with placeholders — not reject the manifest.
        assert result.exit_code == 0
        assert "ACEF Evidence Bundle" in result.output


class TestRecordBadArgsCleanError:
    def _bundle(self, tmp_path: Path) -> Path:
        dst = tmp_path / "b"
        shutil.copytree(_GOLDEN, dst)
        return dst

    def test_bad_record_type_clean_error(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            cli,
            ["record", str(self._bundle(tmp_path)), "--type", "not_a_real_type", "--payload", "{}"],
        )
        assert _clean(result)
        assert result.exit_code != 0
        assert "Error" in result.output
        # An unknown record_type IS ACEF-003.
        assert "ACEF-003" in result.output

    def test_bad_role_clean_error(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            cli,
            [
                "record",
                str(self._bundle(tmp_path)),
                "--type",
                "event_log",
                "--payload",
                "{}",
                "--role",
                "bogus_role",
            ],
        )
        assert _clean(result)
        assert result.exit_code != 0
        assert "Error" in result.output
        # A bad --role is NOT an unknown-record_type error: it must not be
        # mislabeled with ACEF-003.
        assert "ACEF-003" not in result.output
