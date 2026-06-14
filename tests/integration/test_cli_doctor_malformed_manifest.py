"""Stability-shakedown: ``acef doctor`` must surface a clean error (never an
uncaught Python traceback) on a malformed manifest — found by black-box CLI
fuzzing + the whole-codebase review.

Two crashes (only ``doctor`` was affected; validate/verify/inspect short-circuit
on structural validation):

* a parsed-but-non-object manifest (``42`` / ``[]``) or non-object
  ``metadata`` / non-array ``subjects`` reached ``.get(...)`` / ``len(...)`` in
  ``_check_manifest`` -> raw ``AttributeError`` / ``TypeError``;
* a broken-JSON manifest (``{not json``) flowed into ``doctor``'s integrity
  check -> ``integrity.canonicalize_json_str`` -> ``json.loads`` -> raw
  ``json.JSONDecodeError``.
"""

from __future__ import annotations

import glob
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from acef.cli.main import cli
from acef.integrity import ACEFCanonicalizationError, canonicalize_json_str

_GOLDEN = next(p for p in sorted(glob.glob("tests/conformance/golden-bundles/*")) if Path(p).is_dir())


def _bundle(tmp_path: Path, manifest_bytes: bytes) -> Path:
    dst = tmp_path / "b"
    shutil.copytree(_GOLDEN, dst)
    (dst / "acef-manifest.json").write_bytes(manifest_bytes)
    return dst


class TestDoctorMalformedManifestNoTraceback:
    @pytest.mark.parametrize(
        "manifest_bytes",
        [
            b"42",  # scalar
            b"[]",  # array
            b'"x"',  # string
            b"{not json",  # broken JSON -> integrity hash path
            b'{"metadata": "x"}',  # non-object metadata
            b'{"metadata": 5, "subjects": []}',  # non-object metadata
            b'{"subjects": 5}',  # non-array subjects -> len() TypeError
            b'{"subjects": "x"}',
            b"\xff\xfe{}",  # non-UTF-8 (regression: already fixed, stays clean)
        ],
    )
    def test_doctor_never_raises_uncaught_exception(self, tmp_path: Path, manifest_bytes: bytes) -> None:
        bundle = _bundle(tmp_path, manifest_bytes)
        result = CliRunner().invoke(cli, ["doctor", str(bundle)])
        # A clean CLI error is a non-zero exit with NO uncaught non-SystemExit
        # exception. Before the fix this was AttributeError/TypeError/JSONDecodeError.
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            f"doctor raised an uncaught {type(result.exception).__name__}: {result.exception}"
        )
        assert result.exit_code != 0
        assert "Traceback (most recent call last)" not in result.output


class TestCanonicalizeJsonStrBrokenJson:
    @pytest.mark.parametrize("bad", ["{not json", "", "{", "[1,", '{"a":}'])
    def test_broken_json_raises_structured_canonicalization_error(self, bad: str) -> None:
        """A syntactically broken hash-domain ``.json`` file must raise the
        structured ACEFCanonicalizationError (ACEF-051), not a raw
        json.JSONDecodeError, so hashing a corrupt file never crashes."""
        with pytest.raises(ACEFCanonicalizationError):
            canonicalize_json_str(bad)

    def test_valid_json_still_canonicalizes(self) -> None:
        out = canonicalize_json_str('{"b":1,"a":2}')
        assert out == b'{"a":2,"b":1}'
