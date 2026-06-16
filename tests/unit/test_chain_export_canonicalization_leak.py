"""Stability-shakedown (pass 2): the public ``acef.chain()`` and
``export_directory``/``export_archive`` APIs must surface a structured
``ACEFError`` (ACEF-051) — never the raw ``ACEFCanonicalizationError`` (a
``ValueError`` subclass that is NOT an ``ACEFError``) — when a hash-domain file
fails RFC-8785 canonicalization.

* ``chain(prior_bundle_dir)`` hashes an UNTRUSTED prior bundle; a BOM-prefixed
  manifest (or non-NFC filename) made ``compute_content_hashes`` raise
  ``ACEFCanonicalizationError`` straight out of the public API.
* ``export_*`` only caught ``OSError``; on a normalization-on-read filesystem a
  hash-domain file can fail canonicalization, leaking the same raw error.
"""

from __future__ import annotations

import glob
import shutil
from pathlib import Path

import pytest

import acef
from acef.errors import ACEFError, ACEFExportError, ACEFFormatError
from acef.integrity import ACEFCanonicalizationError
from acef.package import Package

_GOLDEN = next(p for p in sorted(glob.glob("tests/conformance/golden-bundles/*")) if Path(p).is_dir())


def test_acef_canonicalization_error_is_not_acef_error() -> None:
    """Premise: ACEFCanonicalizationError is a ValueError, not an ACEFError, so a
    caller catching ACEFError would NOT catch it if it leaked."""
    assert not issubclass(ACEFCanonicalizationError, ACEFError)


class TestChainCanonicalizationLeak:
    def test_chain_bom_manifest_raises_structured(self, tmp_path: Path) -> None:
        dst = tmp_path / "prior"
        shutil.copytree(_GOLDEN, dst)
        # Prepend a UTF-8 BOM to the manifest (forbidden in the hash domain).
        raw = (dst / "acef-manifest.json").read_bytes()
        (dst / "acef-manifest.json").write_bytes(b"\xef\xbb\xbf" + raw)
        with pytest.raises(ACEFError) as exc:
            acef.chain(str(dst))
        assert isinstance(exc.value, ACEFFormatError)
        assert exc.value.code == "ACEF-051"


class TestExportCanonicalizationLeak:
    def test_export_directory_wraps_canonicalization_error(self, tmp_path: Path, monkeypatch) -> None:
        """A normalization-on-read filesystem fault is simulated by forcing the
        hash computation to raise ACEFCanonicalizationError; export must wrap it
        as a structured ACEFExportError (ACEF-051)."""
        pkg = Package(producer={"name": "Acme", "version": "1.0.0"})
        pkg.add_subject("ai_system", "Sys")
        pkg.record(record_type="x-foo", payload={"k": "v"})

        def _boom(*a, **k):
            raise ACEFCanonicalizationError("simulated NFD-on-read fault", path=Path("artifacts/x"))

        monkeypatch.setattr("acef.export.compute_content_hashes", _boom)
        with pytest.raises(ACEFExportError) as exc:
            from acef.export import export_directory

            export_directory(pkg, str(tmp_path / "out"))
        assert exc.value.code == "ACEF-051"

    def test_export_archive_wraps_canonicalization_error(self, tmp_path: Path, monkeypatch) -> None:
        pkg = Package(producer={"name": "Acme", "version": "1.0.0"})
        pkg.add_subject("ai_system", "Sys")
        pkg.record(record_type="x-foo", payload={"k": "v"})

        def _boom(*a, **k):
            raise ACEFCanonicalizationError("simulated NFD-on-read fault", path=Path("artifacts/x"))

        monkeypatch.setattr("acef.export.compute_content_hashes", _boom)
        with pytest.raises(ACEFExportError) as exc:
            from acef.export import export_archive

            export_archive(pkg, str(tmp_path / "out.acef.tar.gz"))
        assert exc.value.code == "ACEF-051"
