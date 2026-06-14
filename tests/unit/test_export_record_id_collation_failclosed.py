"""Stability-shakedown: ``export_directory`` / ``export_archive`` must fail closed
with a structured ``ACEFExportError`` (ACEF-052) — never a raw
``UnicodeEncodeError`` — when a record carries a ``record_id`` / ``timestamp``
that holds a lone UTF-16 surrogate.

``sort_records`` orders records by ``utf16_collation_key(timestamp)`` then
``utf16_collation_key(record_id)`` (== ``str.encode("utf-16-be")``).
``Package.record()`` admits a surrogate-bearing ``record_id`` override with no
strict-UTF-8 check, so before the fix the surrogate reached the collation
encoder and raised a raw ``UnicodeEncodeError`` mid-sort, leaking from the public
export API. The whole-codebase review found this (record-type collation was
already hardened; record_id/timestamp were left unguarded).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acef.errors import ACEFExportError
from acef.export import export_archive, export_directory
from acef.package import Package


def _package_with_record_id(record_id: str) -> Package:
    pkg = Package(producer={"name": "Acme", "version": "1.0.0"})
    pkg.add_subject("ai_system", "Sys")
    pkg.record(record_type="x-foo", record_id=record_id, payload={"k": "v"})
    return pkg


class TestSurrogateRecordIdFailsClosed:
    def test_export_directory_surrogate_record_id_raises_acef_052(self, tmp_path: Path) -> None:
        pkg = _package_with_record_id("urn:acef:rec:\udce9")
        with pytest.raises(ACEFExportError) as exc:
            export_directory(pkg, str(tmp_path / "out"))
        assert exc.value.code == "ACEF-052"

    def test_export_archive_surrogate_record_id_raises_acef_052(self, tmp_path: Path) -> None:
        pkg = _package_with_record_id("urn:acef:rec:\udce9")
        with pytest.raises(ACEFExportError) as exc:
            export_archive(pkg, str(tmp_path / "out.acef.tar.gz"))
        assert exc.value.code == "ACEF-052"

    def test_valid_ascii_record_id_still_exports(self, tmp_path: Path) -> None:
        """A normal ASCII URN record_id (minted) exports cleanly — no false
        rejection by the new collation guard."""
        pkg = Package(producer={"name": "Acme", "version": "1.0.0"})
        pkg.add_subject("ai_system", "Sys")
        pkg.record(record_type="x-foo", payload={"k": "v"})  # minted ASCII record_id
        out = tmp_path / "ok"
        export_directory(pkg, str(out))
        assert (out / "acef-manifest.json").exists()


class TestBuildManifestSurrogateRecordId:
    """roborev follow-up: Package.build_manifest() is a third public path that
    calls sort_records directly; it must also fail closed with ACEF-052 on a
    surrogate-bearing record_id, not leak a raw UnicodeEncodeError."""

    def test_build_manifest_surrogate_record_id_raises_acef_052(self) -> None:
        pkg = _package_with_record_id("urn:acef:rec:\udce9")
        with pytest.raises(ACEFExportError) as exc:
            pkg.build_manifest()
        assert exc.value.code == "ACEF-052"
