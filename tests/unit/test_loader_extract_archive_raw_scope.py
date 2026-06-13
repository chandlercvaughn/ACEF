"""``extract_archive_raw`` must not mask caller-raised ``OSError`` as archive corruption.

Finding (roborev Low, F-M4-MERKLE-MANDATORY): ``extract_archive_raw`` wrapped its
``yield`` inside ``try/except (... OSError) -> ACEFFormatError("Malformed or corrupt
archive")``. Because the generator re-raises a caller's exception at the ``yield``
point, ANY ``OSError`` raised by the CALLER's code inside the
``with extract_archive_raw(...) as p:`` block was caught by that handler and REWRITTEN
to an ``ACEFFormatError`` archive-corruption error — hiding the real failure (a missing
file the caller tried to open, a permission error, a disk-full write, etc.).

RED proof (before the fix): a caller that raises ``OSError("caller boom")`` inside the
``with`` block surfaces as ``ACEFFormatError("Malformed or corrupt archive: ...")``
instead of the original ``OSError``. After the fix the original ``OSError`` propagates
UNCHANGED.

The fix must KEEP both genuine behaviours: a genuinely malformed/corrupt archive still
raises ``ACEFFormatError`` (ACEF-050), and a healthy archive still extracts, yields its
bundle root, and cleans up the temp directory when the block exits.
"""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from acef.errors import ACEFFormatError
from acef.loader import extract_archive_raw
from acef.package import Package
from tests.unit.test_validate_archive_integrity import _build_raw_archive


def _healthy_archive(pkg: Package, tmp_dir: Path) -> Path:
    """Export ``pkg`` to a bundle dir and pack it into a raw, valid ``.tar.gz``."""
    bundle_dir = tmp_dir / "healthy.acef"
    pkg.export(str(bundle_dir))
    archive = tmp_dir / "healthy.acef.tar.gz"
    _build_raw_archive(bundle_dir, archive)
    return archive


class TestExtractArchiveRawExceptionScope:
    """The pre-yield extraction is guarded; the caller's block is NOT."""

    def test_caller_oserror_propagates_unmasked(self, minimal_package: Package, tmp_dir: Path) -> None:
        """A caller raising ``OSError`` inside the ``with`` block must propagate as
        that exact ``OSError`` — NOT be rewritten to an archive-corruption
        ``ACEFFormatError``.

        RED proof: before the fix this raised
        ``ACEFFormatError("Malformed or corrupt archive: ...")`` because the
        caller's ``OSError`` was caught at the ``yield`` and rewritten.
        """
        archive = _healthy_archive(minimal_package, tmp_dir)

        with pytest.raises(OSError, match="caller boom") as exc_info:
            with extract_archive_raw(archive) as bundle_dir:
                assert bundle_dir.exists()
                raise OSError("caller boom")

        # The escaping exception is the caller's, unchanged — not an ACEFFormatError.
        assert not isinstance(exc_info.value, ACEFFormatError)
        assert str(exc_info.value) == "caller boom"

    def test_caller_filenotfound_propagates_unmasked(self, minimal_package: Package, tmp_dir: Path) -> None:
        """``FileNotFoundError`` (an ``OSError`` subclass) from the caller's block
        must propagate as ``FileNotFoundError``, not be masked."""
        archive = _healthy_archive(minimal_package, tmp_dir)

        with pytest.raises(FileNotFoundError):
            with extract_archive_raw(archive) as bundle_dir:
                # Opening a non-existent file inside the yielded dir is the
                # caller's failure, not an archive-corruption failure.
                open(str(bundle_dir / "definitely-missing.bin"), "rb")

    def test_healthy_archive_yields_and_cleans_up(self, minimal_package: Package, tmp_dir: Path) -> None:
        """A healthy archive still extracts, yields a real bundle root containing
        the manifest, and removes the temp directory on block exit."""
        archive = _healthy_archive(minimal_package, tmp_dir)

        with extract_archive_raw(archive) as bundle_dir:
            captured = bundle_dir
            assert bundle_dir.exists()
            assert (bundle_dir / "acef-manifest.json").exists()

        # Temp dir cleaned up after the block.
        assert not captured.exists()

    def test_corrupt_archive_still_raises_acefformaterror(self, tmp_dir: Path) -> None:
        """A genuinely malformed/corrupt archive still raises ``ACEFFormatError``
        (ACEF-050) from the GUARDED extraction work — this must not regress."""
        corrupt = tmp_dir / "corrupt.acef.tar.gz"
        # Valid gzip stream, but the decompressed bytes are not a tar archive.
        with gzip.open(str(corrupt), "wb") as gz:
            gz.write(b"this is not a tar archive at all")

        with pytest.raises(ACEFFormatError) as exc_info:
            with extract_archive_raw(corrupt) as _bundle_dir:
                pass

        assert exc_info.value.code == "ACEF-050"
        assert "Malformed or corrupt archive" in str(exc_info.value)

    def test_missing_archive_still_raises_acefformaterror(self, tmp_dir: Path) -> None:
        """A non-existent archive path still raises ``ACEFFormatError`` (ACEF-050)
        before any extraction — unchanged by the scope fix."""
        missing = tmp_dir / "nope.acef.tar.gz"

        with pytest.raises(ACEFFormatError) as exc_info:
            with extract_archive_raw(missing):
                pass

        assert exc_info.value.code == "ACEF-050"
