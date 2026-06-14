"""Loader manifest-read robustness: non-UTF-8 / unreadable manifest must surface
as a structured ``ACEFFormatError`` (ACEF-050), not a RAW exception traceback
leaking out of the public ``acef.load()`` deserialization API.

Finding (runtime fuzzing, stability-shakedown):

    ``_load_directory`` reads the manifest with
    ``json.loads(manifest_path.read_text(encoding="utf-8"))`` and its ``except``
    catches ONLY ``json.JSONDecodeError``. ``Path.read_text(encoding="utf-8")``
    raises ``UnicodeDecodeError`` (a ``ValueError`` subclass, NOT a
    ``json.JSONDecodeError``) on non-UTF-8 manifest bytes, and ``OSError`` on a
    read race / unreadable path. Neither is caught, so the PUBLIC ``acef.load()``
    API leaks a RAW exception traceback.

    EMPIRICALLY REPRODUCED (pre-fix):
        ``acef.load(<dir bundle whose acef-manifest.json = b"\\xff\\xfe{}">)``
        ->  ``UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in
            position 0: invalid start byte``
    The ARCHIVE load path (``.acef.tar.gz``) reproduces the SAME raw error,
    because both the directory and archive load paths funnel the manifest read
    through ``_load_directory``.

    This is the SAME class already fixed in ``integrity_checker.py`` (catch
    ``(json.JSONDecodeError, UnicodeDecodeError, OSError)`` -> ACEF-050) and the
    CLI (inspect/doctor/validate) — but the loader's OWN manifest read was
    missed.

The fix broadens the manifest-read ``except`` to
``(json.JSONDecodeError, UnicodeDecodeError, OSError)``, reusing the loader's
existing ``ACEFFormatError(code="ACEF-050")`` malformed-manifest path. Every
test here asserts ``acef.load()`` raises a structured ``ACEFFormatError`` with
code ACEF-050 (never a raw ``UnicodeDecodeError`` / ``OSError``). A final
positive test pins that a VALID bundle still loads cleanly (no over-rejection).
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

import acef
from acef.errors import ACEFFormatError

# Non-UTF-8 manifest bytes: a UTF-16 BOM (0xff 0xfe) followed by ``{}``. This is
# NOT decodable as UTF-8 (``0xff`` is an invalid UTF-8 start byte), so
# ``read_text(encoding="utf-8")`` raises ``UnicodeDecodeError`` BEFORE
# ``json.loads`` ever runs.
_NON_UTF8_MANIFEST = b"\xff\xfe{}"


def _build_dir_bundle(bundle: Path, manifest_bytes: bytes) -> Path:
    """Write ``acef-manifest.json`` (raw bytes) into a fresh dir bundle."""
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "acef-manifest.json").write_bytes(manifest_bytes)
    return bundle


def _build_archive_bundle(archive: Path, manifest_bytes: bytes) -> Path:
    """Build a deterministic ``.acef.tar.gz`` whose ``acef-manifest.json`` member
    holds ``manifest_bytes`` verbatim (mtime=0 for byte-stability)."""
    with tarfile.open(str(archive), "w:gz") as tar:
        info = tarfile.TarInfo("acef-manifest.json")
        info.size = len(manifest_bytes)
        info.mtime = 0
        tar.addfile(info, io.BytesIO(manifest_bytes))
    return archive


# ---------------------------------------------------------------------------
# RED: a non-UTF-8 manifest must surface as a structured ACEF-050 error,
# not a raw ``UnicodeDecodeError`` traceback, on BOTH load paths.
# ---------------------------------------------------------------------------


def test_directory_non_utf8_manifest_raises_acef_050(tmp_path: Path) -> None:
    """``acef.load(<dir>)`` with a non-UTF-8 ``acef-manifest.json`` must raise a
    structured ``ACEFFormatError`` (ACEF-050).

    Pre-fix this leaked a RAW
    ``UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 0:
    invalid start byte`` out of the public ``acef.load()`` API.
    """
    bundle = _build_dir_bundle(tmp_path / "bundle", _NON_UTF8_MANIFEST)

    with pytest.raises(ACEFFormatError) as exc_info:
        acef.load(str(bundle))

    assert exc_info.value.code == "ACEF-050"
    # And NOT a raw UnicodeDecodeError leaking through.
    assert not isinstance(exc_info.value, UnicodeDecodeError)


def test_archive_non_utf8_manifest_raises_acef_050(tmp_path: Path) -> None:
    """``acef.load(<.acef.tar.gz>)`` with a non-UTF-8 ``acef-manifest.json``
    member must raise a structured ``ACEFFormatError`` (ACEF-050) — the archive
    path funnels the manifest read through ``_load_directory`` and reproduced the
    SAME raw ``UnicodeDecodeError`` pre-fix."""
    archive = _build_archive_bundle(tmp_path / "bundle.acef.tar.gz", _NON_UTF8_MANIFEST)

    with pytest.raises(ACEFFormatError) as exc_info:
        acef.load(str(archive))

    assert exc_info.value.code == "ACEF-050"
    assert not isinstance(exc_info.value, UnicodeDecodeError)


def test_directory_unreadable_manifest_raises_acef_050(tmp_path: Path) -> None:
    """An ``OSError`` on the manifest read (here: ``acef-manifest.json`` is a
    DIRECTORY, so ``read_text`` raises ``IsADirectoryError`` — an ``OSError``)
    must also surface as a structured ACEF-050, never a raw ``OSError``."""
    bundle = tmp_path / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    # Make the manifest path a directory: ``exists()`` is True, but
    # ``read_text`` raises ``IsADirectoryError`` (subclass of ``OSError``).
    (bundle / "acef-manifest.json").mkdir()

    with pytest.raises(ACEFFormatError) as exc_info:
        acef.load(str(bundle))

    assert exc_info.value.code == "ACEF-050"
    assert not isinstance(exc_info.value, OSError)


# ---------------------------------------------------------------------------
# GREEN guard: valid manifests still load cleanly (no over-rejection) and a
# genuinely malformed (but UTF-8) manifest still raises ACEF-050 as before.
# ---------------------------------------------------------------------------


def _valid_manifest() -> dict:
    return {
        "metadata": {
            "package_id": "urn:acef:pkg:11111111-1111-1111-1111-111111111111",
            "timestamp": "2026-01-01T00:00:00Z",
            "producer": {"name": "test-producer", "version": "1.0.0"},
        },
        "versioning": {"core_version": "1.0.0", "profiles_version": "1.0.0"},
        "subjects": [],
        "entities": {
            "components": [],
            "datasets": [],
            "actors": [],
            "relationships": [],
        },
        "profiles": [],
        "record_files": [],
        "audit_trail": [],
    }


def test_valid_utf8_manifest_still_loads(tmp_path: Path) -> None:
    """A well-formed UTF-8 manifest still loads cleanly — the broadened
    ``except`` must not over-reject valid bundles."""
    bundle = tmp_path / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "acef-manifest.json").write_text(json.dumps(_valid_manifest()), encoding="utf-8")

    pkg = acef.load(str(bundle))
    assert pkg.metadata.package_id == "urn:acef:pkg:11111111-1111-1111-1111-111111111111"


def test_malformed_utf8_json_manifest_still_raises_acef_050(tmp_path: Path) -> None:
    """A manifest that is valid UTF-8 but malformed JSON still raises ACEF-050
    via the existing ``json.JSONDecodeError`` arm — the fix only WIDENS the
    caught set, it must not narrow the existing behavior."""
    bundle = tmp_path / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "acef-manifest.json").write_text("{ not json", encoding="utf-8")

    with pytest.raises(ACEFFormatError) as exc_info:
        acef.load(str(bundle))

    assert exc_info.value.code == "ACEF-050"
