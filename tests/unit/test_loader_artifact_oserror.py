"""Stability-shakedown (pass 2): the public ``acef.load()`` must surface a
structured ``ACEFError`` — never a raw ``OSError`` — when an artifact under
``artifacts/`` cannot be read.

The artifact-loading loop in ``loader.py`` walked ``artifacts/`` with
``rglob``/``is_file``/``stat``/``read_bytes``, all UNGUARDED. A permission-denied
(mode ``000``), vanished-mid-load, or otherwise unreadable artifact in an
UNTRUSTED bundle therefore raised a raw ``PermissionError``/``OSError`` straight
out of ``load()`` (empirically: a ``0o000`` artifact → ``[Errno 13] Permission
denied``). The intentional 1 GB / 10 GB size-limit ``ACEFFormatError`` raises
(NOT ``OSError``) must still propagate unwrapped.
"""

from __future__ import annotations

import glob
import os
import shutil
from pathlib import Path

import pytest

import acef
from acef.errors import ACEFError, ACEFFormatError

_GOLDEN = next(p for p in sorted(glob.glob("tests/conformance/golden-bundles/*")) if Path(p).is_dir())

_IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def test_permission_error_is_not_acef_error() -> None:
    """Premise: PermissionError is an OSError, not an ACEFError — a caller
    catching ACEFError would NOT catch it if it leaked."""
    assert issubclass(PermissionError, OSError)
    assert not issubclass(PermissionError, ACEFError)


@pytest.mark.skipif(_IS_ROOT, reason="root bypasses file read permissions; chmod 000 would not block the read")
def test_load_unreadable_artifact_raises_structured(tmp_path: Path) -> None:
    dst = tmp_path / "b"
    shutil.copytree(_GOLDEN, dst)
    art = dst / "artifacts"
    art.mkdir(exist_ok=True)
    bad = art / "secret.bin"
    bad.write_bytes(b"unreadable artifact bytes")
    os.chmod(bad, 0o000)
    try:
        with pytest.raises(ACEFError) as exc:
            acef.load(str(dst))
        assert isinstance(exc.value, ACEFFormatError)
        assert exc.value.code == "ACEF-050"
    finally:
        # Restore so pytest's tmp_path teardown can remove the file.
        os.chmod(bad, 0o644)


@pytest.mark.skipif(_IS_ROOT, reason="root bypasses directory scan permissions; chmod 000 would not block the scan")
def test_load_unreadable_artifact_subdir_raises_structured(tmp_path: Path) -> None:
    """A present-but-unreadable SUBDIRECTORY under artifacts/ must fail loudly,
    not be silently skipped. ``Path.rglob`` suppresses directory-scan OSErrors, so
    the prior implementation silently DROPPED the unreadable subtree's artifacts —
    yielding an incomplete bundle. Explicit traversal must raise ACEF-050."""
    dst = tmp_path / "b"
    shutil.copytree(_GOLDEN, dst)
    art = dst / "artifacts"
    art.mkdir(exist_ok=True)
    locked = art / "locked"
    locked.mkdir()
    (locked / "inner.bin").write_bytes(b"unreadable subtree artifact")
    os.chmod(locked, 0o000)
    try:
        with pytest.raises(ACEFError) as exc:
            acef.load(str(dst))
        assert isinstance(exc.value, ACEFFormatError)
        assert exc.value.code == "ACEF-050"
    finally:
        # Restore so pytest's tmp_path teardown can recurse into the dir.
        os.chmod(locked, 0o755)


def test_load_nested_readable_artifact_succeeds(tmp_path: Path) -> None:
    """Happy-path guard: a readable NESTED artifact (under a subdirectory) is
    still captured — the explicit traversal must descend like rglob did."""
    dst = tmp_path / "b"
    shutil.copytree(_GOLDEN, dst)
    art = dst / "artifacts"
    art.mkdir(exist_ok=True)
    nested = art / "sub" / "deep"
    nested.mkdir(parents=True)
    (nested / "n.bin").write_bytes(b"nested artifact bytes")
    pkg = acef.load(str(dst))
    assert pkg.attachments.get("artifacts/sub/deep/n.bin") == b"nested artifact bytes"


def test_load_readable_artifact_succeeds(tmp_path: Path) -> None:
    """Happy-path guard: a normal readable artifact still loads and is captured
    as an attachment (the OSError guard must not change the success path)."""
    dst = tmp_path / "b"
    shutil.copytree(_GOLDEN, dst)
    art = dst / "artifacts"
    art.mkdir(exist_ok=True)
    (art / "ok.bin").write_bytes(b"readable artifact bytes")
    pkg = acef.load(str(dst))
    assert pkg.attachments.get("artifacts/ok.bin") == b"readable artifact bytes"
