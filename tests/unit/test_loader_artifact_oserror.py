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
_POSIX = os.name == "posix"
# chmod(0o000) only denies access under POSIX permission semantics; on Windows it
# does not block scanning/reading, so the chmod-based tests are POSIX-only. The
# monkeypatch-injection tests below cover the same guards platform-independently.
_SKIP_CHMOD = not _POSIX or _IS_ROOT
_SKIP_CHMOD_REASON = "POSIX-only: relies on chmod 0o000 permission semantics (root bypasses them)"


def _golden_copy(tmp_path: Path) -> Path:
    dst = tmp_path / "b"
    shutil.copytree(_GOLDEN, dst)
    (dst / "artifacts").mkdir(exist_ok=True)
    return dst


def test_permission_error_is_not_acef_error() -> None:
    """Premise: PermissionError is an OSError, not an ACEFError — a caller
    catching ACEFError would NOT catch it if it leaked."""
    assert issubclass(PermissionError, OSError)
    assert not issubclass(PermissionError, ACEFError)


@pytest.mark.skipif(_SKIP_CHMOD, reason=_SKIP_CHMOD_REASON)
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


@pytest.mark.skipif(_SKIP_CHMOD, reason=_SKIP_CHMOD_REASON)
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
    dst = _golden_copy(tmp_path)
    (dst / "artifacts" / "ok.bin").write_bytes(b"readable artifact bytes")
    pkg = acef.load(str(dst))
    assert pkg.attachments.get("artifacts/ok.bin") == b"readable artifact bytes"


# --- Platform-independent (monkeypatch-injection) coverage of the guards. ---


def test_isfile_suppression_does_not_silently_skip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Python >=3.12 ``Path.is_file()`` SUPPRESSES ``OSError`` and returns ``False``
    for a present-but-unstattable entry (e.g. a symlink to an unreadable target),
    so gating artifact reads on ``is_file()`` SILENTLY DROPS such an artifact. The
    loader must ``stat()`` directly instead. Simulate the suppression by forcing
    ``is_file()`` → ``False`` for a present, readable artifact: it must STILL be
    captured (proving ``is_file()`` is no longer the gate). RED on the is_file-gated
    implementation (the artifact is skipped), GREEN once the loader stats first."""
    dst = _golden_copy(tmp_path)
    (dst / "artifacts" / "x.bin").write_bytes(b"present artifact")
    real_is_file = Path.is_file

    def fake_is_file(self: Path) -> bool:
        if self.name == "x.bin":
            return False  # simulate the >=3.12 OSError-suppression
        return real_is_file(self)

    monkeypatch.setattr(Path, "is_file", fake_is_file)
    pkg = acef.load(str(dst))
    assert pkg.attachments.get("artifacts/x.bin") == b"present artifact"


def test_artifact_dir_scan_error_raises_structured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Platform-independent: a directory-scan ``OSError`` delivered through
    ``os.walk``'s ``onerror`` callback must surface as structured ACEF-050."""
    dst = _golden_copy(tmp_path)
    real_walk = os.walk

    def fake_walk(top, *args, **kwargs):  # type: ignore[no-untyped-def]
        onerror = kwargs.get("onerror")
        if onerror is not None and Path(top).name == "artifacts":
            onerror(PermissionError(13, "Permission denied", str(top)))
        return real_walk(top, *args, **kwargs)

    monkeypatch.setattr("acef.loader.os.walk", fake_walk)
    with pytest.raises(ACEFFormatError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-050"


def test_artifact_stat_error_raises_structured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Platform-independent: a per-file ``lstat()`` failure must surface as ACEF-050.
    (The loader probes with ``lstat`` — no-follow — so symlinks can be rejected
    before following; this patches ``lstat`` accordingly.)"""
    dst = _golden_copy(tmp_path)
    (dst / "artifacts" / "x.bin").write_bytes(b"present artifact")
    real_lstat = Path.lstat

    def fake_lstat(self: Path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if self.name == "x.bin":
            raise PermissionError(13, "Permission denied", str(self))
        return real_lstat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    with pytest.raises(ACEFFormatError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-050"


def test_artifact_read_error_raises_structured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Platform-independent: a per-file ``read_bytes()`` failure must surface as
    ACEF-050."""
    dst = _golden_copy(tmp_path)
    (dst / "artifacts" / "x.bin").write_bytes(b"present artifact")
    real_read = Path.read_bytes

    def fake_read(self: Path) -> bytes:
        if self.name == "x.bin":
            raise PermissionError(13, "Permission denied", str(self))
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", fake_read)
    with pytest.raises(ACEFFormatError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-050"


# --- SECURITY: symlinks under artifacts/ are a path-escape / data-exposure vector
# in a DIRECTORY bundle. The archive (tar) load path and the integrity hash domain
# already reject symlinks (ACEF-052); the directory load path MUST match. (POSIX-only:
# symlink creation + the escape scenario are POSIX semantics.)


@pytest.mark.skipif(not _POSIX, reason="symlink path-escape semantics are POSIX-specific")
def test_load_rejects_artifact_symlink_escaping_bundle(tmp_path: Path) -> None:
    """A directory bundle with artifacts/<name> -> <path OUTSIDE the bundle> must be
    REJECTED (ACEF-052), NOT have the external file's contents read into
    Package.attachments. RED on a symlink-following loader (the external secret is
    captured), GREEN once symlinks are rejected pre-follow."""
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("EXTERNAL DATA THAT MUST NOT BE READ", encoding="utf-8")
    dst = _golden_copy(tmp_path)
    (dst / "artifacts" / "leak").symlink_to(outside)
    with pytest.raises(ACEFError) as exc:
        acef.load(str(dst))
    assert isinstance(exc.value, ACEFFormatError)
    assert exc.value.code == "ACEF-052"


@pytest.mark.skipif(not _POSIX, reason="symlink path-escape semantics are POSIX-specific")
def test_load_rejects_artifact_symlink_inside_bundle(tmp_path: Path) -> None:
    """ANY artifact symlink is rejected — even one resolving inside the bundle —
    matching the archive path's blanket symlink rejection."""
    dst = _golden_copy(tmp_path)
    target = dst / "artifacts" / "real.bin"
    target.write_bytes(b"real artifact bytes")
    (dst / "artifacts" / "alias").symlink_to(target)
    with pytest.raises(ACEFFormatError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-052"


@pytest.mark.skipif(not _POSIX, reason="symlink path-escape semantics are POSIX-specific")
def test_load_rejects_symlinked_artifacts_dir(tmp_path: Path) -> None:
    """A symlinked ``artifacts/`` directory itself is rejected (os.walk would
    otherwise follow the top symlink and read the target dir's files)."""
    external = tmp_path / "external_dir"
    external.mkdir()
    (external / "f.bin").write_bytes(b"external dir file")
    dst = tmp_path / "b"
    shutil.copytree(_GOLDEN, dst)
    art = dst / "artifacts"
    if art.exists() or art.is_symlink():
        shutil.rmtree(art)
    art.symlink_to(external, target_is_directory=True)
    with pytest.raises(ACEFFormatError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-052"


@pytest.mark.skipif(not _POSIX, reason="symlink path-escape semantics are POSIX-specific")
def test_load_rejects_symlinked_artifact_subdir(tmp_path: Path) -> None:
    """A symlinked SUBDIRECTORY under artifacts/ is rejected."""
    external = tmp_path / "external_sub"
    external.mkdir()
    (external / "f.bin").write_bytes(b"external subtree file")
    dst = _golden_copy(tmp_path)
    (dst / "artifacts" / "sublink").symlink_to(external, target_is_directory=True)
    with pytest.raises(ACEFFormatError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-052"
