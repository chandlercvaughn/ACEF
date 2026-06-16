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

import errno
import glob
import os
import shutil
import stat
from pathlib import Path

import pytest

import acef
from acef.errors import ACEFError, ACEFFormatError
from acef.loader import _FD_WALK_SUPPORTED, _MAX_ARTIFACT_DIR_DEPTH

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


@pytest.mark.skipif(not _FD_WALK_SUPPORTED, reason="targets the POSIX fd-anchored artifact reader")
def test_artifact_dir_scan_error_raises_structured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A directory-scan ``OSError`` must surface as structured ACEF-050. The
    fd-anchored reader scans with ``os.listdir(dir_fd)``; inject the failure there."""
    dst = _golden_copy(tmp_path)
    (dst / "artifacts" / "x.bin").write_bytes(b"present artifact")
    real_listdir = os.listdir

    def fake_listdir(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if isinstance(path, int):  # an fd -> the artifact scan
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_listdir(path, *args, **kwargs)

    monkeypatch.setattr("acef.loader.os.listdir", fake_listdir)
    with pytest.raises(ACEFFormatError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-050"


@pytest.mark.skipif(not _FD_WALK_SUPPORTED, reason="targets the POSIX fd-anchored artifact reader")
def test_artifact_stat_error_raises_structured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A per-entry ``lstat()`` failure must surface as ACEF-050. The fd-anchored
    reader probes with ``os.lstat(name, dir_fd=...)``; inject the failure there."""
    dst = _golden_copy(tmp_path)
    (dst / "artifacts" / "x.bin").write_bytes(b"present artifact")
    real_lstat = os.lstat

    def fake_lstat(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if path == "x.bin":
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr("acef.loader.os.lstat", fake_lstat)
    with pytest.raises(ACEFFormatError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-050"


@pytest.mark.skipif(not _FD_WALK_SUPPORTED, reason="targets the POSIX fd-anchored artifact reader")
def test_artifact_read_error_raises_structured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A read failure on the opened artifact fd must surface as ACEF-050. The
    bounded reader uses ``os.read(fd, n)``; inject the failure there."""
    dst = _golden_copy(tmp_path)
    (dst / "artifacts" / "x.bin").write_bytes(b"present artifact")

    def fake_read(fd, n):  # type: ignore[no-untyped-def]
        raise OSError(errno.EIO, "simulated I/O error")

    monkeypatch.setattr("acef.loader.os.read", fake_read)
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


@pytest.mark.skipif(not _POSIX, reason="symlink path-escape semantics are POSIX-specific")
def test_load_rejects_dangling_artifacts_symlink(tmp_path: Path) -> None:
    """A DANGLING ``artifacts/`` symlink (target missing) must be rejected
    (ACEF-052), not silently ignored. ``Path.exists()`` FOLLOWS symlinks and returns
    False for a broken symlink, so the ``is_symlink()`` guard must run BEFORE
    ``exists()``. RED while the guard sits inside the ``if exists()`` block (the
    dangling symlink reports exists()==False and is skipped)."""
    dst = tmp_path / "b"
    shutil.copytree(_GOLDEN, dst)
    art = dst / "artifacts"
    if art.is_symlink():
        art.unlink()
    elif art.exists():
        shutil.rmtree(art)
    art.symlink_to(tmp_path / "nonexistent_target")
    with pytest.raises(ACEFFormatError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-052"


@pytest.mark.skipif(not _POSIX, reason="O_NOFOLLOW / symlink-swap race semantics are POSIX-specific")
def test_load_artifact_symlink_swap_race_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """TOCTOU: even if the no-follow PROBE is fooled into seeing a regular file
    (simulating a regular-file -> symlink swap between the lstat probe and the read),
    the loader must reject the symlink at OPEN time (O_NOFOLLOW) and never read its
    target. RED while the loader reads via a path that re-follows symlinks
    (``Path.read_bytes``); GREEN once it opens the fd once with O_NOFOLLOW."""
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("EXTERNAL DATA THAT MUST NOT BE READ", encoding="utf-8")
    dst = _golden_copy(tmp_path)
    real_reg = dst / "artifacts" / "real.bin"
    real_reg.write_bytes(b"a genuine regular artifact")
    leak = dst / "artifacts" / "leak"
    leak.symlink_to(outside)
    reg_lstat = os.lstat(str(real_reg))  # a genuine regular-file stat_result
    real_oslstat = os.lstat

    def fake_lstat(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if path == "leak":
            return reg_lstat  # pretend the symlink is a regular file (probe fooled)
        return real_oslstat(path, *args, **kwargs)

    monkeypatch.setattr("acef.loader.os.lstat", fake_lstat)
    with pytest.raises(ACEFFormatError) as exc:
        acef.load(str(dst))
    # Rejected at OPEN time by O_NOFOLLOW (ELOOP), not the fooled lstat probe.
    assert exc.value.code == "ACEF-052"


@pytest.mark.skipif(not _FD_WALK_SUPPORTED, reason="targets the POSIX fd-anchored artifact reader")
def test_load_subdir_symlink_swap_race_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """ANCESTOR anchoring: even if the probe is fooled into seeing a symlinked
    SUBDIRECTORY as a real directory (simulating an ancestor-dir -> symlink swap), the
    fd-anchored reader opens the subdir with O_DIRECTORY|O_NOFOLLOW relative to its
    parent fd, so the swap is rejected (ELOOP -> ACEF-052) and the traversal cannot
    escape the bundle. This is the guarantee O_NOFOLLOW-on-the-leaf alone cannot
    give."""
    external = tmp_path / "external_dir"
    external.mkdir()
    (external / "f.bin").write_bytes(b"external dir file")
    dst = _golden_copy(tmp_path)
    (dst / "artifacts" / "sublink").symlink_to(external, target_is_directory=True)
    real_dir_stat = os.lstat(str(dst / "artifacts"))  # a genuine directory stat_result
    real_oslstat = os.lstat

    def fake_lstat(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if path == "sublink":
            return real_dir_stat  # pretend the dir-symlink is a real directory
        return real_oslstat(path, *args, **kwargs)

    monkeypatch.setattr("acef.loader.os.lstat", fake_lstat)
    with pytest.raises(ACEFFormatError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-052"


@pytest.mark.skipif(not _FD_WALK_SUPPORTED, reason="targets the POSIX fd-anchored artifact reader")
def test_load_rejects_excessive_artifact_nesting(tmp_path: Path) -> None:
    """Defense-in-depth: artifact subdirectory nesting beyond the bound is rejected
    (ACEF-050) — the fd-anchored reader recurses, and an unbounded depth would
    exhaust the stack."""
    dst = _golden_copy(tmp_path)
    deep = dst / "artifacts"
    for _ in range(_MAX_ARTIFACT_DIR_DEPTH + 2):
        deep = deep / "d"
    deep.mkdir(parents=True)
    (deep / "leaf.bin").write_bytes(b"too deep")
    with pytest.raises(ACEFFormatError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-050"


def test_load_artifact_growth_after_stat_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Finding D (post-stat growth): the per-file size limit is enforced on the
    ACTUAL bytes read, not a pre-read fstat() that a mutable file can outrun. Simulate
    a file that fstat() reports as within-limit but is actually larger: the BOUNDED
    read must reject it (ACEF-050) rather than store the over-budget bytes."""

    class _FakeStat:
        # A within-limit regular-file stat that lies about size.
        st_mode = stat.S_IFREG | 0o644
        st_size = 8

    dst = _golden_copy(tmp_path)
    (dst / "artifacts" / "x.bin").write_bytes(b"x" * 4096)  # real file is far larger
    monkeypatch.setattr("acef.loader._MAX_ARTIFACT_FILE_SIZE", 8)
    real_fstat = os.fstat

    def fake_fstat(fd):  # type: ignore[no-untyped-def]
        st = real_fstat(fd)
        if stat.S_ISREG(st.st_mode) and st.st_size == 4096:
            return _FakeStat()  # report the artifact as 8 bytes (passes the early check)
        return st

    monkeypatch.setattr("acef.loader.os.fstat", fake_fstat)
    with pytest.raises(ACEFFormatError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-050"
