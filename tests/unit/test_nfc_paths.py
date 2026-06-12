"""Tests for UTF-8 NFC enforcement across the hash domain (F-M3-NFC-PATHS).

Covers three audit findings, all rooted in spec §3.1.1 line 513:
"All paths in the manifest and hashes MUST use forward slashes (`/`), be
relative to the bundle root, use UTF-8 NFC normalization, and not contain
`.` or `..` segments."

- export-determinism-1 (VAL-FIX-EXPORT-001): the three attachment-path
  validators (caller-supplied, final, export-time) must reject non-NFC paths
  with ACEF-052.
- integrity-jcs-merkle-3 (VAL-FIX-INTEGRITY-003): filesystem-discovered
  content-hashes/Merkle keys must be NFC-checked so a non-NFC on-disk filename
  cannot enter the hash domain.
- integrity-jcs-merkle-6 (VAL-FIX-INTEGRITY-006): consistency — once -3 lands,
  both file CONTENT NFC (already enforced for .json/.jsonl) and file PATH NFC
  (now enforced) are covered across the hash domain.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path

import pytest

from acef.errors import ACEFError, ACEFExportError
from acef.integrity import (
    ACEFCanonicalizationError,
    compute_content_hashes,
)
from acef.package import (
    Package,
    _validate_attachment_path,
    _validate_raw_attachment_path,
)

# 'café.txt' authored as NFD: 'cafe' + COMBINING ACUTE ACCENT (U+0301) + '.txt'.
# This is byte-distinct from the NFC composed form ('é' = U+00E9) yet renders
# identically, which is exactly the determinism hazard the NFC MUST closes.
_NFD_NAME = "café.txt"
_NFC_NAME = unicodedata.normalize("NFC", _NFD_NAME)


def _assert_is_nfd(name: str) -> None:
    assert unicodedata.normalize("NFC", name) != name, f"test fixture {name!r} is unexpectedly already NFC"


def _assert_is_nfc(name: str) -> None:
    assert unicodedata.normalize("NFC", name) == name


def test_fixture_sanity() -> None:
    """The NFD fixture is genuinely non-NFC and its NFC form is distinct."""
    _assert_is_nfd(_NFD_NAME)
    _assert_is_nfc(_NFC_NAME)
    assert _NFD_NAME != _NFC_NAME
    assert _NFD_NAME.encode("utf-8") != _NFC_NAME.encode("utf-8")


# ---------------------------------------------------------------------------
# VAL-FIX-EXPORT-001 — the three attachment-path validators reject non-NFC.
# ---------------------------------------------------------------------------


def test_validate_raw_attachment_path_rejects_nfd() -> None:
    """Caller-supplied (raw) validator rejects an NFD path with ACEF-052."""
    with pytest.raises(ACEFError) as exc_info:
        _validate_raw_attachment_path(_NFD_NAME)
    assert exc_info.value.code == "ACEF-052"


def test_validate_raw_attachment_path_accepts_nfc() -> None:
    """Caller-supplied (raw) validator accepts the NFC form."""
    _validate_raw_attachment_path(_NFC_NAME)


def test_validate_attachment_path_rejects_nfd() -> None:
    """Final (artifacts/-prefixed) validator rejects an NFD path with ACEF-052."""
    with pytest.raises(ACEFError) as exc_info:
        _validate_attachment_path(f"artifacts/{_NFD_NAME}")
    assert exc_info.value.code == "ACEF-052"


def test_validate_attachment_path_accepts_nfc() -> None:
    """Final (artifacts/-prefixed) validator accepts the NFC form."""
    _validate_attachment_path(f"artifacts/{_NFC_NAME}")


def test_validate_export_attachment_path_rejects_nfd() -> None:
    """Export-time validator rejects an NFD path."""
    from acef.export import _validate_export_attachment_path

    with pytest.raises(ACEFExportError):
        _validate_export_attachment_path(f"artifacts/{_NFD_NAME}")


def test_validate_export_attachment_path_accepts_nfc() -> None:
    """Export-time validator accepts the NFC form."""
    from acef.export import _validate_export_attachment_path

    _validate_export_attachment_path(f"artifacts/{_NFC_NAME}")


def test_add_attachment_rejects_nfd_via_public_api() -> None:
    """The public Package.add_attachment surface rejects an NFD path (ACEF-052)."""
    pkg = Package()
    with pytest.raises(ACEFError) as exc_info:
        pkg.add_attachment(_NFD_NAME, b"hi")
    assert exc_info.value.code == "ACEF-052"
    # The non-NFC path must NOT have entered the attachments dict.
    assert all(unicodedata.normalize("NFC", p) == p for p in pkg._attachments)


def test_add_attachment_accepts_nfc_via_public_api() -> None:
    """The public Package.add_attachment surface accepts the NFC form."""
    pkg = Package()
    pkg.add_attachment(_NFC_NAME, b"hi")
    stored = list(pkg._attachments)
    assert stored == [f"artifacts/{_NFC_NAME}"]
    assert all(unicodedata.normalize("NFC", p) == p for p in stored)


# ---------------------------------------------------------------------------
# VAL-FIX-INTEGRITY-003 — filesystem-discovered keys are NFC-checked.
# ---------------------------------------------------------------------------


def _write_bundle_with_artifact_name(bundle_dir: Path, artifact_name: str) -> Path:
    (bundle_dir / "acef-manifest.json").write_text("{}", encoding="utf-8")
    artifacts = bundle_dir / "artifacts"
    artifacts.mkdir()
    fpath = artifacts / artifact_name
    fpath.write_bytes(b"hi")
    return fpath


def test_compute_content_hashes_rejects_nfd_filename(tmp_path: Path) -> None:
    """A non-NFC on-disk filename must not enter the content-hashes/Merkle keys.

    Without enforcement the rglob-discovered relative path becomes a non-NFC
    content-hashes.json key (and Merkle leaf path), bypassing the manifest-path
    NFC enforcement. We require a structured diagnostic instead.
    """
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    fpath = _write_bundle_with_artifact_name(bundle, _NFD_NAME)
    # Skip only if the host filesystem silently normalized the name to NFC
    # (some filesystems do); on such a host the hazard is unreachable.
    on_disk = fpath.parent.iterdir()
    on_disk_names = [p.name for p in on_disk]
    if all(unicodedata.normalize("NFC", n) == n for n in on_disk_names):
        pytest.skip("host filesystem normalized the NFD filename to NFC")

    with pytest.raises(ACEFCanonicalizationError):
        compute_content_hashes(bundle)


def test_compute_content_hashes_accepts_nfc_filename(tmp_path: Path) -> None:
    """An NFC on-disk filename is admitted as an NFC content-hashes key."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    _write_bundle_with_artifact_name(bundle, _NFC_NAME)

    hashes = compute_content_hashes(bundle)
    assert f"artifacts/{_NFC_NAME}" in hashes
    for key in hashes:
        assert unicodedata.normalize("NFC", key) == key


def test_compute_content_hashes_ascii_bundle_unaffected(tmp_path: Path) -> None:
    """Negative control: an all-ASCII bundle (like every golden) is unaffected."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    _write_bundle_with_artifact_name(bundle, "eval-report.txt")

    hashes = compute_content_hashes(bundle)
    assert hashes == {
        "acef-manifest.json": hashes["acef-manifest.json"],
        "artifacts/eval-report.txt": hashes["artifacts/eval-report.txt"],
    }
    for key in hashes:
        assert unicodedata.normalize("NFC", key) == key
