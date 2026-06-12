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
    build_merkle_tree,
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

# A lone UTF-16 low surrogate (U+DCE9). This arises when a POSIX filename is
# decoded with the surrogateescape error handler, or from a caller-supplied
# str literal. It is *already NFC* (unicodedata.normalize("NFC", s) == s) yet it
# is NOT valid UTF-8 (str.encode("utf-8") raises UnicodeEncodeError), so it must
# never enter the UTF-8 hash-domain path contract (spec §3.1.1). roborev finding
# 2 (MEDIUM): such a string previously slipped past every NFC-only check.
_SURROGATE_NAME = "a\udce9.txt"


def _assert_surrogate_is_nfc_but_not_utf8(name: str) -> None:
    assert unicodedata.normalize("NFC", name) == name, "fixture must be NFC to prove the NFC-only check is insufficient"
    with pytest.raises(UnicodeEncodeError):
        name.encode("utf-8")


def test_surrogate_fixture_sanity() -> None:
    """The surrogate fixture is NFC-equal yet invalid UTF-8 (the exact bypass)."""
    _assert_surrogate_is_nfc_but_not_utf8(_SURROGATE_NAME)


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
    """Export-time validator rejects an NFD path with ACEF-052.

    roborev finding 1 (LOW): the export-time NFC rejection must carry the
    designated path code ACEF-052, not the ACEFExportError default (ACEF-050).
    """
    from acef.export import _validate_export_attachment_path

    with pytest.raises(ACEFExportError) as exc_info:
        _validate_export_attachment_path(f"artifacts/{_NFD_NAME}")
    assert exc_info.value.code == "ACEF-052"


def test_validate_export_attachment_path_accepts_nfc() -> None:
    """Export-time validator accepts the NFC form."""
    from acef.export import _validate_export_attachment_path

    _validate_export_attachment_path(f"artifacts/{_NFC_NAME}")


# ---------------------------------------------------------------------------
# roborev finding 2 (MEDIUM) — strict UTF-8: surrogate paths are NFC-equal but
# invalid UTF-8 and must be rejected at all four hash-domain path sites with
# the right ACEF code, while valid NFC UTF-8 still passes.
# ---------------------------------------------------------------------------


def test_validate_raw_attachment_path_rejects_surrogate() -> None:
    """Raw validator rejects a surrogate (NFC-equal, invalid UTF-8) with ACEF-052."""
    with pytest.raises(ACEFError) as exc_info:
        _validate_raw_attachment_path(_SURROGATE_NAME)
    assert exc_info.value.code == "ACEF-052"


def test_validate_attachment_path_rejects_surrogate() -> None:
    """Final validator rejects a surrogate (NFC-equal, invalid UTF-8) with ACEF-052."""
    with pytest.raises(ACEFError) as exc_info:
        _validate_attachment_path(f"artifacts/{_SURROGATE_NAME}")
    assert exc_info.value.code == "ACEF-052"


def test_validate_export_attachment_path_rejects_surrogate() -> None:
    """Export validator rejects a surrogate (NFC-equal, invalid UTF-8) with ACEF-052."""
    from acef.export import _validate_export_attachment_path

    with pytest.raises(ACEFExportError) as exc_info:
        _validate_export_attachment_path(f"artifacts/{_SURROGATE_NAME}")
    assert exc_info.value.code == "ACEF-052"


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


# ---------------------------------------------------------------------------
# Centralized helper — single source of truth for strict-UTF-8 + NFC on
# hash-domain paths, reused at all four sites (package raw/final, export,
# integrity discovered-key). roborev finding 2 (MEDIUM).
# ---------------------------------------------------------------------------


def test_path_problem_helper_flags_surrogate() -> None:
    """The shared helper returns a non-None reason for an NFC-equal surrogate."""
    from acef.integrity import path_nfc_utf8_problem

    assert path_nfc_utf8_problem(_SURROGATE_NAME) is not None


def test_path_problem_helper_flags_nfd() -> None:
    """The shared helper returns a non-None reason for an NFD (non-NFC) path."""
    from acef.integrity import path_nfc_utf8_problem

    assert path_nfc_utf8_problem(_NFD_NAME) is not None


def test_path_problem_helper_accepts_valid_nfc_utf8() -> None:
    """The shared helper returns None for a valid NFC UTF-8 path."""
    from acef.integrity import path_nfc_utf8_problem

    assert path_nfc_utf8_problem(_NFC_NAME) is None
    assert path_nfc_utf8_problem("artifacts/eval-report.txt") is None


def test_compute_content_hashes_rejects_surrogate_discovered_key(tmp_path: Path) -> None:
    """A discovered on-disk filename that is NFC-equal but invalid UTF-8 must be
    rejected at the integrity site (ACEFCanonicalizationError), not admitted as
    a hash-domain key. Skipped if the host filesystem cannot create the name."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "acef-manifest.json").write_text("{}", encoding="utf-8")
    artifacts = bundle / "artifacts"
    artifacts.mkdir()
    try:
        (artifacts / _SURROGATE_NAME).write_bytes(b"hi")
    except (OSError, UnicodeEncodeError, ValueError):
        pytest.skip("host filesystem cannot create a surrogate-bearing filename")

    on_disk_names = [p.name for p in artifacts.iterdir()]
    if not any(unicodedata.normalize("NFC", n) == n and _is_invalid_utf8(n) for n in on_disk_names):
        pytest.skip("host filesystem normalized away the surrogate filename")

    with pytest.raises(ACEFCanonicalizationError):
        compute_content_hashes(bundle)


def _is_invalid_utf8(name: str) -> bool:
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return False


# ---------------------------------------------------------------------------
# roborev finding 1 (MEDIUM) — consumer-side loader._validate_path.
#
# The load/validation path checker did NFC-only validation; a JSON-decoded
# lone surrogate (e.g. an escaped "\udce9" in a manifest record_files path or
# a record attachment path) is NFC-equal and therefore bypassed ACEF-052 at
# this site even though the producer-side helper rejects it. The fix routes
# _validate_path through the shared path_nfc_utf8_problem() helper so the
# strict-UTF-8 check (which the NFC-only test cannot make) is applied on the
# consumer side too. Regression for both manifest record_files paths and
# record attachment paths.
# ---------------------------------------------------------------------------

# A surrogate-bearing relative path under records/ (the manifest record_files
# shape) and under artifacts/ (the record attachment shape). Both are NFC-equal
# but invalid UTF-8 — the exact bypass roborev flagged.
_SURROGATE_RECORD_PATH = "records/a\udce9.jsonl"
_SURROGATE_ATTACHMENT_PATH = "artifacts/a\udce9.bin"


def test_loader_validate_path_rejects_surrogate_record_file() -> None:
    """loader._validate_path rejects a surrogate manifest record_files path.

    RED before the fix: the NFC-only check passes the (NFC-equal) surrogate
    path and _validate_path returns None, so an un-encodable record file path
    loads/validates. After: ACEF-052.
    """
    from acef.loader import _validate_path

    _assert_surrogate_is_nfc_but_not_utf8("a\udce9.jsonl")
    with pytest.raises(ACEFError) as exc_info:
        _validate_path(_SURROGATE_RECORD_PATH)
    assert exc_info.value.code == "ACEF-052"


def test_loader_validate_path_rejects_surrogate_attachment_path() -> None:
    """loader._validate_path rejects a surrogate record attachment path.

    Same bypass class as the record_files case but for an artifacts/-prefixed
    attachment path referenced from a record. After the fix: ACEF-052.
    """
    from acef.loader import _validate_path

    _assert_surrogate_is_nfc_but_not_utf8("a\udce9.bin")
    with pytest.raises(ACEFError) as exc_info:
        _validate_path(_SURROGATE_ATTACHMENT_PATH)
    assert exc_info.value.code == "ACEF-052"


def test_loader_validate_path_rejects_nfd_record_file() -> None:
    """loader._validate_path still rejects an NFD (non-NFC) path with ACEF-052.

    Pre-existing NFC enforcement must remain after routing through the helper.
    """
    from acef.loader import _validate_path

    with pytest.raises(ACEFError) as exc_info:
        _validate_path(f"records/{_NFD_NAME}")
    assert exc_info.value.code == "ACEF-052"


def test_loader_validate_path_accepts_valid_nfc_utf8() -> None:
    """loader._validate_path accepts ordinary NFC UTF-8 relative paths.

    Negative control: ASCII and composed-NFC paths (like every golden) still
    pass after the helper is applied.
    """
    from acef.loader import _validate_path

    _validate_path("records/records-0001.jsonl")
    _validate_path(f"artifacts/{_NFC_NAME}")


# ---------------------------------------------------------------------------
# roborev finding 2 (MEDIUM) — Merkle / content-hash-key verification.
#
# content-hashes.json keys are encoded directly during Merkle verification.
# An untrusted escaped-surrogate key passes JSON load + value-type checks
# then raised a RAW UnicodeEncodeError at path.encode("utf-8") in
# build_merkle_tree instead of a structured path diagnostic. The fix validates
# the keys with path_nfc_utf8_problem() before encoding, raising a structured
# ACEFCanonicalizationError (ACEF-051/052) that the integrity checker maps to a
# diagnostic — never a raw exception.
# ---------------------------------------------------------------------------


def test_build_merkle_tree_rejects_surrogate_key_structured() -> None:
    """build_merkle_tree raises a structured ACEFCanonicalizationError (not a
    raw UnicodeEncodeError) for an NFC-equal but invalid-UTF-8 key.

    RED before: ``{'a\\udce9.txt': <hex>}`` leaks
    ``UnicodeEncodeError('utf-8', ..., 'surrogates not allowed')`` at
    ``path.encode('utf-8')``.
    """
    key = "a\udce9.txt"
    _assert_surrogate_is_nfc_but_not_utf8(key)
    content_hashes = {key: "a" * 64}
    with pytest.raises(ACEFCanonicalizationError):
        build_merkle_tree(content_hashes)


def test_build_merkle_tree_rejects_nfd_key_structured() -> None:
    """build_merkle_tree raises a structured diagnostic for an NFD (non-NFC) key."""
    content_hashes = {_NFD_NAME: "a" * 64}
    with pytest.raises(ACEFCanonicalizationError):
        build_merkle_tree(content_hashes)


def test_verify_merkle_root_surrogate_key_no_raw_unicode_error() -> None:
    """verify_merkle_root surfaces a structured ACEFCanonicalizationError for a
    surrogate key rather than letting a raw UnicodeEncodeError escape."""
    from acef.integrity import verify_merkle_root

    content_hashes = {"a\udce9.txt": "a" * 64}
    with pytest.raises(ACEFCanonicalizationError):
        verify_merkle_root(content_hashes, "deadbeef")


def test_build_merkle_tree_accepts_valid_nfc_utf8_keys() -> None:
    """Negative control: ordinary NFC UTF-8 keys build a tree (no regression)."""
    content_hashes = {
        "acef-manifest.json": "a" * 64,
        f"artifacts/{_NFC_NAME}": "b" * 64,
    }
    tree = build_merkle_tree(content_hashes)
    assert "root" in tree
    assert len(tree["leaves"]) == 2


def test_merkle_verify_surrogate_key_is_structured_not_raw_unicode(
    tmp_path: Path,
) -> None:
    """The Merkle-verify path raises a STRUCTURED ACEFCanonicalizationError (an
    ACEF exception carrying a §3.1.1 message) for a JSON-decoded surrogate
    content-hashes.json key, instead of leaking a raw UnicodeEncodeError.

    This exercises the real untrusted-input shape: an attacker-supplied
    content-hashes.json whose key is an escaped lone surrogate, JSON-decoded by
    the consumer, reaching verify_merkle_root. The key-text guard lives in
    build_merkle_tree (this feature's boundary); the consumer wrapper that maps
    the structured error to an ACEF-051 ValidationDiagnostic lives in the
    integrity checker (owned by another feature). Asserting the structured type
    here proves the raw-exception leak is closed at this feature's boundary.
    """
    import json

    from acef.integrity import verify_merkle_root

    hashes_dir = tmp_path / "hashes"
    hashes_dir.mkdir()
    surrogate_key = "artifacts/a\udce9.bin"
    content_hashes_text = json.dumps({surrogate_key: "a" * 64})
    (hashes_dir / "content-hashes.json").write_text(content_hashes_text, encoding="utf-8")

    # Reload exactly as the consumer does (json.loads decodes the \udce9 escape
    # back into a lone surrogate string key).
    reloaded = json.loads((hashes_dir / "content-hashes.json").read_text(encoding="utf-8"))
    bad_key = next(iter(reloaded))
    _assert_surrogate_is_nfc_but_not_utf8(bad_key)

    with pytest.raises(ACEFCanonicalizationError):
        verify_merkle_root(reloaded, "deadbeef")
    # And specifically NOT a raw UnicodeEncodeError.
    try:
        verify_merkle_root(reloaded, "deadbeef")
    except UnicodeEncodeError:  # pragma: no cover - regression guard
        pytest.fail("verify_merkle_root leaked a raw UnicodeEncodeError")
    except ACEFCanonicalizationError:
        pass
