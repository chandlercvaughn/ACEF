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


# ---------------------------------------------------------------------------
# roborev finding (MEDIUM) — integrity-checker wrapper for the Merkle-verify
# ACEFCanonicalizationError.
#
# verify_merkle_root() (above) now raises ACEFCanonicalizationError for an
# invalid content-hashes.json key (surrogate / non-NFC). But the Merkle check in
# integrity_checker.check_integrity() did NOT wrap that call in the same _CanonErr
# try/except the content-hash verification already uses. Consequence:
#   - direct check_integrity() callers got a RAW ACEFCanonicalizationError, and
#   - validate_bundle() caught it in its generic ACEF-001 untrusted-input backstop
#     instead of surfacing the intended structured ACEF-051 diagnostic.
# The fix wraps verify_merkle_root() in the SAME _CanonErr try/except, appending
# an ACEF-051 ValidationDiagnostic at /hashes/content-hashes.json (the surrogate
# key lives in content-hashes.json; build_merkle_tree raises with path=None, so
# the path is the content-hashes.json file, matching the existing ACEF-051
# construction in this file).
# ---------------------------------------------------------------------------


def _write_surrogate_keyed_bundle(tmp_path: Path) -> Path:
    """Build a minimal bundle dir whose content-hashes.json carries a surrogate
    key, plus a merkle-tree.json, so check_integrity() reaches the Merkle branch.

    The surrogate key is escaped by ``json.dumps`` and decoded back into a lone
    surrogate by the consumer's ``json.loads`` — the real untrusted-input shape.
    It is *not present on disk*, so the on-disk content-hash verification raises
    no canonicalization error (only an ACEF-014 "not found"); the
    ACEFCanonicalizationError originates in the Merkle-root verification step.
    """
    import hashlib
    import json

    bundle_dir = tmp_path / "surrogate_bundle"
    hashes_dir = bundle_dir / "hashes"
    hashes_dir.mkdir(parents=True)

    manifest_path = bundle_dir / "acef-manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")
    manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()

    surrogate_key = "artifacts/a\udce9.bin"
    content_hashes = {"acef-manifest.json": manifest_hash, surrogate_key: "a" * 64}
    (hashes_dir / "content-hashes.json").write_text(json.dumps(content_hashes), encoding="utf-8")
    (hashes_dir / "merkle-tree.json").write_text(json.dumps({"root": "deadbeef"}), encoding="utf-8")
    return bundle_dir


def test_check_integrity_surrogate_merkle_key_is_structured_acef_051(
    tmp_path: Path,
) -> None:
    """check_integrity() returns a STRUCTURED ACEF-051 diagnostic (not a raw
    exception) for a surrogate content-hashes.json key encountered during
    Merkle-root verification.

    RED before the wrapper: verify_merkle_root() -> build_merkle_tree() raised a
    raw ACEFCanonicalizationError that escaped check_integrity() entirely.
    """
    from acef.validation.integrity_checker import check_integrity

    bundle_dir = _write_surrogate_keyed_bundle(tmp_path)

    # Must NOT raise a raw exception out of check_integrity.
    diagnostics = check_integrity(bundle_dir)

    acef_051 = [d for d in diagnostics if d.code == "ACEF-051"]
    assert acef_051, (
        "Surrogate Merkle key must surface a structured ACEF-051 diagnostic, "
        f"got: {[(d.code, d.message) for d in diagnostics]}"
    )
    assert acef_051[0].path == "/hashes/content-hashes.json"


def test_validate_bundle_surrogate_merkle_key_not_acef_001_backstop(
    tmp_path: Path,
) -> None:
    """validate_bundle() surfaces the structured ACEF-051 (via the integrity
    checker) rather than falling into the generic ACEF-001 untrusted-input
    backstop for a surrogate content-hashes.json key.

    RED before the wrapper: the raw ACEFCanonicalizationError propagated up to
    validate_bundle()'s ``except Exception`` backstop -> ACEF-001.

    roborev finding (MEDIUM): the assertion below was originally only
    ``"ACEF-051" in codes``. But ``_run_validation_phases()`` LATER re-loads the
    SAME content-hashes.json and calls ``compute_bundle_digest()`` (the
    evidence_bundle_ref digest), whose RFC-8785 canonicalization raises on the
    surrogate key. That digest site's ``except`` tuple did not cover the
    canonicalization fault, so the exception escaped to the ACEF-001 backstop —
    meaning ACEF-051 AND ACEF-001 BOTH appeared for the same malformed key. The
    structural ACEF-051 emitted upstream is the authoritative diagnostic; the
    generic ACEF-001 backstop MUST NOT fire for it. Assert both: ACEF-051
    present, ACEF-001 absent.
    """
    from acef.validation.engine import validate_bundle

    bundle_dir = _write_surrogate_keyed_bundle(tmp_path)

    assessment = validate_bundle(str(bundle_dir))
    codes = {d["code"] for d in assessment.structural_errors}
    assert "ACEF-051" in codes, (
        "Surrogate Merkle key must produce a structured ACEF-051 via the "
        f"integrity checker, got structural error codes: {sorted(codes)}"
    )
    assert "ACEF-001" not in codes, (
        "The bundle-digest canonicalization site must not let the surrogate key "
        "reach the generic ACEF-001 backstop; ACEF-051 is the authoritative "
        f"diagnostic. Got structural error codes: {sorted(codes)}"
    )


def _write_well_formed_digest_bundle(tmp_path: Path) -> Path:
    """Build a minimal but well-formed bundle: a real artifact on disk, a
    matching content-hashes.json, and a correct merkle-tree.json. Used to prove
    the bundle-digest happy path is unchanged by the surrogate guard.
    """
    import json

    from acef.integrity import build_merkle_tree, compute_content_hashes

    bundle_dir = tmp_path / "wellformed_bundle"
    hashes_dir = bundle_dir / "hashes"
    hashes_dir.mkdir(parents=True)
    (bundle_dir / "acef-manifest.json").write_text("{}", encoding="utf-8")
    artifacts = bundle_dir / "artifacts"
    artifacts.mkdir()
    (artifacts / "eval-report.txt").write_bytes(b"hi")

    content_hashes = compute_content_hashes(bundle_dir)
    (hashes_dir / "content-hashes.json").write_text(json.dumps(content_hashes), encoding="utf-8")
    (hashes_dir / "merkle-tree.json").write_text(json.dumps(build_merkle_tree(content_hashes)), encoding="utf-8")
    return bundle_dir


def test_validate_bundle_well_formed_digest_still_computed(tmp_path: Path) -> None:
    """Negative control: the surrogate guard must not break the happy path — a
    well-formed (all-ASCII, like every golden) bundle still gets its
    evidence_bundle_ref.content_hash computed (a ``sha256:`` digest), with no
    ACEF-051 and no ACEF-001.
    """
    from acef.validation.engine import validate_bundle

    bundle_dir = _write_well_formed_digest_bundle(tmp_path)

    assessment = validate_bundle(str(bundle_dir))
    codes = {d["code"] for d in assessment.structural_errors}
    assert "ACEF-051" not in codes, f"unexpected ACEF-051 on a well-formed bundle: {sorted(codes)}"
    assert "ACEF-001" not in codes, f"unexpected ACEF-001 on a well-formed bundle: {sorted(codes)}"
    assert assessment.evidence_bundle_ref.content_hash.startswith("sha256:"), (
        f"well-formed bundle digest must be computed normally, got: {assessment.evidence_bundle_ref.content_hash!r}"
    )


# ---------------------------------------------------------------------------
# roborev finding (MEDIUM) — the bundle-digest guard was too NARROW.
#
# The prior commit (4a699c8) only caught UnicodeEncodeError / UnicodeDecodeError
# / ACEFCanonicalizationError / json/OS errors at the digest site. But
# compute_bundle_digest() RFC-8785-canonicalizes the JSON-decoded
# content-hashes.json, and json.loads accepts JSON tokens that rfc8785 REJECTS:
#   - a numeric / NaN / Infinity value -> rfc8785.FloatDomainError
#   - an out-of-range integer value     -> rfc8785.IntegerDomainError
# Both subclass rfc8785.CanonicalizationError, which the old tuple did NOT cover,
# so the exception escaped the digest site and re-fired as the generic ACEF-001
# untrusted-input backstop — duplicating the authoritative structural ACEF-014
# (non-string content-hashes.json value) emitted upstream by the integrity
# checker. The fix closes the WHOLE family (not one more exception type):
#   1. validate that the loaded content_hashes is dict[str, str] before
#      computing the digest; skip computation (leave content_hash unset) if not.
#   2. wrap compute_bundle_digest() in the BASE rfc8785.CanonicalizationError
#      (plus UnicodeEncodeError / ACEFCanonicalizationError) so any present or
#      future canonicalization fault leaves the digest unset rather than reaching
#      the ACEF-001 backstop.
# Each test below asserts: the authoritative structural code is present AND
# "ACEF-001" not in codes.
# ---------------------------------------------------------------------------


def _write_bundle_with_raw_content_hashes(tmp_path: Path, raw_json: str, name: str) -> Path:
    """Build a minimal bundle dir whose content-hashes.json is written from a
    RAW JSON string (so we can inject tokens — NaN, bare numbers, lists — that
    Python's ``json`` module accepts but ``rfc8785`` rejects).

    Includes a merkle-tree.json so the integrity checker reaches the digest
    flow, mirroring the surrogate-key fixture.
    """
    bundle_dir = tmp_path / name
    hashes_dir = bundle_dir / "hashes"
    hashes_dir.mkdir(parents=True)
    (bundle_dir / "acef-manifest.json").write_text("{}", encoding="utf-8")
    (hashes_dir / "content-hashes.json").write_text(raw_json, encoding="utf-8")
    (hashes_dir / "merkle-tree.json").write_text('{"root": "deadbeef"}', encoding="utf-8")
    return bundle_dir


def test_compute_bundle_digest_raises_canonicalization_error_on_nan_value() -> None:
    """Sanity: compute_bundle_digest() raises a CanonicalizationError (NOT one
    of the previously-caught types) for a NaN value — this is the exact escape
    the narrow guard missed.
    """
    import rfc8785

    from acef.integrity import compute_bundle_digest

    with pytest.raises(rfc8785.CanonicalizationError):
        compute_bundle_digest({"acef-manifest.json": float("nan")})


def test_validate_bundle_numeric_content_hash_value_not_acef_001_backstop(
    tmp_path: Path,
) -> None:
    """validate_bundle() must NOT fire the ACEF-001 backstop for a numeric
    (NaN) content-hashes.json value.

    RED before the comprehensive fix: the integrity checker emits the
    authoritative ACEF-014 (non-string value), but the digest site then calls
    compute_bundle_digest() which raises rfc8785.FloatDomainError — uncaught by
    the narrow tuple — so ACEF-001 ALSO appeared. After the fix the digest is
    simply left unset and only ACEF-014 remains.
    """
    from acef.validation.engine import validate_bundle

    # json.loads accepts the bare NaN token (Python extension); rfc8785 rejects
    # it. The value is a float, so the integrity checker's dict[str,str] guard
    # emits ACEF-014 upstream.
    bundle_dir = _write_bundle_with_raw_content_hashes(tmp_path, '{"acef-manifest.json": NaN}', "nan_value_bundle")

    assessment = validate_bundle(str(bundle_dir))
    codes = {d["code"] for d in assessment.structural_errors}
    assert "ACEF-014" in codes, (
        "A non-string (numeric) content-hashes.json value must produce the "
        f"authoritative structural ACEF-014, got: {sorted(codes)}"
    )
    assert "ACEF-001" not in codes, (
        "The bundle-digest site must not let a numeric content-hash value reach "
        f"the generic ACEF-001 backstop. Got structural error codes: {sorted(codes)}"
    )
    assert assessment.evidence_bundle_ref.content_hash == "", (
        f"An uncomputable digest must leave content_hash unset, got: {assessment.evidence_bundle_ref.content_hash!r}"
    )


def test_validate_bundle_out_of_range_integer_value_not_acef_001_backstop(
    tmp_path: Path,
) -> None:
    """validate_bundle() must NOT fire ACEF-001 for an out-of-range integer
    content-hashes.json value (rfc8785.IntegerDomainError — the sibling of the
    FloatDomainError case, both under CanonicalizationError).
    """
    from acef.validation.engine import validate_bundle

    huge_int = "1" + "0" * 400
    bundle_dir = _write_bundle_with_raw_content_hashes(
        tmp_path,
        '{"acef-manifest.json": ' + huge_int + "}",
        "huge_int_value_bundle",
    )

    assessment = validate_bundle(str(bundle_dir))
    codes = {d["code"] for d in assessment.structural_errors}
    assert "ACEF-014" in codes, (
        "A non-string (integer) content-hashes.json value must produce the "
        f"authoritative structural ACEF-014, got: {sorted(codes)}"
    )
    assert "ACEF-001" not in codes, (
        "The bundle-digest site must not let an out-of-range integer content-hash "
        f"value reach the ACEF-001 backstop. Got: {sorted(codes)}"
    )
    assert assessment.evidence_bundle_ref.content_hash == ""


def test_validate_bundle_list_content_hash_value_not_acef_001_backstop(
    tmp_path: Path,
) -> None:
    """A non-scalar (list) content-hashes.json value must not reach ACEF-001
    either. The dict[str, str] guard skips the digest computation entirely so
    no AttributeError/canonicalization fault escapes.
    """
    from acef.validation.engine import validate_bundle

    bundle_dir = _write_bundle_with_raw_content_hashes(
        tmp_path, '{"acef-manifest.json": ["not", "a", "hash"]}', "list_value_bundle"
    )

    assessment = validate_bundle(str(bundle_dir))
    codes = {d["code"] for d in assessment.structural_errors}
    assert "ACEF-014" in codes, f"A list content-hashes.json value must produce ACEF-014, got: {sorted(codes)}"
    assert "ACEF-001" not in codes, f"A list content-hash value must not reach ACEF-001. Got: {sorted(codes)}"
    assert assessment.evidence_bundle_ref.content_hash == ""


def test_content_hashes_is_str_mapping_predicate() -> None:
    """The digest-site dict[str, str] guard accepts only str->str mappings and
    rejects every non-conformant shape (non-dict, non-str value, non-str key).
    """
    from acef.validation.engine import _content_hashes_is_str_mapping

    assert _content_hashes_is_str_mapping({"a.txt": "deadbeef"}) is True
    assert _content_hashes_is_str_mapping({}) is True
    assert _content_hashes_is_str_mapping({"a.txt": 123}) is False
    assert _content_hashes_is_str_mapping({"a.txt": float("nan")}) is False
    assert _content_hashes_is_str_mapping({"a.txt": ["x"]}) is False
    assert _content_hashes_is_str_mapping({"a.txt": {"nested": "x"}}) is False
    assert _content_hashes_is_str_mapping({"a.txt": None}) is False
    assert _content_hashes_is_str_mapping({1: "deadbeef"}) is False
    assert _content_hashes_is_str_mapping(["a.txt", "deadbeef"]) is False
    assert _content_hashes_is_str_mapping("not a dict") is False
    assert _content_hashes_is_str_mapping(None) is False


def test_validate_bundle_string_value_but_non_canonicalizable_not_acef_001(
    tmp_path: Path,
) -> None:
    """Belt-and-suspenders: even a content-hashes.json whose values are all
    strings (so it passes the dict[str, str] guard) must not reach ACEF-001 if
    canonicalization were to fault for any reason. Here a surrogate KEY (NFC-
    equal, valid string, not UTF-8-encodable) re-confirms the base-exception
    catch keeps ACEF-001 absent while ACEF-051 is the authoritative diagnostic.

    This is the same family as the surrogate-key test but verified through the
    public validate_bundle() path to lock in that the dict[str, str] guard
    (which a surrogate key PASSES, since the key is a str) does not regress the
    exception catch added alongside it.
    """
    import json

    from acef.validation.engine import validate_bundle

    bundle_dir = tmp_path / "surrogate_str_value_bundle"
    hashes_dir = bundle_dir / "hashes"
    hashes_dir.mkdir(parents=True)
    (bundle_dir / "acef-manifest.json").write_text("{}", encoding="utf-8")
    surrogate_key = "artifacts/a\udce9.bin"
    content_hashes = {"acef-manifest.json": "a" * 64, surrogate_key: "b" * 64}
    (hashes_dir / "content-hashes.json").write_text(json.dumps(content_hashes), encoding="utf-8")
    (hashes_dir / "merkle-tree.json").write_text('{"root": "deadbeef"}', encoding="utf-8")

    assessment = validate_bundle(str(bundle_dir))
    codes = {d["code"] for d in assessment.structural_errors}
    assert "ACEF-051" in codes, (
        "A surrogate key (a valid str value passes the dict[str,str] guard) "
        f"must still produce the structured ACEF-051, got: {sorted(codes)}"
    )
    assert "ACEF-001" not in codes, (
        f"The base-exception catch must keep the surrogate-key fault out of the ACEF-001 backstop. Got: {sorted(codes)}"
    )
    assert assessment.evidence_bundle_ref.content_hash == ""
