"""Tar-member ordering must use RFC 8785 UTF-16 collation, not code-point order.

Structural-review P1: the directory-bundle -> archive path in
``src/acef/export.py`` sorted tar member relpaths with Python's default ``str``
sort (Unicode CODE-POINT order). The TypeScript reference exporter
(``packages/sdk-typescript/src/bundle_export.ts``) sorts the SAME relpaths with
``Array.prototype.sort()`` == UTF-16 CODE-UNIT order. For supplementary-plane
member names (U+10000+), code-point order and UTF-16 order DIVERGE, so the two
reference exporters emitted tar members in DIFFERENT order -> DIFFERENT
``.acef.tar.gz`` bytes -> violation of the §3.1.3 byte-identical-archive MUST.

Every other ordering domain in the hash domain already routes through
``integrity.utf16_collation_key`` (content-hashes.json key order, Merkle leaf
order, record sort). The tar member sort is brought onto the same single source
of truth here.

Concrete divergence used below:
  - ``artifacts/ﬀ.txt``   U+FB00 (BMP, LATIN SMALL LIGATURE FF)
  - ``artifacts/𐀀.txt``  U+10000 (supplementary, LINEAR B SYLLABLE B008 A)

Code-point sort -> [ﬀ (FB00), 𐀀 (10000)].
UTF-16 sort     -> [𐀀 (begins with surrogate 0xD800 < 0xFB00), ﬀ].
"""

from __future__ import annotations

import tarfile
from pathlib import Path

from acef import integrity
from acef.package import Package

# Supplementary-plane (U+10000) and BMP (U+FB00) basenames. Both are short,
# NFC-stable, and well under the 100-byte USTAR member-name domain, so they
# pass the SDK add_attachment path and the export-time USTAR validator.
_NAME_BMP = "ﬀ.txt"  # U+FB00
_NAME_SUPPLEMENTARY = "𐀀.txt"  # U+10000


def _build_package_with(names: list[str]) -> Package:
    pkg = Package(producer={"name": "collation-test", "version": "1.0.0"})
    pkg.add_subject(
        subject_type="ai_system",
        name="CollationSystem",
        version="1.0.0",
        provider="acme",
        risk_classification="high-risk",
    )
    pkg.add_profile(profile_id="eu-ai-act-v1", provisions=["article-9"])
    pkg.record(
        record_type="risk_register",
        provisions=["article-9"],
        payload={"risk_id": "R-001", "description": "Collation risk"},
        timestamp="2025-01-01T00:00:01Z",
        record_id="urn:acef:rec:00000001-0000-0000-0000-000000000001",
    )
    for name in names:
        pkg.add_attachment(name, name.encode("utf-8"))
    return pkg


def _ordered_artifact_members(archive: Path) -> list[str]:
    """Return artifacts/* file member names in their on-disk tar order."""
    with tarfile.open(str(archive), mode="r:gz") as tar:
        members = [m.name for m in tar.getmembers() if not m.isdir()]
    # Strip the ``<bundle>.acef/`` prefix and keep only artifact members.
    out: list[str] = []
    for name in members:
        idx = name.find("/artifacts/")
        if idx != -1:
            out.append(name[idx + 1 :])  # ``artifacts/<basename>``
    return out


def _ordered_artifact_dir_members(archive: Path) -> list[str]:
    """Return artifacts/* DIRECTORY member names in their on-disk tar order."""
    with tarfile.open(str(archive), mode="r:gz") as tar:
        members = [m.name for m in tar.getmembers() if m.isdir()]
    out: list[str] = []
    for name in members:
        # ``getmembers`` may return dir names with or without a trailing slash;
        # normalize away the trailing slash for stable comparison.
        normalized = name.rstrip("/")
        idx = normalized.find("/artifacts/")
        if idx != -1:
            out.append(normalized[idx + 1 :])  # ``artifacts/<dirname>``
    return out


def test_supplementary_plane_members_sorted_by_utf16_collation(
    tmp_path: Path,
) -> None:
    """Tar member order for supplementary-plane artifact names matches the
    UTF-16 collation (the TS exporter order), NOT Python code-point order.

    RED (pre-fix): export.py sorts ``all_files`` with default ``str`` sort, so
    the emitted artifact order is the code-point order
    ``['artifacts/ﬀ.txt', 'artifacts/𐀀.txt']`` which != the UTF-16 order
    ``['artifacts/𐀀.txt', 'artifacts/ﬀ.txt']`` -> this assertion FAILS.
    GREEN (post-fix): both orders coincide.
    """
    pkg = _build_package_with([_NAME_BMP, _NAME_SUPPLEMENTARY])
    archive = tmp_path / "collation.acef.tar.gz"
    pkg.export(str(archive))

    emitted = _ordered_artifact_members(archive)

    relpaths = [f"artifacts/{_NAME_BMP}", f"artifacts/{_NAME_SUPPLEMENTARY}"]
    expected_utf16 = sorted(relpaths, key=integrity.utf16_collation_key)
    expected_codepoint = sorted(relpaths)

    # Guard the premise: the two collations genuinely diverge for these names,
    # so this test actually exercises the supplementary-plane divergence.
    assert expected_utf16 != expected_codepoint, (
        "premise broken: U+FB00 vs U+10000 must order differently under code-point vs UTF-16 collation"
    )

    assert emitted == expected_utf16, (
        "Tar artifact members must be emitted in UTF-16 collation order to "
        "match the TS exporter and the rest of the hash domain.\n"
        f"  emitted (on-disk order): {emitted!r}\n"
        f"  expected (utf16):        {expected_utf16!r}\n"
        f"  code-point order:        {expected_codepoint!r}"
    )


def test_ascii_member_order_unchanged_control(tmp_path: Path) -> None:
    """ASCII control: code-point order == UTF-16 order, so member order is
    unchanged by the collation-key sort (no churn for the all-ASCII corpus that
    covers every golden bundle and existing vector)."""
    ascii_names = ["a.txt", "b.txt", "z.txt", "m.txt"]
    pkg = _build_package_with(ascii_names)
    archive = tmp_path / "ascii.acef.tar.gz"
    pkg.export(str(archive))

    emitted = _ordered_artifact_members(archive)
    relpaths = [f"artifacts/{n}" for n in ascii_names]

    # For ASCII, code-point and UTF-16 collations coincide; assert both.
    assert sorted(relpaths) == sorted(relpaths, key=integrity.utf16_collation_key)
    assert emitted == sorted(relpaths, key=integrity.utf16_collation_key)


# Supplementary-plane (U+10000) and BMP (U+FB00) DIRECTORY basenames carrying
# nested artifact files. The production change also reorders DIRECTORY members
# (``all_dirs.sort(key=utf16_collation_key)``), so the member-order MUST is
# exercised for dir members too, not only file members.
_DIR_BMP = "ﬀdir"  # U+FB00
_DIR_SUPPLEMENTARY = "𐀀dir"  # U+10000


def test_supplementary_plane_dir_members_sorted_by_utf16_collation(
    tmp_path: Path,
) -> None:
    """Tar DIRECTORY member order for supplementary-plane artifact directory
    names matches the UTF-16 collation (the TS exporter order), NOT Python
    code-point order.

    The production change sorts ``all_dirs`` (the tar directory members) by
    ``integrity.utf16_collation_key`` exactly as it does ``all_files``; without
    that, code-point order would emit ``artifacts/ﬀdir`` before
    ``artifacts/𐀀dir`` while the TS exporter emits ``artifacts/𐀀dir`` first
    (its first UTF-16 unit 0xD800 < 0xFB00) -> divergent ``.acef.tar.gz`` bytes.
    """
    pkg = _build_package_with([])
    pkg.add_attachment(f"{_DIR_BMP}/x.txt", b"x")
    pkg.add_attachment(f"{_DIR_SUPPLEMENTARY}/y.txt", b"y")

    archive = tmp_path / "dir-collation.acef.tar.gz"
    pkg.export(str(archive))

    emitted_dirs = _ordered_artifact_dir_members(archive)

    dir_relpaths = [f"artifacts/{_DIR_BMP}", f"artifacts/{_DIR_SUPPLEMENTARY}"]
    expected_utf16 = sorted(dir_relpaths, key=integrity.utf16_collation_key)
    expected_codepoint = sorted(dir_relpaths)

    # Guard the premise: the two collations genuinely diverge for these dirs.
    assert expected_utf16 != expected_codepoint, (
        "premise broken: U+FB00 vs U+10000 dir names must order differently under code-point vs UTF-16 collation"
    )

    # The walk emits the bundle-root, records/, artifacts/, hashes/, signatures/
    # directories too; restrict to the two artifact subdirectories under test
    # and assert THEY appear in UTF-16 collation order relative to each other.
    relevant = [d for d in emitted_dirs if d in set(dir_relpaths)]
    assert relevant == expected_utf16, (
        "Tar artifact DIRECTORY members must be emitted in UTF-16 collation "
        "order to match the TS exporter and the rest of the hash domain.\n"
        f"  emitted (on-disk order): {relevant!r}\n"
        f"  expected (utf16):        {expected_utf16!r}\n"
        f"  code-point order:        {expected_codepoint!r}"
    )
