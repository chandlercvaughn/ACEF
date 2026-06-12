"""Tar-format cross-language parity (VAL-FIX-EXPORT-003 / export-determinism-3).

Python's ``tarfile`` default format is ``PAX_FORMAT`` (``tarfile.DEFAULT_FORMAT
== 2``). For a member name containing non-ASCII UTF-8 — which §3.1.1 line 513
PERMITS (paths use UTF-8 NFC, so non-ASCII names are valid) — PAX emits an
``x`` extended-header block that the TypeScript USTAR writer
(``bundle_export.ts`` ``buildTarHeader``) never produces. That divergence
breaks the §3.1.3 byte-identical-archive MUST ("Byte-identical archives are
REQUIRED for conformance testing").

``export_archive`` must therefore pin ``format=tarfile.USTAR_FORMAT`` so a
non-ASCII member name (< 100 bytes) is stored as raw UTF-8 in the USTAR
``name`` field with NO extended header — exactly matching the TS USTAR writer.

These tests assert, at the raw-tar-bytes level:

* a non-ASCII NFC artifact member is encoded WITHOUT a PAX ``x`` extended
  header (the RED reproduction: pre-fix the first member block carries
  typeflag ``b"x"``);
* the member name is the raw UTF-8 bytes in the USTAR ``name`` field;
* two exports of the same bundle are byte-identical (determinism);
* an ASCII-only bundle's archive is byte-neutral under the format pin (the
  critical regression guard — PAX == USTAR for short ASCII names).
"""

from __future__ import annotations

import gzip
import hashlib
import tarfile
from io import BytesIO
from pathlib import Path

import pytest

from acef import export as export_module
from acef.errors import ACEFExportError
from acef.export import _validate_ustar_member_name, export_archive, export_directory
from acef.package import Package

# A non-ASCII NFC artifact filename, 36 UTF-8 bytes incl. the ``artifacts/``
# member prefix — well under USTAR's 100-byte name cap, so it MUST encode as a
# plain USTAR member with no long-name / extended-header machinery.
NON_ASCII_NAME = "café-ünïcode.txt"

TAR_BLOCK = 512
# Offset of the typeflag byte within a 512-byte tar header block.
TYPEFLAG_OFFSET = 156
# USTAR name field: bytes [0:100] of the header block.
NAME_FIELD = slice(0, 100)


def _build_package_with_artifact(filename: str) -> Package:
    pkg = Package(producer={"name": "test-tool", "version": "1.0.0"})
    system = pkg.add_subject(
        "ai_system",
        name="Test System",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )
    pkg.add_attachment(filename, b"artifact body")
    pkg.record(
        "evaluation_report",
        provisions=["article-9"],
        payload={"result": "pass"},
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
        attachments=[{"path": f"artifacts/{filename}", "media_type": "text/plain"}],
    )
    return pkg


def _tar_bytes(archive_path: Path) -> bytes:
    return gzip.decompress(archive_path.read_bytes())


def _iter_header_blocks(tar_bytes: bytes) -> list[bytes]:
    """Yield the 512-byte header block of every member (skips data + padding).

    Walks the tar stream member-by-member using the ``size`` recorded in each
    header so data blocks are not mistaken for headers.
    """
    blocks: list[bytes] = []
    with tarfile.open(fileobj=BytesIO(tar_bytes), mode="r") as tf:
        members = tf.getmembers()
    # Re-walk the raw stream to capture the on-disk header blocks (getmembers
    # parses but does not expose raw bytes). We reconstruct offsets from the
    # parsed member sizes/types.
    offset = 0
    for m in members:
        blocks.append(tar_bytes[offset : offset + TAR_BLOCK])
        data_blocks = (m.size + TAR_BLOCK - 1) // TAR_BLOCK
        offset += TAR_BLOCK + data_blocks * TAR_BLOCK
    return blocks


def _has_pax_extended_header(tar_bytes: bytes) -> bool:
    """True if any member header block carries the PAX ``x`` typeflag (0x78).

    A PAX extended header is a dedicated member block with typeflag ``x`` that
    precedes the real member; USTAR never emits one.
    """
    n_blocks = len(tar_bytes) // TAR_BLOCK
    for i in range(n_blocks):
        block = tar_bytes[i * TAR_BLOCK : (i + 1) * TAR_BLOCK]
        if block == b"\x00" * TAR_BLOCK:
            continue
        if block[TYPEFLAG_OFFSET : TYPEFLAG_OFFSET + 1] == b"x":
            return True
    return False


@pytest.mark.conformance
def test_non_ascii_member_has_no_pax_extended_header(tmp_dir: Path) -> None:
    """RED→GREEN: a non-ASCII NFC artifact member must be USTAR, no PAX header.

    Pre-fix (``tarfile.open(mode="w")`` → PAX) this archive contains an ``x``
    extended-header block for the non-ASCII member; the TS USTAR writer never
    emits one, so the archives diverge. Pinning USTAR_FORMAT removes the PAX
    block.
    """
    pkg = _build_package_with_artifact(NON_ASCII_NAME)
    out = tmp_dir / "nonascii.acef.tar.gz"
    export_archive(pkg, str(out))

    tar_bytes = _tar_bytes(out)
    assert not _has_pax_extended_header(tar_bytes), (
        "PAX extended-header block ('x' typeflag) present for a non-ASCII member "
        "name — Python emitted PAX where the TS USTAR writer emits a plain USTAR "
        "header, breaking cross-language byte parity."
    )


@pytest.mark.conformance
def test_non_ascii_member_name_is_raw_utf8_ustar(tmp_dir: Path) -> None:
    """The non-ASCII member name is stored as raw UTF-8 in the USTAR name field.

    This is what the TS USTAR writer does (``writeString`` copies
    ``Buffer.from(name, "utf-8")`` into name[0:100]); pinning USTAR makes Python
    match it byte-for-byte rather than relocating the name into a PAX header.
    """
    pkg = _build_package_with_artifact(NON_ASCII_NAME)
    out = tmp_dir / "nonascii.acef.tar.gz"
    export_archive(pkg, str(out))

    tar_bytes = _tar_bytes(out)
    expected_member = f"nonascii.acef/artifacts/{NON_ASCII_NAME}".encode()
    # The raw UTF-8 member name must appear in a USTAR name field (within a
    # header block, not a PAX payload). Confirm a header block whose name[0:100]
    # begins with the expected raw UTF-8 bytes exists.
    found = False
    for block in _iter_header_blocks(tar_bytes):
        name_field = block[NAME_FIELD].rstrip(b"\x00")
        if name_field == expected_member:
            found = True
            assert block[TYPEFLAG_OFFSET : TYPEFLAG_OFFSET + 1] == b"0", (
                "non-ASCII member must be a regular USTAR file (typeflag '0')"
            )
            break
    assert found, (
        f"expected raw-UTF-8 USTAR member name {expected_member!r} not found in "
        "any header block — the name was not stored verbatim in name[0:100]."
    )
    # And the parsed member must carry NO pax_headers. (tarfile's read-mode
    # ``TarFile.format`` attribute is the handle's DEFAULT and always reads back
    # as PAX(2) regardless of the on-disk format, so it is NOT a reliable signal;
    # an empty ``pax_headers`` dict is the authoritative "no PAX extended header
    # was consumed for this member" signal.)
    with tarfile.open(fileobj=BytesIO(tar_bytes), mode="r") as tf:
        member = tf.getmember(expected_member.decode("utf-8"))
        assert member.pax_headers == {}, (
            "member carries PAX extended-header fields — Python wrote a PAX "
            f"header instead of a plain USTAR header: {member.pax_headers!r}"
        )


@pytest.mark.conformance
def test_non_ascii_archive_is_deterministic(tmp_dir: Path) -> None:
    """Exporting the SAME non-ASCII bundle twice yields byte-identical archives.

    A single ``Package`` is built once (its wall-clock metadata timestamp is
    thus fixed) and exported twice to the SAME output basename in separate
    directories — ``export_archive`` derives the tar-root ``bundle_name`` from
    the output filename, so equal basenames isolate run-order as the only
    variable. This mirrors the determinism precedent in
    ``tests/unit/test_export_loader.py``.
    """
    pkg = _build_package_with_artifact(NON_ASCII_NAME)
    out1 = tmp_dir / "run1" / "det.acef.tar.gz"
    out2 = tmp_dir / "run2" / "det.acef.tar.gz"
    out1.parent.mkdir(parents=True, exist_ok=True)
    out2.parent.mkdir(parents=True, exist_ok=True)
    export_archive(pkg, str(out1))
    export_archive(pkg, str(out2))
    h1 = hashlib.sha256(out1.read_bytes()).hexdigest()
    h2 = hashlib.sha256(out2.read_bytes()).hexdigest()
    assert h1 == h2, "non-ASCII archive export is not byte-reproducible across runs"


@pytest.mark.conformance
def test_member_name_encoding_is_utf8_regardless_of_process_default(
    tmp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED→GREEN (Finding 1): member-name bytes are UTF-8 even on a non-UTF-8 default.

    ``tarfile.open(...)`` without an explicit ``encoding`` falls back to
    ``TarFile.encoding`` — the class attribute bound to ``tarfile.ENCODING``
    (derived from the filesystem encoding) at interpreter start. On a non-UTF-8
    locale that default is e.g. ``latin-1``, so a non-ASCII member name is
    written with latin-1 bytes (``b"caf\\xe9..."``) instead of the
    §3.1.1-required UTF-8 (``b"caf\\xc3\\xa9..."``). The TS USTAR writer always
    emits ``Buffer.from(name, "utf-8")``, so a latin-1 default here breaks the
    §3.1.3 byte-identical-archive MUST in an environment-dependent way.

    This test simulates a non-UTF-8 process default by patching
    ``tarfile.TarFile.encoding`` (the class-attribute fallback ``tarfile.open``
    reads when no explicit ``encoding`` is supplied — patching the module-level
    ``tarfile.ENCODING`` would NOT change it because the class attribute was
    bound at class-definition time) to ``latin-1`` BEFORE export. Pre-fix
    (``tarfile.open`` has no explicit ``encoding``) the non-ASCII member is
    written as latin-1 bytes and this assertion fails; pinning
    ``encoding="utf-8", errors="strict"`` makes the output UTF-8 regardless of
    the patched default.
    """
    # Simulate a non-UTF-8 default locale: the class-attribute fallback that
    # tarfile.open() reads when no explicit encoding is supplied.
    monkeypatch.setattr(export_module.tarfile.TarFile, "encoding", "latin-1")

    pkg = _build_package_with_artifact(NON_ASCII_NAME)
    out = tmp_dir / "locale.acef.tar.gz"
    export_archive(pkg, str(out))

    tar_bytes = _tar_bytes(out)
    expected_member = f"locale.acef/artifacts/{NON_ASCII_NAME}".encode()  # UTF-8
    latin1_member = f"locale.acef/artifacts/{NON_ASCII_NAME}".encode("latin-1")
    assert expected_member != latin1_member, "test premise: name must differ across codecs"

    found = False
    for block in _iter_header_blocks(tar_bytes):
        name_field = block[NAME_FIELD].rstrip(b"\x00")
        if name_field == expected_member:
            found = True
            break
        assert name_field != latin1_member, (
            "member name was written with the (patched) latin-1 process default "
            f"instead of UTF-8: {name_field!r} — locale-dependent encoding breaks "
            "cross-language byte parity with the TS UTF-8 writer."
        )
    assert found, (
        f"expected UTF-8 member name {expected_member!r} not found — encoding was "
        "not pinned to UTF-8 independent of the process default."
    )


@pytest.mark.conformance
def test_member_name_at_or_over_100_utf8_bytes_is_rejected_like_ts(tmp_dir: Path) -> None:
    """RED→GREEN (Finding 2): a >=100-UTF-8-byte member name is rejected, not split.

    The TS ``buildArchive`` ``assertShortName`` REJECTS any full member name
    (the ``<bundleName>/<relpath>`` string, trailing ``/`` for dirs) whose UTF-8
    length is ``>= 100`` bytes, throwing rather than emitting GNU/PAX long-name
    machinery. Python's ``tarfile`` instead either prefix-splits the name across
    the USTAR ``name``/``prefix`` fields (silent byte-divergence from TS) or
    raises a raw ``ValueError("name is too long")`` when the leaf alone is too
    long — both break parity. ``export_archive`` must mirror TS exactly: a
    structured ``ACEFExportError`` for any member name ``>= 100`` UTF-8 bytes.

    A leaf of 120 ``a`` bytes makes the full member path ~146 UTF-8 bytes, well
    over the 100-byte USTAR short-name domain.
    """
    long_leaf = "a" * 120 + ".txt"
    pkg = _build_package_with_artifact(long_leaf)
    out = tmp_dir / "longleaf.acef.tar.gz"
    with pytest.raises(ACEFExportError) as exc_info:
        export_archive(pkg, str(out))
    msg = str(exc_info.value)
    assert "100" in msg, f"rejection must cite the 100-byte USTAR domain: {msg!r}"


@pytest.mark.conformance
def test_long_bundle_name_prefix_pushes_member_over_100_is_rejected(tmp_dir: Path) -> None:
    """RED→GREEN (Finding 2): the ``<bundleName>/`` prefix counts toward the 100.

    A long ``bundle_name`` plus an otherwise-short artifact can push the FULL
    member path to ``>= 100`` UTF-8 bytes even though the leaf is tiny. Python's
    ``tarfile`` would prefix-split this across ``name``/``prefix`` (the TS writer
    rejects it), so the full member path — including the ``<bundleName>/``
    prefix — must be the rejection domain, identical to TS ``assertShortName``.

    ``export_archive`` derives ``bundle_name`` from the output filename, so an
    80-byte output basename yields an ~83-byte ``<bundleName>/`` prefix; with
    ``artifacts/report.txt`` (20 bytes) the full member exceeds 100 bytes.
    """
    long_basename = "b" * 80
    out = tmp_dir / f"{long_basename}.acef.tar.gz"
    full_member = f"{long_basename}.acef/artifacts/report.txt"
    assert len(full_member.encode("utf-8")) >= 100, "test premise: full member >= 100 bytes"

    pkg = _build_package_with_artifact("report.txt")
    with pytest.raises(ACEFExportError) as exc_info:
        export_archive(pkg, str(out))
    assert "100" in str(exc_info.value)


@pytest.mark.conformance
def test_member_name_just_under_100_bytes_exports_fine(tmp_dir: Path) -> None:
    """Negative control (Finding 2): a member name < 100 UTF-8 bytes still exports.

    The boundary mirrors TS: ``>= 100`` rejects, ``< 100`` passes. A full member
    path of exactly 99 UTF-8 bytes must export successfully and round-trip.
    """
    # Full member path target: "<basename>.acef/artifacts/<leaf>" == 99 bytes.
    # Choose a basename whose ".acef/artifacts/" + leaf totals 99.
    basename = "shortpkg"  # 8 bytes
    prefix = f"{basename}.acef/artifacts/"  # 8 + 16 = 24 bytes
    leaf_len = 99 - len(prefix.encode("utf-8"))  # 75 bytes leaf
    leaf = ("c" * (leaf_len - 4)) + ".txt"
    full_member = f"{prefix}{leaf}"
    assert len(full_member.encode("utf-8")) == 99, len(full_member.encode("utf-8"))

    pkg = _build_package_with_artifact(leaf)
    out = tmp_dir / f"{basename}.acef.tar.gz"
    export_archive(pkg, str(out))
    tar_bytes = _tar_bytes(out)
    expected = full_member.encode("utf-8")
    names = {b[NAME_FIELD].rstrip(b"\x00") for b in _iter_header_blocks(tar_bytes)}
    assert expected in names, f"99-byte member {expected!r} should export as a plain USTAR member; got {names!r}"


@pytest.mark.conformance
def test_ascii_only_archive_is_byte_neutral_under_format_pin(tmp_dir: Path) -> None:
    """Negative control: ASCII-only archives carry no PAX header either way.

    For short ASCII names PAX == USTAR byte-for-byte, so pinning USTAR_FORMAT is
    byte-neutral for ASCII bundles. This is the guard that the format pin does
    NOT perturb the committed ASCII golden/Freddy parity bundles.
    """
    pkg = _build_package_with_artifact("ascii-report.txt")
    out = tmp_dir / "ascii.acef.tar.gz"
    export_archive(pkg, str(out))
    tar_bytes = _tar_bytes(out)
    # No PAX extended-header block — true under both PAX and USTAR for short
    # ASCII names. This is the byte-neutrality guard: pinning USTAR does not
    # change the bytes of an ASCII-only archive (PAX == USTAR here). The
    # tarfile reader reports format PAX(2) for these byte-identical archives by
    # heuristic, so we deliberately do NOT assert tf.format for the ASCII case;
    # byte-neutrality is established by the absence of any extended header.
    assert not _has_pax_extended_header(tar_bytes)


@pytest.mark.conformance
def test_validator_surrogate_member_name_raises_structured_acef_052() -> None:
    """RED→GREEN (Finding 1): a surrogate-bearing member name raises ACEF-052.

    ``bundle_name`` is derived directly from the export ``output_path`` basename
    (``export_archive`` line ~237) and flows unvalidated into
    ``_validate_ustar_member_name`` as the root/dir/file member prefix. A
    basename holding a lone UTF-16 surrogate (e.g. a POSIX filename decoded with
    ``surrogateescape``) is a valid Python ``str`` but is NOT encodable as
    UTF-8, so the validator's ``name.encode("utf-8")`` byte-length check raises a
    RAW ``UnicodeEncodeError`` — bypassing the documented ``ACEFExportError``
    surface every other export path-rejection uses.

    Pre-fix the validator raises ``UnicodeEncodeError``; the fix must route the
    member name through the strict-UTF-8 path check first and raise a structured
    ``ACEFExportError`` with the designated path code ``ACEF-052`` (consistent
    with ``_validate_export_attachment_path``), matching the §3.1.1 UTF-8 path
    contract.
    """
    member = "a\udce9.acef/"  # lone surrogate in the bundle-name prefix
    # Premise: this str is NOT UTF-8 encodable, so the raw encode would throw.
    with pytest.raises(UnicodeEncodeError):
        member.encode("utf-8")
    with pytest.raises(ACEFExportError) as exc_info:
        _validate_ustar_member_name(member)
    assert exc_info.value.code == "ACEF-052", (
        "surrogate-bearing member name must raise the designated path code "
        f"ACEF-052, not {exc_info.value.code!r} or a raw UnicodeEncodeError"
    )


@pytest.mark.conformance
def test_validator_member_name_at_exactly_100_bytes_is_rejected() -> None:
    """RED→GREEN (Finding 2): the EXACT 100-byte boundary is rejected (``>= 100``).

    The TS ``assertShortName`` rejects any full member name whose UTF-8 length is
    ``>= 100`` bytes, so 100 is INCLUSIVE. The other Finding-2 cases use 99 bytes
    (pass) and well-over-100 bytes (reject); neither pins the exact boundary, so
    an off-by-one regression (``> 100`` instead of ``>= 100``) would slip through.
    This case exercises a full member name of EXACTLY 100 UTF-8 bytes — measured
    the way the validator measures it: the complete member string including the
    ``<bundle_name>/`` prefix and trailing ``/`` for a directory member — and
    asserts ``ACEFExportError`` (ACEF-052) is raised, locking the inclusive
    boundary.
    """
    # 100 ASCII bytes == 100 UTF-8 bytes; a trailing "/" makes it a dir member.
    member = "x" * 99 + "/"
    assert len(member.encode("utf-8")) == 100, len(member.encode("utf-8"))
    with pytest.raises(ACEFExportError) as exc_info:
        _validate_ustar_member_name(member)
    assert exc_info.value.code == "ACEF-052"
    assert "100" in str(exc_info.value)


@pytest.mark.conformance
def test_validator_member_name_at_99_bytes_is_accepted() -> None:
    """Negative control (Finding 2): exactly 99 UTF-8 bytes is accepted.

    Pairs with the exact-100 boundary case: ``< 100`` passes, ``>= 100`` rejects.
    A 99-byte full member name must NOT raise, proving the boundary is at 100 and
    not at 99 (which would be an over-strict off-by-one in the other direction).
    """
    member = "y" * 99
    assert len(member.encode("utf-8")) == 99
    # Must not raise.
    _validate_ustar_member_name(member)


def _build_simple_package() -> Package:
    """A minimal valid package with no artifacts (basename is the only variable)."""
    pkg = Package(producer={"name": "test-tool", "version": "1.0.0"})
    system = pkg.add_subject(
        "ai_system",
        name="Test System",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )
    pkg.record(
        "evaluation_report",
        provisions=["article-9"],
        payload={"result": "pass"},
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    return pkg


@pytest.mark.conformance
def test_export_archive_surrogate_output_basename_raises_structured_acef_052(
    tmp_dir: Path,
) -> None:
    """RED→GREEN (Finding 1, ORDERING): the PUBLIC surface raises ACEF-052.

    ``export_archive`` derives ``bundle_name`` from the ``output_path`` basename
    and constructs/creates ``bundle_dir`` (via ``export_directory``) BEFORE the
    in-tar ``_validate_ustar_member_name`` runs. For a surrogate-bearing output
    basename — a valid Python ``str`` that the host filesystem encoder rejects —
    the FS work happens FIRST: on a strict-encoder host the basename raises a raw
    ``UnicodeEncodeError``; on a ``surrogateescape``-tolerant host (e.g. macOS)
    the directory ``mkdir`` fails with ``OSError`` ("Illegal byte sequence")
    re-wrapped as the GENERIC ``ACEF-050`` ("Failed to export bundle"). Either
    way the public surface does NOT surface the designated path code ACEF-052 —
    the structured-error contract is wrong and the validator never runs.

    The fix validates the derived ``bundle_name`` as a USTAR member name at the
    entry point, BEFORE any FS work, so the public surface deterministically
    raises ``ACEFExportError`` code ACEF-052 for a surrogate basename on every
    host.
    """
    # Premise: this str is NOT UTF-8 encodable, so any FS / encode path on it
    # would throw a raw / generic error before the path domain is checked.
    surrogate_base = "a\udce9"
    with pytest.raises(UnicodeEncodeError):
        surrogate_base.encode("utf-8")

    out = tmp_dir / f"{surrogate_base}.acef.tar.gz"
    with pytest.raises(ACEFExportError) as exc_info:
        export_archive(_build_simple_package(), str(out))
    assert exc_info.value.code == "ACEF-052", (
        "a surrogate output basename must surface the designated path code "
        f"ACEF-052 through the public export_archive surface, not {exc_info.value.code!r} "
        "(ACEF-050 generic / raw UnicodeEncodeError) — entry-point validation must "
        "run before any filesystem work"
    )


@pytest.mark.conformance
def test_export_directory_surrogate_output_basename_raises_structured_acef_052(
    tmp_dir: Path,
) -> None:
    """RED→GREEN (Finding 1, ORDERING): export_directory public surface → ACEF-052.

    ``export_directory`` is the other public entry point: it derives a
    bundle_name (the output-path basename) and ``mkdir``-s ``bundle_dir`` from it
    BEFORE any member-name validation. A surrogate-bearing basename therefore
    fails inside ``mkdir`` (raw ``UnicodeEncodeError`` on a strict-encoder host,
    or ``OSError`` "Illegal byte sequence" → generic ``ACEF-050`` on macOS)
    instead of the designated path code. The entry-point validation must run on
    BOTH surfaces so neither leaks a raw / generic error.
    """
    surrogate_base = "a\udce9"
    out = tmp_dir / f"{surrogate_base}.acef"
    with pytest.raises(ACEFExportError) as exc_info:
        export_directory(_build_simple_package(), str(out))
    assert exc_info.value.code == "ACEF-052", (
        "a surrogate output basename must surface ACEF-052 through the public "
        f"export_directory surface, not {exc_info.value.code!r}"
    )


@pytest.mark.conformance
def test_export_directory_too_long_output_basename_raises_acef_052_before_fs_work(
    tmp_dir: Path,
) -> None:
    """RED→GREEN (Finding 1, ORDERING): export_directory >=100-byte basename → ACEF-052.

    A directory bundle's basename IS the bundle name: it becomes the tar-root
    member (``<bundle_name>/``) of any archive later built from the directory,
    so both public surfaces must share one permitted name domain. Pre-fix
    ``export_directory`` performs NO name validation at all — a
    >=100-UTF-8-byte basename silently SUCCEEDS, producing a directory bundle
    that ``export_archive`` (and the TS writer) would reject. The entry-point
    validation must reject it as ACEF-052 BEFORE any FS work, leaving no bundle
    directory behind (the ordering proof).
    """
    long_base = "z" * 110  # "<base>/" root member is 111 bytes >= 100
    out = tmp_dir / long_base
    with pytest.raises(ACEFExportError) as exc_info:
        export_directory(_build_simple_package(), str(out))
    assert exc_info.value.code == "ACEF-052"
    assert "100" in str(exc_info.value), "rejection must cite the 100-byte USTAR domain, not a generic export error"
    assert not out.exists(), (
        "validation must run BEFORE any filesystem work — no bundle directory may be created for a rejected basename"
    )


@pytest.mark.conformance
def test_export_archive_too_long_output_basename_raises_acef_052_before_fs_work(
    tmp_dir: Path,
) -> None:
    """RED→GREEN (Finding 1, ORDERING): a >=100-byte basename → ACEF-052 at entry.

    A ``>= 100``-UTF-8-byte output basename makes the tar-root member
    (``<bundle_name>/``) breach the USTAR short-name domain on its own (no
    artifact needed). Pre-fix this is only caught DEEP in the tar loop after
    ``export_directory`` already created the bundle dir, manifest, hashes and
    Merkle tree. The entry-point validation must reject it as ACEF-052 BEFORE any
    of that FS work — a structured path error, never a deep tar error.
    """
    long_base = "z" * 110  # 110 bytes; "<base>.acef/" root member is ~116 bytes
    out = tmp_dir / f"{long_base}.acef.tar.gz"
    with pytest.raises(ACEFExportError) as exc_info:
        export_archive(_build_simple_package(), str(out))
    assert exc_info.value.code == "ACEF-052"
    assert "100" in str(exc_info.value), "rejection must cite the 100-byte USTAR domain, not a generic export error"


@pytest.mark.conformance
def test_export_archive_normal_output_basename_exports_fine(tmp_dir: Path) -> None:
    """Negative control (Finding 1, ORDERING): a normal basename still exports.

    The entry-point validation must NOT perturb the happy path: a normal
    (short, ASCII, NFC) output basename exports a valid archive that exists and
    round-trips. Guards against an over-eager entry-point check.
    """
    out = tmp_dir / "normal-bundle.acef.tar.gz"
    result = export_archive(_build_simple_package(), str(out))
    assert result == out
    assert out.exists()
    # The archive is a valid gzip tar with the expected root member present.
    tar_bytes = _tar_bytes(out)
    names = {b[NAME_FIELD].rstrip(b"\x00") for b in _iter_header_blocks(tar_bytes)}
    assert b"normal-bundle.acef/" in names


@pytest.mark.conformance
def test_export_directory_normal_output_basename_exports_fine(tmp_dir: Path) -> None:
    """Negative control (Finding 1, ORDERING): export_directory happy path intact.

    A normal output basename must still produce a populated directory bundle.
    Guards the second public surface against an over-eager entry-point check.
    """
    out = tmp_dir / "normal-dir-bundle.acef"
    result = export_directory(_build_simple_package(), str(out))
    assert result == out
    assert (out / "acef-manifest.json").exists()
    assert (out / "records").is_dir()
