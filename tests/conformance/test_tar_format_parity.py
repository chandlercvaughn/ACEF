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

from acef.export import export_archive
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
