"""Deterministic gzip helper for ACEF cross-language archive parity.

ACEF Spec §3.1.3 requires gzip output with:
    - compression level 6
    - mtime field = 0
    - OS field = 0xFF (unknown)
    - owner 0/0, permissions 0644/0755 (those apply to the tar layer, not gzip)

Python's `gzip` module does not let callers set the OS byte directly (it
hard-codes platform default — 3 = Unix on macOS/Linux). For byte-equal
output to other language SDKs (Node TypeScript in particular), this module
hand-rolls the 10-byte gzip header plus raw DEFLATE (`zlib.compressobj`
with `wbits=-15`) plus CRC-32 + ISIZE trailer.

Header layout (RFC 1952 §2.3.1):
    bytes 0..1  : magic       0x1f 0x8b
    byte  2     : method      0x08 (DEFLATE)
    byte  3     : flags       0x00 (no FNAME / FEXTRA / FCOMMENT / FHCRC / FTEXT)
    bytes 4..7  : mtime       0x00 0x00 0x00 0x00 (per ACEF determinism rule)
    byte  8     : XFL         0x00 (matches what `gzip.GzipFile` emits at level=6,
                              which is what the existing exporter at
                              `src/acef/export.py:_stream_gzip` produces; keeping
                              this preserves byte-equality with already-shipped
                              golden bundles)
    byte  9     : OS          0xff (unknown — per ACEF spec §3.1.3)

Trailer (RFC 1952 §2.3.1):
    bytes 0..3  : CRC-32 of uncompressed input (little-endian)
    bytes 4..7  : ISIZE — uncompressed size mod 2**32 (little-endian)
"""

from __future__ import annotations

import zlib

# Gzip header constants per RFC 1952.
_GZIP_MAGIC = b"\x1f\x8b"
_DEFLATE_METHOD = 0x08
_NO_FLAGS = 0x00
_DETERMINISTIC_MTIME = b"\x00\x00\x00\x00"
_XFL_DEFAULT = 0x00  # Matches Python gzip.GzipFile output for compresslevel=6
_OS_UNKNOWN = 0xFF


def deterministic_gzip(data: bytes, *, level: int = 6) -> bytes:
    """Return a gzip-format byte string for `data` with deterministic header bytes.

    Args:
        data: Uncompressed input bytes.
        level: zlib compression level (default 6 per ACEF spec §3.1.3).

    Returns:
        Bytes forming a complete gzip member: 10-byte header + raw DEFLATE
        stream + 8-byte trailer (CRC-32 LE + ISIZE LE). Header fields fixed
        to: mtime=0, XFL=0x00, OS=0xFF.

    Raises:
        TypeError: If `data` is not bytes-like.
        ValueError: If `level` is outside the zlib-accepted range 0..9.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"deterministic_gzip expects bytes, got {type(data).__name__}")
    if not (0 <= level <= 9):
        raise ValueError(f"deterministic_gzip level must be 0..9, got {level}")

    payload = bytes(data)

    # Raw DEFLATE (no zlib wrapper, no gzip wrapper): wbits = -15.
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    compressed = compressor.compress(payload) + compressor.flush()

    crc = zlib.crc32(payload) & 0xFFFFFFFF
    isize = len(payload) & 0xFFFFFFFF

    header = (
        _GZIP_MAGIC + bytes([_DEFLATE_METHOD, _NO_FLAGS]) + _DETERMINISTIC_MTIME + bytes([_XFL_DEFAULT, _OS_UNKNOWN])
    )
    trailer = crc.to_bytes(4, "little") + isize.to_bytes(4, "little")

    return header + compressed + trailer
