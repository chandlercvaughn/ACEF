/**
 * Deterministic gzip helper for ACEF cross-language archive parity.
 *
 * Byte-for-byte mirror of `src/acef/exporter_gzip.py:deterministic_gzip`.
 *
 * ACEF Spec §3.1.3 requires gzip output with:
 *     - compression level 6
 *     - mtime field = 0
 *     - OS field = 0xFF (unknown)
 *
 * Node's `zlib.gzipSync` does not let callers fix the mtime/OS bytes (it
 * encodes Node's platform OS code, currently 0x03 on Linux/macOS). To
 * produce byte-equal output to Python's hand-rolled gzip, we emit the
 * 10-byte header explicitly, then raw DEFLATE via `zlib.deflateRawSync`,
 * then the CRC-32 + ISIZE trailer.
 *
 * Header layout (RFC 1952 §2.3.1):
 *     bytes 0..1  : magic       0x1f 0x8b
 *     byte  2     : method      0x08 (DEFLATE)
 *     byte  3     : flags       0x00
 *     bytes 4..7  : mtime       0x00 0x00 0x00 0x00
 *     byte  8     : XFL         0x00 (matches Python gzip.GzipFile at level=6)
 *     byte  9     : OS          0xff (unknown)
 *
 * Trailer:
 *     bytes 0..3  : CRC-32 little-endian
 *     bytes 4..7  : ISIZE little-endian
 */

import { deflateRawSync, crc32 as zlibCrc32 } from "node:zlib";

/** Fixed 10-byte gzip header per ACEF spec §3.1.3 determinism. */
const GZIP_HEADER: Buffer = Buffer.from([
    0x1f, 0x8b, // magic
    0x08,       // DEFLATE method
    0x00,       // flags (none)
    0x00, 0x00, 0x00, 0x00, // mtime = 0
    0x00,       // XFL = 0
    0xff,       // OS = unknown
]);

/**
 * Compute CRC-32 of a Buffer using Node's built-in zlib.crc32 when
 * available (Node 22+), and falling back to a table-based implementation
 * for older runtimes.
 *
 * The fallback uses the standard reflected polynomial 0xedb88320 — same as
 * Python's `zlib.crc32` and the gzip / zlib reference implementations.
 */
function crc32(buf: Buffer): number {
    if (typeof zlibCrc32 === "function") {
        // Node 22+: native CRC-32. Returns an unsigned 32-bit integer.
        // The function signature accepts a single Uint8Array argument.
        return zlibCrc32(buf) >>> 0;
    }
    return crc32Fallback(buf);
}

/** Lazy-initialized CRC-32 lookup table for the fallback path. */
let CRC_TABLE: Uint32Array | null = null;

function getCrcTable(): Uint32Array {
    if (CRC_TABLE !== null) return CRC_TABLE;
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) {
            c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
        }
        table[n] = c >>> 0;
    }
    CRC_TABLE = table;
    return table;
}

function crc32Fallback(buf: Buffer): number {
    const table = getCrcTable();
    let crc = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
        const byte = buf[i] as number;
        const idx = (crc ^ byte) & 0xff;
        crc = (table[idx] as number) ^ (crc >>> 8);
    }
    return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Return a gzip-format Buffer for `data` with deterministic header bytes.
 *
 * Mirrors `acef.exporter_gzip.deterministic_gzip`. Byte-equal output is
 * required for cross-language parity (VAL-PARITY-001).
 *
 * @param data  Uncompressed input bytes.
 * @param level zlib compression level (default 6 per ACEF spec §3.1.3).
 * @returns Buffer containing header + raw DEFLATE + CRC32-LE + ISIZE-LE.
 * @throws TypeError on non-Buffer input.
 * @throws RangeError on out-of-range compression level.
 */
export function deterministicGzip(data: Buffer, level: number = 6): Buffer {
    if (!Buffer.isBuffer(data)) {
        throw new TypeError(
            `deterministicGzip expects a Buffer, got ${typeof data}`,
        );
    }
    if (!Number.isInteger(level) || level < 0 || level > 9) {
        throw new RangeError(
            `deterministicGzip level must be integer 0..9, got ${level}`,
        );
    }

    // Raw DEFLATE — no zlib wrapper, no gzip wrapper. Equivalent to
    // Python's `zlib.compressobj(level, DEFLATED, -15)`.
    const compressed: Buffer = deflateRawSync(data, { level });

    const crc = crc32(data);
    const isize = data.length >>> 0; // mod 2^32 little-endian

    const trailer = Buffer.alloc(8);
    trailer.writeUInt32LE(crc, 0);
    trailer.writeUInt32LE(isize, 4);

    return Buffer.concat([GZIP_HEADER, compressed, trailer]);
}
