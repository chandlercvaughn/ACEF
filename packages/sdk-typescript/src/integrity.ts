/**
 * ACEF integrity module — RFC 8785 (JCS) canonicalization, SHA-256 hashing,
 * and Merkle tree construction.
 *
 * Ports `src/acef/integrity.py` to TypeScript. The output of `canonicalize`
 * is byte-equal to Python's `rfc8785.dumps` for every input the spec
 * defines as canonicalizable. Numeric handling follows RFC 8785 §3.2.2.3
 * (IEEE-754 ECMAScript Number.prototype.toString algorithm), which Python's
 * rfc8785 library mirrors. String escaping follows RFC 8259 §7 minimal
 * escapes only. Object keys are sorted by UTF-16 code-unit order, which
 * matches RFC 8785's code-point ordering for all Basic Multilingual Plane
 * characters and produces well-defined output for surrogate pairs (the
 * rfc8785 Python library uses the same ordering via Python's default
 * string sort).
 *
 * VAL-TS-005: byte-equal to Python's output for RFC 8785 reference vectors.
 */

import { createHash } from "node:crypto";

/**
 * Return a reason string if `path` violates the hash-domain path text contract
 * (spec §3.1.1), else `null`. Ports `acef.integrity.path_nfc_utf8_problem` so
 * the TypeScript exporter rejects the SAME paths the Python validator does —
 * otherwise TS could emit a `content-hashes.json` / Merkle tree Python rejects
 * (cross-language divergence). Three checks, in order:
 *   1. Strict UTF-8 — no lone (unpaired) UTF-16 surrogate.
 *   2. No Unicode control characters (general category Cc: U+0000–U+001F,
 *      U+007F–U+009F, including NUL). This is the Appendix D.5 premise.
 *   3. NFC normalization.
 */
export function pathTextProblem(path: string): string | null {
    for (let i = 0; i < path.length; i++) {
        const c = path.charCodeAt(i);
        if (c >= 0xd800 && c <= 0xdbff) {
            const next = i + 1 < path.length ? path.charCodeAt(i + 1) : 0;
            if (next < 0xdc00 || next > 0xdfff) {
                return "path is not valid UTF-8 (contains a lone surrogate)";
            }
            i++; // valid surrogate pair
        } else if (c >= 0xdc00 && c <= 0xdfff) {
            return "path is not valid UTF-8 (contains a lone surrogate)";
        }
    }
    if (/\p{Cc}/u.test(path)) {
        return "path contains a Unicode control character (general category Cc)";
    }
    if (path.normalize("NFC") !== path) {
        return "path is not UTF-8 NFC normalized";
    }
    return null;
}

/**
 * RFC 8785 (JCS) canonicalize a JSON-serializable value to UTF-8 bytes.
 *
 * Rules implemented:
 *  - `null`, `true`, `false` → JSON literals
 *  - Numbers: integers without fractional → bare integer; finite floats →
 *    ECMAScript Number.toString shortest representation; non-finite (NaN,
 *    Infinity) → throw, since RFC 8785 forbids them
 *  - Strings: minimal RFC 8259 escapes (`\"`, `\\`, `\b`, `\f`, `\n`,
 *    `\r`, `\t`, `\uXXXX` for control chars < 0x20)
 *  - Arrays: element-by-element canonicalize, joined with `,`
 *  - Objects: keys sorted by UTF-16 code-unit order, each entry as
 *    `key:value` joined with `,`. Keys themselves are JSON-encoded.
 */
export function canonicalize(value: unknown): Uint8Array {
    const str = canonicalizeToString(value);
    return new TextEncoder().encode(str);
}

function canonicalizeToString(value: unknown): string {
    if (value === null || value === undefined) {
        // RFC 8785 has no `undefined`; treat it as `null` for consistency
        // with how Python's json module (and rfc8785) ignore undefined
        // dict values. Callers should not pass `undefined` directly.
        if (value === undefined) {
            throw new TypeError("canonicalize: undefined is not RFC 8785 representable");
        }
        return "null";
    }
    if (typeof value === "boolean") {
        return value ? "true" : "false";
    }
    if (typeof value === "number") {
        return encodeNumber(value);
    }
    if (typeof value === "bigint") {
        // BigInt encodes as a bare integer literal. Python's rfc8785 emits
        // arbitrary-precision integers identically.
        return value.toString();
    }
    if (typeof value === "string") {
        return encodeString(value);
    }
    if (Array.isArray(value)) {
        const parts = value.map(canonicalizeToString);
        return "[" + parts.join(",") + "]";
    }
    if (typeof value === "object") {
        // Plain object → sorted-keys serialization.
        const obj = value as Record<string, unknown>;
        const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
        const parts = keys.map((k) => encodeString(k) + ":" + canonicalizeToString(obj[k]));
        return "{" + parts.join(",") + "}";
    }
    throw new TypeError(
        `canonicalize: unsupported value of type ${typeof value}`,
    );
}

/**
 * Encode a number per RFC 8785 §3.2.2.3.
 *
 * The spec defers to ECMAScript's Number.prototype.toString, which is
 * exactly what `String(n)` invokes in JS. For integers this produces
 * `42`, for floats `1.5`, for negative zero `0` (NOT `-0`), and for
 * scientific-notation candidates the shortest round-trip representation
 * (e.g., `1e+21`).
 *
 * RFC 8785 forbids NaN and ±Infinity in canonical output; those throw.
 */
function encodeNumber(n: number): string {
    if (!Number.isFinite(n)) {
        throw new RangeError(`canonicalize: ${n} is not RFC 8785 representable (must be finite)`);
    }
    if (Object.is(n, -0)) {
        return "0";
    }
    // ECMAScript Number.toString IS RFC 8785's number algorithm, with a few
    // exponent-form details. For typical JSON workloads this is byte-exact
    // to Python's rfc8785 output for the integers/floats produced by JSON
    // parsing.
    return String(n);
}

/**
 * Encode a string per RFC 8259 §7 minimal escapes (also RFC 8785 §3.2.2.2).
 */
function encodeString(s: string): string {
    let out = '"';
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        switch (c) {
            case 0x22: // "
                out += '\\"';
                break;
            case 0x5c: // \
                out += "\\\\";
                break;
            case 0x08: // \b
                out += "\\b";
                break;
            case 0x09: // \t
                out += "\\t";
                break;
            case 0x0a: // \n
                out += "\\n";
                break;
            case 0x0c: // \f
                out += "\\f";
                break;
            case 0x0d: // \r
                out += "\\r";
                break;
            default:
                if (c < 0x20) {
                    out += "\\u" + c.toString(16).padStart(4, "0");
                } else {
                    // All other code units (incl. surrogate halves) pass
                    // through unescaped. RFC 8785 mandates UTF-8 encoding
                    // of the result, which TextEncoder handles when we
                    // convert to bytes.
                    out += s[i];
                }
        }
    }
    out += '"';
    return out;
}

/**
 * Parse a JSON string and re-canonicalize via RFC 8785.
 */
export function canonicalizeJsonString(jsonStr: string): Uint8Array {
    return canonicalize(JSON.parse(jsonStr));
}

/**
 * SHA-256 of bytes, returns lowercase hex.
 */
export function sha256Hex(data: Uint8Array | Buffer | string): string {
    const h = createHash("sha256");
    if (typeof data === "string") {
        h.update(data, "utf-8");
    } else {
        h.update(data);
    }
    return h.digest("hex");
}

/**
 * Compute the canonical bundle digest per ACEF spec §3.1.3:
 *   sha256:<hex of SHA-256 over RFC 8785 canonicalized content-hashes.json>
 */
export function computeBundleDigest(contentHashes: Record<string, string>): string {
    const canonical = canonicalize(contentHashes);
    return "sha256:" + sha256Hex(canonical);
}

/**
 * Merkle tree leaf shape per spec §3.1.3.
 */
export interface MerkleLeaf {
    path: string;
    hash: string;
}

export interface MerkleTree {
    leaves: MerkleLeaf[];
    root: string;
}

/**
 * Build a Merkle tree from content-hashes.json entries.
 *
 * - Leaf: SHA-256(path-bytes || 0x00 || hex-hash-bytes)
 * - Inner: SHA-256(left_digest || right_digest) over raw 32-byte digests
 * - Odd leaf: promoted unchanged (NOT duplicated)
 *
 * Matches `acef.integrity.build_merkle_tree` byte-for-byte for any input.
 */
export function buildMerkleTree(contentHashes: Record<string, string>): MerkleTree {
    const entries = Object.entries(contentHashes).sort(([a], [b]) =>
        a < b ? -1 : a > b ? 1 : 0,
    );
    if (entries.length === 0) {
        const emptyRoot = sha256Hex(new Uint8Array(0));
        return { leaves: [], root: emptyRoot };
    }

    // Reject any key violating the §3.1.1 path text contract BEFORE encoding —
    // mirrors `acef.integrity.build_merkle_tree`, so TS and Python agree on which
    // bundles are well-formed (no control/NUL/non-NFC/surrogate keys enter the
    // hash domain).
    for (const [path] of entries) {
        const problem = pathTextProblem(path);
        if (problem !== null) {
            throw new Error(
                `content-hashes.json key violates spec §3.1.1 (${problem}): ${JSON.stringify(path)}`,
            );
        }
    }

    const leaves: MerkleLeaf[] = [];
    let current: Buffer[] = [];
    for (const [path, hashHex] of entries) {
        leaves.push({ path, hash: hashHex });
        const pathBytes = Buffer.from(path, "utf-8");
        const hashBytes = Buffer.from(hashHex, "utf-8");
        const leafBuf = Buffer.concat([pathBytes, Buffer.from([0x00]), hashBytes]);
        const leafHash = createHash("sha256").update(leafBuf).digest();
        current.push(leafHash);
    }

    while (current.length > 1) {
        const next: Buffer[] = [];
        for (let i = 0; i < current.length; i += 2) {
            if (i + 1 < current.length) {
                const combined = Buffer.concat([current[i]!, current[i + 1]!]);
                next.push(createHash("sha256").update(combined).digest());
            } else {
                // Odd leaf — promoted unchanged.
                next.push(current[i]!);
            }
        }
        current = next;
    }

    return { leaves, root: current[0]!.toString("hex") };
}
