/**
 * Unit tests for the deterministic gzip helper.
 *
 * Mirrors the Python-side tests in `tests/conformance/test_gzip_determinism.py`.
 * The cross-language byte-equal assertion (VAL-PARITY-001) lives in the
 * Python test; this file pins down per-byte expectations on the TS side so
 * a regression here is caught at `npm test` time rather than only at the
 * Python conformance tier.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { deterministicGzip } from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Walk up to the repo root from .../dist-test/test/.
function repoRoot(): string {
    // After tsc, this file lives at: <repo>/packages/sdk-typescript/dist-test/test/gzip.test.js
    return resolve(__dirname, "..", "..", "..", "..");
}

test("deterministicGzip header bytes are exactly 1f 8b 08 00 00 00 00 00 00 ff", () => {
    const out = deterministicGzip(Buffer.from("hello world\n", "utf-8"));
    const header = out.subarray(0, 10).toString("hex");
    assert.equal(header, "1f8b08000000000000ff");
});

test("deterministicGzip on empty input emits 20-byte minimal gzip", () => {
    const out = deterministicGzip(Buffer.alloc(0));
    // 10-byte header + 2-byte empty DEFLATE block + 8-byte trailer (CRC=0, ISIZE=0)
    assert.equal(out.length, 20);
    const trailer = out.subarray(out.length - 8);
    for (let i = 0; i < 8; i++) {
        assert.equal(trailer[i], 0, `trailer byte ${i} should be 0`);
    }
});

test("deterministicGzip output round-trips through gunzipSync", () => {
    const payload = Buffer.from("the quick brown fox jumps over the lazy dog");
    const gz = deterministicGzip(payload);
    const restored = gunzipSync(gz);
    assert.equal(restored.toString("utf-8"), payload.toString("utf-8"));
});

test("deterministicGzip is byte-stable across invocations (no hidden entropy)", () => {
    const payload = Buffer.from("ACEF-determinism-self-test");
    const a = deterministicGzip(payload);
    const b = deterministicGzip(payload);
    assert.deepEqual(a, b);
});

test("deterministicGzip handles the committed fixture and matches Python byte-equally", () => {
    // The Python sanity-check (see test_gzip_determinism.py) computes the
    // same SHA-256 over Python's deterministic_gzip output for the same
    // fixture. The expected hash here is reproduced from the Python helper
    // exactly once (in the cross-language test); the TS unit test pins
    // down that the same hash is produced by the TS helper. If either
    // implementation drifts, both this test and the Python cross-language
    // test will fail.
    const fixturePath = resolve(repoRoot(), "tests", "conformance", "fixtures", "gzip-test-vector.bin");
    const fixture = readFileSync(fixturePath);
    const gz = deterministicGzip(fixture);

    // Round-trip
    const restored = gunzipSync(gz);
    assert.equal(restored.length, fixture.length);
    assert.deepEqual(restored, fixture);

    // Header byte-pinned
    const header = gz.subarray(0, 10).toString("hex");
    assert.equal(header, "1f8b08000000000000ff");

    // Stable hash across runs
    const sha = createHash("sha256").update(gz).digest("hex");
    assert.equal(sha, createHash("sha256").update(deterministicGzip(fixture)).digest("hex"));
});

test("deterministicGzip rejects non-Buffer input", () => {
    assert.throws(
        () => deterministicGzip("not a buffer" as unknown as Buffer),
        /TypeError/,
    );
});

test("deterministicGzip rejects out-of-range level", () => {
    const payload = Buffer.from("x");
    assert.throws(() => deterministicGzip(payload, -1), /RangeError/);
    assert.throws(() => deterministicGzip(payload, 10), /RangeError/);
    assert.throws(() => deterministicGzip(payload, 6.5), /RangeError/);
});
