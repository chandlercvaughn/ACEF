/**
 * Cross-language parity (PhD re-review CRYPTO-2, roborev on fe2496b): the
 * hash-domain path text contract (spec §3.1.1) — strict UTF-8, NO Unicode
 * control characters (category Cc, incl. NUL), and NFC — must be enforced in the
 * TypeScript SDK too, so TS cannot emit a `content-hashes.json` / Merkle tree the
 * Python validator (`acef.integrity.path_nfc_utf8_problem`) rejects. Mirrors
 * `tests/unit/test_nfc_paths.py`.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { pathTextProblem, buildMerkleTree } from "../src/integrity.js";

const C = (code: number): string => "a" + String.fromCharCode(code) + "b";
const NUL = C(0x00);
const CONTROL_PATHS = [C(0x00), C(0x01), C(0x1f), C(0x7f), C(0x09), C(0x0a), C(0x9f)];

// 'cafe' + COMBINING ACUTE ACCENT (U+0301): explicitly NFD (byte-distinct from
// the composed U+00E9 form yet rendering identically). 'caf' + composed é: NFC.
const NFD_NAME = "caf" + "e" + String.fromCharCode(0x0301) + ".txt";
const NFC_NAME = "caf" + String.fromCharCode(0x00e9) + ".txt";

test("pathTextProblem flags control characters (including NUL)", () => {
    for (const p of CONTROL_PATHS) {
        const reason = pathTextProblem(p);
        assert.ok(
            reason !== null && /control/i.test(reason),
            `${JSON.stringify(p)} must be rejected as a control char`,
        );
    }
});

test("pathTextProblem flags a lone surrogate and a non-NFC path", () => {
    assert.ok(pathTextProblem("a\uD800b") !== null, "lone high surrogate must be rejected");
    assert.notEqual(NFD_NAME, NFD_NAME.normalize("NFC"), "fixture must be genuinely NFD");
    assert.ok(pathTextProblem(NFD_NAME) !== null, "NFD path must be rejected");
});

test("pathTextProblem accepts clean ASCII and printable NFC paths", () => {
    assert.equal(pathTextProblem("records/risk_register.jsonl"), null);
    assert.equal(pathTextProblem("artifacts/sub/eval-report.txt"), null);
    assert.equal(pathTextProblem("artifacts/" + NFC_NAME), null); // composed é (NFC)
});

test("buildMerkleTree rejects a NUL-bearing content-hashes key", () => {
    assert.throws(
        () => buildMerkleTree({ [NUL]: "ab".repeat(32), "c/d.json": "cd".repeat(32) }),
        /3\.1\.1/,
    );
});

test("buildMerkleTree rejects a non-NUL control key and accepts clean keys", () => {
    assert.throws(() => buildMerkleTree({ [C(0x1f)]: "ab".repeat(32) }), /3\.1\.1/);
    const tree = buildMerkleTree({
        "acef-manifest.json": "ab".repeat(32),
        "records/r.jsonl": "cd".repeat(32),
    });
    assert.ok(typeof tree.root === "string" && tree.root.length === 64);
});
