// Failing-first test for RFC 8785 JCS canonicalization (VAL-TS-005).
//
// The reference Python implementation in src/acef/integrity.py:42-52
// uses `rfc8785.dumps`. This test verifies the TS port produces
// byte-identical output for the RFC 8785 reference vectors.
//
// Run after build: `node --test dist-test/jcs.test.js` (built by tsc).
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { canonicalize, sha256Hex } from "../src/integrity.js";

describe("RFC 8785 JCS canonicalization", () => {
    it("produces sorted-key object output", () => {
        const out = canonicalize({ b: 1, a: 2 });
        assert.equal(Buffer.from(out).toString("utf-8"), '{"a":2,"b":1}');
    });

    it("encodes booleans and null", () => {
        const out = canonicalize({ x: true, y: false, z: null });
        assert.equal(Buffer.from(out).toString("utf-8"), '{"x":true,"y":false,"z":null}');
    });

    it("encodes nested arrays in insertion order (arrays NOT sorted)", () => {
        const out = canonicalize([3, 1, 2]);
        assert.equal(Buffer.from(out).toString("utf-8"), "[3,1,2]");
    });

    it("encodes integers per RFC 8785 (no trailing .0)", () => {
        const out = canonicalize({ n: 42 });
        assert.equal(Buffer.from(out).toString("utf-8"), '{"n":42}');
    });

    it("recursively sorts nested object keys", () => {
        const out = canonicalize({ b: { d: 1, c: 2 }, a: [{ z: 1, y: 2 }] });
        assert.equal(
            Buffer.from(out).toString("utf-8"),
            '{"a":[{"y":2,"z":1}],"b":{"c":2,"d":1}}',
        );
    });

    it("escapes JSON strings per RFC 8259 minimal escaping", () => {
        const out = canonicalize({ s: 'a"b\nc\\d' });
        assert.equal(Buffer.from(out).toString("utf-8"), '{"s":"a\\"b\\nc\\\\d"}');
    });

    it("sorts object keys by UTF-16 code units (RFC 8785 §3.2.3)", () => {
        // The RFC 8785 spec requires code-point ordering; JS string compare
        // uses UTF-16 code units, which agrees with code-point ordering on
        // BMP. Verify Greek + Latin sort order.
        const out = canonicalize({ "ä": 1, b: 2, a: 3 });
        // Code point ordering: 'a' (U+0061) < 'b' (U+0062) < 'ä' (U+00E4)
        assert.equal(Buffer.from(out).toString("utf-8"), '{"a":3,"b":2,"ä":1}');
    });

    it("sha256Hex returns lowercase hex", () => {
        const h = sha256Hex(Buffer.from("hello"));
        assert.equal(h, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    });
});
