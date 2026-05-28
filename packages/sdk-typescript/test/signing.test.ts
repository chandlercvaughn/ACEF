// Failing-first tests for JWS detached signing (VAL-TS-006).
//
// Reference: src/acef/signing.py:415-489 (create_detached_jws) +
// :492-614 (verify_detached_jws). RS256 + ES256 only. ES256 uses
// raw r||s signature format (64 bytes), not DER.
import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { describe, it } from "node:test";

import { createDetachedJws, verifyDetachedJws } from "../src/signing.js";

describe("JWS detached signing (RS256)", () => {
    it("round-trips a payload with RSA-2048 key", () => {
        const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
        const payload = Buffer.from('{"hello":"world"}', "utf-8");
        const jws = createDetachedJws(payload, privateKey, { kid: "test-key" });
        // Detached JWS: header..signature
        assert.match(jws, /^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$/);
        const header = verifyDetachedJws(jws, payload, publicKey);
        assert.equal(header["alg"], "RS256");
        assert.equal(header["kid"], "test-key");
    });

    it("rejects tampered payload", () => {
        const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
        const payload = Buffer.from("original", "utf-8");
        const jws = createDetachedJws(payload, privateKey, { kid: "k1" });
        const tampered = Buffer.from("tampered", "utf-8");
        assert.throws(() => verifyDetachedJws(jws, tampered, publicKey));
    });

    it("requires kid in header (spec §3.1.3)", () => {
        const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
        assert.throws(() => createDetachedJws(Buffer.from("x"), privateKey, { kid: "" }));
    });
});

describe("JWS detached signing (ES256)", () => {
    it("round-trips a payload with EC P-256 key", () => {
        const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
        const payload = Buffer.from('{"a":1}', "utf-8");
        const jws = createDetachedJws(payload, privateKey, { kid: "ec-key" });
        const header = verifyDetachedJws(jws, payload, publicKey);
        assert.equal(header["alg"], "ES256");
    });

    it("uses raw r||s signature format (64 bytes for P-256)", () => {
        const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
        const payload = Buffer.from("x", "utf-8");
        const jws = createDetachedJws(payload, privateKey, { kid: "k" });
        const parts = jws.split(".");
        // base64url-decode signature without padding
        const sigB64 = parts[2];
        const padded = sigB64 + "=".repeat((4 - (sigB64.length % 4)) % 4);
        const sig = Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
        assert.equal(sig.length, 64, `ES256 signature must be 64 bytes (raw r||s); got ${sig.length}`);
    });
});

describe("JWS algorithm whitelist (VAL-SIGNATURE-004 mirror)", () => {
    it("rejects unsupported algorithm via header tampering on verify", () => {
        const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
        const jws = createDetachedJws(Buffer.from("x"), privateKey, { kid: "k" });
        const [hdr, , sig] = jws.split(".");
        const decoded = JSON.parse(
            Buffer.from(hdr + "=".repeat((4 - (hdr.length % 4)) % 4), "base64").toString("utf-8"),
        );
        decoded.alg = "HS256";
        const newHdr = Buffer.from(JSON.stringify(decoded))
            .toString("base64")
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
        assert.throws(
            () => verifyDetachedJws(`${newHdr}..${sig}`, Buffer.from("x"), publicKey),
            /Unsupported JWS algorithm|HS256/,
        );
    });
});
