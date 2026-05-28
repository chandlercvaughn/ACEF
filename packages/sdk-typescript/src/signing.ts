/**
 * ACEF signing module — JWS detached signatures (RS256 + ES256 only).
 *
 * Ports `src/acef/signing.py` to TypeScript. Cross-language interop is
 * established by:
 *  - identical JWS compact serialization `<header_b64>..<sig_b64>` (no payload)
 *  - identical header encoding (sorted keys, no whitespace, base64url no pad)
 *  - identical signature byte layout: PKCS#1 v1.5 for RS256, raw r||s
 *    (64 bytes for P-256) for ES256
 *
 * VAL-TS-006: a Python-signed bundle verifies under TS and vice versa.
 */

import {
    createPrivateKey,
    createPublicKey,
    createSign,
    createVerify,
    KeyObject,
    sign as cryptoSign,
    verify as cryptoVerify,
} from "node:crypto";

import { canonicalize } from "./integrity.js";

/** Whitelisted JWS algorithms per spec §3.1.3. */
const ALLOWED_ALGS = new Set(["RS256", "ES256"]);

/**
 * The harness_attestation signed-fields scope (VAL-SIGNATURE-001..004).
 *
 * Mirrors `src/acef/signing.py:49-59` HARNESS_ATTESTATION_SIGNED_FIELDS.
 * JCS sort still applies on serialization; this tuple defines the SCOPE,
 * not the byte order.
 */
export const HARNESS_ATTESTATION_SIGNED_FIELDS: readonly string[] = [
    "attestation_id",
    "state_class",
    "state_transition",
    "bound_evidence_refs",
    "verifier",
    "claim",
    "fake_green_test_ref",
    "signed_at",
    "signer_kid",
];

export type KeyInput = KeyObject | string | Buffer;

export interface JwsHeader {
    alg: "RS256" | "ES256";
    kid: string;
    jwk?: Record<string, string>;
    x5c?: string[];
    [k: string]: unknown;
}

export interface CreateDetachedJwsOptions {
    kid: string;
    x5c?: string[];
}

/** Base64url-encode without padding. */
function base64UrlEncode(bytes: Uint8Array | Buffer): string {
    const b = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Base64url-decode with padding restoration. */
function base64UrlDecode(s: string): Buffer {
    const pad = (4 - (s.length % 4)) % 4;
    const padded = s + "=".repeat(pad);
    return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function normalizePrivateKey(key: KeyInput): KeyObject {
    if (typeof key === "string" || Buffer.isBuffer(key)) {
        return createPrivateKey(key);
    }
    return key;
}

function normalizePublicKey(key: KeyInput): KeyObject {
    if (typeof key === "string" || Buffer.isBuffer(key)) {
        // Could be either a public-key PEM or a cert PEM. createPublicKey
        // accepts both (it extracts the SPKI from a cert).
        return createPublicKey(key);
    }
    if (key.type === "private") {
        return createPublicKey(key);
    }
    return key;
}

function detectAlgorithm(privateKey: KeyObject): "RS256" | "ES256" {
    const t = privateKey.asymmetricKeyType;
    if (t === "rsa" || t === "rsa-pss") {
        return "RS256";
    }
    if (t === "ec") {
        // Validate P-256 curve.
        const det = privateKey.asymmetricKeyDetails;
        const curve = det?.namedCurve;
        if (curve !== "prime256v1" && curve !== "P-256") {
            throw new Error(
                `[ACEF-013] Unsupported EC curve: ${curve}. ACEF requires P-256 (prime256v1) for ES256.`,
            );
        }
        return "ES256";
    }
    throw new Error(`[ACEF-013] Unsupported key type: ${t ?? "unknown"}`);
}

/**
 * Derive a JWK representation of a public key from a private key. Mirrors
 * `_derive_jwk` in the Python module.
 */
function deriveJwk(privateKey: KeyObject): Record<string, string> {
    const alg = detectAlgorithm(privateKey);
    const publicKey = createPublicKey(privateKey);
    if (alg === "RS256") {
        // Node's JWK export gives n,e,d,p,q,... — we strip to public params.
        const jwk = publicKey.export({ format: "jwk" }) as Record<string, string>;
        return { kty: "RSA", n: jwk["n"]!, e: jwk["e"]! };
    } else {
        const jwk = publicKey.export({ format: "jwk" }) as Record<string, string>;
        return { kty: "EC", crv: "P-256", x: jwk["x"]!, y: jwk["y"]! };
    }
}

function loadJwk(jwk: Record<string, unknown>): KeyObject {
    const kty = jwk["kty"];
    if (kty === "RSA") {
        return createPublicKey({ key: jwk as any, format: "jwk" });
    }
    if (kty === "EC") {
        if (jwk["crv"] !== "P-256") {
            throw new Error(
                `[ACEF-013] Unsupported EC curve in JWK: ${jwk["crv"]}. ACEF requires P-256.`,
            );
        }
        return createPublicKey({ key: jwk as any, format: "jwk" });
    }
    throw new Error(`[ACEF-012] Unsupported JWK key type: ${kty}`);
}

/**
 * Create a detached JWS over `payload`.
 *
 * Output format: `<header_b64>..<sig_b64>` (empty middle segment per
 * RFC 7515 detached form).
 *
 * Header always contains `alg`, `kid`, and either `x5c` (if provided) or
 * `jwk` (auto-derived from `privateKey`).
 */
export function createDetachedJws(
    payload: Uint8Array | Buffer,
    privateKey: KeyInput,
    opts: CreateDetachedJwsOptions,
): string {
    if (!opts.kid) {
        throw new Error(
            "[ACEF-013] JWS 'kid' parameter is required (spec §3.1.3 mandates kid in every header)",
        );
    }
    const pk = normalizePrivateKey(privateKey);
    const alg = detectAlgorithm(pk);

    const header: Record<string, unknown> = { alg, kid: opts.kid };
    if (opts.x5c && opts.x5c.length > 0) {
        header["x5c"] = opts.x5c;
    } else {
        header["jwk"] = deriveJwk(pk);
    }

    // JSON encode with sorted keys, no whitespace. Matches Python signing.py:459
    // which uses `json.dumps(..., separators=(",", ":"), sort_keys=True)`.
    const headerJson = jsonStringifySortedKeys(header);
    const headerB64 = base64UrlEncode(Buffer.from(headerJson, "utf-8"));

    const payloadBuf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
    const payloadB64 = base64UrlEncode(payloadBuf);

    const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "ascii");

    let signature: Buffer;
    if (alg === "RS256") {
        signature = createSign("sha256").update(signingInput).sign({
            key: pk,
            padding: 1, // RSA_PKCS1_PADDING — matches Python PKCS1v15
        });
    } else {
        // ES256: Node by default emits DER ECDSA sigs. The `dsaEncoding: 'ieee-p1363'`
        // option emits raw r||s (64 bytes for P-256), matching JWS / Python's
        // utils.decode_dss_signature path.
        signature = cryptoSign("sha256", signingInput, {
            key: pk,
            dsaEncoding: "ieee-p1363",
        });
        if (signature.length !== 64) {
            throw new Error(
                `[ACEF-013] ES256 signature length unexpected: ${signature.length} (must be 64 for P-256)`,
            );
        }
    }

    const sigB64 = base64UrlEncode(signature);
    return `${headerB64}..${sigB64}`;
}

/**
 * Verify a detached JWS over `payload`. Returns the decoded header on
 * success; throws on any failure (mirrors Python's exception-based path).
 */
export function verifyDetachedJws(
    jws: string,
    payload: Uint8Array | Buffer,
    publicKey?: KeyInput,
): JwsHeader {
    const parts = jws.split(".");
    if (parts.length !== 3) {
        throw new Error("[ACEF-012] Invalid JWS format: expected 3 parts");
    }
    const headerB64 = parts[0]!;
    const sigB64 = parts[2]!;

    let header: Record<string, unknown>;
    try {
        header = JSON.parse(base64UrlDecode(headerB64).toString("utf-8"));
    } catch (e) {
        throw new Error(`[ACEF-012] Invalid JWS header: ${(e as Error).message}`);
    }

    const alg = header["alg"];
    if (typeof alg !== "string" || !ALLOWED_ALGS.has(alg)) {
        throw new Error(
            `[ACEF-013] Unsupported JWS algorithm: ${alg} (allowed: RS256, ES256)`,
        );
    }
    if (!header["kid"]) {
        throw new Error("[ACEF-013] JWS header missing required 'kid' field (spec §3.1.3)");
    }

    let resolvedKey: KeyObject;
    if (publicKey !== undefined) {
        resolvedKey = normalizePublicKey(publicKey);
    } else if (header["jwk"] !== undefined) {
        resolvedKey = loadJwk(header["jwk"] as Record<string, unknown>);
    } else if (Array.isArray(header["x5c"]) && header["x5c"].length > 0) {
        // Leaf-cert key extraction (no chain anchoring — caller responsible
        // for higher-assurance verification per spec trust model).
        const leafDer = Buffer.from(header["x5c"][0] as string, "base64");
        // Wrap in PEM for Node.
        const pem =
            "-----BEGIN CERTIFICATE-----\n" +
            leafDer.toString("base64").match(/.{1,64}/g)!.join("\n") +
            "\n-----END CERTIFICATE-----\n";
        resolvedKey = createPublicKey(pem);
    } else {
        throw new Error("[ACEF-012] No public key available: neither x5c nor jwk in header");
    }

    const payloadBuf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
    const payloadB64 = base64UrlEncode(payloadBuf);
    const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "ascii");
    const signature = base64UrlDecode(sigB64);

    let ok: boolean;
    if (alg === "RS256") {
        ok = createVerify("sha256")
            .update(signingInput)
            .verify({ key: resolvedKey, padding: 1 }, signature);
    } else {
        if (signature.length !== 64) {
            throw new Error(
                `[ACEF-012] Invalid ES256 signature length: ${signature.length} (expected 64)`,
            );
        }
        ok = cryptoVerify(
            "sha256",
            signingInput,
            { key: resolvedKey, dsaEncoding: "ieee-p1363" },
            signature,
        );
    }

    if (!ok) {
        throw new Error("[ACEF-012] Signature verification failed");
    }

    return header as unknown as JwsHeader;
}

/**
 * Project a harness_attestation payload down to its 9-field signed scope.
 * Mirrors `_project_harness_attestation_subset` in Python.
 */
function projectHarnessAttestationSubset(payload: Record<string, unknown>): Record<string, unknown> {
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
        throw new Error(
            `[ACEF-012] harness_attestation payload must be an object`,
        );
    }
    const out: Record<string, unknown> = {};
    for (const f of HARNESS_ATTESTATION_SIGNED_FIELDS) {
        if (f in payload) {
            out[f] = payload[f];
        }
    }
    return out;
}

/**
 * Sign a harness_attestation payload over its 9-field scope.
 *
 * Mirrors `sign_harness_attestation` in Python — JCS-canonicalize the
 * subset, then JWS-sign the canonical bytes.
 */
export function signHarnessAttestation(
    payload: Record<string, unknown>,
    privateKey: KeyInput,
    signerKid: string,
): string {
    const subset = projectHarnessAttestationSubset(payload);
    const canonical = canonicalize(subset);
    return createDetachedJws(canonical, privateKey, { kid: signerKid });
}

/**
 * Verify a harness_attestation JWS signature.
 *
 * - Returns `true` on successful cryptographic verification.
 * - Returns `false` on signature-mismatch (tamper detection).
 * - Throws on structural / algorithm-whitelist failures.
 *
 * Mirrors `verify_harness_attestation` in Python.
 */
export function verifyHarnessAttestation(
    payload: Record<string, unknown>,
    signature: string,
    publicKey?: KeyInput,
): boolean {
    const subset = projectHarnessAttestationSubset(payload);
    const canonical = canonicalize(subset);
    try {
        verifyDetachedJws(signature, canonical, publicKey);
        return true;
    } catch (e) {
        const msg = (e as Error).message;
        if (msg.startsWith("[ACEF-013]")) {
            throw e; // alg whitelist / kid missing / curve mismatch
        }
        if (msg.startsWith("[ACEF-012] Signature verification failed")) {
            return false; // tamper detected
        }
        throw e; // other structural errors propagate
    }
}

/**
 * Deterministically JSON-stringify with sorted object keys, no whitespace.
 * Matches Python's `json.dumps(obj, separators=(',', ':'), sort_keys=True)`
 * which the signing module uses for the header.
 */
function jsonStringifySortedKeys(v: unknown): string {
    if (v === null || typeof v !== "object") {
        return JSON.stringify(v);
    }
    if (Array.isArray(v)) {
        return "[" + v.map(jsonStringifySortedKeys).join(",") + "]";
    }
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
    const parts = keys.map((k) => JSON.stringify(k) + ":" + jsonStringifySortedKeys(obj[k]));
    return "{" + parts.join(",") + "}";
}
