# @acef/sdk

TypeScript SDK for the ACEF (AI Compliance Evidence Format) **Core v1.1**. This
package is a separate code path from the Python reference SDK but is built to
produce **byte-identical** output for the three primitives that sit in ACEF's
hash and signature domain: RFC 8785 (JCS) canonicalization, JWS detached
signatures (RS256 / ES256), and deterministic gzip. Same logical input on
either language yields the same canonical bytes, the same content hashes, and
the same signatures — which is what makes a bundle produced by one SDK
verifiable by the other.

---

## Status

This is the **v0.2.0 initial port**. It ships the cross-language parity core and
the v1.1 type surface, not the full bundle lifecycle. Scope is intentionally
narrow so the parity guarantee can be proven before higher-level builders are
ported.

**Implemented** (everything below is a real export from `src/index.ts`):

- **JCS canonicalization** — `canonicalize`, `canonicalizeJsonString`,
  `sha256Hex`, `computeBundleDigest`, `buildMerkleTree` (RFC 8785, byte-equal to
  Python's `acef.integrity`).
- **JWS detached signatures** — `createDetachedJws`, `verifyDetachedJws`,
  `signHarnessAttestation`, `verifyHarnessAttestation`, plus the normative
  `HARNESS_ATTESTATION_SIGNED_FIELDS` scope. **RS256 and ES256 (P-256) only** —
  every other algorithm is rejected.
- **Deterministic gzip** — `deterministicGzip` (level 6, `mtime=0`, `OS=0xFF`),
  byte-equal to `acef.exporter_gzip.deterministic_gzip`.
- **v1.1 record-type models** — typed payloads for all six new Core record
  types (`AuthorizedTestScopePayload`, `ScopeBoundaryEventPayload`,
  `FindingRecordPayload`, `DeliveryVerdictPayload`, `CoverageCellPayload`,
  `HarnessAttestationPayload`) and the five new variant payloads
  (`HumanOversightKillSwitchPayload`, `RegressionDefinitionPayload`,
  `DispositionRecordPayload`, `BadgeStatePayload`,
  `EvidenceFreshnessWindowPayload`).
- **Envelope + manifest builders** — `buildRecordEnvelope` (with the X1–X4
  optional v1.1 envelope fields: `redaction_policy_version`,
  `redaction_attestation_ref`, `tenant_label`, `causation_chain`) and
  `buildManifest` (with the X5/X6 manifest fields: `analysis_mode`,
  `namespaces`).
- **Enum mirrors** — `RECORD_TYPES`, `AnalysisMode`, `StateClass`,
  `AuthorityClass`, `Confidentiality`, `ObligationRole`, and the rest of the
  enum surface.
- **Version selection** — `schemaVersionForCoreVersion`, `SDK_VERSION`,
  `CORE_VERSION`.

**Deferred to a later release** (NOT exported from this package — do not assume
they exist):

- The full `Package` builder (`add_subject`, `record`, `attest`,
  `record_finding`, `record_delivery_verdict`, etc.).
- The bundle **loader** and load-time rejection paths.
- The Ajv / JSON-Schema **validation pipeline** and the validator's
  conditional-required / mode-gated / namespace-lint rules.
- Tar archive assembly and the standalone `acef verify` **CLI**.

For those workflows, use the Python reference SDK (`pip install acef`). This
package covers the parity-critical primitives and the v1.1 typed models a
TypeScript producer needs to construct records that the Python toolchain can
ingest.

---

## Installation

This package is **not yet published to npm**. Install it locally from the repo.

Requirements: **Node.js >= 18** (declared in `package.json` `engines`). The SDK
has zero runtime dependencies — it relies only on the Node `crypto` and `zlib`
built-ins.

From a clone of the ACEF repo, build and link the package:

```bash
cd packages/sdk-typescript
npm install      # dev dependencies (typescript, @types/node) only
npm run build    # emits dist/
```

Then reference it from a consuming project by relative path or `npm link`:

```jsonc
// consumer package.json
{
  "dependencies": {
    "@acef/sdk": "file:../ACEF/packages/sdk-typescript"
  }
}
```

When the package is later published, `npm install @acef/sdk` will be the
supported path; until then, the local `file:` reference (or a workspace entry)
is the way to consume it.

---

## Usage

All examples below import only symbols that this package actually exports. They
are ESM (`"type": "module"` in `package.json`).

### JCS canonicalization (RFC 8785)

```typescript
import { canonicalize, sha256Hex } from "@acef/sdk";

// Object keys are sorted; output is UTF-8 bytes, byte-equal to Python's JCS.
const bytes = canonicalize({ b: 1, a: { d: 2, c: 3 } });
console.log(new TextDecoder().decode(bytes)); // {"a":{"c":3,"d":2},"b":1}

// Content hashing operates on the canonical bytes.
const digest = sha256Hex(bytes);
console.log(digest); // lowercase hex SHA-256
```

### Signing and verifying a harness_attestation (JWS)

`signHarnessAttestation` projects the payload down to its normative 9-field
signed scope (`HARNESS_ATTESTATION_SIGNED_FIELDS`), JCS-canonicalizes that
subset, and produces a detached JWS. The algorithm is auto-detected from the
key (RSA → RS256, P-256 EC → ES256).

```typescript
import { generateKeyPairSync } from "node:crypto";
import {
  signHarnessAttestation,
  verifyHarnessAttestation,
} from "@acef/sdk";

const { privateKey, publicKey } = generateKeyPairSync("ec", {
  namedCurve: "P-256",
});

const attestation = {
  attestation_id: "urn:acef:rec:att-1",
  state_class: "delivery",
  state_transition: {
    from_state: "dispatched",
    to_state: "verified_delivered",
    transitioned_at: "2025-01-01T00:00:00Z",
  },
  bound_evidence_refs: ["urn:acef:rec:verdict-1"],
  verifier: {
    verifier_id: "read-back-1",
    verifier_class: "read_back_verifier",
    verifier_version: "1.0.0",
  },
  claim: "delivery read-back digest matched",
  fake_green_test_ref: "urn:acef:rec:fg-delivery-1",
  signed_at: "2025-01-01T00:00:00Z",
  signer_kid: "es256-key-1",
};

// Returns a detached JWS string: "<header_b64>..<sig_b64>"
const jws = signHarnessAttestation(attestation, privateKey, "es256-key-1");

// true on success; false if the signed scope was tampered with.
const ok = verifyHarnessAttestation(attestation, jws, publicKey);
console.log(ok); // true
```

For arbitrary byte payloads (not a harness_attestation), use the lower-level
`createDetachedJws` / `verifyDetachedJws`:

```typescript
import { createDetachedJws, verifyDetachedJws } from "@acef/sdk";

const payload = new TextEncoder().encode("the quick brown fox");
const jws = createDetachedJws(payload, privateKey, { kid: "es256-key-1" });
const header = verifyDetachedJws(jws, payload, publicKey); // throws on failure
console.log(header.alg); // "ES256"
```

### Deterministic gzip

```typescript
import { deterministicGzip, sha256Hex } from "@acef/sdk";

const data = Buffer.from("hello world\n", "utf-8");
const gz = deterministicGzip(data); // level 6, mtime=0, OS=0xFF
console.log(gz.subarray(0, 10).toString("hex")); // 1f8b080000000000 00ff
console.log(sha256Hex(gz)); // matches Python's deterministic_gzip output
```

### Constructing a typed v1.1 record payload

The agent-reliability payloads are typed interfaces. Build a payload, wrap it in
a record envelope, and the resulting object canonicalizes deterministically.

```typescript
import {
  buildRecordEnvelope,
  canonicalize,
  AUTHORIZED_TEST_SCOPE,
  type AuthorizedTestScopePayload,
} from "@acef/sdk";

const scope: AuthorizedTestScopePayload = {
  scope_id: "urn:acef:rec:scope-1",
  scope_version: "1.0.0",
  subject_ref: "urn:acef:sub:s1",
  authorized_surfaces: [
    {
      surface_type: "api_endpoint",
      surface_identifier: "https://api.example.test/v1",
      authorization_level: "read_write_sandbox",
    },
  ],
  authorized_identities: [
    {
      identity_type: "test_account",
      identity_ref: "urn:acef:actor:test-bot",
      scope_constraint: "sandbox-only",
    },
  ],
  side_effect_policy: { default_disposition: "default_deny" },
  sandbox_boundary: {
    ownership_ledger_ref: "urn:acef:rec:ledger-1",
    preflight_method: "preflight_probe",
  },
  ownership_proof: {
    proof_method: "dns_txt",
    proof_artifact_ref: "urn:acef:rec:proof-1",
    verified_at: "2025-01-01T00:00:00Z",
  },
  effective_from: "2025-01-01T00:00:00Z",
  authorizing_actor_ref: "urn:acef:actor:owner-1",
};

const envelope = buildRecordEnvelope({
  record_id: "urn:acef:rec:00000000-0000-0000-0000-000000000001",
  record_type: AUTHORIZED_TEST_SCOPE,
  timestamp: "2025-01-01T00:00:00Z",
  payload: scope as unknown as Record<string, unknown>,
});

const canonicalBytes = canonicalize(envelope);
```

The manifest builder carries the X5/X6 v1.1 fields:

```typescript
import { buildManifest } from "@acef/sdk";

const manifest = buildManifest({
  metadata: { package_id: "urn:acef:pkg:abc", created_at: "2025-01-01T00:00:00Z" },
  versioning: { core_version: "1.1.0" },
  analysis_mode: "subscriber",
  namespaces: { "x-test": { foo: "bar" } },
});
```

---

## Cross-Language Parity Testing

Parity is verified from the **Python** test suite, which drives this SDK over a
set of small CLI subprocess drivers (`test/jcs-cli.ts`, `test/jws-cli.ts`,
`test/gzip-cli.ts`). The Python side computes its own output and asserts
byte/hash equality against the Node output.

1. Build the TS SDK and its test drivers:

   ```bash
   cd packages/sdk-typescript
   npm install
   npm run build
   npm run build:test   # emits dist-test/, including the CLI drivers
   ```

2. From the repo root, run the parity suite:

   ```bash
   pytest tests/conformance/test_cross_lang_jcs.py \
          tests/conformance/test_cross_lang_jws.py \
          tests/conformance/test_gzip_determinism.py -v
   ```

What each suite verifies:

- **`test_cross_lang_jcs.py` (VAL-TS-005)** — for every RFC 8785 reference
  vector and ACEF-shaped object (including a record envelope with the X1–X4
  fields), `canonicalize` produces output **byte-equal** to Python's
  `acef.integrity.canonicalize`.
- **`test_cross_lang_jws.py` (VAL-TS-006)** — JWS interop in **both
  directions** for **both algorithms**: Python signs / TS verifies and TS
  signs / Python verifies, for RS256 and ES256 (4 sub-tests).
- **`test_gzip_determinism.py` (VAL-PARITY-001)** — for a committed fixture and
  several pathological inputs, `sha256(deterministicGzip(x))` equals
  `sha256(deterministic_gzip(x))` from Python.

These tests **skip** (rather than fail) if `dist-test/` has not been built, so
the Python conformance tier stays green when the TS artifacts are absent. Run
`npm run build:test` first to make them execute.

**Parity guarantee:** same logical input → same canonical bytes → same content
hashes → same signatures across both languages. That is the property the suites
above pin, and it is what lets a bundle produced by one SDK be verified by the
other.

---

## Building from Source

```bash
cd packages/sdk-typescript
npm install          # dev deps only (typescript, @types/node)
npm run build        # tsc -p tsconfig.json → dist/ (.js + .d.ts)
npm test             # builds, then runs node --test over dist-test/test/*.test.js
```

`npm test` compiles the SDK and the test sources, then runs the Node built-in
test runner (`node --test`). The current suite is 26 tests across 7 suites
(JCS, JWS RS256, JWS ES256, JWS algorithm whitelist, envelope/manifest types,
gzip determinism) and exits 0 when clean.

---

## Schema Pinning

The vendored-schema directories `src/schemas/v1/` and `src/schemas/v1.1/` are
present as placeholders for a future schema-validation pipeline; **no schema
files are vendored into this package yet** (validation is deferred — see
**Status**). The authoritative ACEF JSON Schemas live in the repo at
`acef-conventions/v1/` (frozen v1.0) and `acef-conventions/v1.1/` (v1.1
additions), and that registry is the single source of truth. When the
validation pipeline lands, the vendored copies will be pinned to a specific
ACEF commit and kept in lockstep with `acef-conventions/`; until then, consult
`acef-conventions/` directly.
