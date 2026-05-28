// Failing-first tests for RecordEnvelope + Manifest type exports (VAL-TS-004).
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
    AUTHORIZED_TEST_SCOPE,
    HARNESS_ATTESTATION,
    RECORD_TYPES,
    Confidentiality,
    LifecyclePhase,
    AuthorityClass,
    ObligationRole,
} from "../src/models/enums.js";
import {
    buildRecordEnvelope,
    type RecordEnvelope,
} from "../src/models/envelope.js";
import { buildManifest, type Manifest } from "../src/models/manifest.js";

describe("RecordEnvelope (X1-X4 optional v1.1 fields)", () => {
    it("constructs a minimal envelope with defaults", () => {
        const env: RecordEnvelope = buildRecordEnvelope({
            record_id: "urn:acef:rec:00000000-0000-0000-0000-000000000001",
            record_type: AUTHORIZED_TEST_SCOPE,
            timestamp: "2025-01-01T00:00:00Z",
        });
        assert.equal(env.record_type, "authorized_test_scope");
        assert.equal(env.confidentiality, Confidentiality.PUBLIC);
        assert.equal(env.redaction_policy_version, undefined);
        assert.equal(env.tenant_label, undefined);
        assert.equal(env.causation_chain, undefined);
    });

    it("preserves X1-X4 v1.1 extension fields", () => {
        const env = buildRecordEnvelope({
            record_id: "urn:acef:rec:00000000-0000-0000-0000-000000000002",
            record_type: HARNESS_ATTESTATION,
            timestamp: "2025-01-01T00:00:00Z",
            redaction_policy_version: "1.0.0",
            redaction_attestation_ref: "urn:acef:rec:redaction-1",
            tenant_label: "urn:acef:tenant:test",
            causation_chain: ["urn:acef:rec:upstream-1"],
        });
        assert.equal(env.redaction_policy_version, "1.0.0");
        assert.equal(env.tenant_label, "urn:acef:tenant:test");
        assert.deepEqual(env.causation_chain, ["urn:acef:rec:upstream-1"]);
    });
});

describe("Manifest (X5/X6 v1.1 extensions)", () => {
    it("includes analysis_mode and namespaces fields", () => {
        const m: Manifest = buildManifest({
            metadata: { package_id: "urn:acef:pkg:abc", created_at: "2025-01-01T00:00:00Z" },
            analysis_mode: "subscriber",
            namespaces: { "x-test": { foo: "bar" } },
        });
        assert.equal(m.analysis_mode, "subscriber");
        assert.deepEqual(m.namespaces, { "x-test": { foo: "bar" } });
    });
});

describe("RECORD_TYPES enum (VAL-TS-004 coverage)", () => {
    it("includes 16 v1.0 + 6 v1.1 record types", () => {
        // From src/acef/models/enums.py:210-243.
        assert.ok(RECORD_TYPES.has("risk_register"));
        assert.ok(RECORD_TYPES.has("authorized_test_scope"));
        assert.ok(RECORD_TYPES.has("scope_boundary_event"));
        assert.ok(RECORD_TYPES.has("finding_record"));
        assert.ok(RECORD_TYPES.has("delivery_verdict"));
        assert.ok(RECORD_TYPES.has("coverage_cell"));
        assert.ok(RECORD_TYPES.has("harness_attestation"));
        assert.equal(RECORD_TYPES.size, 22);
    });

    it("exports AuthorityClass + ObligationRole + LifecyclePhase enums", () => {
        assert.equal(AuthorityClass.PRIORITY, "priority");
        assert.equal(AuthorityClass.EVIDENCE_DISPUTE, "evidence_dispute");
        assert.equal(ObligationRole.PROVIDER, "provider");
        assert.equal(LifecyclePhase.DEVELOPMENT, "development");
    });
});
