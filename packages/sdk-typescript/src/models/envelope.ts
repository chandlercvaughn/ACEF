/**
 * Mirror of `src/acef/models/records.py` RecordEnvelope (lines 58-116).
 *
 * v1.1 envelope extensions X1-X4 are present as OPTIONAL fields:
 *   X1 redaction_policy_version
 *   X2 redaction_attestation_ref
 *   X3 tenant_label
 *   X4 causation_chain
 *
 * Conditional-required semantics are validator-level (mirror of Python's
 * design — v1.0 bundles validate clean if X1-X4 are absent).
 */

import {
    Confidentiality,
    LifecyclePhase,
    ObligationRole,
    TrustLevel,
} from "./enums.js";

/** Per-record links to entities the record concerns. */
export interface EntityRefs {
    subject_refs?: string[];
    component_refs?: string[];
    dataset_refs?: string[];
    actor_refs?: string[];
    /** Vendor extension namespaces propagate through. */
    [k: string]: unknown;
}

/** Reference to a file under `artifacts/`. */
export interface AttachmentRef {
    path: string;
    hash?: string;
    media_type?: string;
    attachment_type?: string | null;
    description?: string;
}

/** Cryptographic attestation block per spec §3.1.4. */
export interface Attestation {
    method?: string; // default "jws"
    signer?: string;
    signed_fields?: string[];
    signature?: string;
}

/** Per-record retention requirements. */
export interface RecordRetention {
    min_retention_days: number;
    retention_start_event?: string;
    legal_basis?: string;
}

/** Collector tool/person. */
export interface CollectorInfo {
    name: string;
    version?: string;
}

/**
 * RecordEnvelope — common envelope wrapping every record type's payload.
 *
 * Field semantics match Python's RecordEnvelope (records.py:58-116):
 * required fields are non-optional; v1.0 optional fields are optional;
 * v1.1 X1-X4 extensions are optional.
 */
export interface RecordEnvelope {
    record_id: string;
    record_type: string;
    provisions_addressed?: string[];
    timestamp: string;
    lifecycle_phase?: LifecyclePhase;
    collector?: CollectorInfo | string;
    obligation_role?: ObligationRole;
    confidentiality: Confidentiality;
    redaction_method?: string;
    access_policy?: Record<string, unknown>;
    trust_level?: TrustLevel;
    entity_refs?: EntityRefs;
    payload?: Record<string, unknown>;
    attachments?: AttachmentRef[];
    attestation?: Attestation;
    retention?: RecordRetention;

    // v1.1 envelope extensions (X1-X4) — all optional at the type level.
    /** X1: semver tag for the redaction policy applied to this record. */
    redaction_policy_version?: string;
    /** X2: URN of the attestation record proving redaction execution. */
    redaction_attestation_ref?: string;
    /** X3: stable tenant identifier (urn:acef:tenant:<slug>). */
    tenant_label?: string;
    /** X4: ordered upstream-record URNs (most-recent-first). */
    causation_chain?: string[];

    /** Vendor extensions allowed; survive round-trip. */
    [k: string]: unknown;
}

/**
 * Builder helper — accepts a partial input and fills defaults that mirror
 * Pydantic field defaults (records.py:64-77).
 */
export interface BuildRecordEnvelopeInput {
    record_id: string;
    record_type: string;
    timestamp: string;
    confidentiality?: Confidentiality;
    trust_level?: TrustLevel;
    lifecycle_phase?: LifecyclePhase;
    obligation_role?: ObligationRole;
    provisions_addressed?: string[];
    collector?: CollectorInfo | string;
    entity_refs?: EntityRefs;
    payload?: Record<string, unknown>;
    attachments?: AttachmentRef[];
    attestation?: Attestation;
    retention?: RecordRetention;
    redaction_method?: string;
    access_policy?: Record<string, unknown>;
    redaction_policy_version?: string;
    redaction_attestation_ref?: string;
    tenant_label?: string;
    causation_chain?: string[];
}

export function buildRecordEnvelope(input: BuildRecordEnvelopeInput): RecordEnvelope {
    const env: RecordEnvelope = {
        record_id: input.record_id,
        record_type: input.record_type,
        timestamp: input.timestamp,
        confidentiality: input.confidentiality ?? Confidentiality.PUBLIC,
        trust_level: input.trust_level ?? TrustLevel.SELF_ATTESTED,
    };
    // Optional fields are added only when provided so JSON.stringify omits
    // them when undefined (matches Python's `model_dump(exclude_none=True)`).
    if (input.lifecycle_phase !== undefined) env.lifecycle_phase = input.lifecycle_phase;
    if (input.obligation_role !== undefined) env.obligation_role = input.obligation_role;
    if (input.provisions_addressed !== undefined)
        env.provisions_addressed = input.provisions_addressed;
    if (input.collector !== undefined) env.collector = input.collector;
    if (input.entity_refs !== undefined) env.entity_refs = input.entity_refs;
    if (input.payload !== undefined) env.payload = input.payload;
    if (input.attachments !== undefined) env.attachments = input.attachments;
    if (input.attestation !== undefined) env.attestation = input.attestation;
    if (input.retention !== undefined) env.retention = input.retention;
    if (input.redaction_method !== undefined) env.redaction_method = input.redaction_method;
    if (input.access_policy !== undefined) env.access_policy = input.access_policy;
    if (input.redaction_policy_version !== undefined)
        env.redaction_policy_version = input.redaction_policy_version;
    if (input.redaction_attestation_ref !== undefined)
        env.redaction_attestation_ref = input.redaction_attestation_ref;
    if (input.tenant_label !== undefined) env.tenant_label = input.tenant_label;
    if (input.causation_chain !== undefined) env.causation_chain = input.causation_chain;
    return env;
}
