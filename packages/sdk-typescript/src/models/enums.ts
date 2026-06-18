/**
 * ACEF enum mirrors from `src/acef/models/enums.py`.
 *
 * String-valued constants match Python enum `.value` exactly so JSON
 * serialization is byte-identical on both sides. The Python enums:
 *
 *  - SubjectType        — enums.py:8-12
 *  - RiskClassification — enums.py:15-22
 *  - LifecyclePhase     — enums.py:25-33
 *  - ComponentType      — enums.py:36-45
 *  - DatasetSourceType  — enums.py:48-55
 *  - DatasetModality    — enums.py:58-66
 *  - ActorRole          — enums.py:69-78
 *  - AuthorityClass     — enums.py:81-94  (brief §14.5)
 *  - RelationshipType   — enums.py:97-122
 *  - ObligationRole     — enums.py:125-134
 *  - Confidentiality    — enums.py:137-144
 *  - TrustLevel         — enums.py:147-153
 *  - EventType          — enums.py:156-168
 *  - AuditEventType     — enums.py:171-178
 *  - RuleSeverity       — enums.py:181-186
 *  - RuleOutcome        — enums.py:189-195
 *  - ProvisionOutcome   — enums.py:198-215
 *  - RECORD_TYPES       — enums.py:216-262 (16 v1.0 + 7 v1.1)
 */

export const SubjectType = {
    AI_SYSTEM: "ai_system",
    AI_MODEL: "ai_model",
} as const;
export type SubjectType = (typeof SubjectType)[keyof typeof SubjectType];

export const RiskClassification = {
    HIGH_RISK: "high-risk",
    GPAI: "gpai",
    GPAI_SYSTEMIC: "gpai-systemic",
    LIMITED_RISK: "limited-risk",
    MINIMAL_RISK: "minimal-risk",
} as const;
export type RiskClassification = (typeof RiskClassification)[keyof typeof RiskClassification];

export const LifecyclePhase = {
    DESIGN: "design",
    DEVELOPMENT: "development",
    TESTING: "testing",
    DEPLOYMENT: "deployment",
    MONITORING: "monitoring",
    DECOMMISSION: "decommission",
} as const;
export type LifecyclePhase = (typeof LifecyclePhase)[keyof typeof LifecyclePhase];

export const ComponentType = {
    MODEL: "model",
    RETRIEVER: "retriever",
    GUARDRAIL: "guardrail",
    ORCHESTRATOR: "orchestrator",
    TOOL: "tool",
    DATABASE: "database",
    API: "api",
} as const;
export type ComponentType = (typeof ComponentType)[keyof typeof ComponentType];

export const ActorRole = {
    PROVIDER: "provider",
    DEPLOYER: "deployer",
    IMPORTER: "importer",
    DISTRIBUTOR: "distributor",
    AUDITOR: "auditor",
    REGULATOR: "regulator",
    DATA_SUBJECT: "data_subject",
} as const;
export type ActorRole = (typeof ActorRole)[keyof typeof ActorRole];

/**
 * Disposition authority class per brief §14.5.
 * Each class governs which actor types may exercise authority over a
 * disposition_record per the inline matrix in contract.md.
 */
export const AuthorityClass = {
    PRIORITY: "priority",
    SEVERITY_ADVISORY: "severity_advisory",
    ACCEPTED_RISK_REQUEST: "accepted_risk_request",
    FALSE_POSITIVE_ASSERTION: "false_positive_assertion",
    EVIDENCE_DISPUTE: "evidence_dispute",
} as const;
export type AuthorityClass = (typeof AuthorityClass)[keyof typeof AuthorityClass];

export const ObligationRole = {
    PROVIDER: "provider",
    DEPLOYER: "deployer",
    IMPORTER: "importer",
    DISTRIBUTOR: "distributor",
    AUTHORISED_REPRESENTATIVE: "authorised_representative",
    NOTIFIED_BODY: "notified_body",
    PLATFORM: "platform",
} as const;
export type ObligationRole = (typeof ObligationRole)[keyof typeof ObligationRole];

export const Confidentiality = {
    PUBLIC: "public",
    REDACTED: "redacted",
    HASH_COMMITTED: "hash-committed",
    REGULATOR_ONLY: "regulator-only",
    UNDER_NDA: "under-nda",
} as const;
export type Confidentiality = (typeof Confidentiality)[keyof typeof Confidentiality];

export const TrustLevel = {
    SELF_ATTESTED: "self-attested",
    PEER_REVIEWED: "peer-reviewed",
    INDEPENDENTLY_VERIFIED: "independently-verified",
    NOTIFIED_BODY_CERTIFIED: "notified-body-certified",
} as const;
export type TrustLevel = (typeof TrustLevel)[keyof typeof TrustLevel];

export const EventType = {
    INFERENCE: "inference",
    TRAINING: "training",
    EVALUATION: "evaluation",
    DEPLOYMENT: "deployment",
    OVERRIDE: "override",
    ERROR: "error",
    MARKING: "marking",
    DISCLOSURE: "disclosure",
    LOGGING_SPEC: "logging_spec",
    REDACTION: "redaction",
} as const;
export type EventType = (typeof EventType)[keyof typeof EventType];

export const AuditEventType = {
    CREATED: "created",
    UPDATED: "updated",
    REVIEWED: "reviewed",
    SUBMITTED: "submitted",
    CERTIFIED: "certified",
} as const;
export type AuditEventType = (typeof AuditEventType)[keyof typeof AuditEventType];

// -- Record type constants exported as named values for easy reference. --
export const RISK_REGISTER = "risk_register";
export const RISK_TREATMENT = "risk_treatment";
export const DATASET_CARD = "dataset_card";
export const DATA_PROVENANCE = "data_provenance";
export const EVALUATION_REPORT = "evaluation_report";
export const EVENT_LOG = "event_log";
export const HUMAN_OVERSIGHT_ACTION = "human_oversight_action";
export const TRANSPARENCY_DISCLOSURE = "transparency_disclosure";
export const TRANSPARENCY_MARKING = "transparency_marking";
export const DISCLOSURE_LABELING = "disclosure_labeling";
export const COPYRIGHT_RIGHTS_RESERVATION = "copyright_rights_reservation";
export const LICENSE_RECORD = "license_record";
export const INCIDENT_REPORT = "incident_report";
export const GOVERNANCE_POLICY = "governance_policy";
export const CONFORMITY_DECLARATION = "conformity_declaration";
export const EVIDENCE_GAP = "evidence_gap";

// v1.1 agent-reliability primitives (brief §3.1-§3.6).
export const AUTHORIZED_TEST_SCOPE = "authorized_test_scope";
export const SCOPE_BOUNDARY_EVENT = "scope_boundary_event";
export const FINDING_RECORD = "finding_record";
export const DELIVERY_VERDICT = "delivery_verdict";
export const COVERAGE_CELL = "coverage_cell";
export const HARNESS_ATTESTATION = "harness_attestation";

/**
 * RECORD_TYPES — mirror of `enums.py:216-243` `RECORD_TYPES` frozenset.
 * 22 entries total: 16 v1.0 + 6 v1.1.
 */
export const RECORD_TYPES: ReadonlySet<string> = new Set([
    RISK_REGISTER,
    RISK_TREATMENT,
    DATASET_CARD,
    DATA_PROVENANCE,
    EVALUATION_REPORT,
    EVENT_LOG,
    HUMAN_OVERSIGHT_ACTION,
    TRANSPARENCY_DISCLOSURE,
    TRANSPARENCY_MARKING,
    DISCLOSURE_LABELING,
    COPYRIGHT_RIGHTS_RESERVATION,
    LICENSE_RECORD,
    INCIDENT_REPORT,
    GOVERNANCE_POLICY,
    CONFORMITY_DECLARATION,
    EVIDENCE_GAP,
    AUTHORIZED_TEST_SCOPE,
    SCOPE_BOUNDARY_EVENT,
    FINDING_RECORD,
    DELIVERY_VERDICT,
    COVERAGE_CELL,
    HARNESS_ATTESTATION,
]);

/** Mirror of `enums.py:245-253` MANDATORY_RECORD_TYPES. */
export const MANDATORY_RECORD_TYPES: ReadonlySet<string> = new Set([
    RISK_REGISTER,
    RISK_TREATMENT,
    DATASET_CARD,
    DATA_PROVENANCE,
    EVALUATION_REPORT,
]);

/**
 * Analysis-mode values per `manifest.py:56-62` and brief §8.1.
 */
export const AnalysisMode = {
    SUBSCRIBER: "subscriber",
    PUBLIC_ARTIFACT: "public_artifact",
    CANARY: "canary",
    UNATTRIBUTED_ARTIFACT: "unattributed_artifact",
} as const;
export type AnalysisMode = (typeof AnalysisMode)[keyof typeof AnalysisMode];

/**
 * State-class taxonomy per brief §24.5 / Q3. Seven hard-coded values
 * (matches `harness_attestation` state_class enum in agent_reliability.py:447-455).
 */
export const StateClass = {
    STEP: "step",
    FINDING: "finding",
    COVERAGE_CELL: "coverage_cell",
    REGRESSION: "regression",
    DELIVERY: "delivery",
    BADGE: "badge",
    ATTESTATION: "attestation",
} as const;
export type StateClass = (typeof StateClass)[keyof typeof StateClass];
