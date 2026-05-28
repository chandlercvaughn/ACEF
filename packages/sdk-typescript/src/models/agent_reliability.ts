/**
 * Mirror of `src/acef/models/agent_reliability.py` — the six v1.1
 * agent-reliability record payload types and their nested helpers.
 *
 * Each payload structurally matches its v1.1 JSON Schema under
 * `acef-conventions/v1.1/`. Conditional-required rules
 * (e.g., `delivery_state == 'verified_delivered'` requiring
 * read_back + harness_attestation_ref) are validator-level, not
 * model-level — matching Python's design at agent_reliability.py:22-26.
 *
 * Additionally defines the five v1.1 variant payload markers from
 * `acef-conventions/v1.1/variant-registry.json`:
 *   V1 human_oversight_kill_switch
 *   V2 regression_definition
 *   V3 disposition_record
 *   V4 badge_state
 *   V5 evidence_freshness_window
 *
 * VAL-TS-004: all 11 type names appear in the emitted `dist/index.d.ts`.
 */

// ============================================================================
// §3.1 authorized_test_scope
// ============================================================================

export type SurfaceType =
    | "chat_endpoint"
    | "api_endpoint"
    | "tool_endpoint"
    | "rag_endpoint"
    | "browser_target"
    | "package_target"
    | "cli_target"
    | "container_target"
    | "docs_target";

export type AuthorizationLevel =
    | "read_only"
    | "read_write_sandbox"
    | "production_capable_owner_authorized";

export interface AuthorizedSurface {
    surface_type: SurfaceType;
    surface_identifier: string;
    authorization_level: AuthorizationLevel;
}

export type IdentityType =
    | "test_account"
    | "service_principal"
    | "delegated_grant"
    | "freddy_managed_mailbox";

export interface AuthorizedIdentity {
    identity_type: IdentityType;
    identity_ref: string;
    scope_constraint: string;
}

export interface SideEffectAllowEntry {
    action_class: string;
    rationale: string;
}

export interface SideEffectPolicy {
    default_disposition: "default_deny" | "default_allow_sandbox_only";
    explicit_allowlist?: SideEffectAllowEntry[];
    explicit_denylist?: string[];
}

export type PreflightMethod =
    | "resource_naming_scheme"
    | "tenant_label"
    | "dedicated_subaccount"
    | "preflight_probe";

export interface SandboxBoundary {
    ownership_ledger_ref: string;
    preflight_method: PreflightMethod;
}

export type ProofMethod =
    | "dns_txt"
    | "well_known_file"
    | "http_header"
    | "github_oauth"
    | "sso_assertion";

export interface OwnershipProof {
    proof_method: ProofMethod;
    proof_artifact_ref: string;
    verified_at: string; // ISO 8601
}

export interface AuthorizedTestScopePayload {
    scope_id: string;
    scope_version: string;
    subject_ref: string;
    authorized_surfaces: AuthorizedSurface[];
    authorized_identities: AuthorizedIdentity[];
    side_effect_policy: SideEffectPolicy;
    sandbox_boundary: SandboxBoundary;
    ownership_proof: OwnershipProof;
    effective_from: string;
    effective_until?: string;
    authorizing_actor_ref: string;
    kill_switch_ref?: string;
}

// ============================================================================
// §3.2 scope_boundary_event
// ============================================================================

export interface AttemptedAction {
    action_class: string;
    action_target: string;
    action_payload_digest: string; // sha256:<hex>
}

export interface AuthorizedScopeSnapshot {
    scope_id: string;
    scope_version: string;
}

export type DetectorClass =
    | "preflight_probe"
    | "ownership_ledger_check"
    | "side_effect_policy_check"
    | "post_action_audit"
    | "external_alert";

export interface BoundaryDetector {
    detector_class: DetectorClass;
    detector_id: string;
}

export type BoundaryClassification =
    | "intentional_bypass_attempt"
    | "harness_drift"
    | "persona_misbehavior"
    | "scope_definition_ambiguity"
    | "third_party_integration_overreach";

export interface ScopeBoundaryEventPayload {
    event_id: string;
    scope_ref: string;
    attempted_action: AttemptedAction;
    authorized_scope_snapshot: AuthorizedScopeSnapshot;
    classification: BoundaryClassification;
    hard_stop_triggered: boolean;
    hard_stop_attestation_ref?: string;
    detected_at: string;
    detector: BoundaryDetector;
}

// ============================================================================
// §3.3 finding_record
// ============================================================================

export type SeverityLevel = "critical" | "high" | "medium" | "low" | "informational";

export interface FindingSeverity {
    severity_level: SeverityLevel;
    severity_rationale: string;
}

export interface FindingReproduction {
    expected_behavior: string;
    observed_behavior: string;
    reproduction_steps_ref: string;
    evidence_commit_ref: string;
}

export interface FindingAttribution {
    persona_ref: string;
    scenario_ref: string;
    scope_ref: string;
}

export type FindingClass =
    | "safety_failure"
    | "policy_violation"
    | "accuracy_degradation"
    | "robustness_failure"
    | "security_vulnerability"
    | "transparency_failure"
    | "oversight_failure"
    | "data_integrity_failure";

export interface FindingRecordPayload {
    finding_id: string;
    finding_class: FindingClass;
    subject_ref: string;
    severity: FindingSeverity;
    /** sha256:<64-hex>; computed by Package.recordFinding per brief §3.3 / D5 recipe. */
    dedupe_key: string;
    variant_group_id?: string;
    reproduction: FindingReproduction;
    attribution: FindingAttribution;
    regulation_impact?: string[];
    discovered_at: string;
    discovered_in_run_ref: string;
    disposition_history?: string[];
    accepted_risk_ref?: string;
    regression_ref?: string;
}

// ============================================================================
// §3.4 delivery_verdict
// ============================================================================

export type ProviderClass =
    | "plane"
    | "github_issues"
    | "linear"
    | "jira"
    | "slack"
    | "email"
    | "markdown_export"
    | "custom";

export interface DeliveryDestination {
    provider_class: ProviderClass;
    provider_instance_id: string;
    provider_object_id: string;
}

export interface DeliveryWriteAttempt {
    attempted_at: string;
    request_digest: string;
    response_status: number;
    response_digest: string;
}

export interface DeliveryReadBack {
    read_back_at: string;
    read_back_digest: string;
    digest_match: boolean;
}

export interface DeliveryRetryEntry {
    attempted_at: string;
    response_status: number;
    response_digest: string;
}

export type DeliveryState =
    | "drafted"
    | "dispatched"
    | "acknowledged"
    | "verified_delivered"
    | "failed"
    | "drifted";

export type DriftClassification =
    | "external_close_without_resolution"
    | "external_priority_lowered"
    | "external_reassignment"
    | "ticket_deleted";

export interface DeliveryVerdictPayload {
    verdict_id: string;
    finding_ref: string;
    destination: DeliveryDestination;
    write_attempt: DeliveryWriteAttempt;
    read_back?: DeliveryReadBack;
    delivery_state: DeliveryState;
    drift_classification?: DriftClassification;
    retry_history?: DeliveryRetryEntry[];
    harness_attestation_ref?: string;
}

// ============================================================================
// §3.5 coverage_cell (lives in Assessment Bundle)
// ============================================================================

export interface CoverageDimensions {
    scenario_class: string;
    surface_class: string;
    time_window_start: string;
    time_window_end: string;
}

export type FreshnessState =
    | "fresh"
    | "stale_within_grace"
    | "stale_outside_grace"
    | "unverified";

export type CoverageOutcome = "covered" | "gap" | "blocked";

export interface CoverageCellPayload {
    cell_id: string;
    subject_ref: string;
    dimensions: CoverageDimensions;
    bound_evidence_refs: string[];
    freshness_state: FreshnessState;
    freshness_policy_ref: string;
    /**
     * Banned substrings: "compliant", "certified", "AI Act-approved", "guaranteed"
     * — enforced at validator level (ACEF-079, VAL-VALIDATION-008).
     */
    claim_language: string;
    coverage_outcome: CoverageOutcome;
    blocker_ref?: string;
}

// ============================================================================
// §3.6 harness_attestation
// ============================================================================

export interface HarnessStateTransition {
    from_state: string;
    to_state: string;
    transitioned_at: string;
}

/**
 * Verifier class DELIBERATELY excludes "persona" and "llm" — those classes
 * lack determinism required to attest state transitions and are rejected
 * at load time per VAL-LOAD-001/002.
 */
export type VerifierClass =
    | "contract_gate"
    | "read_back_verifier"
    | "cryptographic_verifier"
    | "harness_internal";

export interface HarnessVerifier {
    verifier_id: string;
    verifier_class: VerifierClass;
    verifier_version: string;
}

export type StateClassValue =
    | "step"
    | "finding"
    | "coverage_cell"
    | "regression"
    | "delivery"
    | "badge"
    | "attestation";

export interface HarnessAttestationSignature {
    alg: "RS256" | "ES256";
    value: string;
    signed_fields?: string[];
}

export interface HarnessAttestationPayload {
    attestation_id: string;
    state_class: StateClassValue;
    state_transition: HarnessStateTransition;
    bound_evidence_refs: string[];
    verifier: HarnessVerifier;
    claim: string;
    fake_green_test_ref: string;
    attestation_signature: HarnessAttestationSignature;
    signed_at: string;
    signer_kid: string;
}

// ============================================================================
// v1.1 variant payloads — markers for the 5 entries in variant-registry.json
// ============================================================================

/**
 * V1: human_oversight_kill_switch — parent record_type=human_oversight_action,
 * discriminator /payload/oversight_subtype = "kill_switch".
 */
export interface HumanOversightKillSwitchPayload {
    oversight_subtype: "kill_switch";
    kill_switch_id: string;
    activated_at?: string;
    activator_actor_ref?: string;
    [k: string]: unknown;
}

/**
 * V2: regression_definition — parent record_type=risk_treatment,
 * discriminator /payload/treatment_subtype = "regression_definition".
 */
export interface RegressionDefinitionPayload {
    treatment_subtype: "regression_definition";
    regression_id: string;
    baseline_metric_ref?: string;
    regression_class?: string;
    detected_at?: string;
    [k: string]: unknown;
}

/**
 * V3: disposition_record — parent record_type=risk_treatment,
 * discriminator /payload/treatment_subtype = "external_disposition".
 * Brief §14.5 authority matrix governs which actor×authority_class
 * combinations may have authority_granted=true.
 */
export interface DispositionRecordPayload {
    treatment_subtype: "external_disposition";
    disposition_id: string;
    authority_check?: {
        authority_class: string;
        authority_granted: boolean;
        actor_ref?: string;
    };
    internal_state_unchanged?: boolean;
    [k: string]: unknown;
}

/**
 * V4: badge_state — parent record_type=transparency_disclosure,
 * discriminator /payload/variant = "verification_badge".
 */
export interface BadgeStatePayload {
    variant: "verification_badge";
    badge_id: string;
    badge_state: string;
    issued_at?: string;
    expires_at?: string;
    [k: string]: unknown;
}

/**
 * V5: evidence_freshness_window — parent record_type=evidence_gap,
 * discriminator /payload/gap_subtype = "freshness_window".
 */
export interface EvidenceFreshnessWindowPayload {
    gap_subtype: "freshness_window";
    window_id: string;
    window_start: string;
    window_end: string;
    [k: string]: unknown;
}

// Re-export grouping for easy named imports.
export const V1_1_PAYLOAD_TYPE_NAMES = [
    "AuthorizedTestScopePayload",
    "ScopeBoundaryEventPayload",
    "FindingRecordPayload",
    "DeliveryVerdictPayload",
    "CoverageCellPayload",
    "HarnessAttestationPayload",
    "HumanOversightKillSwitchPayload",
    "RegressionDefinitionPayload",
    "DispositionRecordPayload",
    "BadgeStatePayload",
    "EvidenceFreshnessWindowPayload",
] as const;
