/**
 * @acef/sdk public barrel export.
 *
 * Ports the public surface of the Python reference SDK at `src/acef/`.
 * The TypeScript package is a separate code path but maintains byte-equal
 * output for canonicalization, signing, and bundle serialization (per the
 * cross-language parity contract VAL-TS-005 / VAL-TS-006 / VAL-PARITY-001..003).
 *
 * Version: 0.2.0 — initial TS port, aligned with ACEF Core v1.1.
 */

// Integrity primitives (RFC 8785 JCS + SHA-256 + Merkle)
export {
    canonicalize,
    canonicalizeJsonString,
    sha256Hex,
    computeBundleDigest,
    buildMerkleTree,
    pathTextProblem,
    type MerkleLeaf,
    type MerkleTree,
} from "./integrity.js";

// JWS detached signatures (RS256 + ES256 only)
export {
    HARNESS_ATTESTATION_SIGNED_FIELDS,
    createDetachedJws,
    verifyDetachedJws,
    signHarnessAttestation,
    verifyHarnessAttestation,
    type JwsHeader,
    type CreateDetachedJwsOptions,
    type KeyInput,
} from "./signing.js";

// Deterministic gzip helper (mtime=0, OS=0xFF, level=6 default)
export { deterministicGzip } from "./exporter.js";

// Directory-bundle loader (read path for re-export parity)
export { loadBundle, type LoadedBundle, type RawRecord } from "./loader.js";

// Directory + USTAR-tar exporter (byte-equal to Python export_archive)
export {
    rebuildManifestForExport,
    buildVirtualBundle,
    buildArchive,
    exportArchiveFromDirectory,
    type VirtualBundle,
} from "./bundle_export.js";

// Enum mirrors
export {
    SubjectType,
    RiskClassification,
    LifecyclePhase,
    ComponentType,
    ActorRole,
    AuthorityClass,
    ObligationRole,
    Confidentiality,
    TrustLevel,
    EventType,
    AuditEventType,
    AnalysisMode,
    StateClass,
    RECORD_TYPES,
    MANDATORY_RECORD_TYPES,
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
    INCIDENT_CARD,
} from "./models/enums.js";

// RecordEnvelope + supporting types
export {
    buildRecordEnvelope,
    type RecordEnvelope,
    type BuildRecordEnvelopeInput,
    type EntityRefs,
    type AttachmentRef,
    type Attestation,
    type RecordRetention,
    type CollectorInfo,
} from "./models/envelope.js";

// Manifest + supporting types
export {
    buildManifest,
    type Manifest,
    type BuildManifestInput,
    type PackageMetadata,
    type Versioning,
    type Subject,
    type EntitiesBlock,
    type ProfileEntry,
    type RecordFileEntry,
    type AuditTrailEntry,
} from "./models/manifest.js";

// Agent-reliability payloads (6 v1.1 record types + 5 variants)
export {
    // §3.1
    type AuthorizedTestScopePayload,
    type AuthorizedSurface,
    type AuthorizedIdentity,
    type SideEffectAllowEntry,
    type SideEffectPolicy,
    type SandboxBoundary,
    type OwnershipProof,
    type SurfaceType,
    type AuthorizationLevel,
    type IdentityType,
    type PreflightMethod,
    type ProofMethod,
    // §3.2
    type ScopeBoundaryEventPayload,
    type AttemptedAction,
    type AuthorizedScopeSnapshot,
    type BoundaryDetector,
    type DetectorClass,
    type BoundaryClassification,
    // §3.3
    type FindingRecordPayload,
    type FindingSeverity,
    type FindingReproduction,
    type FindingAttribution,
    type FindingClass,
    type SeverityLevel,
    // §3.4
    type DeliveryVerdictPayload,
    type DeliveryDestination,
    type DeliveryWriteAttempt,
    type DeliveryReadBack,
    type DeliveryRetryEntry,
    type DeliveryState,
    type DriftClassification,
    type ProviderClass,
    // §3.5
    type CoverageCellPayload,
    type CoverageDimensions,
    type FreshnessState,
    type CoverageOutcome,
    // §3.6
    type HarnessAttestationPayload,
    type HarnessStateTransition,
    type HarnessVerifier,
    type HarnessAttestationSignature,
    type StateClassValue,
    type VerifierClass,
    // Variants (5)
    type HumanOversightKillSwitchPayload,
    type RegressionDefinitionPayload,
    type DispositionRecordPayload,
    type BadgeStatePayload,
    type EvidenceFreshnessWindowPayload,
    V1_1_PAYLOAD_TYPE_NAMES,
} from "./models/agent_reliability.js";

/** SDK package version — kept in sync with package.json. */
export const SDK_VERSION = "0.2.0";

/** ACEF Core version this SDK speaks natively. */
export const CORE_VERSION = "1.1.0";

/**
 * Map a `manifest.versioning.core_version` value to the schema directory
 * token. Mirrors Python `schemas/registry.py:41-89`
 * `schema_version_for_core_version`.
 *
 * v1.1 → v1 fallback for unchanged record types is the responsibility of
 * the schema loader (not the version selector itself).
 */
export function schemaVersionForCoreVersion(coreVersion: string | null | undefined): "v1" | "v1.1" {
    if (coreVersion === null || coreVersion === undefined || coreVersion === "") {
        return "v1";
    }
    const parts = coreVersion.split(".");
    const major = parseInt(parts[0] ?? "0", 10);
    if (Number.isNaN(major)) {
        return "v1";
    }
    if (major !== 1) {
        throw new Error(
            `[ACEF-001] Incompatible core_version: ${coreVersion} (validator supports 1.x only)`,
        );
    }
    let minor = 0;
    if (parts.length >= 2) {
        const m = parseInt(parts[1]!, 10);
        if (!Number.isNaN(m)) minor = m;
    }
    return minor <= 0 ? "v1" : "v1.1";
}
