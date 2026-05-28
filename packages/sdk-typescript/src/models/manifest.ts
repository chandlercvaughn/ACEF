/**
 * Mirror of `src/acef/models/manifest.py` Manifest (lines 41-77).
 *
 * v1.1 manifest extensions X5 + X6:
 *   X5 analysis_mode
 *   X6 namespaces
 *
 * Both are optional at the type level; conditional-required behavior is
 * enforced by the validator (mode-gated record-type rules per VAL-VALIDATION-010/011).
 */

import { AnalysisMode, AuditEventType } from "./enums.js";

export interface PackageMetadata {
    package_id: string;
    created_at: string;
    /** Free-form metadata fields pass through. */
    [k: string]: unknown;
}

export interface Versioning {
    /** Defaults to `"1.0.0"`; set to `"1.1.0"` for v1.1 bundles. */
    core_version?: string;
    /** Free-form for per-module versioning. */
    [k: string]: unknown;
}

export interface Subject {
    subject_id: string;
    subject_type: string;
    /** Subjects are open-ended; pass-through extras supported. */
    [k: string]: unknown;
}

export interface EntitiesBlock {
    components?: unknown[];
    datasets?: unknown[];
    actors?: unknown[];
    relationships?: unknown[];
    [k: string]: unknown;
}

export interface ProfileEntry {
    profile_id: string;
    template_version?: string;
    applicable_provisions?: string[];
}

export interface RecordFileEntry {
    path: string;
    record_type: string;
    count?: number;
}

export interface AuditTrailEntry {
    event_type: AuditEventType;
    timestamp: string;
    actor_ref?: string;
    description?: string;
}

/** Bundle manifest matching `acef-manifest.json` per spec §3.1.4. */
export interface Manifest {
    metadata: PackageMetadata;
    versioning?: Versioning;
    subjects?: Subject[];
    entities?: EntitiesBlock;
    profiles?: ProfileEntry[];
    record_files?: RecordFileEntry[];
    audit_trail?: AuditTrailEntry[];

    // v1.1 manifest extensions X5/X6 — optional at type level.
    /** X5: gates which conditional-required envelope fields and record-type rules apply. */
    analysis_mode?: AnalysisMode;
    /** X6: vendor-extension namespaces (keys must match `^x-[a-z0-9-]+/?$`). */
    namespaces?: Record<string, Record<string, unknown>>;

    /** Vendor extensions allowed. */
    [k: string]: unknown;
}

export interface BuildManifestInput {
    metadata: PackageMetadata;
    versioning?: Versioning;
    subjects?: Subject[];
    entities?: EntitiesBlock;
    profiles?: ProfileEntry[];
    record_files?: RecordFileEntry[];
    audit_trail?: AuditTrailEntry[];
    analysis_mode?: AnalysisMode;
    namespaces?: Record<string, Record<string, unknown>>;
}

export function buildManifest(input: BuildManifestInput): Manifest {
    const m: Manifest = { metadata: input.metadata };
    if (input.versioning !== undefined) m.versioning = input.versioning;
    if (input.subjects !== undefined) m.subjects = input.subjects;
    if (input.entities !== undefined) m.entities = input.entities;
    if (input.profiles !== undefined) m.profiles = input.profiles;
    if (input.record_files !== undefined) m.record_files = input.record_files;
    if (input.audit_trail !== undefined) m.audit_trail = input.audit_trail;
    if (input.analysis_mode !== undefined) m.analysis_mode = input.analysis_mode;
    if (input.namespaces !== undefined) m.namespaces = input.namespaces;
    return m;
}
