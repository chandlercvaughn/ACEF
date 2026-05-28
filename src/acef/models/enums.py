"""ACEF enumeration types — all enum values from the spec."""

from __future__ import annotations

from enum import Enum


class SubjectType(str, Enum):
    """AI system or model type per EU AI Act provider/deployer split."""

    AI_SYSTEM = "ai_system"
    AI_MODEL = "ai_model"


class RiskClassification(str, Enum):
    """Risk classification levels per EU AI Act."""

    HIGH_RISK = "high-risk"
    GPAI = "gpai"
    GPAI_SYSTEMIC = "gpai-systemic"
    LIMITED_RISK = "limited-risk"
    MINIMAL_RISK = "minimal-risk"


class LifecyclePhase(str, Enum):
    """AI system lifecycle phases."""

    DESIGN = "design"
    DEVELOPMENT = "development"
    TESTING = "testing"
    DEPLOYMENT = "deployment"
    MONITORING = "monitoring"
    DECOMMISSION = "decommission"


class ComponentType(str, Enum):
    """Entity component types."""

    MODEL = "model"
    RETRIEVER = "retriever"
    GUARDRAIL = "guardrail"
    ORCHESTRATOR = "orchestrator"
    TOOL = "tool"
    DATABASE = "database"
    API = "api"


class DatasetSourceType(str, Enum):
    """Dataset acquisition source types."""

    LICENSED = "licensed"
    SCRAPED = "scraped"
    PUBLIC_DOMAIN = "public_domain"
    SYNTHETIC = "synthetic"
    USER_GENERATED = "user_generated"


class DatasetModality(str, Enum):
    """Dataset modality types."""

    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    TABULAR = "tabular"
    MULTIMODAL = "multimodal"


class SubjectModality(str, Enum):
    """Subject (AI system/model) modality types.

    Distinct from :class:`DatasetModality` because Subjects describe the AI
    system's input/output modalities, not the data modality. The
    ``manifest.schema.json`` enum at ``subjects[*].modalities`` excludes
    ``tabular`` (datasets can be tabular but a Subject is not — a tabular
    classifier still has text or numeric I/O at the system boundary).
    """

    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    MULTIMODAL = "multimodal"


class ActorRole(str, Enum):
    """Actor roles per EU AI Act."""

    PROVIDER = "provider"
    DEPLOYER = "deployer"
    IMPORTER = "importer"
    DISTRIBUTOR = "distributor"
    AUDITOR = "auditor"
    REGULATOR = "regulator"
    DATA_SUBJECT = "data_subject"


class AuthorityClass(str, Enum):
    """Disposition authority class per brief §14.5 disposition matrix.

    Each class describes the kind of authority an actor may exercise over a
    disposition_record. The §14.5 matrix governs which (authority_class ×
    actor_type) combinations may be granted; violations are rejected at load
    time per VAL-LOAD-004.
    """

    PRIORITY = "priority"
    SEVERITY_ADVISORY = "severity_advisory"
    ACCEPTED_RISK_REQUEST = "accepted_risk_request"
    FALSE_POSITIVE_ASSERTION = "false_positive_assertion"
    EVIDENCE_DISPUTE = "evidence_dispute"


class RelationshipType(str, Enum):
    """Entity relationship types (W3C PROV-compatible)."""

    WRAPS = "wraps"
    CALLS = "calls"
    FINE_TUNES = "fine_tunes"
    DEPLOYS = "deploys"
    TRAINS_ON = "trains_on"
    EVALUATES_WITH = "evaluates_with"
    OVERSEES = "oversees"


class ObligationRole(str, Enum):
    """Who is responsible for producing the evidence."""

    PROVIDER = "provider"
    DEPLOYER = "deployer"
    IMPORTER = "importer"
    DISTRIBUTOR = "distributor"
    AUTHORISED_REPRESENTATIVE = "authorised_representative"
    NOTIFIED_BODY = "notified_body"
    PLATFORM = "platform"


class Confidentiality(str, Enum):
    """Evidence confidentiality levels."""

    PUBLIC = "public"
    REDACTED = "redacted"
    HASH_COMMITTED = "hash-committed"
    REGULATOR_ONLY = "regulator-only"
    UNDER_NDA = "under-nda"


class TrustLevel(str, Enum):
    """Evidence trust/provenance levels."""

    SELF_ATTESTED = "self-attested"
    PEER_REVIEWED = "peer-reviewed"
    INDEPENDENTLY_VERIFIED = "independently-verified"
    NOTIFIED_BODY_CERTIFIED = "notified-body-certified"


class EventType(str, Enum):
    """Event log event types."""

    INFERENCE = "inference"
    TRAINING = "training"
    EVALUATION = "evaluation"
    DEPLOYMENT = "deployment"
    OVERRIDE = "override"
    ERROR = "error"
    MARKING = "marking"
    DISCLOSURE = "disclosure"
    LOGGING_SPEC = "logging_spec"
    REDACTION = "redaction"


class AuditEventType(str, Enum):
    """Audit trail event types."""

    CREATED = "created"
    UPDATED = "updated"
    REVIEWED = "reviewed"
    SUBMITTED = "submitted"
    CERTIFIED = "certified"


class RuleSeverity(str, Enum):
    """DSL rule severity levels — used in templates."""

    FAIL = "fail"
    WARNING = "warning"
    INFO = "info"


class RuleOutcome(str, Enum):
    """DSL rule evaluation outcomes."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class ProvisionOutcome(str, Enum):
    """Provision roll-up outcome per 7-step precedence algorithm."""

    SATISFIED = "satisfied"
    NOT_SATISFIED = "not-satisfied"
    PARTIALLY_SATISFIED = "partially-satisfied"
    GAP_ACKNOWLEDGED = "gap-acknowledged"
    SKIPPED = "skipped"
    NOT_ASSESSED = "not-assessed"


# Record types — 16 v1.0 record types + 6 v1.1 agent-reliability primitives
# (authorized_test_scope, scope_boundary_event, finding_record,
#  delivery_verdict, coverage_cell, harness_attestation) per brief §3.1-§3.6.
# coverage_cell lives in Assessment Bundles, not records/, but is registered
# here so cross-cutting type-name checks (e.g., VAL-CONFORMANCE-004 inventory)
# treat it uniformly with the other v1.1 additions.
RECORD_TYPES = frozenset(
    {
        # v1.0 — the original 16
        "risk_register",
        "risk_treatment",
        "dataset_card",
        "data_provenance",
        "evaluation_report",
        "event_log",
        "human_oversight_action",
        "transparency_disclosure",
        "transparency_marking",
        "disclosure_labeling",
        "copyright_rights_reservation",
        "license_record",
        "incident_report",
        "governance_policy",
        "conformity_declaration",
        "evidence_gap",
        # v1.1 — agent-reliability primitives
        "authorized_test_scope",
        "scope_boundary_event",
        "finding_record",
        "delivery_verdict",
        "coverage_cell",
        "harness_attestation",
    }
)

MANDATORY_RECORD_TYPES = frozenset(
    {
        "risk_register",
        "risk_treatment",
        "dataset_card",
        "data_provenance",
        "evaluation_report",
    }
)
