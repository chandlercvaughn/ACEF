"""ACEF error taxonomy — registered error codes with severity and category.

Error codes follow the ACEF specification Section 3.6. The reserved code
range is ACEF-001..ACEF-088 and is **sparsely populated by design**: codes
are grouped by category (001-009 schema, 010-019 integrity, 020-029
reference, 030-039 profile, 040-049 evaluation, 050-059 format, 060-069
merge, 070-080 agent-reliability, 081-088 incident-reporting) and unused
ordinals within each band are left empty to allow future additions without
renumbering.

The **081-088 incident band** is added by ACEF RFC-0002 (Normalized AI
Incident Reporting Profile, v1.1). Unlike the v0.4 codes — which carry a
single problem-text description in the ``(Severity, ErrorCategory,
description)`` 3-tuple of :data:`ERROR_REGISTRY` — every incident code
carries **structured problem + cause + fix-hint** text, modelled by
:class:`IncidentErrorDetail` and registered in :data:`INCIDENT_ERROR_DETAILS`
(keyed by code). The fix-hint is the implementation-facing remediation
sentence RFC-0002 §7 fixes verbatim, so a filer sees what to fix. The
incident codes are deliberately kept OUT of :data:`ERROR_REGISTRY` so the
frozen v1.0 snapshot at ``tests/conformance/fixtures/v1.0-errors.json`` and
the registry-size invariants that govern the v0.4 surface stay byte-equal.

The incident band (RFC-0002 §7) is:

    ACEF-081  ERROR/profile     incident profile declared but taxonomy_crosswalk
                                missing a mandatory member (§5.7)
    ACEF-082  ERROR/format      severity_vector present but not parseable against
                                ACEF-SEV:1.0 (§5.4)
    ACEF-083  ERROR/integrity   public_incident_id id-trust failure — ONE code,
                                two class-tagged branches (offline-deterministic
                                pattern/JWS/snapshot; online-conformance domain-
                                control reject) (§5.3)
    ACEF-084  ERROR/evaluation  eu-ai-act-art73-2026 deadline inconsistent with
                                the shortest applicable clock (§5.7)
    ACEF-085  ERROR/evaluation  a taxonomy_crosswalk member contradicts the value
                                derived from harm_core (§5.5)
    ACEF-086  ERROR/profile     public disclosure without satisfying the §5.11
                                publishability map / declared_publication_basis
    ACEF-087  INFO/profile      realization is near_miss — informational marker,
                                never a failure (§5.5)
    ACEF-088  ERROR/evaluation  record carries both severity and severity_vector
                                and severity disagrees with band() (§5.4)

At time of this writing the registry defines 42 codes total:
  - 31 codes in the v1.0 reserved range (ACEF-001..ACEF-060, sparse)
  - 11 codes added in v1.1 (ACEF-070..ACEF-080) covering agent-reliability
    scenarios introduced by the Freddy adoption work:

    ACEF-070  FATAL/integrity   harness_attestation cites missing or unverifiable required evidence
    ACEF-071  FATAL/integrity   delivery_verdict claims verified_delivered without read-back digest
    ACEF-072  FATAL/integrity   delivery_verdict read-back digest does not match write-back digest
    ACEF-073  FATAL/reference   causation_chain cites an unknown or unsigned URN
    ACEF-074  ERROR/schema      Record missing redaction_policy_version when confidentiality != public
    ACEF-075  FATAL/reference   tenant_label mismatch across records in a single bundle
    ACEF-076  ERROR/schema      state_class record lacks fake-green test reference, OR
                                disposition_record sets internal_state_unchanged=false
    ACEF-077  FATAL/integrity   registered vendor-namespace lint reported a fatal integrity violation
    ACEF-078  ERROR/reference   redaction_attestation_ref points to unresolvable URN
    ACEF-079  ERROR/schema      coverage_cell.claim_language contains banned token
    ACEF-080  ERROR/reference   Bundle declares analysis_mode but lacks required envelope fields for that mode

The v1.0 codes (ACEF-001..ACEF-060) are FROZEN — their (severity, category,
description) tuples are byte-equal to the R0 snapshot at
``tests/conformance/fixtures/v1.0-errors.json`` and must not change.

Each registry value is a 3-tuple ``(Severity, ErrorCategory, description)``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Error severity levels per ACEF spec."""

    FATAL = "fatal"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ErrorCategory(str, Enum):
    """Error categories per ACEF spec."""

    SCHEMA = "schema"
    INTEGRITY = "integrity"
    REFERENCE = "reference"
    PROFILE = "profile"
    EVALUATION = "evaluation"
    FORMAT = "format"
    MERGE = "merge"


# Complete error code registry mapping code -> (severity, category, description)
ERROR_REGISTRY: dict[str, tuple[Severity, ErrorCategory, str]] = {
    "ACEF-001": (Severity.FATAL, ErrorCategory.SCHEMA, "Incompatible module versions in versioning block"),
    "ACEF-002": (Severity.FATAL, ErrorCategory.SCHEMA, "Manifest fails JSON Schema validation"),
    "ACEF-003": (Severity.ERROR, ErrorCategory.SCHEMA, "Unknown record_type — no schema in registry"),
    "ACEF-004": (Severity.FATAL, ErrorCategory.SCHEMA, "Record payload fails record-type JSON Schema validation"),
    "ACEF-010": (Severity.FATAL, ErrorCategory.INTEGRITY, "File hash mismatch"),
    "ACEF-011": (Severity.FATAL, ErrorCategory.INTEGRITY, "Merkle root mismatch"),
    "ACEF-012": (Severity.FATAL, ErrorCategory.INTEGRITY, "Invalid or expired signature"),
    "ACEF-013": (Severity.FATAL, ErrorCategory.INTEGRITY, "Unsupported JWS algorithm"),
    "ACEF-014": (Severity.FATAL, ErrorCategory.INTEGRITY, "Hash index completeness failure"),
    "ACEF-020": (Severity.ERROR, ErrorCategory.REFERENCE, "Dangling entity_refs — URN references nonexistent entity"),
    "ACEF-021": (Severity.ERROR, ErrorCategory.REFERENCE, "Duplicate URNs within the package"),
    "ACEF-022": (Severity.ERROR, ErrorCategory.REFERENCE, "record_files entry references nonexistent file"),
    "ACEF-023": (Severity.ERROR, ErrorCategory.REFERENCE, "Attachment path references file not in artifacts/"),
    "ACEF-025": (Severity.ERROR, ErrorCategory.REFERENCE, "Record count mismatch between manifest and actual JSONL"),
    "ACEF-026": (Severity.ERROR, ErrorCategory.REFERENCE, "Duplicate record_id within the package"),
    "ACEF-027": (
        Severity.WARNING,
        ErrorCategory.REFERENCE,
        "Attachment hash does not match content-hashes.json entry",
    ),
    "ACEF-030": (Severity.ERROR, ErrorCategory.PROFILE, "Unknown profile_id — no matching template"),
    "ACEF-031": (Severity.ERROR, ErrorCategory.PROFILE, "Unknown template_version"),
    "ACEF-032": (Severity.INFO, ErrorCategory.PROFILE, "Provision not yet effective — rules produce skipped outcome"),
    "ACEF-033": (Severity.ERROR, ErrorCategory.PROFILE, "Incompatible module versions between bundle and template"),
    "ACEF-040": (Severity.ERROR, ErrorCategory.EVALUATION, "Required evidence type missing"),
    "ACEF-041": (Severity.WARNING, ErrorCategory.EVALUATION, "Evidence freshness exceeded"),
    "ACEF-042": (Severity.INFO, ErrorCategory.EVALUATION, "evidence_gap acknowledged for provision"),
    "ACEF-043": (Severity.ERROR, ErrorCategory.EVALUATION, "Invalid JSON Pointer in rule field parameter"),
    "ACEF-044": (Severity.ERROR, ErrorCategory.EVALUATION, "Duplicate rule_id in template"),
    "ACEF-045": (Severity.ERROR, ErrorCategory.EVALUATION, "Invalid ECMA-262 regex pattern in rule value"),
    "ACEF-050": (Severity.FATAL, ErrorCategory.FORMAT, "Malformed JSONL line"),
    "ACEF-051": (Severity.FATAL, ErrorCategory.FORMAT, "JSON not canonicalized per RFC 8785"),
    "ACEF-052": (Severity.ERROR, ErrorCategory.FORMAT, "Path contains .. segments or non-UTF-8-NFC characters"),
    "ACEF-053": (Severity.ERROR, ErrorCategory.FORMAT, "Vendor extension field affects conformance outcome"),
    "ACEF-060": (Severity.WARNING, ErrorCategory.MERGE, "Conflicting records from multiple packages"),
    # ----- v1.1 agent-reliability additions (ACEF-070..ACEF-080) -----
    # See module docstring for the full description table. These codes were
    # added in ACEF v0.4 (Freddy adoption) and cover harness attestation,
    # delivery verdict integrity, causation/tenant referential rules,
    # redaction policy hygiene, state-class fake-green requirements, voice
    # rubric claim-lexicon enforcement, and analysis-mode envelope gating.
    "ACEF-070": (
        Severity.FATAL,
        ErrorCategory.INTEGRITY,
        "harness_attestation cites missing or unverifiable required evidence",
    ),
    "ACEF-071": (
        Severity.FATAL,
        ErrorCategory.INTEGRITY,
        "delivery_verdict claims verified_delivered without read-back digest",
    ),
    "ACEF-072": (
        Severity.FATAL,
        ErrorCategory.INTEGRITY,
        "delivery_verdict read-back digest does not match write-back digest",
    ),
    "ACEF-073": (
        Severity.FATAL,
        ErrorCategory.REFERENCE,
        "causation_chain cites an unknown or unsigned URN",
    ),
    "ACEF-074": (
        Severity.ERROR,
        ErrorCategory.SCHEMA,
        "Record missing redaction_policy_version when confidentiality != public",
    ),
    "ACEF-075": (
        Severity.FATAL,
        ErrorCategory.REFERENCE,
        "tenant_label mismatch across records in a single bundle",
    ),
    "ACEF-076": (
        Severity.ERROR,
        ErrorCategory.SCHEMA,
        "state_class record lacks fake-green test reference, or disposition_record sets internal_state_unchanged=false",
    ),
    "ACEF-077": (
        Severity.FATAL,
        ErrorCategory.INTEGRITY,
        "registered vendor-namespace lint reported a fatal integrity violation "
        "(the namespace's registered lint pattern supplies the specific record type and condition)",
    ),
    "ACEF-078": (
        Severity.ERROR,
        ErrorCategory.REFERENCE,
        "redaction_attestation_ref points to unresolvable URN",
    ),
    "ACEF-079": (
        Severity.ERROR,
        ErrorCategory.SCHEMA,
        "coverage_cell.claim_language contains banned token",
    ),
    "ACEF-080": (
        Severity.ERROR,
        ErrorCategory.REFERENCE,
        "Bundle declares analysis_mode but lacks required envelope fields for that mode",
    ),
}


@dataclass(frozen=True)
class IncidentErrorDetail:
    """Structured detail for a post-v1.0 ACEF error code (``problem`` + ``cause``
    + ``fix`` hint).

    Introduced by the RFC-0002 incident band (ACEF-081..088), this is the GENERIC
    structured-detail carrier for any error code added AFTER the frozen v1.0
    surface — the name is historical. The v0.4 codes in :data:`ERROR_REGISTRY`
    carry a single problem-text description; a structured-detail code instead
    carries a **problem** (the failing condition), a **cause** (the spec / RFC
    section it derives from), and a **fix** hint (the implementation-facing
    remediation sentence). ``severity`` and ``category`` reuse the existing
    :class:`Severity` / :class:`ErrorCategory` enums so downstream consumers
    (rendering, Assessment Bundle roll-up) treat such a code uniformly with the
    v0.4 surface. Used by :data:`INCIDENT_ERROR_DETAILS` (incident band) and
    :data:`EXTENDED_ERROR_DETAILS` (other post-v1.0 additions, e.g. ACEF-046).
    """

    severity: Severity
    category: ErrorCategory
    problem: str
    cause: str
    fix: str

    @property
    def description(self) -> str:
        """The single-line problem text, byte-compatible with the v0.4
        ``ERROR_REGISTRY`` description slot (so an incident code can be
        surfaced through the same accessor path as a v0.4 code)."""
        return self.problem


# RFC-0002 §7 incident error band — ACEF-081..088 (eight codes). These are
# kept SEPARATE from ERROR_REGISTRY: the v1.0 snapshot at
# tests/conformance/fixtures/v1.0-errors.json and the registry-size invariants
# that govern the frozen v0.4 surface MUST stay byte-equal, so the incident
# codes live in their own structured map rather than being appended to the
# frozen 3-tuple registry. The fix-hint sentences are lifted verbatim from
# RFC-0002 §7 (Revision 10).
INCIDENT_ERROR_DETAILS: dict[str, IncidentErrorDetail] = {
    "ACEF-081": IncidentErrorDetail(
        severity=Severity.ERROR,
        category=ErrorCategory.PROFILE,
        problem=(
            "incident profile declared but taxonomy_crosswalk missing a mandatory member — "
            "error carries profile_id + RFC 6901 path"
        ),
        cause="RFC-0002 §5.7 (conditional-required crosswalk members per declared profile; Appendix E Q16)",
        fix=(
            "add the missing mandatory crosswalk member named at path for the declared profile_id, "
            "or remove the profile declaration"
        ),
    ),
    "ACEF-082": IncidentErrorDetail(
        severity=Severity.ERROR,
        category=ErrorCategory.FORMAT,
        problem="severity_vector present but not parseable against ACEF-SEV:1.0",
        cause="RFC-0002 §5.4 (ACEF-SEV:1.0 metric grammar)",
        fix="emit a vector conforming to the ACEF-SEV:1.0 grammar in §5.4, or omit severity_vector",
    ),
    "ACEF-083": IncidentErrorDetail(
        severity=Severity.ERROR,
        category=ErrorCategory.INTEGRITY,
        problem=(
            "public_incident_id id-trust failure raised in one of two explicitly class-tagged branches "
            "(this is ONE code, not two): class:offline-deterministic — pattern mismatch, OR (when a "
            "snapshot is bundled) the assigner token is absent from the bundled snapshot, OR JWS "
            "self-inconsistency; class:online-conformance — the OPTIONAL online domain-control proof was "
            "presented but FAILS validation (the reject verdict). A network/DNS timeout or total proof "
            "absence is the explicit unverified non-result and does NOT raise ACEF-083"
        ),
        cause="RFC-0002 §5.3 (offline-deterministic vs OPTIONAL online-conformance id-trust classes)",
        fix=(
            "for class:offline-deterministic, correct public_incident_id to the AIIC-{assigner}-{year}-{random} "
            "pattern, bundle the assigner in the snapshot if one is referenced, and re-sign so the JWS verifies; "
            "for class:online-conformance, present a valid current domain-control proof, or drop the proof to "
            "land on unverified (a non-result, not this error)"
        ),
    ),
    "ACEF-084": IncidentErrorDetail(
        severity=Severity.ERROR,
        category=ErrorCategory.EVALUATION,
        problem=(
            "eu-ai-act-art73-2026 declared and the stated regulatory_timeline deadline is inconsistent with the "
            "shortest applicable clock (death_involved → 10 days; 3.49.b or widespread → 2 days; else 15 days)"
        ),
        cause=(
            "RFC-0002 §5.7 (Art. 73 shortest-clock check; trigger facts read from "
            "incident_report.card_source.eu_ai_act_facts in confidential/source-backed validation and from "
            "incident_card.taxonomy_crosswalk.eu_ai_act in public-card validation)"
        ),
        fix=(
            "set regulatory_timeline to the shortest applicable clock for the declared triggers, "
            "or correct the trigger facts at the source path the validator read"
        ),
    ),
    "ACEF-085": IncidentErrorDetail(
        severity=Severity.ERROR,
        category=ErrorCategory.EVALUATION,
        problem="a present taxonomy_crosswalk member contradicts the value derived from harm_core",
        cause="RFC-0002 §5.5 (one-directional harm_core → scheme derivation tables)",
        fix="re-derive the crosswalk member from harm_core per §5.5, or correct harm_core if it is the wrong value",
    ),
    "ACEF-086": IncidentErrorDetail(
        severity=Severity.ERROR,
        category=ErrorCategory.PROFILE,
        problem=(
            "public disclosure without satisfying the §5.11 publishability map / declared_publication_basis on "
            "special-category or privileged fields"
        ),
        cause="RFC-0002 §5.11 (publishability gate; declared_publication_basis + publishability_map)",
        fix=(
            "add a satisfying declared_publication_basis (Art. 6(1) basis + Art. 9(2) condition, or a declared "
            "anonymization_method), or change the field's disposition to omitted/regulator-only/hash-committed in "
            "card_source.publishability_map"
        ),
    ),
    "ACEF-087": IncidentErrorDetail(
        severity=Severity.INFO,
        category=ErrorCategory.PROFILE,
        problem="realization is near_miss — informational marker, never a failure",
        cause="RFC-0002 §5.5 (near_miss realization; voluntary near-miss contribution)",
        fix="none required — informational; suppress at the consumer if near-miss markers are not wanted",
    ),
    "ACEF-088": IncidentErrorDetail(
        severity=Severity.ERROR,
        category=ErrorCategory.EVALUATION,
        problem=(
            "a record carries both severity and severity_vector and the coarse severity disagrees with the band() "
            "projection (it does not fire when only one of the two is present)"
        ),
        cause="RFC-0002 §5.4 (band(severity_vector) → severity projection consistency; Appendix E Q13)",
        fix="set severity to the band() projection of severity_vector per §5.4, or remove one of the two fields",
    ),
}


# Other post-v1.0 error codes that, like the incident band, are kept OUT of the
# frozen ERROR_REGISTRY (so the v1.0 snapshot + the "post-snapshot ERROR_REGISTRY
# additions live only in 070-080" invariant stay intact) but still need an
# authoritative severity/category + a fix hint. ACEF-046 fills the unused
# evaluation-band ordinal (040-049, spec §3.6) reserved for "unknown comparison
# operator in a rule" (audit finding F13).
EXTENDED_ERROR_DETAILS: dict[str, IncidentErrorDetail] = {
    "ACEF-034": IncidentErrorDetail(
        severity=Severity.ERROR,
        category=ErrorCategory.PROFILE,
        problem=(
            "a provision asserts a retention period with no recorded provenance, or its "
            "retention block is internally inconsistent (a period-bearing kind with no "
            "period, a 'none_stated'/'not_assessed' kind carrying one, an 'inferred' "
            "source whose basis omits the INFERRED token, a 'cited' source with no "
            "normative_text_ref, or a retention_years scalar disagreeing with the "
            "structured block)"
        ),
        cause=(
            "spec §3.6 (error taxonomy). GitHub issue #1: eu-ai-act-2024 asserted "
            "retention_years: 10 on eight provisions with no basis, which for "
            "article-12 is a false statement of law — Art. 12 of Regulation (EU) "
            "2024/1689 states no retention period; Art. 19(1) (provider) and "
            "Art. 26(6) (deployer) govern log retention at 'at least six months'"
        ),
        fix=(
            "give the provision a retention block whose kind, period and source agree: "
            "use kind='none_stated' with source='cited' when the instrument states no "
            "period, kind='not_assessed' with source='not_assessed' when it has not "
            "been assessed, and carry the literal token INFERRED in the basis whenever "
            "source='inferred'; a retention figure with no auditable source must not ship"
        ),
    ),
    "ACEF-035": IncidentErrorDetail(
        severity=Severity.INFO,
        category=ErrorCategory.PROFILE,
        problem=(
            "a provision commences on two or more dates keyed to a classification the "
            "bundle cannot express, and the evaluation instant falls between the "
            "earliest and latest of them, so applicability is INDETERMINATE for this "
            "subject — the reported outcome rests on the EARLIEST limb and is a "
            "conservative projection, not a determination"
        ),
        cause=(
            "spec §3.6. EU AI Act Art. 113 third paragraph point (c), as replaced by "
            "Regulation (EU) 2026/1744 Art. 1 point (40)(b), applies Chapter III "
            "Sections 1-3 from 2 December 2027 to Art. 6(2)/Annex III high-risk "
            "systems and from 2 August 2028 to Art. 6(1)/Annex I. Provision."
            "effective_date holds a single value and the risk_classification enum in "
            "the frozen v1 manifest schema has no Annex I / Annex III member, so the "
            "discriminator cannot be evaluated"
        ),
        fix=(
            "determine the subject's Art. 6 / Annex classification out of band before "
            "relying on this provision's outcome; it is reported against the earliest "
            "commencement limb, so a subject falling under the later limb is reported "
            "as bound sooner than it is. Both limbs are recorded on the provision's "
            "tiered_requirements.adoption block"
        ),
    ),
    "ACEF-046": IncidentErrorDetail(
        severity=Severity.ERROR,
        category=ErrorCategory.EVALUATION,
        problem=(
            "a rule names an unknown operator — either an unknown top-level rule operator "
            "(not a §3.5 built-in) or an unknown comparison `op`"
        ),
        cause=(
            "spec §3.5 (built-in rule operators) / §3.4 (the eight comparison operators: "
            "eq, ne, gt, gte, lt, lte, in, regex)"
        ),
        fix=(
            "correct the rule operator to a §3.5 built-in, or the comparison `op` to one of "
            "eq, ne, gt, gte, lt, lte, in, regex; a typo'd operator is a malformed rule, not a silent false-fail"
        ),
    ),
}


def incident_error_detail(code: str) -> IncidentErrorDetail | None:
    """Return the :class:`IncidentErrorDetail` for an ACEF-081..088 incident
    code, or ``None`` if ``code`` is not an incident code.

    This is the lookup counterpart to indexing :data:`ERROR_REGISTRY` for the
    v0.4 surface. It resolves ONLY the incident band; a v0.4 code (e.g.
    ``ACEF-080``) or an unknown code returns ``None`` so callers can fall back
    to :data:`ERROR_REGISTRY`.
    """
    return INCIDENT_ERROR_DETAILS.get(code)


# The conservative default for an unknown / unregistered code. A code we cannot
# resolve is treated as a generic schema-level ERROR — never silently dropped,
# never elevated. This matches the historical fallback that ``ACEFError`` and
# ``ValidationDiagnostic`` applied inline before the shared resolver existed.
_DEFAULT_ERROR_META: tuple[Severity, ErrorCategory] = (Severity.ERROR, ErrorCategory.SCHEMA)


def resolve_error_meta(code: str) -> tuple[Severity, ErrorCategory]:
    """Resolve any ACEF error code to its ``(Severity, ErrorCategory)`` pair.

    This is the SINGLE source of truth for code → (severity, category) used by
    BOTH public emission paths (:class:`ACEFError` and
    :class:`ValidationDiagnostic`). Resolution order is:

    1. :data:`ERROR_REGISTRY` — the frozen v0.4 + v1.1 agent-reliability surface
       (ACEF-001..ACEF-080). Checked FIRST so the frozen snapshot governs those
       codes unchanged.
    2. :data:`INCIDENT_ERROR_DETAILS` — the RFC-0002 §7 incident band
       (ACEF-081..088). The incident codes are deliberately kept OUT of
       ``ERROR_REGISTRY`` (so the frozen v1.0 snapshot stays byte-equal), but
       they still carry an authoritative ``severity`` + ``category`` on their
       :class:`IncidentErrorDetail`. Without this fallback, an incident code
       emitted through the public APIs would mis-serialize with the conservative
       default — e.g. ACEF-087 would surface as ``error/schema`` instead of its
       correct ``info/profile``.
    3. :data:`_DEFAULT_ERROR_META` — an unknown code is conservatively treated
       as a generic ``error/schema`` so it is never silently dropped.

    Returns the enum pair (not their ``.value`` strings); callers serialize as
    needed.
    """
    registry_entry = ERROR_REGISTRY.get(code)
    if registry_entry is not None:
        severity, category, _ = registry_entry
        return severity, category
    incident = INCIDENT_ERROR_DETAILS.get(code)
    if incident is not None:
        return incident.severity, incident.category
    extended = EXTENDED_ERROR_DETAILS.get(code)
    if extended is not None:
        return extended.severity, extended.category
    return _DEFAULT_ERROR_META


class ACEFError(Exception):
    """Base exception for all ACEF errors."""

    code: str = "ACEF-000"

    def __init__(self, message: str, *, code: str | None = None, details: dict[str, Any] | None = None) -> None:
        self.code = code or self.__class__.code
        self.details = details or {}
        # Resolve severity/category through the SHARED resolver so an incident
        # code (ACEF-081..088, which lives in INCIDENT_ERROR_DETAILS, not the
        # frozen ERROR_REGISTRY) surfaces its correct severity+category — e.g.
        # ACEF-087 is info/profile, ACEF-084 is error/evaluation — instead of
        # the conservative error/schema default.
        self.severity, self.category = resolve_error_meta(self.code)
        super().__init__(f"[{self.code}] {message}")

    @property
    def message(self) -> str:
        """The error message without the code prefix."""
        full = str(self)
        prefix = f"[{self.code}] "
        return full[len(prefix) :] if full.startswith(prefix) else full


class ACEFSchemaError(ACEFError):
    """Schema validation errors (ACEF-001 through ACEF-004)."""

    code = "ACEF-002"


class ACEFIntegrityError(ACEFError):
    """Integrity verification errors (ACEF-010 through ACEF-014)."""

    code = "ACEF-010"


class ACEFReferenceError(ACEFError):
    """Reference integrity errors (ACEF-020 through ACEF-027)."""

    code = "ACEF-020"


class ACEFProfileError(ACEFError):
    """Profile/template errors (ACEF-030 through ACEF-033)."""

    code = "ACEF-030"


class ACEFEvaluationError(ACEFError):
    """Rule evaluation errors (ACEF-040 through ACEF-045)."""

    code = "ACEF-040"


class ACEFFormatError(ACEFError):
    """Format errors (ACEF-050 through ACEF-053)."""

    code = "ACEF-050"


class ACEFMergeError(ACEFError):
    """Merge conflict errors (ACEF-060)."""

    code = "ACEF-060"


class ACEFExportError(ACEFError):
    """Export/serialization errors."""

    code = "ACEF-050"


class ACEFSigningError(ACEFError):
    """Signing/verification errors."""

    code = "ACEF-012"


class LoadRejection(ACEFError):  # noqa: N818  # public API name: a load-time "rejection" verdict, not an *Error-suffixed exception (VAL-LOAD-001..005; referenced widely)
    """Bundle rejected at load time per VAL-LOAD-001..004.

    Carries the ACEF-NNN code that names the rule violated. The caller MUST
    pass ``code`` via ``__init__`` — there is no class-level default, because
    LoadRejection covers multiple distinct codes (currently ACEF-070,
    ACEF-076, ACEF-080) and silently defaulting would mask the rule
    actually tripped.

    Per VAL-LOAD-005, every condition that raises ``LoadRejection`` MUST
    also be detectable by :func:`acef.validation.engine.validate_bundle`
    producing a ``ValidationDiagnostic`` with the same code.
    """

    # No class-level default code — every site that constructs LoadRejection
    # provides one explicitly. Fall back to base ACEF-000 if a caller
    # accidentally omits it (this keeps the exception class valid; the
    # missing-code is caught by the test suite, not silently masked).
    code = "ACEF-000"


class ValidationDiagnostic:
    """A single validation finding — used by the validation engine to collect
    all errors within a phase before stopping."""

    __slots__ = ("code", "severity", "category", "message", "path", "details")

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.path = path
        self.details = details or {}
        # Resolve via the SHARED resolver (ERROR_REGISTRY first, then the
        # incident band in INCIDENT_ERROR_DETAILS). This is the surface the
        # validator (F-M3-VALIDATOR-RULES) and the Assessment Bundle consume, so
        # an ACEF-081..088 diagnostic MUST serialize its correct severity +
        # category (e.g. ACEF-087 → info/profile) rather than the old hardcoded
        # error/schema fallback.
        self.severity, self.category = resolve_error_meta(code)

    def __repr__(self) -> str:
        path_str = f" at {self.path}" if self.path else ""
        return f"ValidationDiagnostic({self.code}, {self.severity.value}, {self.message!r}{path_str})"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for Assessment Bundle structural_errors."""
        result: dict[str, Any] = {
            "code": self.code,
            "severity": self.severity.value,
            "category": self.category.value,
            "message": self.message,
        }
        if self.path:
            result["path"] = self.path
        if self.details:
            result["details"] = self.details
        return result
