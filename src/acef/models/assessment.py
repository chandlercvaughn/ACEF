"""ACEF assessment models — Assessment Bundle data structures."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from acef.models.base import ACEFBaseModel
from acef.models.enums import ProvisionOutcome, RuleOutcome, RuleSeverity
from acef.models.urns import URNType, generate_urn


class Assessor(ACEFBaseModel):
    """The tool/organization that performed the assessment."""

    name: str = "acef-validator"
    version: str = "1.0.0"
    organization: str = "AI Commons"


class EvidenceBundleRef(ACEFBaseModel):
    """Reference to the Evidence Bundle being assessed."""

    content_hash: str = ""
    package_id: str = ""


class RuleResult(ACEFBaseModel):
    """Result of evaluating a single DSL rule."""

    rule_id: str
    provision_id: str
    profile_id: str
    rule_severity: RuleSeverity
    outcome: RuleOutcome
    message: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    subject_scope: list[str] = Field(default_factory=list)
    # Machine-readable ACEF taxonomy code for an ERROR-outcome result raised by
    # an operator (e.g. ACEF-043 invalid JSON Pointer, ACEF-045 invalid regex /
    # malformed date param, ACEF-050 malformed JSONL). ``None`` for passed,
    # failed, skipped results and for genuinely unexpected internal failures, so
    # consumers can distinguish a taxonomy code from an opaque crash
    # (validation-engine-dsl-4). Optional + default None keeps this backward
    # compatible with existing assessment payloads.
    error_code: str | None = None


class ProvisionSummary(ACEFBaseModel):
    """Roll-up summary for a single provision."""

    provision_id: str
    profile_id: str
    provision_outcome: ProvisionOutcome
    subject_scope: list[str] = Field(default_factory=list)
    fail_count: int = 0
    warning_count: int = 0
    skipped_count: int = 0
    evidence_refs: list[str] = Field(default_factory=list)


class AssessmentVersioning(ACEFBaseModel):
    """Assessment Bundle versioning — uses assessment_version, NOT profiles_version.

    Per spec Section 3.7: Assessment Bundles declare core_version and
    assessment_version. The profiles_version is only in Evidence Bundles.
    """

    core_version: str = "1.0.0"
    assessment_version: str = "1.0.0"


class AssessmentIntegrity(ACEFBaseModel):
    """Assessment Bundle integrity (signature) block."""

    signature: dict[str, str] | None = None


class AssessmentBundle(ACEFBaseModel):
    """ACEF Assessment Bundle — validation results for an Evidence Bundle.

    Reproducibility note (audit finding assessment-rollup-5): two of the
    creation-identity scalars below — ``assessment_id`` and ``timestamp`` —
    default to a fresh random URN and the wall-clock creation time
    respectively. Because the ENTIRE bundle (including these two fields) is
    canonicalized and signed by ``sign_assessment``, a default-constructed
    Assessment Bundle is NOT byte-reproducible even over the same evidence
    with the same ``evaluation_instant``. This is intentional and is NOT a
    spec violation: spec §3.7 scopes reproducibility to the evaluation
    RESULTS (``results``/``provision_summary``), which ARE reproducible and
    are pinned by ``evaluation_instant``.

    Pinning ``timestamp`` AND ``assessment_id`` (via ``validate_bundle`` /
    ``validate``) stabilizes the assessment PAYLOAD — the canonical RFC-8785
    bytes that ``sign_assessment`` signs become byte-identical across runs.
    That alone makes an UNSIGNED assessment byte-reproducible. Byte equality
    of the SIGNED artifact (the exported ``.acef-assessment.json`` INCLUDING
    its JWS) ALSO requires a DETERMINISTIC signing algorithm: RS256
    (PKCS1v15) is deterministic, so an RS256-signed assessment over a pinned
    payload is byte-reproducible; ES256 draws a fresh random ECDSA nonce (no
    RFC 6979 deterministic-k), so an ES256-signed assessment is NOT
    byte-reproducible even with both identity scalars pinned — the payload
    bytes match but the signature bytes differ on every export. This mirrors
    the ES256 archive honesty note (audit finding export-determinism-4);
    callers needing a byte-reproducible signed assessment must use RS256.
    """

    versioning: AssessmentVersioning = Field(default_factory=AssessmentVersioning)
    # Creation-identity URN. Defaults to a fresh random ``urn:acef:asx:<uuid4>``
    # per construction → a non-determinism source in the signed bytes. Pin it
    # explicitly (with ``timestamp``) to stabilize the assessment PAYLOAD; a
    # byte-reproducible SIGNED assessment additionally requires RS256, not
    # ES256 (random ECDSA nonce) — assessment-rollup-5.
    assessment_id: str = Field(default_factory=lambda: generate_urn(URNType.ASSESSMENT))
    # Creation timestamp (wall-clock). Intentionally non-reproducible; pin it
    # explicitly (with ``assessment_id``) to stabilize the assessment PAYLOAD —
    # a byte-reproducible SIGNED assessment additionally requires RS256, not
    # ES256. Distinct from ``evaluation_instant``, which pins results.
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
    evaluation_instant: str = Field(default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
    assessor: Assessor = Field(default_factory=Assessor)
    evidence_bundle_ref: EvidenceBundleRef = Field(default_factory=EvidenceBundleRef)
    profiles_evaluated: list[str] = Field(default_factory=list)
    template_digests: dict[str, str] = Field(default_factory=dict)
    results: list[RuleResult] = Field(default_factory=list)
    provision_summary: list[ProvisionSummary] = Field(default_factory=list)
    structural_errors: list[dict[str, Any]] = Field(default_factory=list)
    integrity: AssessmentIntegrity | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON output."""
        return self.model_dump(mode="json")

    def summary(self) -> str:
        """Human-readable summary of assessment results."""
        parts: list[str] = []
        by_profile: dict[str, list[ProvisionSummary]] = {}
        for ps in self.provision_summary:
            by_profile.setdefault(ps.profile_id, []).append(ps)

        for profile_id, summaries in by_profile.items():
            total = len(summaries)
            passed = sum(1 for s in summaries if s.provision_outcome == ProvisionOutcome.SATISFIED)
            gaps = sum(1 for s in summaries if s.provision_outcome == ProvisionOutcome.GAP_ACKNOWLEDGED)
            part = f"{profile_id}: {passed}/{total} provisions passed"
            if gaps:
                part += f", {gaps} gap acknowledged"
            parts.append(part)

        return " | ".join(parts) if parts else "No provisions evaluated"

    def errors(self) -> list[dict[str, Any]]:
        """Return all structural errors and failed rule results."""
        result: list[dict[str, Any]] = list(self.structural_errors)
        for r in self.results:
            if r.outcome == RuleOutcome.FAILED:
                result.append(
                    {
                        "rule_id": r.rule_id,
                        "provision_id": r.provision_id,
                        "severity": r.rule_severity.value,
                        "outcome": r.outcome.value,
                        "message": r.message,
                    }
                )
        return result
