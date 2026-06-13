"""Pydantic payload models for the v1.1 agent-reliability record types.

These five payload models mirror the JSON Schemas under
``acef-conventions/v1.1/`` for the new record types introduced in ACEF
v0.4 per brief ``planning/freddy-on-acef-requirements-v0.1.md`` §3.1-§3.6:

- :class:`AuthorizedTestScopePayload` — §3.1
- :class:`ScopeBoundaryEventPayload` — §3.2
- :class:`FindingRecordPayload` — §3.3
- :class:`DeliveryVerdictPayload` — §3.4
- :class:`HarnessAttestationPayload` — §3.6

§3.5 ``coverage_cell`` has NO payload model here: it is an Assessment-Bundle
inventory concept defined inline in
``assessment-bundle.schema.json#/properties/coverage_cells`` (no standalone
``coverage_cell.schema.json``), validated as raw dicts by
``acef.validation.v1_1_rules`` (audit records-payloads-5).

Each model inherits :class:`ACEFBaseModel` (``extra='allow'``) so that
vendor-prefixed extension keys round-trip losslessly. Field optionality
matches each schema's ``required`` array exactly: schema-required fields
are non-default; schema-optional fields default to ``None``.

The complex conditional-required rules (e.g., ``delivery_state ==
'verified_delivered'`` requiring ``read_back`` + ``harness_attestation_ref``;
``hard_stop_triggered: true`` requiring ``hard_stop_attestation_ref``) are
enforced at the validator level — not at the model layer — so that
partially-populated payloads can be constructed mid-pipeline before being
fed through ``acef.load()`` / ``acef.validate_bundle()`` for the final
conditional checks.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from acef.models.base import ACEFBaseModel

# ---------- §3.1 authorized_test_scope ----------


class AuthorizedSurface(ACEFBaseModel):
    """One entry in ``authorized_test_scope.authorized_surfaces``."""

    surface_type: Literal[
        "chat_endpoint",
        "api_endpoint",
        "tool_endpoint",
        "rag_endpoint",
        "browser_target",
        "package_target",
        "cli_target",
        "container_target",
        "docs_target",
    ]
    surface_identifier: str
    authorization_level: Literal[
        "read_only",
        "read_write_sandbox",
        "production_capable_owner_authorized",
    ]


class AuthorizedIdentity(ACEFBaseModel):
    """One entry in ``authorized_test_scope.authorized_identities``."""

    identity_type: Literal[
        "test_account",
        "service_principal",
        "delegated_grant",
        "freddy_managed_mailbox",
    ]
    identity_ref: str
    scope_constraint: str


class SideEffectAllowEntry(ACEFBaseModel):
    """One entry in ``side_effect_policy.explicit_allowlist``."""

    action_class: str
    rationale: str


class SideEffectPolicy(ACEFBaseModel):
    """``authorized_test_scope.side_effect_policy``."""

    default_disposition: Literal["default_deny", "default_allow_sandbox_only"]
    explicit_allowlist: list[SideEffectAllowEntry] = Field(default_factory=list)
    explicit_denylist: list[str] = Field(default_factory=list)


class SandboxBoundary(ACEFBaseModel):
    """``authorized_test_scope.sandbox_boundary``."""

    ownership_ledger_ref: str
    preflight_method: Literal[
        "resource_naming_scheme",
        "tenant_label",
        "dedicated_subaccount",
        "preflight_probe",
    ]


class OwnershipProof(ACEFBaseModel):
    """``authorized_test_scope.ownership_proof``."""

    proof_method: Literal[
        "dns_txt",
        "well_known_file",
        "http_header",
        "github_oauth",
        "sso_assertion",
    ]
    proof_artifact_ref: str
    verified_at: str  # ISO 8601 date-time


class AuthorizedTestScopePayload(ACEFBaseModel):
    """Payload for ``authorized_test_scope`` per brief §3.1.

    Mirrors ``acef-conventions/v1.1/authorized_test_scope.schema.json``.
    The cross-field rule (``production_capable_owner_authorized`` requires
    ownership_proof.proof_method in {dns_txt, well_known_file, sso_assertion}
    AND kill_switch_ref) is enforced by the validator, not by this model.
    """

    scope_id: str
    scope_version: str
    subject_ref: str
    authorized_surfaces: list[AuthorizedSurface]
    authorized_identities: list[AuthorizedIdentity]
    side_effect_policy: SideEffectPolicy
    sandbox_boundary: SandboxBoundary
    ownership_proof: OwnershipProof
    effective_from: str  # ISO 8601 date-time
    effective_until: str | None = None
    authorizing_actor_ref: str
    kill_switch_ref: str | None = None


# ---------- §3.2 scope_boundary_event ----------


class AttemptedAction(ACEFBaseModel):
    """``scope_boundary_event.attempted_action``."""

    action_class: str
    action_target: str
    action_payload_digest: str  # sha256:<hex>


class AuthorizedScopeSnapshot(ACEFBaseModel):
    """``scope_boundary_event.authorized_scope_snapshot``."""

    scope_id: str
    scope_version: str


class BoundaryDetector(ACEFBaseModel):
    """``scope_boundary_event.detector``."""

    detector_class: Literal[
        "preflight_probe",
        "ownership_ledger_check",
        "side_effect_policy_check",
        "post_action_audit",
        "external_alert",
    ]
    detector_id: str


class ScopeBoundaryEventPayload(ACEFBaseModel):
    """Payload for ``scope_boundary_event`` per brief §3.2.

    Mirrors ``acef-conventions/v1.1/scope_boundary_event.schema.json``. The
    conditional ``hard_stop_triggered=true → hard_stop_attestation_ref
    required`` rule is enforced at validator level.
    """

    event_id: str
    scope_ref: str
    attempted_action: AttemptedAction
    authorized_scope_snapshot: AuthorizedScopeSnapshot
    classification: Literal[
        "intentional_bypass_attempt",
        "harness_drift",
        "persona_misbehavior",
        "scope_definition_ambiguity",
        "third_party_integration_overreach",
    ]
    hard_stop_triggered: bool
    hard_stop_attestation_ref: str | None = None
    detected_at: str  # ISO 8601 date-time
    detector: BoundaryDetector


# ---------- §3.3 finding_record ----------


class FindingSeverity(ACEFBaseModel):
    """``finding_record.severity``."""

    severity_level: Literal["critical", "high", "medium", "low", "informational"]
    severity_rationale: str


class FindingReproduction(ACEFBaseModel):
    """``finding_record.reproduction``."""

    expected_behavior: str
    observed_behavior: str
    reproduction_steps_ref: str
    evidence_commit_ref: str


class FindingAttribution(ACEFBaseModel):
    """``finding_record.attribution``."""

    persona_ref: str
    scenario_ref: str
    scope_ref: str


class FindingRecordPayload(ACEFBaseModel):
    """Payload for ``finding_record`` per brief §3.3.

    Mirrors ``acef-conventions/v1.1/finding_record.schema.json``.

    NORMATIVE dedupe_key recipe (brief §3.3 + design decision D5)::

        dedupe_key = "sha256:" + hex(SHA-256(JCS-canonicalize({
            "class": finding_class,
            "subject_ref": subject_ref,
            "expected_behavior": reproduction.expected_behavior,
            "reproduction_steps_ref_content_hash":
                SHA-256-of-content-at-reproduction.reproduction_steps_ref,
        })))

    Canonicalization MUST follow RFC 8785 (JCS). Identical recipes across
    runs MUST collapse to one dedupe_key byte-equal. No hash agility in
    v0.4 — sha256 only. Computation is performed by the SDK builder
    ``Package.record_finding()``; this model captures the resulting hash.
    """

    finding_id: str
    finding_class: Literal[
        "safety_failure",
        "policy_violation",
        "accuracy_degradation",
        "robustness_failure",
        "security_vulnerability",
        "transparency_failure",
        "oversight_failure",
        "data_integrity_failure",
    ]
    subject_ref: str
    severity: FindingSeverity
    dedupe_key: str  # pattern: ^sha256:[0-9a-f]{64}$
    variant_group_id: str | None = None
    reproduction: FindingReproduction
    attribution: FindingAttribution
    regulation_impact: list[str] | None = None
    discovered_at: str  # ISO 8601 date-time
    discovered_in_run_ref: str
    disposition_history: list[str] | None = None
    accepted_risk_ref: str | None = None
    regression_ref: str | None = None


# ---------- §3.4 delivery_verdict ----------


class DeliveryDestination(ACEFBaseModel):
    """``delivery_verdict.destination``."""

    provider_class: Literal[
        "plane",
        "github_issues",
        "linear",
        "jira",
        "slack",
        "email",
        "markdown_export",
        "custom",
    ]
    provider_instance_id: str
    provider_object_id: str


class DeliveryWriteAttempt(ACEFBaseModel):
    """``delivery_verdict.write_attempt``."""

    attempted_at: str  # ISO 8601 date-time
    request_digest: str  # sha256:<hex>
    response_status: int
    response_digest: str  # sha256:<hex>


class DeliveryReadBack(ACEFBaseModel):
    """``delivery_verdict.read_back``."""

    read_back_at: str  # ISO 8601 date-time
    read_back_digest: str  # sha256:<hex>
    digest_match: bool


class DeliveryRetryEntry(ACEFBaseModel):
    """One entry in ``delivery_verdict.retry_history``."""

    attempted_at: str
    response_status: int
    response_digest: str


class DeliveryVerdictPayload(ACEFBaseModel):
    """Payload for ``delivery_verdict`` per brief §3.4.

    Mirrors ``acef-conventions/v1.1/delivery_verdict.schema.json``. The
    triple-requirement for ``delivery_state == 'verified_delivered'`` and
    the ``delivery_state == 'drifted'`` requires-drift_classification rule
    are enforced at validator level.
    """

    verdict_id: str
    finding_ref: str
    destination: DeliveryDestination
    write_attempt: DeliveryWriteAttempt
    read_back: DeliveryReadBack | None = None
    delivery_state: Literal[
        "drafted",
        "dispatched",
        "acknowledged",
        "verified_delivered",
        "failed",
        "drifted",
    ]
    drift_classification: (
        Literal[
            "external_close_without_resolution",
            "external_priority_lowered",
            "external_reassignment",
            "ticket_deleted",
        ]
        | None
    ) = None
    retry_history: list[DeliveryRetryEntry] | None = None
    harness_attestation_ref: str | None = None


# ---------- §3.5 coverage_cell (lives in Assessment Bundle) ----------
#
# coverage_cell has NO standalone records/ payload model. It is an
# Assessment-Bundle inventory concept defined INLINE in
# ``assessment-bundle.schema.json#/properties/coverage_cells`` (there is no
# ``coverage_cell.schema.json``), and the validator
# (``acef.validation.v1_1_rules.lint_coverage_cell_claim_language``) reads the
# ``coverage_cells`` entries as raw dicts off the assessment bundle. The former
# ``CoverageCellPayload`` / ``CoverageDimensions`` models were orphaned — never
# constructed anywhere in src/ — and gave a false impression of type-checked
# coverage-cell construction; they were removed (audit records-payloads-5). If a
# future Assessment-Bundle builder needs type-checked cell construction, add the
# model back WITH a construction call site and a parity test at that time.


# ---------- §3.6 harness_attestation ----------


class HarnessStateTransition(ACEFBaseModel):
    """``harness_attestation.state_transition``."""

    from_state: str
    to_state: str
    transitioned_at: str  # ISO 8601 date-time


class HarnessVerifier(ACEFBaseModel):
    """``harness_attestation.verifier``.

    The ``verifier_class`` enum DELIBERATELY excludes ``persona`` and ``llm``
    per brief §3.6 / VAL-LOAD-001/002 — those classes lack the determinism
    required to attest state transitions and are rejected at load time.
    """

    verifier_id: str
    verifier_class: Literal[
        "contract_gate",
        "read_back_verifier",
        "cryptographic_verifier",
        "harness_internal",
    ]
    verifier_version: str


class HarnessAttestationSignature(ACEFBaseModel):
    """``harness_attestation.attestation_signature``.

    Per VAL-SIGNATURE-001, ``signed_fields`` MUST equal exactly::

        ['attestation_id', 'state_class', 'state_transition',
         'bound_evidence_refs', 'verifier', 'claim',
         'fake_green_test_ref', 'signed_at', 'signer_kid']

    Algorithm MUST be RS256 or ES256; other algorithms emit ACEF-013.
    """

    alg: Literal["RS256", "ES256"]
    value: str
    signed_fields: list[str] | None = None


class HarnessAttestationPayload(ACEFBaseModel):
    """Payload for ``harness_attestation`` per brief §3.6.

    Mirrors ``acef-conventions/v1.1/harness_attestation.schema.json``.

    State-class taxonomy (the seven values) is hard-coded per brief §24.5 /
    design decision D3. Values outside the enum emit ACEF-076 at validation
    time. Empty ``bound_evidence_refs`` emits ACEF-070.
    """

    attestation_id: str
    state_class: Literal[
        "step",
        "finding",
        "coverage_cell",
        "regression",
        "delivery",
        "badge",
        "attestation",
    ]
    state_transition: HarnessStateTransition
    bound_evidence_refs: list[str]
    verifier: HarnessVerifier
    claim: str
    fake_green_test_ref: str
    attestation_signature: HarnessAttestationSignature
    signed_at: str  # ISO 8601 date-time
    signer_kid: str


__all__ = [
    "AuthorizedTestScopePayload",
    "ScopeBoundaryEventPayload",
    "FindingRecordPayload",
    "DeliveryVerdictPayload",
    "HarnessAttestationPayload",
    # Nested helpers — exported for advanced builder use cases.
    "AuthorizedSurface",
    "AuthorizedIdentity",
    "SideEffectAllowEntry",
    "SideEffectPolicy",
    "SandboxBoundary",
    "OwnershipProof",
    "AttemptedAction",
    "AuthorizedScopeSnapshot",
    "BoundaryDetector",
    "FindingSeverity",
    "FindingReproduction",
    "FindingAttribution",
    "DeliveryDestination",
    "DeliveryWriteAttempt",
    "DeliveryReadBack",
    "DeliveryRetryEntry",
    "HarnessStateTransition",
    "HarnessVerifier",
    "HarnessAttestationSignature",
]
