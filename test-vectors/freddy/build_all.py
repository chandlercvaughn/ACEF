"""Build every Freddy conformance bundle under test-vectors/freddy/.

Run from repo root::

    python test-vectors/freddy/build_all.py

Produces:
  test-vectors/freddy/pass/        — 9 bundles that MUST validate clean
  test-vectors/freddy/fail/        — 11 bundles that MUST emit a specific ACEF-NNN
  test-vectors/freddy/fake-green/  — 7 bundles, one per state class,
                                     each MUST fail validation (the
                                     state cannot be reached without
                                     the intentionally-absent precursor)

Every bundle's README.md declares its requirement-name, test-criterion
ID, and (for fail/fake-green) the expected ACEF-NNN code per brief §7.2.

The build is byte-deterministic: re-running this script over the same
source tree produces byte-equal bundle contents (VAL-CONFORMANCE §7.2 / TC7).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the builders package is importable regardless of CWD.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _builders._common import (  # noqa: E402
    FAKE_GREEN_URN_MAP,
    FIXED_LATER_TIMESTAMP,
    FIXED_LATEST_TIMESTAMP,
    FIXED_TIMESTAMP,
    authorized_test_scope_payload,
    base_manifest,
    base_record,
    delivery_verdict_payload,
    fake_green_urn_for,
    finding_record_payload,
    harness_attestation_payload,
    scope_boundary_event_payload,
    sha256_hex,
    urn,
    write_bundle,
)


# ===========================================================================
# Shared canonical content — the subscriber-mode full-loop bundle is the
# reference bundle (per dispatch prompt "canonical reference"). Other pass
# bundles reuse subsets of its records.
# ===========================================================================


def _common_actors() -> list[dict]:
    """Actors used across bundles. The 'customer' actor in the brief
    §14.5 matrix maps to ACEF Core's 'deployer' role (per
    authority_matrix.py:23). Authority_class is carried as a Pydantic-
    model extension (VAL-MODEL-006); v1 manifest schema permits
    additional properties on actors so the field surfaces cleanly."""
    return [
        {
            "actor_id": urn("actor", 51),
            "name": "Customer Test Authorizer",
            "role": "deployer",
            "organization": "Acme Corp",
            "authority_class": "accepted_risk_request",
        },
        {
            "actor_id": urn("actor", 52),
            "name": "Freddy Ops",
            "role": "auditor",
            "organization": "Freddy",
        },
        {
            "actor_id": urn("actor", 70),
            "name": "Harness Contract Gate v1",
            "role": "auditor",
            "organization": "Freddy",
        },
        {
            "actor_id": urn("actor", 50),
            "name": "Freddy Test Account",
            "role": "auditor",
            "organization": "Freddy",
        },
        {
            "actor_id": urn("actor", 60),
            "name": "Probe Persona alpha",
            "role": "auditor",
            "organization": "Freddy",
        },
    ]


def _common_subjects() -> list[dict]:
    return [
        {
            "subject_id": urn("sub", 1),
            "subject_type": "ai_system",
            "name": "Acme Customer Chatbot",
            "version": "2.3.0",
            "provider": "Acme Corp",
            "risk_classification": "high-risk",
            "modalities": ["text"],
            "lifecycle_phase": "deployment",
            "lifecycle_timeline": [],
        }
    ]


# ---------------------------------------------------------------------------
# Records used by the canonical full-loop pass bundle. Reused (and trimmed)
# across other bundles.
# ---------------------------------------------------------------------------


def _scope_record() -> dict:
    return base_record(
        record_id=urn("rec", 1),
        record_type="authorized_test_scope",
        timestamp=FIXED_TIMESTAMP,
        payload=authorized_test_scope_payload(scope_idx=1),
        entity_refs={
            "subject_refs": [urn("sub", 1)],
            "actor_refs": [urn("actor", 51)],
        },
    )


def _sbe_record_soft() -> dict:
    # hard_stop_triggered=false — no attestation_ref required.
    return base_record(
        record_id=urn("rec", 2),
        record_type="scope_boundary_event",
        timestamp=FIXED_TIMESTAMP,
        payload=scope_boundary_event_payload(event_idx=1, hard_stop_triggered=False),
        entity_refs={"subject_refs": [urn("sub", 1)]},
    )


def _finding_record(finding_idx: int = 1) -> dict:
    return base_record(
        record_id=urn("rec", 10 + finding_idx),
        record_type="finding_record",
        timestamp=FIXED_TIMESTAMP,
        payload=finding_record_payload(finding_idx=finding_idx),
        entity_refs={"subject_refs": [urn("sub", 1)]},
    )


def _delivery_record(*, verdict_idx: int = 1, verified: bool = False) -> dict:
    """Delivery verdict; verified=True yields the full verified_delivered triple."""
    if verified:
        payload = delivery_verdict_payload(
            verdict_idx=verdict_idx,
            finding_ref=urn("finding", 1),
            delivery_state="verified_delivered",
            include_read_back=True,
            read_back_matches=True,
            harness_attestation_ref=urn("att", 1),
        )
    else:
        payload = delivery_verdict_payload(
            verdict_idx=verdict_idx,
            finding_ref=urn("finding", 1),
            delivery_state="dispatched",
            include_read_back=False,
        )
    return base_record(
        record_id=urn("rec", 20 + verdict_idx),
        record_type="delivery_verdict",
        timestamp=FIXED_LATER_TIMESTAMP,
        payload=payload,
        entity_refs={"subject_refs": [urn("sub", 1)]},
    )


def _harness_attestation_record(
    *,
    attestation_idx: int = 1,
    state_class: str = "delivery",
    bound_to: list[str] | None = None,
) -> dict:
    return base_record(
        record_id=urn("rec", 30 + attestation_idx),
        record_type="harness_attestation",
        timestamp=FIXED_LATER_TIMESTAMP,
        payload=harness_attestation_payload(
            attestation_idx=attestation_idx,
            state_class=state_class,
            bound_evidence_refs=bound_to or [urn("rec", 21)],
            fake_green_test_ref=fake_green_urn_for(state_class),
        ),
        entity_refs={"subject_refs": [urn("sub", 1)]},
    )


# ===========================================================================
# PASS BUNDLES (9)
# ===========================================================================


def build_pass_subscriber_full_loop(root: Path) -> None:
    """The canonical reference bundle. Exercises every new record type AND
    every new variant discriminator (5 variants from F-M1-VARIANTS).

    VAL-CONFORMANCE-004: must contain ≥1 record of each of
        authorized_test_scope, scope_boundary_event, finding_record,
        delivery_verdict, harness_attestation
    AND ≥1 record per new variant discriminator value:
        kill_switch (human_oversight_action)
        regression_definition (risk_treatment)
        external_disposition (risk_treatment)
        verification_badge (transparency_disclosure)
        freshness_window (evidence_gap)
    Plus a coverage_cell entry in the sibling Assessment Bundle.
    """
    bundle = root / "pass" / "subscriber-mode-full-loop.acef"

    records = [
        _scope_record(),
        _sbe_record_soft(),
        _finding_record(finding_idx=1),
        # First delivery (dispatched, no read_back) so a later verified
        # delivery has prior history.
        _delivery_record(verdict_idx=1, verified=False),
        # Verified delivery — references harness_attestation rec 31 (att 1).
        _delivery_record(verdict_idx=2, verified=True),
        # Harness attestation binding the verified delivery.
        _harness_attestation_record(
            attestation_idx=1,
            state_class="delivery",
            bound_to=[urn("rec", 22)],  # ref the verified delivery_verdict
        ),
        # Variant V1: kill_switch human_oversight_action
        # Parent v1 required: action_type (enum). The kill_switch variant
        # rides on action_type='stop' (the closest semantic match).
        base_record(
            record_id=urn("rec", 40),
            record_type="human_oversight_action",
            timestamp=FIXED_TIMESTAMP,
            payload={
                "action_type": "stop",
                "oversight_subtype": "kill_switch",
                "operator_actor_ref": urn("actor", 51),
                "triggered_at": FIXED_TIMESTAMP,
                "rationale": "Operator-triggered hard stop during sensitive test slice.",
            },
        ),
        # Variant V2: regression_definition risk_treatment
        # Parent v1 required: risk_id, treatment_type, control_description, implementation_status
        base_record(
            record_id=urn("rec", 41),
            record_type="risk_treatment",
            timestamp=FIXED_TIMESTAMP,
            payload={
                "risk_id": urn("rec", 411),
                "treatment_type": "mitigate",
                "control_description": "Persistent regression suite blocking re-introduction of unsafe-instruction defect.",
                "implementation_status": "implemented",
                "treatment_subtype": "regression_definition",
                "regression_id": urn("rec", 410),
                "regression_definition": {
                    "name": "Persistent unsafe-instruction regression",
                    "based_on_finding_ref": urn("finding", 1),
                },
                "active": True,
            },
        ),
        # Variant V3: external_disposition risk_treatment
        base_record(
            record_id=urn("rec", 42),
            record_type="risk_treatment",
            timestamp=FIXED_TIMESTAMP,
            entity_refs={"actor_refs": [urn("actor", 51)]},
            payload={
                "risk_id": urn("rec", 421),
                "treatment_type": "accept",
                "control_description": "Customer-asserted accepted-risk disposition; documented exception with compensating monitoring.",
                "implementation_status": "implemented",
                "treatment_subtype": "external_disposition",
                "disposition_class": "accepted_risk_request",
                "asserting_actor_ref": urn("actor", 51),
                "authority_check": {
                    "authority_class": "accepted_risk_request",
                    "authority_granted": True,
                    "actor_ref": urn("actor", 51),
                },
                "internal_state_unchanged": True,
                "asserted_at": FIXED_TIMESTAMP,
            },
        ),
        # Variant V4: verification_badge transparency_disclosure.
        # v1.1 schema overlay requires: badge_id, subject_ref, page_state,
        # integrity_state, evidence_chain_root_ref, freshness_state_ref.
        # When page_state in {green, provisional}, public_artifact_link
        # is also required. Parent v1 also requires disclosure_type.
        base_record(
            record_id=urn("rec", 43),
            record_type="transparency_disclosure",
            timestamp=FIXED_TIMESTAMP,
            payload={
                "disclosure_type": "transparency_report",
                "variant": "verification_badge",
                "badge_id": urn("rec", 430),
                "subject_ref": urn("sub", 1),
                "page_state": "green",
                "integrity_state": "verified",
                "evidence_chain_root_ref": urn("rec", 11),
                "freshness_state_ref": urn("rec", 44),
                "public_artifact_link": "https://badges.example.test/acme/chatbot",
            },
        ),
        # Variant V5: freshness_window evidence_gap.
        # Parent v1 required: missing_record_type, reason.
        # v1.1 overlay requires when gap_subtype='freshness_window':
        # window_start, window_end, refresh_due_at, current_freshness_state.
        base_record(
            record_id=urn("rec", 44),
            record_type="evidence_gap",
            timestamp=FIXED_TIMESTAMP,
            payload={
                "missing_record_type": "evaluation_report",
                "reason": "scheduled",
                "gap_subtype": "freshness_window",
                "window_start": FIXED_TIMESTAMP,
                "window_end": "2026-08-01T00:00:00Z",
                "refresh_due_at": "2026-07-15T00:00:00Z",
                "current_freshness_state": "fresh",
            },
        ),
    ]

    # Sibling assessment bundle carrying the coverage_cell + clean claim_language.
    assessment_bundle = {
        "evaluation_instant": FIXED_LATEST_TIMESTAMP,
        "coverage_cells": [
            {
                "cell_id": urn("rec", 60),
                "subject_ref": urn("sub", 1),
                "scenario_class": "safety_probe_battery",
                "surface_class": "chat_endpoint",
                "freshness_window_ref": urn("rec", 44),
                "bound_evidence_refs": [urn("rec", 11), urn("rec", 22), urn("rec", 31)],
                "claim_language": (
                    "Evidence covers the safety probe battery slice within the declared freshness window."
                ),
            }
        ],
    }

    readme = """# subscriber-mode-full-loop

**Requirement:** Brief §7.1 (canonical reference) + VAL-CONFORMANCE-004
**Test criterion ID:** VAL-CONFORMANCE-001 (pass), VAL-CONFORMANCE-004 (inventory)
**Expected code:** none (pass bundle MUST validate clean)

This is the canonical reference bundle for ACEF v0.4 / Freddy Profile.
It exercises every new v1.1 record type:

- authorized_test_scope (1 record)
- scope_boundary_event (1 record, soft — no hard_stop)
- finding_record (1 record, dedupe_key auto-computed per brief §3.3)
- delivery_verdict (2 records — one dispatched, one verified_delivered with read-back triple)
- harness_attestation (1 record, RS256 signed_fields scope normative)

…AND every new variant discriminator (per F-M1-VARIANTS):

- human_oversight_action / kill_switch (V1)
- risk_treatment / regression_definition (V2)
- risk_treatment / external_disposition (V3)
- transparency_disclosure / verification_badge (V4)
- evidence_gap / freshness_window (V5)

A sibling Assessment Bundle carries the coverage_cell entry
(coverage_cell lives in the assessment bundle per VAL-SCHEMA-006).
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=100,
            analysis_mode="subscriber",
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=records,
        readme=readme,
        assessment_bundle=assessment_bundle,
    )


def build_pass_public_artifact_mode(root: Path) -> None:
    """analysis_mode=public_artifact. Authorized scope + a finding only —
    NO delivery_verdict (forbidden in public mode), NO disposition_record."""
    bundle = root / "pass" / "public-artifact-mode.acef"
    records = [
        _scope_record(),
        _finding_record(finding_idx=1),
        _harness_attestation_record(
            attestation_idx=2,
            state_class="finding",
            bound_to=[urn("rec", 11)],  # finding record
        ),
    ]
    readme = """# public-artifact-mode

**Requirement:** Brief §6.6 (analysis_mode=public_artifact) + VAL-CONFORMANCE-001
**Test criterion ID:** VAL-CONFORMANCE-001
**Expected code:** none

A v1.1 bundle declaring `analysis_mode: "public_artifact"`. Contains
authorized_test_scope, finding_record, harness_attestation. Per brief
§6.6 / plan WS3.9, public_artifact forbids delivery_verdict and any
disposition_record (external_disposition variant) — this bundle omits
both.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=101,
            analysis_mode="public_artifact",
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=records,
        readme=readme,
    )


def build_pass_canary_mode(root: Path) -> None:
    """analysis_mode=canary. Includes a badge_state=unsupported as required."""
    bundle = root / "pass" / "canary-mode.acef"
    records = [
        _scope_record(),
        _finding_record(finding_idx=1),
        _harness_attestation_record(
            attestation_idx=3,
            state_class="finding",
            bound_to=[urn("rec", 11)],
        ),
        # canary requires badge_state=unsupported (rule (c) in mode-gates).
        # v1.1 overlay still requires the badge_id / integrity_state /
        # evidence_chain_root_ref / freshness_state_ref set, but
        # public_artifact_link is NOT required for page_state='unsupported'.
        #
        # confidentiality is the ACCESS-class 'regulator-only' (NOT the
        # transform-class 'redacted'): canary mode merely forbids PUBLIC
        # disclosures, and this record retains its cleartext badge payload.
        # Since fix-F-M2-REDACTION the validator routes 'redacted'/
        # 'hash-committed' records carrying X1+X2 to commitment-shape
        # validation (the stored payload must BE the apply_redaction
        # commitment), so labeling this cleartext record 'redacted' would be
        # the non-conformant "claimed redacted, actually raw" state and emit
        # ACEF-004. X1/X2 stay populated — ACEF-074 requires X1 on every
        # non-public record regardless of class.
        base_record(
            record_id=urn("rec", 70),
            record_type="transparency_disclosure",
            timestamp=FIXED_TIMESTAMP,
            confidentiality="regulator-only",
            redaction_policy_version="1.0.0",
            redaction_attestation_ref=urn("rec", 99),
            payload={
                "disclosure_type": "transparency_report",
                "variant": "verification_badge",
                "badge_id": urn("rec", 700),
                "subject_ref": urn("sub", 1),
                "page_state": "unsupported",
                "integrity_state": "unverified",
                "evidence_chain_root_ref": urn("rec", 11),
                "freshness_state_ref": urn("rec", 99),
                "rationale": "Canary mode: badge unsupported.",
            },
        ),
        # Required X1/X2 attestation record (event_log) to satisfy X2 ref
        # resolution. v1 event_log.event_type enum: [inference, training,
        # evaluation, deployment, override, error, marking, disclosure,
        # logging_spec]. Redaction events ride on 'logging_spec' until a
        # dedicated enum value is added by a future spec amendment.
        base_record(
            record_id=urn("rec", 99),
            record_type="event_log",
            timestamp=FIXED_TIMESTAMP,
            payload={
                "event_type": "logging_spec",
                "policy_version": "1.0.0",
                "applied_at": FIXED_TIMESTAMP,
                "rationale": "Redaction-attestation event_log per VAL-REDACTION-002.",
            },
        ),
    ]
    readme = """# canary-mode

**Requirement:** Brief §6.6 (analysis_mode=canary) + VAL-CONFORMANCE-001
**Test criterion ID:** VAL-CONFORMANCE-001
**Expected code:** none

Canary mode forbids public transparency_disclosures except badges with
page_state='unsupported'. Bundle includes such a non-public badge plus
the redaction_attestation event_log it references.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=102,
            analysis_mode="canary",
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=records,
        readme=readme,
    )


def build_pass_verified_delivery(root: Path) -> None:
    """Tight focus: a verified_delivered delivery_verdict + its harness_attestation."""
    bundle = root / "pass" / "verified-delivery.acef"
    records = [
        _scope_record(),
        _finding_record(finding_idx=1),
        _delivery_record(verdict_idx=2, verified=True),
        _harness_attestation_record(
            attestation_idx=1,
            state_class="delivery",
            bound_to=[urn("rec", 22)],
        ),
    ]
    readme = """# verified-delivery

**Requirement:** Brief §3.4 verified_delivered triple-requirement + VAL-CONFORMANCE-001
**Test criterion ID:** VAL-CONFORMANCE-001
**Expected code:** none

Demonstrates a clean verified_delivered delivery_verdict: read_back +
read_back.digest_match=true + harness_attestation_ref all present. The
read_back_digest byte-equals write_attempt.request_digest.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=103,
            analysis_mode="subscriber",
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=records,
        readme=readme,
    )


def build_pass_regression_active_with_fix_verification(root: Path) -> None:
    """An active regression_definition with a paired fix-verification attestation."""
    bundle = root / "pass" / "regression-active-with-fix-verification.acef"
    records = [
        _scope_record(),
        _finding_record(finding_idx=1),
        # Active regression_definition variant.
        base_record(
            record_id=urn("rec", 41),
            record_type="risk_treatment",
            timestamp=FIXED_TIMESTAMP,
            payload={
                "risk_id": urn("rec", 411),
                "treatment_type": "mitigate",
                "control_description": "Persistent regression suite blocking re-introduction of unsafe-instruction defect.",
                "implementation_status": "implemented",
                "treatment_subtype": "regression_definition",
                "regression_id": urn("rec", 410),
                "regression_definition": {
                    "name": "Persistent unsafe-instruction regression",
                    "based_on_finding_ref": urn("finding", 1),
                },
                "active": True,
            },
        ),
        # Fix-verification attestation (state_class=regression).
        _harness_attestation_record(
            attestation_idx=5,
            state_class="regression",
            bound_to=[urn("rec", 41), urn("rec", 11)],
        ),
    ]
    readme = """# regression-active-with-fix-verification

**Requirement:** Brief §4.2 regression_definition + paired regression-class
attestation. VAL-CONFORMANCE-001.
**Test criterion ID:** VAL-CONFORMANCE-001
**Expected code:** none

An active regression_definition is paired with a harness_attestation
whose state_class='regression' and bound_evidence_refs includes the
regression record + the originating finding.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=104,
            analysis_mode="subscriber",
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=records,
        readme=readme,
    )


def build_pass_badge_green_with_fresh_coverage(root: Path) -> None:
    """A verification_badge=green backed by a fresh coverage_cell + attestation."""
    bundle = root / "pass" / "badge-green-with-fresh-coverage.acef"
    records = [
        _scope_record(),
        _finding_record(finding_idx=1),
        # Badge state — green page_state requires public_artifact_link.
        base_record(
            record_id=urn("rec", 43),
            record_type="transparency_disclosure",
            timestamp=FIXED_TIMESTAMP,
            payload={
                "disclosure_type": "transparency_report",
                "variant": "verification_badge",
                "badge_id": urn("rec", 430),
                "subject_ref": urn("sub", 1),
                "page_state": "green",
                "integrity_state": "verified",
                "evidence_chain_root_ref": urn("rec", 11),
                "freshness_state_ref": urn("rec", 44),
                "public_artifact_link": "https://badges.example.test/acme/chatbot",
            },
        ),
        # Freshness window (v1.1 freshness_window variant).
        base_record(
            record_id=urn("rec", 44),
            record_type="evidence_gap",
            timestamp=FIXED_TIMESTAMP,
            payload={
                "missing_record_type": "evaluation_report",
                "reason": "scheduled",
                "gap_subtype": "freshness_window",
                "window_start": FIXED_TIMESTAMP,
                "window_end": "2026-08-01T00:00:00Z",
                "refresh_due_at": "2026-07-15T00:00:00Z",
                "current_freshness_state": "fresh",
            },
        ),
        # Badge attestation (state_class=badge).
        _harness_attestation_record(
            attestation_idx=6,
            state_class="badge",
            bound_to=[urn("rec", 43), urn("rec", 44)],
        ),
    ]
    assessment_bundle = {
        "evaluation_instant": FIXED_LATEST_TIMESTAMP,
        "coverage_cells": [
            {
                "cell_id": urn("rec", 60),
                "subject_ref": urn("sub", 1),
                "scenario_class": "safety_probe_battery",
                "surface_class": "chat_endpoint",
                "freshness_window_ref": urn("rec", 44),
                "bound_evidence_refs": [urn("rec", 11), urn("rec", 36)],
                "claim_language": "Evidence covers the slice within the freshness window.",
            }
        ],
    }
    readme = """# badge-green-with-fresh-coverage

**Requirement:** Brief §4.4 badge_state=verification_badge backed by fresh coverage
**Test criterion ID:** VAL-CONFORMANCE-001
**Expected code:** none

A green verification_badge transparency_disclosure paired with: a
freshness_window evidence_gap, a coverage_cell (in sibling assessment
bundle) inside the window, and a state_class='badge' harness_attestation.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=105,
            analysis_mode="subscriber",
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=records,
        readme=readme,
        assessment_bundle=assessment_bundle,
    )


def build_pass_badge_provisional_with_reason(root: Path) -> None:
    """badge_state=provisional with a documented reason. No fresh coverage required."""
    bundle = root / "pass" / "badge-provisional-with-reason.acef"
    records = [
        _scope_record(),
        _finding_record(finding_idx=1),
        base_record(
            record_id=urn("rec", 43),
            record_type="transparency_disclosure",
            timestamp=FIXED_TIMESTAMP,
            payload={
                "disclosure_type": "transparency_report",
                "variant": "verification_badge",
                "badge_id": urn("rec", 430),
                "subject_ref": urn("sub", 1),
                "page_state": "provisional",
                "integrity_state": "verified",
                "evidence_chain_root_ref": urn("rec", 11),
                "freshness_state_ref": urn("rec", 44),
                "public_artifact_link": "https://badges.example.test/acme/chatbot",
                # provisional_reason is enum-typed in v1.1 overlay schema:
                # [partial_coverage, pending_freshness_reconciliation,
                #  accepted_risk_in_effect].
                "provisional_reason": "pending_freshness_reconciliation",
            },
        ),
        _harness_attestation_record(
            attestation_idx=7,
            state_class="badge",
            bound_to=[urn("rec", 11), urn("rec", 43)],
        ),
    ]
    readme = """# badge-provisional-with-reason

**Requirement:** Brief §4.4 badge_state=provisional carries an explicit rationale
**Test criterion ID:** VAL-CONFORMANCE-001
**Expected code:** none

A provisional badge does NOT require fresh coverage but MUST carry a
rationale string. No harness_attestation is required for a provisional
state.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=106,
            analysis_mode="subscriber",
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=records,
        readme=readme,
    )


def build_pass_accepted_risk_disposition(root: Path) -> None:
    """external_disposition asserting accepted_risk_request, authority granted to customer."""
    bundle = root / "pass" / "accepted-risk-disposition.acef"
    records = [
        _scope_record(),
        _finding_record(finding_idx=1),
        # disposition_record variant — customer + accepted_risk_request is GRANTED in matrix.
        base_record(
            record_id=urn("rec", 42),
            record_type="risk_treatment",
            timestamp=FIXED_TIMESTAMP,
            entity_refs={"actor_refs": [urn("actor", 51)]},
            payload={
                "risk_id": urn("rec", 421),
                "treatment_type": "accept",
                "control_description": "Customer-asserted accepted-risk disposition; documented exception with compensating monitoring.",
                "implementation_status": "implemented",
                "treatment_subtype": "external_disposition",
                "disposition_class": "accepted_risk_request",
                "asserting_actor_ref": urn("actor", 51),  # customer actor
                "authority_check": {
                    "authority_class": "accepted_risk_request",
                    "authority_granted": True,
                    "actor_ref": urn("actor", 51),
                },
                "internal_state_unchanged": True,
                "asserted_at": FIXED_TIMESTAMP,
                "rationale": "Customer accepted residual risk; documented exception.",
            },
        ),
        # subscriber mode requires a harness_attestation.
        _harness_attestation_record(
            attestation_idx=8,
            state_class="finding",
            bound_to=[urn("rec", 11)],
        ),
    ]
    readme = """# accepted-risk-disposition

**Requirement:** Brief §14.5 authority matrix — customer may grant
accepted_risk_request authority. VAL-CONFORMANCE-001.
**Test criterion ID:** VAL-CONFORMANCE-001
**Expected code:** none

An external_disposition risk_treatment record where the asserting actor
is a customer-role actor with authority_class=accepted_risk_request and
authority_granted=true. internal_state_unchanged=true per brief §V3.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=107,
            analysis_mode="subscriber",
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=records,
        readme=readme,
    )


def build_pass_multi_finding_with_dedupe_collapse(root: Path) -> None:
    """Two finding_records with IDENTICAL dedupe_key inputs MUST produce
    byte-equal dedupe_keys (brief §3.3 normative recipe / VAL-SDK-003)."""
    bundle = root / "pass" / "multi-finding-with-dedupe-collapse.acef"
    # Two findings with identical class + subject + expected + reproduction_hash
    # MUST collapse — they will share dedupe_key.
    finding_a = base_record(
        record_id=urn("rec", 11),
        record_type="finding_record",
        timestamp=FIXED_TIMESTAMP,
        payload=finding_record_payload(
            finding_idx=1,
            finding_class="safety_failure",
            expected="system refuses unsafe instruction",
            reproduction_steps_content_hash=sha256_hex("shared-repro-steps"),
        ),
    )
    finding_b = base_record(
        record_id=urn("rec", 12),
        record_type="finding_record",
        timestamp=FIXED_TIMESTAMP,
        payload=finding_record_payload(
            finding_idx=2,
            finding_class="safety_failure",
            expected="system refuses unsafe instruction",
            reproduction_steps_content_hash=sha256_hex("shared-repro-steps"),
        ),
    )
    # Sanity: assert they collapsed (build-time check, not runtime).
    assert finding_a["payload"]["dedupe_key"] == finding_b["payload"]["dedupe_key"], (
        "dedupe_key recipe non-deterministic — VAL-SDK-003 broken"
    )

    records = [
        _scope_record(),
        finding_a,
        finding_b,
        # subscriber mode requires a harness_attestation.
        _harness_attestation_record(
            attestation_idx=9,
            state_class="finding",
            bound_to=[urn("rec", 11), urn("rec", 12)],
        ),
    ]
    readme = """# multi-finding-with-dedupe-collapse

**Requirement:** Brief §3.3 dedupe_key normative recipe + VAL-SDK-003
**Test criterion ID:** VAL-CONFORMANCE-001
**Expected code:** none

Two finding_records with identical (class, subject_ref,
expected_behavior, reproduction_steps_ref_content_hash) produce
BYTE-EQUAL dedupe_key strings. The bundle still validates clean —
collapse is a downstream concern, the bundle just carries the shared
dedupe_key for the assessment phase to group on.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=108,
            analysis_mode="subscriber",
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=records,
        readme=readme,
    )


# ===========================================================================
# FAIL BUNDLES (11)
# ===========================================================================


def build_fail_verified_delivery_without_readback(root: Path) -> None:
    bundle = root / "fail" / "verified-delivery-without-readback"
    # verified_delivered but NO read_back, NO harness_attestation_ref.
    bad_delivery = base_record(
        record_id=urn("rec", 22),
        record_type="delivery_verdict",
        timestamp=FIXED_LATER_TIMESTAMP,
        payload=delivery_verdict_payload(
            verdict_idx=2,
            delivery_state="verified_delivered",
            include_read_back=False,  # missing read_back
            harness_attestation_ref=None,  # missing attestation
        ),
    )
    readme = """# verified-delivery-without-readback

**Requirement:** Brief §3.4 verified_delivered requires read_back triple
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-071

The bundle declares delivery_state='verified_delivered' but omits both
read_back and harness_attestation_ref. The validator's
enforce_delivery_verdict_integrity emits ACEF-071. (Schema allOf may
ALSO emit ACEF-004 for the missing required fields; the conformance
driver asserts ACEF-071 is present.)
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=200,
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=[_scope_record(), _finding_record(), bad_delivery],
        readme=readme,
    )


def build_fail_verified_delivery_digest_mismatch(root: Path) -> None:
    bundle = root / "fail" / "verified-delivery-digest-mismatch"
    # verified_delivered with read_back present but read_back_digest does NOT
    # byte-equal write_attempt.request_digest. We deliberately violate the
    # schema's digest_match=true constraint by setting digest_match=true
    # (so the schema's allOf is content with the read_back shape) but
    # supply a non-matching read_back_digest — the validator's
    # enforce_delivery_verdict_integrity catches this.
    write_attempt_digest = sha256_hex("delivery-request-2")
    payload = {
        "verdict_id": urn("delivery", 2),
        "finding_ref": urn("finding", 1),
        "destination": {
            "provider_class": "plane",
            "provider_instance_id": "plane-host-001",
            "provider_object_id": "EPOCHLYPLA-99",
        },
        "write_attempt": {
            "attempted_at": FIXED_TIMESTAMP,
            "request_digest": write_attempt_digest,
            "response_status": 200,
            "response_digest": sha256_hex("response-2"),
        },
        "read_back": {
            "read_back_at": FIXED_LATER_TIMESTAMP,
            "read_back_digest": sha256_hex("DIFFERENT-content-than-request"),
            "digest_match": True,  # claim true, but the digests differ — that's the violation
        },
        "delivery_state": "verified_delivered",
        "harness_attestation_ref": urn("att", 1),
    }
    bad_delivery = base_record(
        record_id=urn("rec", 22),
        record_type="delivery_verdict",
        timestamp=FIXED_LATER_TIMESTAMP,
        payload=payload,
    )
    # Add a benign harness_attestation so harness_attestation_ref resolves
    # (avoids piling on unrelated diagnostics).
    har = _harness_attestation_record(attestation_idx=1, state_class="delivery", bound_to=[urn("rec", 22)])
    readme = """# verified-delivery-digest-mismatch

**Requirement:** Brief §3.4 read_back digest must byte-equal write digest
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-072

The bundle's delivery_verdict has read_back.digest_match=true (so the
schema allOf is satisfied) BUT the read_back_digest does not byte-equal
write_attempt.request_digest. Validator's
enforce_delivery_verdict_integrity emits ACEF-072.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=201,
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=[_scope_record(), _finding_record(), bad_delivery, har],
        readme=readme,
    )


def build_fail_harness_attestation_empty_evidence(root: Path) -> None:
    bundle = root / "fail" / "harness-attestation-empty-evidence"
    # harness_attestation with empty bound_evidence_refs.
    bad_har = base_record(
        record_id=urn("rec", 31),
        record_type="harness_attestation",
        timestamp=FIXED_LATER_TIMESTAMP,
        payload=harness_attestation_payload(
            attestation_idx=1,
            state_class="finding",
            bound_evidence_refs=[],  # the violation
            fake_green_test_ref=fake_green_urn_for("finding"),
        ),
    )
    readme = """# harness-attestation-empty-evidence

**Requirement:** Brief §3.6 empty bound_evidence_refs emits ACEF-070
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-070

The bundle's harness_attestation declares state_class='finding' but
carries an empty bound_evidence_refs array. A state-class attestation
without any binding is structurally unverifiable.
Validator's enforce_harness_evidence_binding emits ACEF-070.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=202,
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=[_scope_record(), _finding_record(), bad_har],
        readme=readme,
    )


def build_fail_harness_attestation_persona_as_verifier(root: Path) -> None:
    bundle = root / "fail" / "harness-attestation-persona-as-verifier"
    # harness_attestation with verifier_class='persona'.
    bad_payload = harness_attestation_payload(
        attestation_idx=1,
        state_class="finding",
        bound_evidence_refs=[urn("rec", 11)],
        verifier_class="contract_gate",  # placeholder; will overwrite below
        fake_green_test_ref=fake_green_urn_for("finding"),
    )
    # Override verifier_class to the banned 'persona' value (schema enum
    # excludes this, so we bypass the helper's defaults).
    bad_payload["verifier"]["verifier_class"] = "persona"

    bad_har = base_record(
        record_id=urn("rec", 31),
        record_type="harness_attestation",
        timestamp=FIXED_LATER_TIMESTAMP,
        payload=bad_payload,
    )
    readme = """# harness-attestation-persona-as-verifier

**Requirement:** Brief §3.6 persona/llm verifier banned (VAL-LOAD-001)
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-070

The bundle's harness_attestation declares verifier_class='persona' —
banned per brief §3.6 because persona verifiers lack determinism.
Loader rejects this at load time (LoadRejection); validator's
enforce_harness_verifier_class mirrors the rejection with ACEF-070.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=203,
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=[_scope_record(), _finding_record(), bad_har],
        readme=readme,
    )


def build_fail_badge_green_with_failed_integrity(root: Path) -> None:
    bundle = root / "fail" / "badge-green-with-failed-integrity"
    # We declare a content-hashes.json with a hash that does NOT match the
    # actual records/finding_record.jsonl content. Validator's integrity
    # checker emits ACEF-014 (hash mismatch).
    records = [_scope_record(), _finding_record()]
    # Wrong hash to trigger ACEF-014.
    wrong_hashes = {
        "records/finding_record.jsonl": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "records/authorized_test_scope.jsonl": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    }
    readme = """# badge-green-with-failed-integrity

**Requirement:** Brief §7.1 — bundle with failed integrity is rejected
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-014

Bundle's content-hashes.json declares zeros for the record files but
the actual file content hashes to non-zero. Validator's integrity
checker emits ACEF-014 (content hash mismatch).

Code choice: ACEF-014 is the documented integrity-hash-mismatch code
in the pre-v1.1 registry. Per dispatch prompt "ACEF-080 if mode
violation; otherwise a freshness/integrity error such as ACEF-014 —
document choice": this bundle has no mode violation, so ACEF-014.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=204,
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=records,
        readme=readme,
        content_hashes=wrong_hashes,
    )


def build_fail_cross_tenant_references_in_one_bundle(root: Path) -> None:
    bundle = root / "fail" / "cross-tenant-references-in-one-bundle"
    # Two records with distinct tenant_labels under analysis_mode=subscriber.
    rec_a = base_record(
        record_id=urn("rec", 1),
        record_type="risk_register",
        timestamp=FIXED_TIMESTAMP,
        tenant_label="tenant-alpha",
        payload={"summary": "alpha tenant risk register entry"},
    )
    rec_b = base_record(
        record_id=urn("rec", 2),
        record_type="risk_register",
        timestamp=FIXED_TIMESTAMP,
        tenant_label="tenant-beta",
        payload={"summary": "beta tenant risk register entry"},
    )
    readme = """# cross-tenant-references-in-one-bundle

**Requirement:** Brief §X3 tenant_label uniformity (VAL-VALIDATION-003)
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-075

Bundle has analysis_mode='subscriber' AND two records with distinct
tenant_label values ('tenant-alpha' and 'tenant-beta'). Validator's
enforce_tenant_uniformity emits ACEF-075.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=205,
            analysis_mode="subscriber",
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=[
            rec_a,
            rec_b,
            _scope_record(),
            _harness_attestation_record(
                attestation_idx=1,
                state_class="finding",
                bound_to=[urn("rec", 1)],
            ),
        ],
        readme=readme,
    )


def build_fail_voice_rubric_with_claim_token(root: Path) -> None:
    bundle = root / "fail" / "voice-rubric-with-claim-token"
    # Need the namespace declared in manifest.namespaces for the lint to fire.
    # Per VAL-VALIDATION-012 the x-freddy/voice-rubric-emission lint fires
    # for content that contains a banned claim-lexicon token AND lacks a
    # paired harness_attestation_ref.
    # The bundled freddy lint expects a structured scan result
    # (claim_lexicon_scan_result.tokens_found) and the rejection_state
    # field per brief §5.2 — see bundled_freddy.lint_voice_rubric_emission.
    voice_rec = base_record(
        record_id=urn("rec", 80),
        record_type="x-freddy/voice-rubric-emission",
        timestamp=FIXED_TIMESTAMP,
        payload={
            "emission_id": urn("rec", 800),
            "voice": "alpha",
            "prose": "The system is fully compliant with the safety policy.",
            "claim_lexicon_scan_result": {
                "tokens_found": ["compliant"],
            },
            "rejection_state": "accepted",
            # Deliberately no harness_attestation_ref — the lint fires.
        },
    )
    readme = """# voice-rubric-with-claim-token

**Requirement:** Brief §F2 / VAL-VALIDATION-012 — x-freddy/voice-rubric-emission
banned claim-lexicon token without paired harness_attestation_ref
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-077

The bundle declares manifest.namespaces['x-freddy'] (so the
bundled_freddy lint is active) and includes a
x-freddy/voice-rubric-emission record whose prose contains the banned
token 'compliant' AND lacks a paired harness_attestation_ref. The
namespace-lint hook emits ACEF-077.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=206,
            subjects=_common_subjects(),
            actors=_common_actors(),
            namespaces={"x-freddy": {"voice-rubric-emission": {"enabled": True}}},
        ),
        records=[_scope_record(), voice_rec],
        readme=readme,
    )


def build_fail_scope_boundary_event_without_stop_attest(root: Path) -> None:
    bundle = root / "fail" / "scope-boundary-event-without-stop-attest"
    # hard_stop_triggered=true but NO hard_stop_attestation_ref → schema allOf
    # emits ACEF-004 per the v1.1 scope_boundary_event schema.
    bad_sbe = base_record(
        record_id=urn("rec", 2),
        record_type="scope_boundary_event",
        timestamp=FIXED_TIMESTAMP,
        payload=scope_boundary_event_payload(
            event_idx=1,
            hard_stop_triggered=True,
            hard_stop_attestation_ref=None,  # missing
        ),
    )
    readme = """# scope-boundary-event-without-stop-attest

**Requirement:** Brief §3.2 allOf hard_stop_attestation_ref required when hard_stop_triggered=true
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-004

The bundle's scope_boundary_event has hard_stop_triggered=true but no
hard_stop_attestation_ref. The v1.1 schema's allOf conditional fires,
emitting ACEF-004 (schema validation failure).
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=207,
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=[_scope_record(), bad_sbe],
        readme=readme,
    )


def build_fail_external_disposition_overrides_internal(root: Path) -> None:
    bundle = root / "fail" / "external-disposition-overrides-internal"
    # disposition_record with internal_state_unchanged=false → ACEF-076 mirror.
    bad_disp = base_record(
        record_id=urn("rec", 42),
        record_type="risk_treatment",
        timestamp=FIXED_TIMESTAMP,
        payload={
            "treatment_subtype": "external_disposition",
            "disposition_class": "accepted_risk_request",
            "asserting_actor_ref": urn("actor", 51),
            "authority_check": {
                "authority_class": "accepted_risk_request",
                "authority_granted": True,
            },
            "internal_state_unchanged": False,  # the violation
            "asserted_at": FIXED_TIMESTAMP,
        },
    )
    readme = """# external-disposition-overrides-internal

**Requirement:** Brief §V3 external_disposition advisory; MUST NOT mutate internal state
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-076

The bundle's risk_treatment (external_disposition variant) sets
internal_state_unchanged=false — external dispositions are advisory
per brief §V3. Validator's enforce_disposition_internal_state mirrors
the loader's LoadRejection with ACEF-076.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=208,
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=[_scope_record(), _finding_record(), bad_disp],
        readme=readme,
    )


def build_fail_public_artifact_with_delivery_verdict(root: Path) -> None:
    bundle = root / "fail" / "public-artifact-with-delivery-verdict"
    # public_artifact mode + delivery_verdict → ACEF-080.
    bad_delivery = _delivery_record(verdict_idx=1, verified=False)
    readme = """# public-artifact-with-delivery-verdict

**Requirement:** Brief §6.6 — public_artifact forbids delivery_verdict
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-080

Bundle declares analysis_mode='public_artifact' but contains a
delivery_verdict record. Validator's enforce_mode_gated_forbidden_types
emits ACEF-080.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=209,
            analysis_mode="public_artifact",
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=[_scope_record(), _finding_record(), bad_delivery],
        readme=readme,
    )


def build_fail_non_public_record_without_redaction_pol(root: Path) -> None:
    bundle = root / "fail" / "non-public-record-without-redaction-pol"
    # A record with confidentiality='redacted' AND no redaction_policy_version.
    bad_rec = base_record(
        record_id=urn("rec", 50),
        record_type="event_log",
        timestamp=FIXED_TIMESTAMP,
        confidentiality="redacted",
        # Deliberately omit redaction_policy_version (and X2 too — the
        # check we want to trigger is ACEF-074 for X1 missing).
        payload={"event_type": "redaction", "applied_at": FIXED_TIMESTAMP},
    )
    readme = """# non-public-record-without-redaction-pol

**Requirement:** Brief §X1 redaction_policy_version required for non-public records
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-074

Bundle has a record with confidentiality='redacted' but no
redaction_policy_version. Validator's enforce_redaction_policy_version
emits ACEF-074.
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=210,
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=[_scope_record(), bad_rec],
        readme=readme,
    )


# ===========================================================================
# FAKE-GREEN BUNDLES (7) — one per state_class
#
# Each bundle declares the state without the precursor evidence the
# state class requires. The validator MUST emit at least one ERROR/FATAL.
# README documents the intentionally-absent precursor.
# ===========================================================================


def _fake_green_bundle(
    *,
    root: Path,
    state_class: str,
    dir_name: str,
    package_idx: int,
    extra_records: list[dict] | None = None,
    intentionally_absent: str = "",
    expected_codes: str = "ACEF-070 / ACEF-076",
) -> None:
    """Common skeleton for fake-green bundles.

    A harness_attestation declaring the target state_class is paired
    with an empty bound_evidence_refs OR a bound_evidence_ref URN that
    does not resolve. Either way, the validator emits ACEF-070 (broken
    binding). The README explains which precursor was intentionally
    omitted to make the state unreachable without it.
    """
    bundle = root / "fake-green" / dir_name

    # harness_attestation declaring the state_class with an UNRESOLVABLE
    # bound_evidence_ref. The URN is well-formed but points to a record
    # not in the bundle and not in any declared external bundle —
    # enforce_harness_evidence_binding emits ACEF-070.
    har = base_record(
        record_id=urn("rec", 31),
        record_type="harness_attestation",
        timestamp=FIXED_LATER_TIMESTAMP,
        payload=harness_attestation_payload(
            attestation_idx=1,
            state_class=state_class,
            bound_evidence_refs=[urn("rec", 9999)],  # not in bundle
            fake_green_test_ref=fake_green_urn_for(state_class),
        ),
    )
    records = [_scope_record(), har]
    if extra_records:
        records = records + extra_records

    readme = f"""# {dir_name}

**Requirement:** Brief §7.1 fake-green vector for state_class={state_class!r}
**Test criterion ID:** VAL-CONFORMANCE-003
**Expected code(s):** {expected_codes}

The bundle declares a harness_attestation with state_class={state_class!r}
but binds it to a URN that does not resolve to any record in this
bundle. The state cannot be reached without the bound evidence — that
is the whole point of the fake-green test (brief §24.5 / Prove-It
Doctrine).

**Intentionally absent precursor:** {intentionally_absent}

Validator MUST emit at least one ERROR/FATAL diagnostic
(typically ACEF-070).
"""
    write_bundle(
        bundle,
        manifest=base_manifest(
            package_idx=package_idx,
            subjects=_common_subjects(),
            actors=_common_actors(),
        ),
        records=records,
        readme=readme,
    )


def build_fake_green_step(root: Path) -> None:
    _fake_green_bundle(
        root=root,
        state_class="step",
        dir_name="cannot-reach-step-without-evidence",
        package_idx=300,
        intentionally_absent=(
            "The event_log record(s) that would normally bind the step "
            "transition to concrete evidence are deliberately omitted "
            "from the bundle."
        ),
    )


def build_fake_green_finding(root: Path) -> None:
    _fake_green_bundle(
        root=root,
        state_class="finding",
        dir_name="cannot-reach-finding-without-evidence",
        package_idx=301,
        intentionally_absent=(
            "The finding_record's reproduction.evidence_commit_ref target "
            "is deliberately not present in the bundle — there is no "
            "evidence the finding actually reproduces."
        ),
    )


def build_fake_green_coverage_cell(root: Path) -> None:
    _fake_green_bundle(
        root=root,
        state_class="coverage_cell",
        dir_name="cannot-reach-coverage-cell-without-evidence",
        package_idx=302,
        intentionally_absent=(
            "No coverage_cell evidence in the sibling assessment bundle, "
            "and no scenario/surface-class probe records that would "
            "populate it."
        ),
    )


def build_fake_green_regression(root: Path) -> None:
    # For regression, the precursor is a risk_treatment regression_definition
    # plus a fix-verification attestation. We omit both — only the attesting
    # harness_attestation is present and bound to a non-existent record.
    _fake_green_bundle(
        root=root,
        state_class="regression",
        dir_name="cannot-reach-active-regression-without-fix-verification",
        package_idx=303,
        intentionally_absent=(
            "No risk_treatment record with treatment_subtype="
            "regression_definition exists, and no fix-verification "
            "evidence is present."
        ),
    )


def build_fake_green_delivery(root: Path) -> None:
    _fake_green_bundle(
        root=root,
        state_class="delivery",
        dir_name="cannot-reach-verified-delivery-without-readback",
        package_idx=304,
        intentionally_absent=("No delivery_verdict record with a read_back block and matching digests is present."),
    )


def build_fake_green_badge(root: Path) -> None:
    _fake_green_bundle(
        root=root,
        state_class="badge",
        dir_name="cannot-reach-green-badge-without-fresh-coverage",
        package_idx=305,
        intentionally_absent=(
            "No coverage_cell (in any sibling assessment bundle) and no evidence_gap freshness_window are present."
        ),
    )


def build_fake_green_attestation(root: Path) -> None:
    # For attestation state class, the precursor is a chain — a prior
    # attestation that justified the transition. Omit any prior attestation.
    _fake_green_bundle(
        root=root,
        state_class="attestation",
        dir_name="cannot-reach-attestation-without-precursor-attestation",
        package_idx=306,
        intentionally_absent=(
            "No precursor harness_attestation record exists in the bundle — the attestation chain has no anchor."
        ),
    )


# ===========================================================================
# Main
# ===========================================================================


def main() -> None:
    root = Path(__file__).resolve().parent
    print(f"Building Freddy conformance bundles under {root}", file=sys.stderr)

    # Pass bundles (9)
    build_pass_subscriber_full_loop(root)
    build_pass_public_artifact_mode(root)
    build_pass_canary_mode(root)
    build_pass_verified_delivery(root)
    build_pass_regression_active_with_fix_verification(root)
    build_pass_badge_green_with_fresh_coverage(root)
    build_pass_badge_provisional_with_reason(root)
    build_pass_accepted_risk_disposition(root)
    build_pass_multi_finding_with_dedupe_collapse(root)

    # Fail bundles (11)
    build_fail_verified_delivery_without_readback(root)
    build_fail_verified_delivery_digest_mismatch(root)
    build_fail_harness_attestation_empty_evidence(root)
    build_fail_harness_attestation_persona_as_verifier(root)
    build_fail_badge_green_with_failed_integrity(root)
    build_fail_cross_tenant_references_in_one_bundle(root)
    build_fail_voice_rubric_with_claim_token(root)
    build_fail_scope_boundary_event_without_stop_attest(root)
    build_fail_external_disposition_overrides_internal(root)
    build_fail_public_artifact_with_delivery_verdict(root)
    build_fail_non_public_record_without_redaction_pol(root)

    # Fake-green bundles (7)
    build_fake_green_step(root)
    build_fake_green_finding(root)
    build_fake_green_coverage_cell(root)
    build_fake_green_regression(root)
    build_fake_green_delivery(root)
    build_fake_green_badge(root)
    build_fake_green_attestation(root)

    print(f"Built {len(FAKE_GREEN_URN_MAP)} fake-green URNs", file=sys.stderr)


if __name__ == "__main__":
    main()
