"""Tests for acef.validation.rule_engine — scope filtering, conditions, evaluation."""

from __future__ import annotations

from acef.models.enums import LifecyclePhase, ObligationRole, RuleOutcome
from acef.models.records import EntityRefs, RecordEnvelope
from acef.templates.models import EvaluationRule, Provision, RuleCondition, RuleScope
from acef.validation.rule_engine import (
    _check_condition,
    _matches_scope,
    evaluate_rules_for_subject,
)


def _make_record(
    record_type: str = "risk_register",
    payload: dict | None = None,
    obligation_role: ObligationRole | None = None,
    lifecycle_phase: LifecyclePhase | None = None,
    subject_refs: list[str] | None = None,
    timestamp: str = "2025-06-01T00:00:00Z",
) -> RecordEnvelope:
    """Helper to create test records."""
    return RecordEnvelope(
        record_type=record_type,
        payload=payload or {"description": "test"},
        obligation_role=obligation_role,
        lifecycle_phase=lifecycle_phase,
        entity_refs=EntityRefs(subject_refs=subject_refs or []),
        timestamp=timestamp,
    )


class TestMatchesScope:
    """Test _matches_scope filtering logic."""

    def test_none_scope_matches_all(self) -> None:
        record = _make_record()
        assert _matches_scope(record, None)

    def test_obligation_role_match(self) -> None:
        record = _make_record(obligation_role=ObligationRole.PROVIDER)
        scope = {"obligation_roles": ["provider"]}
        assert _matches_scope(record, scope)

    def test_obligation_role_mismatch(self) -> None:
        record = _make_record(obligation_role=ObligationRole.DEPLOYER)
        scope = {"obligation_roles": ["provider"]}
        assert not _matches_scope(record, scope)

    def test_obligation_role_none_record_mismatches(self) -> None:
        record = _make_record(obligation_role=None)
        scope = {"obligation_roles": ["provider"]}
        assert not _matches_scope(record, scope)

    def test_lifecycle_phase_match(self) -> None:
        record = _make_record(lifecycle_phase=LifecyclePhase.DEPLOYMENT)
        scope = {"lifecycle_phases": ["deployment"]}
        assert _matches_scope(record, scope)

    def test_lifecycle_phase_mismatch(self) -> None:
        record = _make_record(lifecycle_phase=LifecyclePhase.DESIGN)
        scope = {"lifecycle_phases": ["deployment"]}
        assert not _matches_scope(record, scope)

    def test_lifecycle_phase_none_mismatches(self) -> None:
        record = _make_record(lifecycle_phase=None)
        scope = {"lifecycle_phases": ["deployment"]}
        assert not _matches_scope(record, scope)

    def test_modalities_match(self) -> None:
        record = _make_record()
        scope = {"modalities": ["text", "image"]}
        assert _matches_scope(record, scope, subject_modalities=["text"])

    def test_modalities_mismatch(self) -> None:
        record = _make_record()
        scope = {"modalities": ["image", "video"]}
        assert not _matches_scope(record, scope, subject_modalities=["text"])

    def test_modalities_ignored_when_none_subject(self) -> None:
        record = _make_record()
        scope = {"modalities": ["image"]}
        assert _matches_scope(record, scope, subject_modalities=None)

    def test_empty_scope_dict_matches_all(self) -> None:
        record = _make_record()
        assert _matches_scope(record, {})

    def test_combined_scope_all_match(self) -> None:
        record = _make_record(
            obligation_role=ObligationRole.PROVIDER,
            lifecycle_phase=LifecyclePhase.DEPLOYMENT,
        )
        scope = {
            "obligation_roles": ["provider"],
            "lifecycle_phases": ["deployment"],
            "modalities": ["text"],
        }
        assert _matches_scope(record, scope, subject_modalities=["text"])

    def test_combined_scope_one_mismatch(self) -> None:
        record = _make_record(
            obligation_role=ObligationRole.PROVIDER,
            lifecycle_phase=LifecyclePhase.DESIGN,
        )
        scope = {
            "obligation_roles": ["provider"],
            "lifecycle_phases": ["deployment"],
        }
        assert not _matches_scope(record, scope)


class TestCheckCondition:
    """Test _check_condition evaluation."""

    def test_none_condition_returns_true(self) -> None:
        assert _check_condition(None)

    def test_empty_condition_returns_true(self) -> None:
        assert _check_condition({})

    def test_if_provision_effective_true_when_effective(self) -> None:
        assert _check_condition(
            {"if_provision_effective": True},
            provision_effective=True,
        )

    def test_if_provision_effective_false_when_not_effective(self) -> None:
        assert not _check_condition(
            {"if_provision_effective": True},
            provision_effective=False,
        )

    def test_if_system_type_match(self) -> None:
        assert _check_condition(
            {"if_system_type": ["gpai", "gpai-systemic"]},
            subject_type="gpai",
        )

    def test_if_system_type_mismatch(self) -> None:
        assert not _check_condition(
            {"if_system_type": ["gpai", "gpai-systemic"]},
            subject_type="high-risk",
        )

    def test_if_system_type_empty_subject(self) -> None:
        assert _check_condition(
            {"if_system_type": ["gpai"]},
            subject_type="",
        )


class TestEvaluateRulesForSubject:
    """Test the rule evaluation pipeline."""

    def test_basic_rule_evaluation(self) -> None:
        provisions = [
            Provision(
                provision_id="test-prov",
                provision_name="Test Provision",
                normative_text_ref="Section 1",
                description="Test provision description",
                required_evidence_types=["risk_register"],
                evaluation=[
                    EvaluationRule(
                        rule_id="test-rule-1",
                        rule="has_record_type",
                        params={"type": "risk_register", "min_count": 1},
                        severity="fail",
                        message="Need risk_register",
                    ),
                ],
            ),
        ]
        records = [_make_record()]
        results = evaluate_rules_for_subject(
            provisions,
            records,
            profile_id="test-profile",
        )
        assert len(results) == 1
        assert results[0].outcome == RuleOutcome.PASSED

    def test_rule_skipped_when_condition_not_met(self) -> None:
        provisions = [
            Provision(
                provision_id="test-prov",
                provision_name="Test",
                normative_text_ref="Sec 1",
                description="Test desc",
                required_evidence_types=["risk_register"],
                evaluation=[
                    EvaluationRule(
                        rule_id="cond-rule",
                        rule="has_record_type",
                        params={"type": "risk_register", "min_count": 1},
                        severity="fail",
                        message="Need records",
                        condition=RuleCondition(if_system_type=["gpai"]),
                    ),
                ],
            ),
        ]
        records = [_make_record()]
        results = evaluate_rules_for_subject(
            provisions,
            records,
            profile_id="test-profile",
            subject_risk_classification="high-risk",
        )
        assert len(results) == 1
        assert results[0].outcome == RuleOutcome.SKIPPED

    def test_provision_skipped_when_not_applicable_to_subject(self) -> None:
        provisions = [
            Provision(
                provision_id="gpai-only",
                provision_name="GPAI Only",
                normative_text_ref="Sec 53",
                description="Only for GPAI",
                required_evidence_types=["risk_register"],
                applicable_to=["gpai", "gpai-systemic"],
                evaluation=[
                    EvaluationRule(
                        rule_id="gpai-rule",
                        rule="has_record_type",
                        params={"type": "risk_register", "min_count": 1},
                        severity="fail",
                        message="Need risk_register",
                    ),
                ],
            ),
        ]
        records = [_make_record()]
        results = evaluate_rules_for_subject(
            provisions,
            records,
            profile_id="test-profile",
            subject_risk_classification="high-risk",
        )
        assert len(results) == 0

    def test_unknown_operator_produces_error(self) -> None:
        provisions = [
            Provision(
                provision_id="test-prov",
                provision_name="Test",
                normative_text_ref="Sec 1",
                description="Test desc",
                required_evidence_types=[],
                evaluation=[
                    EvaluationRule(
                        rule_id="bad-rule",
                        rule="nonexistent_operator",
                        params={},
                        severity="fail",
                        message="Bad operator",
                    ),
                ],
            ),
        ]
        records = [_make_record()]
        results = evaluate_rules_for_subject(
            provisions,
            records,
            profile_id="test-profile",
        )
        assert len(results) == 1
        assert results[0].outcome == RuleOutcome.ERROR
        assert "Unknown operator" in (results[0].message or "")

    def test_subject_scoped_filtering(self) -> None:
        subject_id = "urn:acef:sub:00000000-0000-0000-0000-000000000001"
        other_id = "urn:acef:sub:00000000-0000-0000-0000-000000000002"
        provisions = [
            Provision(
                provision_id="test-prov",
                provision_name="Test",
                normative_text_ref="Sec 1",
                description="Test desc",
                required_evidence_types=["risk_register"],
                evaluation=[
                    EvaluationRule(
                        rule_id="sub-rule",
                        rule="has_record_type",
                        params={"type": "risk_register", "min_count": 1},
                        severity="fail",
                        message="Need risk_register for subject",
                    ),
                ],
            ),
        ]
        # Record linked to a different subject
        records = [_make_record(subject_refs=[other_id])]
        results = evaluate_rules_for_subject(
            provisions,
            records,
            profile_id="test-profile",
            subject_id=subject_id,
        )
        assert len(results) == 1
        assert results[0].outcome == RuleOutcome.FAILED

    def test_auto_generated_rules_from_required_evidence_types(self) -> None:
        provisions = [
            Provision(
                provision_id="auto-prov",
                provision_name="Auto Provision",
                normative_text_ref="Sec 1",
                description="Test auto-generated rules",
                required_evidence_types=["dataset_card", "data_provenance"],
                evaluation=[],  # No explicit rules
            ),
        ]
        records = [
            _make_record(record_type="dataset_card"),
            _make_record(record_type="data_provenance"),
        ]
        results = evaluate_rules_for_subject(
            provisions,
            records,
            profile_id="test-profile",
        )
        assert len(results) == 2
        assert all(r.outcome == RuleOutcome.PASSED for r in results)

    def test_evidence_freshness_receives_evaluation_instant(self) -> None:
        provisions = [
            Provision(
                provision_id="fresh-prov",
                provision_name="Freshness Check",
                normative_text_ref="Sec 1",
                description="Test freshness",
                required_evidence_types=["risk_register"],
                evaluation=[
                    EvaluationRule(
                        rule_id="fresh-rule",
                        rule="evidence_freshness",
                        params={"max_days": 365, "reference_date": "validation_time"},
                        severity="warning",
                        message="Evidence is stale",
                    ),
                ],
            ),
        ]
        records = [_make_record(timestamp="2025-06-01T00:00:00Z")]
        results = evaluate_rules_for_subject(
            provisions,
            records,
            profile_id="test-profile",
            evaluation_instant="2025-06-15T00:00:00Z",
        )
        # F2: the required_evidence_types existence rule is ALWAYS expanded (spec §3.5
        # line 1221), so the provision yields TWO results — the risk_register existence
        # rule AND the evidence_freshness rule — both PASSED (a risk_register IS present).
        assert len(results) == 2
        assert all(r.outcome == RuleOutcome.PASSED for r in results)
        assert any(r.rule_id == "fresh-prov-risk_register-exists" for r in results)

    def test_required_evidence_types_existence_enforced_even_with_evaluation_rules(self) -> None:
        """F2 (CRITICAL): required_evidence_types/minimum_evidence_count are syntactic
        sugar ALWAYS expanded into has_record_type existence rules before evaluation (spec
        §3.5 line 1221) — NOT only when the provision has no evaluation rules. Previously
        the existence requirement was silently DROPPED whenever any evaluation rule was
        present, so a provision whose evaluation rules are universal operators (which PASS
        vacuously on zero matching records) rolled up to SATISFIED with ZERO evidence —
        a regulator-facing false-PASS (the shipped China-CAC cac-watermark provision)."""
        provisions = [
            Provision(
                provision_id="watermark",
                provision_name="Marking",
                normative_text_ref="CAC Art. X",
                description="Synthetic-content marking must be present.",
                required_evidence_types=["transparency_marking"],
                evaluation=[
                    EvaluationRule(
                        rule_id="marking-method-present",
                        rule="field_present",
                        params={"field": "/marking_method"},
                        severity="fail",
                        message="marking_method required",
                    ),
                ],
            ),
        ]
        results = evaluate_rules_for_subject(provisions, [], profile_id="china-cac")
        existence = [r for r in results if r.rule_id == "watermark-transparency_marking-exists"]
        assert existence, "required_evidence_types MUST expand into a has_record_type existence rule"
        assert existence[0].outcome == RuleOutcome.FAILED, (
            "zero transparency_marking records MUST FAIL the existence requirement (no false-PASS)"
        )

    def test_explicit_has_record_type_dedups_the_auto_existence_rule(self) -> None:
        """Spec §3.5 line 1221 precedence: if the provision already declares an explicit
        has_record_type rule for type T, that rule wins and the auto-generated existence
        rule for T is SKIPPED (a min_count disagreement resolves to the evaluation rule)."""
        provisions = [
            Provision(
                provision_id="p",
                provision_name="P",
                normative_text_ref="x",
                description="x",
                required_evidence_types=["risk_register"],
                minimum_evidence_count={"risk_register": 5},  # disagrees with the explicit rule
                evaluation=[
                    EvaluationRule(
                        rule_id="explicit-rr",
                        rule="has_record_type",
                        params={"type": "risk_register", "min_count": 1},
                        severity="fail",
                        message="at least 1 risk_register",
                    ),
                ],
            ),
        ]
        results = evaluate_rules_for_subject(provisions, [_make_record()], profile_id="t")
        rr_existence = [r for r in results if r.rule_id == "p-risk_register-exists"]
        assert not rr_existence, "the auto existence rule for risk_register must be deduped by the explicit one"
        # The explicit rule (min_count 1) PASSES on the single record (the min_count:5
        # sugar did NOT override it).
        explicit = [r for r in results if r.rule_id == "explicit-rr"]
        assert explicit and explicit[0].outcome == RuleOutcome.PASSED

    def test_scope_risk_classification_filtering(self) -> None:
        provisions = [
            Provision(
                provision_id="scoped-prov",
                provision_name="Scoped",
                normative_text_ref="Sec 1",
                description="Test scope filtering",
                required_evidence_types=["risk_register"],
                evaluation=[
                    EvaluationRule(
                        rule_id="scoped-rule",
                        rule="has_record_type",
                        params={"type": "risk_register", "min_count": 1},
                        severity="fail",
                        message="Need records",
                        scope=RuleScope(risk_classifications=["gpai"]),
                    ),
                ],
            ),
        ]
        records = [_make_record()]
        results = evaluate_rules_for_subject(
            provisions,
            records,
            profile_id="test-profile",
            subject_risk_classification="high-risk",
        )
        assert len(results) == 1
        assert results[0].outcome == RuleOutcome.SKIPPED


class TestUnknownOperatorAttachesACEF046:
    """PhD-review finding 37: an unknown rule operator returned RuleOutcome.ERROR
    with free-text but NO error_code, so a consumer could not machine-detect it.
    The unknown-operator error now carries ACEF-046 (unified with the unknown
    comparison-`op` case), routing to NOT_ASSESSED via the §3.7 P3 error step."""

    def test_unknown_rule_operator_error_carries_acef_046(self) -> None:
        provisions = [
            Provision(
                provision_id="test-prov",
                provision_name="Test",
                normative_text_ref="Sec 1",
                description="d",
                required_evidence_types=[],
                evaluation=[
                    EvaluationRule(
                        rule_id="bad-op-rule",
                        rule="frobnicate",  # not in OPERATOR_REGISTRY
                        params={},
                        severity="fail",
                        message="unknown operator",
                    ),
                ],
            ),
        ]
        results = evaluate_rules_for_subject(provisions, [_make_record()], profile_id="test-profile")
        assert len(results) == 1
        assert results[0].outcome == RuleOutcome.ERROR
        assert results[0].error_code == "ACEF-046", (
            f"unknown-operator error must carry ACEF-046, got {results[0].error_code!r}"
        )
