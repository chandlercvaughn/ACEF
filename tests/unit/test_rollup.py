"""Tests for acef.validation.rollup — 7-step provision outcome precedence algorithm."""

from __future__ import annotations

from acef.models.assessment import RuleResult
from acef.models.enums import ProvisionOutcome, RuleOutcome, RuleSeverity
from acef.models.records import RecordEnvelope
from acef.validation.rollup import compute_provision_outcome


def _rule_result(
    outcome: RuleOutcome,
    severity: RuleSeverity = RuleSeverity.FAIL,
    provision_id: str = "prov-1",
    rule_id: str = "rule-1",
    evidence_refs: list[str] | None = None,
) -> RuleResult:
    """Helper to create rule results."""
    return RuleResult(
        rule_id=rule_id,
        provision_id=provision_id,
        profile_id="test-profile",
        rule_severity=severity,
        outcome=outcome,
        evidence_refs=evidence_refs or [],
    )


class TestProvisionRollup:
    """Test all 7 cases of the provision outcome precedence algorithm."""

    def test_step1_fail_severity_failed_gives_not_satisfied(self):
        """Step 1: Any fail-severity rule failed -> NOT_SATISFIED."""
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.FAILED, RuleSeverity.FAIL, rule_id="r2"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_SATISFIED
        assert summary.fail_count == 1

    def test_step2_rule_errored_gives_not_assessed(self):
        """Step 2: Any rule errored -> NOT_ASSESSED."""
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.ERROR, RuleSeverity.FAIL, rule_id="r2"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_ASSESSED

    def test_step3_all_skipped_gives_skipped(self):
        """Step 3: All rules skipped -> SKIPPED."""
        results = [
            _rule_result(RuleOutcome.SKIPPED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.SKIPPED, RuleSeverity.WARNING, rule_id="r2"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SKIPPED
        assert summary.skipped_count == 2

    def test_step4_evidence_gap_no_fails_gives_gap_acknowledged(self):
        """Step 4: Evidence gap exists + no fail-severity failures -> GAP_ACKNOWLEDGED."""
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
        ]
        # Create an evidence_gap record for this provision
        gap_record = RecordEnvelope(
            record_type="evidence_gap",
            provisions_addressed=["prov-1"],
            payload={"reason": "Data not yet available"},
        )
        summary = compute_provision_outcome("prov-1", "test-profile", results, [gap_record])
        assert summary.provision_outcome == ProvisionOutcome.GAP_ACKNOWLEDGED

    def test_step5_warning_failed_gives_partially_satisfied(self):
        """Step 5: All fails passed, some warnings failed -> PARTIALLY_SATISFIED."""
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.FAILED, RuleSeverity.WARNING, rule_id="r2"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.PARTIALLY_SATISFIED
        assert summary.warning_count == 1

    def test_step6_all_passed_gives_satisfied(self):
        """Step 6: All rules passed -> SATISFIED."""
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.PASSED, RuleSeverity.WARNING, rule_id="r2"),
            _rule_result(RuleOutcome.PASSED, RuleSeverity.INFO, rule_id="r3"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SATISFIED

    def test_spec_rollup_algorithm_guards_the_rule_less_case(self):
        """roborev on 4092a07 (re-pinned to the finding-18 rewrite): the no-rules
        case must be guarded so the 'ALL rules …' universals never match vacuously.
        Post-rewrite the guard is step 1 ('No-rules guard') and the algorithm is a
        single ordered first-match list; the impl checks total==0 FIRST."""
        from pathlib import Path

        spec = (Path(__file__).resolve().parents[2] / "planning" / "ACEF-Spec-Outline-v0.1.md").read_text(
            encoding="utf-8"
        )
        idx = spec.find("No-rules guard")
        assert idx != -1, "spec must state the no-rules guard as the first ordered step"
        algo = spec[idx : idx + 1600]
        # The universals must still require ≥1 rule so they cannot shadow the guard.
        assert "≥1 rule" in algo, "spec must require ≥1 rule for the 'ALL rules …' universal steps"
        # The impl agrees: a rule-less provision is NOT_ASSESSED.
        summary = compute_provision_outcome("p", "prof", [], [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_ASSESSED

    def test_step6_passed_plus_skipped_mix_gives_satisfied(self):
        """F40: a PASSED + SKIPPED mix (no fails/errors/warnings/gaps) is
        SATISFIED — skipped rules (condition false: out-of-scope / not-yet-
        effective) are non-applicable and do NOT block satisfaction. The literal
        "ALL rules passed" is a special case; a passed+skipped mix must NOT fall
        through to NOT_ASSESSED (reserved for an ERRORED or rule-less provision).
        Two conformant validators must agree here — pins spec §3.7 step 6 ↔ impl."""
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.SKIPPED, RuleSeverity.FAIL, rule_id="r2"),
            _rule_result(RuleOutcome.PASSED, RuleSeverity.WARNING, rule_id="r3"),
            _rule_result(RuleOutcome.SKIPPED, RuleSeverity.WARNING, rule_id="r4"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SATISFIED

    def test_step7_no_rules_gives_not_assessed(self):
        """Step 7: No rules for provision -> NOT_ASSESSED."""
        summary = compute_provision_outcome("prov-1", "test-profile", [], [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_ASSESSED

    def test_evidence_refs_collected(self):
        """Evidence refs from all rules are collected and deduplicated."""
        results = [
            _rule_result(
                RuleOutcome.PASSED,
                RuleSeverity.FAIL,
                rule_id="r1",
                evidence_refs=["rec-1", "rec-2"],
            ),
            _rule_result(
                RuleOutcome.PASSED,
                RuleSeverity.FAIL,
                rule_id="r2",
                evidence_refs=["rec-2", "rec-3"],
            ),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.evidence_refs == ["rec-1", "rec-2", "rec-3"]

    def test_subject_scope_passed_through(self):
        """Subject scope is passed through to the summary."""
        results = [_rule_result(RuleOutcome.PASSED)]
        summary = compute_provision_outcome(
            "prov-1",
            "test-profile",
            results,
            [],
            subject_scope=["urn:acef:sub:00000000-0000-0000-0000-000000000001"],
        )
        assert summary.subject_scope == ["urn:acef:sub:00000000-0000-0000-0000-000000000001"]

    def test_fail_severity_takes_precedence_over_error(self):
        """Step 1 takes precedence over Step 2."""
        results = [
            _rule_result(RuleOutcome.FAILED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.ERROR, RuleSeverity.FAIL, rule_id="r2"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_SATISFIED

    def test_info_failed_does_not_block_satisfied(self):
        """F7: a FAILED info-severity rule must NOT demote a provision to NOT_ASSESSED.

        info severity is INFORMATIONAL (spec §3.5 line 1167; the taxonomy defines info as
        "informational observations"), so an info rule is non-gating. The spec's
        provision-outcome PRECEDENCE LIST (§3.7 / conformance checklist line 1704:
        "not-satisfied > error > skipped > gap-acknowledged > partially-satisfied >
        satisfied") shows NOT_ASSESSED is reserved for step 2 (error) and step 7 (no rules)
        ONLY — it is NOT a valid outcome for a provision whose rules were evaluated with no
        error. The earlier literal reading of step 6 (assessment-rollup-1) mis-resolved this
        gap by falling info-failed through to NOT_ASSESSED, which falsely reports a
        FULLY-ASSESSED provision as un-assessable. With all fail- and warning-severity rules
        PASSED, the provision is SATISFIED; the info failure is recorded per-rule but does
        not gate the rollup.
        """
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.FAILED, RuleSeverity.INFO, rule_id="r2"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SATISFIED
        # The info-failed rule is neither a fail nor a warning tally.
        assert summary.fail_count == 0
        assert summary.warning_count == 0

    def test_info_failed_mixed_with_passed_and_skipped_is_satisfied(self):
        """A passed + skipped + info-failed mix is SATISFIED (F7).

        Skipped rules are not-applicable; the only "failed" rule is an info (non-gating)
        rule. All fail/warning requirements passed, so the provision is SATISFIED — not the
        spec-disallowed NOT_ASSESSED.
        """
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.SKIPPED, RuleSeverity.FAIL, rule_id="r2"),
            _rule_result(RuleOutcome.FAILED, RuleSeverity.INFO, rule_id="r3"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SATISFIED

    def test_info_passed_still_satisfied(self):
        """An info rule that PASSED does not block SATISFIED — only a FAILED info
        rule does. Guards the fix against over-correcting (info-passed is benign).
        """
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.PASSED, RuleSeverity.INFO, rule_id="r2"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SATISFIED

    def test_error_takes_precedence_over_evidence_gap(self):
        """Step 2 (error -> NOT_ASSESSED) takes precedence over step 4
        (evidence_gap -> GAP_ACKNOWLEDGED).

        A provision with BOTH an errored rule AND an evidence_gap record for the
        same provision must roll up to NOT_ASSESSED, never GAP_ACKNOWLEDGED — the
        spec precedence order lists error (step 2) before gap (step 4). This pins
        the step-2-over-step-4 boundary that was previously untested
        (assessment-rollup-3).
        """
        results = [
            _rule_result(RuleOutcome.ERROR, RuleSeverity.FAIL, rule_id="r1"),
        ]
        gap_record = RecordEnvelope(
            record_type="evidence_gap",
            provisions_addressed=["prov-1"],
            payload={"reason": "Data not yet available"},
        )
        summary = compute_provision_outcome("prov-1", "test-profile", results, [gap_record])
        assert summary.provision_outcome == ProvisionOutcome.NOT_ASSESSED
