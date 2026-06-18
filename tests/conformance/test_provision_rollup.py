"""Conformance test: provision rollup — 7-step deterministic precedence algorithm.

Tests all 7 cases in the provision outcome algorithm:
1. Any fail-severity rule failed -> NOT_SATISFIED
2. Any rule errored -> NOT_ASSESSED
3. All rules skipped -> SKIPPED
4. Evidence gap exists, no fails failed -> GAP_ACKNOWLEDGED
5. All fails passed, some warnings failed -> PARTIALLY_SATISFIED
6. All rules passed -> SATISFIED
7. No rules for provision -> NOT_ASSESSED
"""

from __future__ import annotations

from pathlib import Path

from acef.models.assessment import RuleResult
from acef.models.enums import ProvisionOutcome, RuleOutcome, RuleSeverity
from acef.models.records import RecordEnvelope
from acef.validation.rollup import compute_provision_outcome


def _make_rule_result(
    provision_id: str = "test-provision",
    profile_id: str = "test-profile",
    outcome: RuleOutcome = RuleOutcome.PASSED,
    severity: RuleSeverity = RuleSeverity.FAIL,
    rule_id: str = "rule-1",
    evidence_refs: list[str] | None = None,
) -> RuleResult:
    """Create a RuleResult for testing."""
    return RuleResult(
        rule_id=rule_id,
        provision_id=provision_id,
        profile_id=profile_id,
        rule_severity=severity,
        outcome=outcome,
        evidence_refs=evidence_refs or [],
    )


class TestProvisionRollup:
    """7-step deterministic precedence algorithm conformance."""

    def test_step1_fail_severity_failed_produces_not_satisfied(self) -> None:
        """Step 1: Any fail-severity rule failed -> NOT_SATISFIED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.FAIL, rule_id="r1"),
            _make_rule_result(outcome=RuleOutcome.FAILED, severity=RuleSeverity.FAIL, rule_id="r2"),
        ]
        summary = compute_provision_outcome("test-provision", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_SATISFIED
        assert summary.fail_count == 1

    def test_step2_rule_error_produces_not_assessed(self) -> None:
        """Step 2: Any rule errored (and no fail-severity failures) -> NOT_ASSESSED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.FAIL, rule_id="r1"),
            _make_rule_result(outcome=RuleOutcome.ERROR, severity=RuleSeverity.FAIL, rule_id="r2"),
        ]
        summary = compute_provision_outcome("test-provision", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_ASSESSED

    def test_step3_all_skipped_produces_skipped(self) -> None:
        """Step 3: All rules skipped -> SKIPPED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.SKIPPED, severity=RuleSeverity.FAIL, rule_id="r1"),
            _make_rule_result(outcome=RuleOutcome.SKIPPED, severity=RuleSeverity.WARNING, rule_id="r2"),
        ]
        summary = compute_provision_outcome("test-provision", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SKIPPED
        assert summary.skipped_count == 2

    def test_step4_evidence_gap_produces_gap_acknowledged(self) -> None:
        """Step 4: Evidence gap exists, no fail-severity failures -> GAP_ACKNOWLEDGED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.FAIL, rule_id="r1"),
        ]
        # Create an evidence_gap record for this provision
        gap_record = RecordEnvelope(
            record_type="evidence_gap",
            provisions_addressed=["test-provision"],
            payload={"gap_type": "missing_evidence", "description": "test gap"},
        )
        summary = compute_provision_outcome("test-provision", "test-profile", results, [gap_record])
        assert summary.provision_outcome == ProvisionOutcome.GAP_ACKNOWLEDGED

    def test_step5_warnings_failed_produces_partially_satisfied(self) -> None:
        """Step 5: All fail-severity rules passed, some warnings failed -> PARTIALLY_SATISFIED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.FAIL, rule_id="r1"),
            _make_rule_result(outcome=RuleOutcome.FAILED, severity=RuleSeverity.WARNING, rule_id="r2"),
        ]
        summary = compute_provision_outcome("test-provision", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.PARTIALLY_SATISFIED
        assert summary.warning_count == 1

    def test_step6_all_passed_produces_satisfied(self) -> None:
        """Step 6: All rules passed -> SATISFIED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.FAIL, rule_id="r1"),
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.WARNING, rule_id="r2"),
        ]
        summary = compute_provision_outcome("test-provision", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SATISFIED

    def test_step7_no_rules_produces_not_assessed(self) -> None:
        """Step 7: No rules for provision -> NOT_ASSESSED."""
        summary = compute_provision_outcome("test-provision", "test-profile", [], [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_ASSESSED

    def test_multi_subject_separate_provision_summaries(self, tmp_dir: Path) -> None:
        """Multi-subject evaluation produces separate provision_summary per subject."""
        from acef.package import Package as Pkg
        from acef.validation.engine import validate_bundle

        # Build a package with two subjects
        pkg = Pkg(producer={"name": "multi-subj", "version": "1.0.0"})
        sys1 = pkg.add_subject(
            "ai_system",
            name="System Alpha",
            risk_classification="high-risk",
            modalities=["text"],
        )
        sys2 = pkg.add_subject(
            "ai_system",
            name="System Beta",
            risk_classification="high-risk",
            modalities=["text"],
        )
        pkg.add_profile("eu-ai-act-2024", provisions=["article-9"])

        # Add records only for sys1
        pkg.record(
            "risk_register",
            provisions=["article-9"],
            payload={"description": "Risk for Alpha", "likelihood": "high", "severity": "high"},
            obligation_role="provider",
            entity_refs={"subject_refs": [sys1.id]},
        )
        pkg.record(
            "risk_treatment",
            provisions=["article-9"],
            payload={"treatment_type": "mitigate", "description": "Treatment Alpha"},
            obligation_role="provider",
            entity_refs={"subject_refs": [sys1.id]},
        )

        bundle_dir = tmp_dir / "multi_subject"
        pkg.export(str(bundle_dir))

        assessment = validate_bundle(
            bundle_dir,
            profiles=["eu-ai-act-2024"],
            evaluation_instant="2027-01-01T00:00:00Z",
        )

        # Should have provision summaries for both subjects
        art9_summaries = [s for s in assessment.provision_summary if s.provision_id == "article-9"]
        subjects_in_summaries = set()
        for s in art9_summaries:
            for subj in s.subject_scope:
                subjects_in_summaries.add(subj)

        assert sys1.id in subjects_in_summaries, "Subject Alpha should have a provision summary"
        assert sys2.id in subjects_in_summaries, "Subject Beta should have a provision summary"

    def test_step6_mix_passed_and_skipped_produces_satisfied(self) -> None:
        """Passed + skipped (no failures/errors) produces SATISFIED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.FAIL, rule_id="r1"),
            _make_rule_result(outcome=RuleOutcome.SKIPPED, severity=RuleSeverity.FAIL, rule_id="r2"),
        ]
        summary = compute_provision_outcome("test-provision", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SATISFIED


class TestNotYetEffectivePerSubjectScope:
    """assessment-rollup-2: a not-yet-effective PER-SUBJECT provision in a
    multi-subject bundle must emit one SKIPPED summary PER SUBJECT, each with the
    correct subject_scope — not a single package-scoped SKIPPED summary with
    empty subject_scope.

    Spec §3.7 (normative): "provision_summary[] entries MUST include
    subject_scope identifying which subject(s) the summary covers." A future
    effective_date does not exempt a per-subject provision from per-subject
    attribution.
    """

    def test_not_yet_effective_per_subject_emits_per_subject_summaries(self, tmp_dir: Path) -> None:
        """A future-effective per-subject provision yields one SKIPPED summary
        per subject, each scoped to exactly that subject."""
        from acef.package import Package as Pkg
        from acef.templates.models import EvaluationRule, Provision, Template
        from acef.templates.registry import load_template
        from acef.validation.engine import validate_bundle

        tid = "conformance-not-yet-effective-per-subject"

        template = Template(
            template_id=tid,
            template_name="Conformance Not-Yet-Effective Per-Subject Test",
            version="1.0.0",
            provisions=[
                Provision(
                    provision_id="future-prov-01",
                    provision_name="Future Per-Subject Provision",
                    # default (per-subject) evaluation_scope
                    effective_date="2099-01-01",
                    evaluation=[
                        EvaluationRule(
                            rule_id="future-prov-01-check",
                            rule="has_record_type",
                            params={"type": "risk_register", "min_count": 1},
                            severity="fail",
                            message="Need a risk register",
                        ),
                    ],
                ),
            ],
        )

        template_path = Path(__file__).parent.parent.parent / "src" / "acef" / "templates" / f"{tid}.json"
        template_path.write_text(template.model_dump_json(indent=2), encoding="utf-8")

        try:
            load_template.cache_clear()

            pkg = Pkg(producer={"name": "future-per-subject", "version": "1.0.0"})
            sys1 = pkg.add_subject(
                "ai_system",
                name="System Alpha",
                risk_classification="high-risk",
                modalities=["text"],
            )
            sys2 = pkg.add_subject(
                "ai_system",
                name="System Beta",
                risk_classification="high-risk",
                modalities=["text"],
            )
            pkg.add_profile(tid, provisions=["future-prov-01"])
            # A record so the bundle is non-empty; the provision is not yet in force.
            pkg.record(
                "risk_register",
                provisions=["future-prov-01"],
                payload={"description": "Risk Alpha", "likelihood": "low", "severity": "low"},
                obligation_role="provider",
                entity_refs={"subject_refs": [sys1.id]},
            )

            bundle_dir = tmp_dir / "not_yet_effective_per_subject"
            pkg.export(str(bundle_dir))

            # Evaluate BEFORE the future effective_date.
            assessment = validate_bundle(
                bundle_dir,
                profiles=[tid],
                evaluation_instant="2026-01-01T00:00:00Z",
            )

            future_summaries = [s for s in assessment.provision_summary if s.provision_id == "future-prov-01"]

            # One SKIPPED summary per subject — not a single empty-scope summary.
            assert len(future_summaries) == 2, (
                f"Not-yet-effective per-subject provision must produce one summary per subject, "
                f"got {len(future_summaries)}"
            )
            for s in future_summaries:
                assert s.provision_outcome == ProvisionOutcome.SKIPPED, f"Expected SKIPPED, got {s.provision_outcome}"
                assert len(s.subject_scope) == 1, (
                    f"Each per-subject not-yet-effective summary must carry exactly one subject, "
                    f"got subject_scope={s.subject_scope}"
                )

            scoped_subjects = {s.subject_scope[0] for s in future_summaries}
            assert scoped_subjects == {sys1.id, sys2.id}, (
                f"Per-subject not-yet-effective summaries must cover BOTH subjects with correct "
                f"subject_scope; got {scoped_subjects}, expected {{{sys1.id}, {sys2.id}}}"
            )
        finally:
            if template_path.exists():
                template_path.unlink()
            load_template.cache_clear()

    def test_not_yet_effective_package_scoped_emits_single_summary(self, tmp_dir: Path) -> None:
        """A future-effective PACKAGE-scoped provision still yields exactly ONE
        summary with empty subject_scope (the package-scope branch is unchanged)."""
        from acef.package import Package as Pkg
        from acef.templates.models import EvaluationRule, Provision, Template
        from acef.templates.registry import load_template
        from acef.validation.engine import validate_bundle

        tid = "conformance-not-yet-effective-package"

        template = Template(
            template_id=tid,
            template_name="Conformance Not-Yet-Effective Package Test",
            version="1.0.0",
            provisions=[
                Provision(
                    provision_id="future-pkg-01",
                    provision_name="Future Package Provision",
                    evaluation_scope="package",
                    effective_date="2099-01-01",
                    evaluation=[
                        EvaluationRule(
                            rule_id="future-pkg-01-check",
                            rule="has_record_type",
                            params={"type": "governance_policy", "min_count": 1},
                            severity="fail",
                            message="Need a governance policy",
                        ),
                    ],
                ),
            ],
        )

        template_path = Path(__file__).parent.parent.parent / "src" / "acef" / "templates" / f"{tid}.json"
        template_path.write_text(template.model_dump_json(indent=2), encoding="utf-8")

        try:
            load_template.cache_clear()

            pkg = Pkg(producer={"name": "future-package", "version": "1.0.0"})
            pkg.add_subject(
                "ai_system",
                name="System A",
                risk_classification="high-risk",
                modalities=["text"],
            )
            pkg.add_subject(
                "ai_system",
                name="System B",
                risk_classification="high-risk",
                modalities=["text"],
            )
            pkg.add_profile(tid, provisions=["future-pkg-01"])
            pkg.record(
                "governance_policy",
                provisions=["future-pkg-01"],
                payload={"policy_type": "quality_management", "description": "QMS"},
                obligation_role="provider",
            )

            bundle_dir = tmp_dir / "not_yet_effective_package"
            pkg.export(str(bundle_dir))

            assessment = validate_bundle(
                bundle_dir,
                profiles=[tid],
                evaluation_instant="2026-01-01T00:00:00Z",
            )

            future_summaries = [s for s in assessment.provision_summary if s.provision_id == "future-pkg-01"]
            assert len(future_summaries) == 1, (
                f"Not-yet-effective package-scoped provision must produce exactly 1 summary, "
                f"got {len(future_summaries)}"
            )
            assert future_summaries[0].provision_outcome == ProvisionOutcome.SKIPPED
            assert future_summaries[0].subject_scope == [], (
                f"Package-scoped not-yet-effective summary must have empty subject_scope, "
                f"got {future_summaries[0].subject_scope}"
            )
        finally:
            if template_path.exists():
                template_path.unlink()
            load_template.cache_clear()


class TestPackageScopedEvaluation:
    """Verifier M3: Package-scoped evaluation conformance test.

    evaluation_scope: "package" should produce a single provision_summary
    for the entire package, not per-subject.
    """

    def test_package_scoped_evaluation_produces_single_summary(self, tmp_dir: Path) -> None:
        """A package-scoped provision produces exactly one provision_summary (no per-subject split)."""
        from acef.package import Package as Pkg
        from acef.templates.models import EvaluationRule, Provision, Template
        from acef.templates.registry import load_template
        from acef.validation.engine import validate_bundle

        # Use a unique template ID to avoid cache collisions with other tests
        tid = "conformance-pkg-scope-single"

        template = Template(
            template_id=tid,
            template_name="Conformance Package Scope Test",
            version="1.0.0",
            provisions=[
                Provision(
                    provision_id="pkg-gov-01",
                    provision_name="Governance Policy Required",
                    evaluation_scope="package",
                    evaluation=[
                        EvaluationRule(
                            rule_id="pkg-gov-01-check",
                            rule="has_record_type",
                            params={"type": "governance_policy", "min_count": 1},
                            severity="fail",
                            message="At least one governance_policy record required",
                        ),
                    ],
                ),
            ],
        )

        template_path = Path(__file__).parent.parent.parent / "src" / "acef" / "templates" / f"{tid}.json"
        template_path.write_text(template.model_dump_json(indent=2), encoding="utf-8")

        try:
            load_template.cache_clear()

            pkg = Pkg(producer={"name": "pkg-scope-test", "version": "1.0.0"})
            pkg.add_subject(
                "ai_system",
                name="System A",
                risk_classification="high-risk",
                modalities=["text"],
            )
            pkg.add_subject(
                "ai_system",
                name="System B",
                risk_classification="high-risk",
                modalities=["text"],
            )
            pkg.add_profile(tid, provisions=["pkg-gov-01"])

            pkg.record(
                "governance_policy",
                provisions=["pkg-gov-01"],
                payload={
                    "policy_type": "quality_management",
                    "description": "Organization-level QMS policy",
                },
                obligation_role="provider",
            )

            bundle_dir = tmp_dir / "pkg_scope_conformance"
            pkg.export(str(bundle_dir))

            assessment = validate_bundle(
                bundle_dir,
                profiles=[tid],
                evaluation_instant="2026-01-15T00:00:00Z",
            )

            # Should produce exactly 1 provision_summary for pkg-gov-01
            pkg_gov_summaries = [s for s in assessment.provision_summary if s.provision_id == "pkg-gov-01"]
            assert len(pkg_gov_summaries) == 1, (
                f"Package-scoped provision should produce exactly 1 summary, got {len(pkg_gov_summaries)}"
            )

            summary = pkg_gov_summaries[0]
            assert len(summary.subject_scope) == 0, "Package-scoped summary should not have subject_scope"

            assert summary.provision_outcome == ProvisionOutcome.SATISFIED, (
                f"Expected SATISFIED, got {summary.provision_outcome}"
            )
        finally:
            if template_path.exists():
                template_path.unlink()
            load_template.cache_clear()

    def test_package_scoped_not_per_subject(self, tmp_dir: Path) -> None:
        """Package-scoped provisions do NOT create per-subject summaries."""
        from acef.package import Package as Pkg
        from acef.templates.models import EvaluationRule, Provision, Template
        from acef.templates.registry import load_template
        from acef.validation.engine import validate_bundle

        tid = "conformance-pkg-scope-dual"

        template = Template(
            template_id=tid,
            template_name="Conformance Package Scope Dual Test",
            version="1.0.0",
            provisions=[
                Provision(
                    provision_id="pkg-check-02",
                    evaluation_scope="package",
                    evaluation=[
                        EvaluationRule(
                            rule_id="pkg-check-02-rule",
                            rule="has_record_type",
                            params={"type": "governance_policy", "min_count": 1},
                            severity="fail",
                            message="Need governance policy",
                        ),
                    ],
                ),
                Provision(
                    provision_id="subj-check-02",
                    evaluation=[
                        EvaluationRule(
                            rule_id="subj-check-02-rule",
                            rule="has_record_type",
                            params={"type": "risk_register", "min_count": 1},
                            severity="fail",
                            message="Need risk register",
                        ),
                    ],
                ),
            ],
        )

        template_path = Path(__file__).parent.parent.parent / "src" / "acef" / "templates" / f"{tid}.json"
        template_path.write_text(template.model_dump_json(indent=2), encoding="utf-8")

        try:
            load_template.cache_clear()

            pkg = Pkg(producer={"name": "dual-scope", "version": "1.0.0"})
            sys1 = pkg.add_subject(
                "ai_system",
                name="System X",
                risk_classification="high-risk",
                modalities=["text"],
            )
            pkg.add_subject(
                "ai_system",
                name="System Y",
                risk_classification="high-risk",
                modalities=["text"],
            )
            pkg.add_profile(tid, provisions=["pkg-check-02", "subj-check-02"])

            pkg.record(
                "governance_policy",
                provisions=["pkg-check-02"],
                payload={"policy_type": "quality_management", "description": "QMS"},
            )
            pkg.record(
                "risk_register",
                provisions=["subj-check-02"],
                payload={"description": "Risk", "likelihood": "low", "severity": "low"},
                entity_refs={"subject_refs": [sys1.id]},
            )

            bundle_dir = tmp_dir / "dual_scope"
            pkg.export(str(bundle_dir))

            assessment = validate_bundle(
                bundle_dir,
                profiles=[tid],
                evaluation_instant="2026-01-15T00:00:00Z",
            )

            # Package-scoped: exactly 1 summary
            pkg_summaries = [s for s in assessment.provision_summary if s.provision_id == "pkg-check-02"]
            assert len(pkg_summaries) == 1, f"Package-scoped should have 1 summary, got {len(pkg_summaries)}"

            # Per-subject: 2 summaries (one per subject)
            subj_summaries = [s for s in assessment.provision_summary if s.provision_id == "subj-check-02"]
            assert len(subj_summaries) == 2, f"Per-subject should have 2 summaries, got {len(subj_summaries)}"
        finally:
            if template_path.exists():
                template_path.unlink()
            load_template.cache_clear()


class TestRulelessProvisionEndToEnd:
    """PhD re-review FM-2: §3.7 step 1 / Appendix C P1 (a provision with NO rules
    -> not-assessed) was unreachable end-to-end. The engine rolled up only
    provisions that emitted RuleResults (seen_provisions), so a rule-less provision
    (empty evaluation, no required_evidence_types) silently vanished from the
    Assessment Bundle instead of surfacing NOT_ASSESSED. Shipped templates all have
    rules on every provision, so the gap was reachable only via custom/third-party
    templates, which the models permit."""

    def test_ruleless_package_provision_surfaces_not_assessed(self, tmp_dir: Path) -> None:
        """A rule-less PACKAGE-scoped provision surfaces exactly one NOT_ASSESSED
        summary; a normal sibling provision is unaffected."""
        from acef.models.enums import ProvisionOutcome
        from acef.package import Package as Pkg
        from acef.templates.models import EvaluationRule, Provision, Template
        from acef.templates.registry import load_template
        from acef.validation.engine import validate_bundle

        tid = "conformance-ruleless-package"
        template = Template(
            template_id=tid,
            template_name="Conformance Rule-less Package Provision Test",
            version="1.0.0",
            provisions=[
                Provision(
                    provision_id="ruleless-pkg-01",
                    provision_name="Rule-less Package Provision",
                    evaluation_scope="package",
                    # no evaluation rules and no required_evidence_types -> zero RuleResults
                ),
                Provision(
                    provision_id="normal-pkg-01",
                    provision_name="Normal Package Provision",
                    evaluation_scope="package",
                    evaluation=[
                        EvaluationRule(
                            rule_id="normal-pkg-01-check",
                            rule="has_record_type",
                            params={"type": "risk_register", "min_count": 1},
                            severity="fail",
                            message="Need a risk register",
                        ),
                    ],
                ),
            ],
        )
        template_path = Path(__file__).parent.parent.parent / "src" / "acef" / "templates" / f"{tid}.json"
        template_path.write_text(template.model_dump_json(indent=2), encoding="utf-8")
        try:
            load_template.cache_clear()
            pkg = Pkg(producer={"name": "ruleless", "version": "1.0.0"})
            sys1 = pkg.add_subject("ai_system", name="System A", risk_classification="high-risk", modalities=["text"])
            pkg.add_profile(tid, provisions=["ruleless-pkg-01", "normal-pkg-01"])
            pkg.record(
                "risk_register",
                provisions=["normal-pkg-01"],
                payload={"description": "R", "likelihood": "low", "severity": "low"},
                obligation_role="provider",
                entity_refs={"subject_refs": [sys1.id]},
            )
            bundle_dir = tmp_dir / "ruleless_pkg"
            pkg.export(str(bundle_dir))
            assessment = validate_bundle(bundle_dir, profiles=[tid], evaluation_instant="2026-01-01T00:00:00Z")

            ruleless = [s for s in assessment.provision_summary if s.provision_id == "ruleless-pkg-01"]
            assert len(ruleless) == 1, (
                f"Rule-less provision must surface exactly one NOT_ASSESSED summary, got {len(ruleless)} "
                f"(provision_ids: {[s.provision_id for s in assessment.provision_summary]})"
            )
            assert ruleless[0].provision_outcome == ProvisionOutcome.NOT_ASSESSED
            assert any(s.provision_id == "normal-pkg-01" for s in assessment.provision_summary)
        finally:
            if template_path.exists():
                template_path.unlink()
            load_template.cache_clear()

    def test_ruleless_per_subject_provision_surfaces_not_assessed_per_subject(self, tmp_dir: Path) -> None:
        """A rule-less PER-SUBJECT provision surfaces one NOT_ASSESSED per applicable
        subject (mirroring the per-subject split), each scoped to that subject."""
        from acef.models.enums import ProvisionOutcome
        from acef.package import Package as Pkg
        from acef.templates.models import Provision, Template
        from acef.templates.registry import load_template
        from acef.validation.engine import validate_bundle

        tid = "conformance-ruleless-per-subject"
        template = Template(
            template_id=tid,
            template_name="Conformance Rule-less Per-Subject Provision Test",
            version="1.0.0",
            provisions=[
                Provision(
                    provision_id="ruleless-subj-01",
                    provision_name="Rule-less Per-Subject Provision",
                    # default per-subject scope, no rules
                ),
            ],
        )
        template_path = Path(__file__).parent.parent.parent / "src" / "acef" / "templates" / f"{tid}.json"
        template_path.write_text(template.model_dump_json(indent=2), encoding="utf-8")
        try:
            load_template.cache_clear()
            pkg = Pkg(producer={"name": "ruleless-subj", "version": "1.0.0"})
            s1 = pkg.add_subject("ai_system", name="System A", risk_classification="high-risk", modalities=["text"])
            s2 = pkg.add_subject("ai_system", name="System B", risk_classification="high-risk", modalities=["text"])
            pkg.add_profile(tid, provisions=["ruleless-subj-01"])
            pkg.record(
                "risk_register",
                provisions=["ruleless-subj-01"],
                payload={"description": "R", "likelihood": "low", "severity": "low"},
                obligation_role="provider",
                entity_refs={"subject_refs": [s1.id]},
            )
            bundle_dir = tmp_dir / "ruleless_subj"
            pkg.export(str(bundle_dir))
            assessment = validate_bundle(bundle_dir, profiles=[tid], evaluation_instant="2026-01-01T00:00:00Z")

            summaries = [s for s in assessment.provision_summary if s.provision_id == "ruleless-subj-01"]
            assert len(summaries) == 2, (
                f"Rule-less per-subject provision must surface one summary per subject; got {len(summaries)}"
            )
            for s in summaries:
                assert s.provision_outcome == ProvisionOutcome.NOT_ASSESSED
                assert len(s.subject_scope) == 1
            assert {s.subject_scope[0] for s in summaries} == {s1.id, s2.id}
        finally:
            if template_path.exists():
                template_path.unlink()
            load_template.cache_clear()

    def test_ruleless_not_yet_effective_provision_surfaces_not_assessed(self, tmp_dir: Path) -> None:
        """roborev Medium on 11abc69: a provision that is BOTH rule-less AND
        not-yet-effective must still surface (NOT_ASSESSED), not vanish. The NYE
        synthesis produces no SKIPPED results for a rule-less provision, and it is
        then excluded from further evaluation — so without the §3.7 step-1 backfill
        in the NYE branch it disappears entirely."""
        from acef.models.enums import ProvisionOutcome
        from acef.package import Package as Pkg
        from acef.templates.models import Provision, Template
        from acef.templates.registry import load_template
        from acef.validation.engine import validate_bundle

        tid = "conformance-ruleless-future-effective"
        template = Template(
            template_id=tid,
            template_name="Conformance Rule-less Future-Effective Provision Test",
            version="1.0.0",
            provisions=[
                Provision(
                    provision_id="ruleless-future-01",
                    provision_name="Rule-less Future-Effective Package Provision",
                    evaluation_scope="package",
                    effective_date="2099-01-01",
                    # no rules
                ),
            ],
        )
        template_path = Path(__file__).parent.parent.parent / "src" / "acef" / "templates" / f"{tid}.json"
        template_path.write_text(template.model_dump_json(indent=2), encoding="utf-8")
        try:
            load_template.cache_clear()
            pkg = Pkg(producer={"name": "ruleless-future", "version": "1.0.0"})
            sys1 = pkg.add_subject("ai_system", name="System A", risk_classification="high-risk", modalities=["text"])
            pkg.add_profile(tid, provisions=["ruleless-future-01"])
            pkg.record(
                "risk_register",
                provisions=["ruleless-future-01"],
                payload={"description": "R", "likelihood": "low", "severity": "low"},
                obligation_role="provider",
                entity_refs={"subject_refs": [sys1.id]},
            )
            bundle_dir = tmp_dir / "ruleless_future"
            pkg.export(str(bundle_dir))
            # Evaluate BEFORE the future effective_date.
            assessment = validate_bundle(bundle_dir, profiles=[tid], evaluation_instant="2026-01-01T00:00:00Z")

            summaries = [s for s in assessment.provision_summary if s.provision_id == "ruleless-future-01"]
            assert len(summaries) == 1, (
                f"Rule-less not-yet-effective provision must surface exactly one summary, got {len(summaries)} "
                f"(provision_ids: {[s.provision_id for s in assessment.provision_summary]})"
            )
            assert summaries[0].provision_outcome == ProvisionOutcome.NOT_ASSESSED
        finally:
            if template_path.exists():
                template_path.unlink()
            load_template.cache_clear()

    def test_required_evidence_only_not_yet_effective_provision_surfaces_skipped(self, tmp_dir: Path) -> None:
        """roborev Medium on ba878d6: a future-effective provision whose ONLY rules
        come from required_evidence_types (no explicit evaluation) must still surface
        (SKIPPED), not vanish. _synthesize_skipped now expands required_evidence_types
        into synthetic SKIPPED has_record_type results."""
        from acef.models.enums import ProvisionOutcome
        from acef.package import Package as Pkg
        from acef.templates.models import Provision, Template
        from acef.templates.registry import load_template
        from acef.validation.engine import validate_bundle

        tid = "conformance-reqevidence-future-effective"
        template = Template(
            template_id=tid,
            template_name="Conformance Required-Evidence Future-Effective Provision Test",
            version="1.0.0",
            provisions=[
                Provision(
                    provision_id="reqevidence-future-01",
                    provision_name="Required-Evidence-Only Future-Effective Package Provision",
                    evaluation_scope="package",
                    effective_date="2099-01-01",
                    required_evidence_types=["risk_register"],  # implicit rule, no explicit evaluation
                ),
            ],
        )
        template_path = Path(__file__).parent.parent.parent / "src" / "acef" / "templates" / f"{tid}.json"
        template_path.write_text(template.model_dump_json(indent=2), encoding="utf-8")
        try:
            load_template.cache_clear()
            pkg = Pkg(producer={"name": "reqevidence-future", "version": "1.0.0"})
            sys1 = pkg.add_subject("ai_system", name="System A", risk_classification="high-risk", modalities=["text"])
            pkg.add_profile(tid, provisions=["reqevidence-future-01"])
            pkg.record(
                "risk_register",
                provisions=["reqevidence-future-01"],
                payload={"description": "R", "likelihood": "low", "severity": "low"},
                obligation_role="provider",
                entity_refs={"subject_refs": [sys1.id]},
            )
            bundle_dir = tmp_dir / "reqevidence_future"
            pkg.export(str(bundle_dir))
            assessment = validate_bundle(bundle_dir, profiles=[tid], evaluation_instant="2026-01-01T00:00:00Z")

            summaries = [s for s in assessment.provision_summary if s.provision_id == "reqevidence-future-01"]
            assert len(summaries) == 1, (
                f"Required-evidence-only not-yet-effective provision must surface exactly one summary, "
                f"got {len(summaries)} (provision_ids: {[s.provision_id for s in assessment.provision_summary]})"
            )
            assert summaries[0].provision_outcome == ProvisionOutcome.SKIPPED
        finally:
            if template_path.exists():
                template_path.unlink()
            load_template.cache_clear()


class TestPerSubjectVanishingSummaries:
    """Fresh systems committee (FM-ENGINE-1 @905302e): a non-empty subjects list of
    only non-dict entries is truthy but yields no evaluable subject; the effective
    per-subject branch looped+continued and dropped ALL per-subject summaries
    instead of falling through to package-level evaluation. Gating on
    concrete_subjects (the NYE sibling already does) fixes it."""

    def test_per_subject_summaries_survive_all_non_dict_subjects(self, tmp_dir: Path) -> None:
        import json

        from acef.models.enums import ProvisionOutcome
        from acef.package import Package as Pkg
        from acef.templates.models import EvaluationRule, Provision, Template
        from acef.templates.registry import load_template
        from acef.validation.engine import validate_bundle

        tid = "conformance-per-subject-nondict"
        template = Template(
            template_id=tid,
            template_name="Per-Subject Non-Dict Subjects Test",
            version="1.0.0",
            provisions=[
                Provision(
                    provision_id="subj-prov-01",
                    provision_name="Per-Subject Provision",
                    evaluation=[
                        EvaluationRule(
                            rule_id="subj-prov-01-check",
                            rule="has_record_type",
                            params={"type": "risk_register", "min_count": 1},
                            severity="fail",
                            message="need a risk register",
                        ),
                    ],
                ),
            ],
        )
        template_path = Path(__file__).parent.parent.parent / "src" / "acef" / "templates" / f"{tid}.json"
        template_path.write_text(template.model_dump_json(indent=2), encoding="utf-8")
        try:
            load_template.cache_clear()
            pkg = Pkg(producer={"name": "nondict", "version": "1.0.0"})
            s1 = pkg.add_subject("ai_system", name="S", risk_classification="high-risk", modalities=["text"])
            pkg.add_profile(tid, provisions=["subj-prov-01"])
            pkg.record(
                "risk_register",
                provisions=["subj-prov-01"],
                payload={"description": "R", "likelihood": "low", "severity": "low"},
                obligation_role="provider",
                entity_refs={"subject_refs": [s1.id]},
            )
            bundle_dir = tmp_dir / "nondict"
            pkg.export(str(bundle_dir))
            # Tamper: replace subjects with a non-empty list of ONLY non-dict entries.
            mp = bundle_dir / "acef-manifest.json"
            manifest = json.loads(mp.read_text(encoding="utf-8"))
            manifest["subjects"] = ["not-a-dict", 42]
            mp.write_text(json.dumps(manifest), encoding="utf-8")

            assessment = validate_bundle(bundle_dir, profiles=[tid], evaluation_instant="2026-01-01T00:00:00Z")
            # The per-subject provision must NOT vanish — it falls back to a
            # package-level summary (even though the bundle is fatal for the
            # malformed subjects; this is diagnostic completeness, §3.6).
            summaries = [s for s in assessment.provision_summary if s.provision_id == "subj-prov-01"]
            assert len(summaries) >= 1, (
                f"per-subject provision must not vanish on all-non-dict subjects; "
                f"provision_ids={[s.provision_id for s in assessment.provision_summary]}"
            )
            # The risk_register exists, so the package-level fallback is SATISFIED.
            assert summaries[0].provision_outcome == ProvisionOutcome.SATISFIED
        finally:
            if template_path.exists():
                template_path.unlink()
            load_template.cache_clear()
