"""ACEF-035 — applicability is INDETERMINATE during a split commencement window.

roborev finding on 0753d47 (High): "All Chapter III provisions become effective
on the earlier Annex III date for every 'high-risk' subject. The validator
ignores tiered_requirements, so Annex I systems are evaluated eight months
early." Correct.

Regulation (EU) 2026/1744 Art. 1 point (40)(b) replaced Art. 113 third paragraph
point (c): Chapter III Sections 1-3 apply from 2027-12-02 for Art. 6(2)/Annex III
high-risk systems and from 2028-08-02 for Art. 6(1)/Annex I. ACEF cannot express
that discriminator — ``effective_date`` is a single value, and the
``risk_classification`` enum in the FROZEN v1 manifest schema has no Annex I /
Annex III member — so ``effective_date`` carries the earlier limb.

Storing the earlier limb alone and returning an unqualified binary is the
documented anti-pattern: between the two dates a validator would tell an Annex I
provider its obligation is live eight months early, with the caveat visible only
in documentation. Rules-as-code practice models one provision as multiple
applicability-guarded regimes (LegalRuleML separates entry-into-force from
applicability; ELI's ``date_applicability`` is repeatable). Where the guard
cannot be evaluated, the defensible output is INDETERMINATE naming the missing
attribute — the XACML precedent, where ``Indeterminate`` is a decision distinct
from ``NotApplicable``.

ACEF-035 is that signal. It is INFO severity: it does not fail a bundle, and it
does not change any rule outcome. It tells the reader the tool could not settle
applicability from the evidence available, so the earlier-limb result is a
conservative projection rather than a determination.
"""

from __future__ import annotations

import pytest

from acef.errors import EXTENDED_ERROR_DETAILS, ErrorCategory, Severity, resolve_error_meta
from acef.validation.engine import split_commencement_state

# Amended Art. 113 third para (c)(i) and (c)(ii).
EARLY = "2027-12-02"
LATE = "2028-08-02"

ADOPTION = {
    "annex_iii_high_risk": EARLY,
    "annex_i_high_risk": LATE,
    "basis": "Art. 113 third para (c) as replaced by Reg. (EU) 2026/1744 Art. 1 pt (40)(b)",
}


class TestACEF035IsRegistered:
    def test_code_is_in_the_taxonomy(self) -> None:
        assert "ACEF-035" in EXTENDED_ERROR_DETAILS

    def test_code_is_info_severity_not_an_error(self) -> None:
        """An unresolvable classification is a scope limitation, not a failure.

        Escalating it would fail every conformant bundle evaluated inside the
        window, which is worse than the silence it replaces.
        """
        severity, category = resolve_error_meta("ACEF-035")
        assert severity == Severity.INFO, (
            f"ACEF-035 must be info; got {severity}. Reporting 'cannot determine' as an "
            "error would fail bundles that are perfectly conformant"
        )
        assert category == ErrorCategory.PROFILE


class TestSplitWindowDetection:
    """`split_commencement_state` maps an instant onto the three regimes."""

    def test_before_both_limbs_is_not_indeterminate(self) -> None:
        """Nothing has commenced; ACEF-032 already covers not-yet-effective."""
        state = split_commencement_state(ADOPTION, "2027-01-01T00:00:00Z")
        assert state is None

    def test_inside_the_window_is_indeterminate(self) -> None:
        state = split_commencement_state(ADOPTION, "2028-01-15T00:00:00Z")
        assert state is not None
        assert state["earliest"] == EARLY
        assert state["latest"] == LATE
        assert "annex_i_high_risk" in state["undetermined_classes"]

    def test_on_the_earlier_limb_is_indeterminate(self) -> None:
        """Boundary: the earlier limb HAS commenced, the later has not."""
        assert split_commencement_state(ADOPTION, f"{EARLY}T00:00:00Z") is not None

    def test_on_the_later_limb_is_settled(self) -> None:
        """Boundary: once the last limb commences, every class is covered."""
        assert split_commencement_state(ADOPTION, f"{LATE}T00:00:00Z") is None

    def test_after_both_limbs_is_settled(self) -> None:
        assert split_commencement_state(ADOPTION, "2029-01-01T00:00:00Z") is None

    def test_single_limb_is_never_indeterminate(self) -> None:
        """One date is unambiguous — no window, nothing to report."""
        single = {"annex_iii_high_risk": EARLY, "basis": "x"}
        assert split_commencement_state(single, "2028-01-15T00:00:00Z") is None

    def test_absent_adoption_block_is_never_indeterminate(self) -> None:
        assert split_commencement_state(None, "2028-01-15T00:00:00Z") is None
        assert split_commencement_state({}, "2028-01-15T00:00:00Z") is None

    def test_non_date_values_are_ignored(self) -> None:
        """`basis` is prose, not a limb; it must not be parsed as a date."""
        state = split_commencement_state(ADOPTION, "2028-01-15T00:00:00Z")
        assert state is not None
        assert "basis" not in state["undetermined_classes"]

    def test_missing_evaluation_instant_is_never_indeterminate(self) -> None:
        assert split_commencement_state(ADOPTION, None) is None


class TestDiagnosticContent:
    """The diagnostic must name the missing attribute, per the XACML precedent."""

    def test_detail_text_names_the_discriminator(self) -> None:
        detail = EXTENDED_ERROR_DETAILS["ACEF-035"]
        blob = f"{detail.problem} {detail.cause} {detail.fix}".lower()
        assert "annex" in blob, "the diagnostic must name the classification it needs"
        assert "indeterminate" in blob or "cannot" in blob

    def test_detail_says_the_result_is_a_projection(self) -> None:
        """A reader must not mistake the earlier-limb result for a determination."""
        detail = EXTENDED_ERROR_DETAILS["ACEF-035"]
        blob = f"{detail.problem} {detail.cause} {detail.fix}".lower()
        assert "conservative" in blob or "projection" in blob or "earliest" in blob


class TestTemplateCarriesBothLimbs:
    """roborev: 'the existing Article 9-17 provisions do not even record the later limb'."""

    @pytest.mark.parametrize(
        "pid",
        [
            "article-9",
            "article-10",
            "article-11",
            "article-12",
            "article-13",
            "article-14",
            "article-15",
            "article-17",
            "article-19",
            "article-26.6",
        ],
    )
    def test_every_chapter_iii_provision_records_both_limbs(self, pid: str) -> None:
        from acef.templates.registry import load_template

        prov = next(p for p in load_template("eu-ai-act-2024").provisions if p.provision_id == pid)
        tiered = prov.tiered_requirements
        assert tiered is not None, f"{pid} records no adoption block"
        adoption = tiered.get("adoption")
        assert adoption is not None, f"{pid} has no tiered_requirements.adoption"
        assert adoption.get("annex_iii_high_risk") == EARLY
        assert adoption.get("annex_i_high_risk") == LATE, (
            f"{pid} stores only the earlier limb; the later one is unrecoverable"
        )
        assert "2026/1744" in adoption.get("basis", "")

    @pytest.mark.parametrize("pid", ["article-50.2", "article-53"])
    def test_non_chapter_iii_provisions_have_no_adoption_block(self, pid: str) -> None:
        """Art. 50 (Ch. IV) and Art. 53 (Ch. V) were not amended — single date each."""
        from acef.templates.registry import load_template

        prov = next(p for p in load_template("eu-ai-act-2024").provisions if p.provision_id == pid)
        adoption = (prov.tiered_requirements or {}).get("adoption")
        assert adoption is None, f"{pid} is not subject to the Art. 113(c) split"


class TestDiagnosticFiresThroughValidateBundle:
    """The signal must reach a real validation run.

    A detection helper that nothing calls is the documentation-only anti-pattern
    this code exists to avoid: the evaluator would still return an unqualified
    binary while the caveat sat in prose.
    """

    @staticmethod
    def _bundle(tmp_path, instant: str):
        from acef.package import Package
        from acef.validation.engine import validate_bundle

        pkg = Package(producer={"name": "t", "version": "1"})
        system = pkg.add_subject("ai_system", name="S", version="1")
        pkg.add_profile("eu-ai-act-2024", provisions=["article-9"])
        pkg.record(
            "risk_register",
            provisions=["article-9"],
            payload={
                "risk_id": "R-1",
                "description": "d",
                "category": "safety",
                "likelihood": "likely",
                "severity": "major",
                "risk_level": "high",
            },
            obligation_role="provider",
            entity_refs={"subject_refs": [system.id]},
            timestamp="2028-01-01T00:00:00Z",
        )
        out = tmp_path / "b"
        pkg.export(str(out))
        return validate_bundle(out, profiles=["eu-ai-act-2024"], evaluation_instant=instant)

    def _codes(self, assessment) -> list[str]:
        return [d.get("code") for d in assessment.structural_errors]

    def test_inside_the_window_emits_acef_035(self, tmp_path) -> None:
        codes = self._codes(self._bundle(tmp_path, "2028-01-15T00:00:00Z"))
        assert "ACEF-035" in codes, f"no indeterminate signal inside the split window; got {codes}"
        assert "ACEF-032" not in codes, "the provision HAS commenced under the earlier limb"

    def test_after_both_limbs_emits_nothing(self, tmp_path) -> None:
        codes = self._codes(self._bundle(tmp_path, "2029-01-01T00:00:00Z"))
        assert "ACEF-035" not in codes, "applicability is settled once every limb commences"

    def test_before_both_limbs_emits_only_not_yet_effective(self, tmp_path) -> None:
        codes = self._codes(self._bundle(tmp_path, "2027-01-01T00:00:00Z"))
        assert "ACEF-032" in codes
        assert "ACEF-035" not in codes, "ACEF-032 already covers not-yet-commenced"

    def test_diagnostic_names_the_missing_classification(self, tmp_path) -> None:
        assessment = self._bundle(tmp_path, "2028-01-15T00:00:00Z")
        msg = next(d["message"] for d in assessment.structural_errors if d.get("code") == "ACEF-035")
        assert "annex_i_high_risk" in msg, "must name the attribute that would settle it"
        assert "2028-08-02" in msg and "2027-12-02" in msg, "both limbs must be visible"

    def test_indeterminacy_does_not_change_any_rule_outcome(self, tmp_path) -> None:
        """Info severity: it annotates the result, it does not alter it."""
        inside = self._bundle(tmp_path / "a", "2028-01-15T00:00:00Z")
        after = self._bundle(tmp_path / "b", "2029-01-01T00:00:00Z")
        assert [r.outcome for r in inside.results] == [r.outcome for r in after.results]
