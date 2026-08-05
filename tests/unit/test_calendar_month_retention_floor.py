"""The Art. 19(1) / 26(6) floor is six CALENDAR months, not 180 days.

roborev finding on 0753d47 (Medium): "The declared requirement is six calendar
months from record creation, but enforcement reduces it to 180 days and ignores
the retention start event. Six months can exceed 180 days, and a policy using
another anchor can therefore pass without satisfying the modeled requirement."

Measured: six calendar months spans 181 to 184 days depending on which months it
crosses, so a 180-day threshold under-enforces by up to four days. No fixed
day-count is correct for every anchor — 184 would reject a valid 181-day
February-anchored policy, and 181 would accept a short August-anchored one.

The retention block already carries the truth: ``period {value: 6, unit:
months}`` plus ``anchor_event``. What the DSL cannot do is calendar arithmetic —
``exists_where_any`` compares a stored integer against a constant, and there is
no operator that resolves a duration against a per-record anchor date.

So the day-count threshold is retained as a NECESSARY-BUT-NOT-SUFFICIENT screen
set to the floor's lower bound (181, the minimum any six-month span can be),
catching the gross violations it can catch, and ACEF-036 reports that exact
calendar satisfaction was not verified. Reporting the limit is the difference
between a screen and a false assurance.
"""

from __future__ import annotations

import datetime as dt

import pytest

from acef.errors import EXTENDED_ERROR_DETAILS, ErrorCategory, Severity, resolve_error_meta
from acef.templates.registry import load_template
from acef.validation.engine import calendar_months_to_days


class TestCalendarArithmetic:
    def test_six_months_never_fits_in_180_days(self) -> None:
        """The premise of the finding, verified over every start month."""
        spans = set()
        for year in (2027, 2028):
            for month in range(1, 13):
                start = dt.date(year, month, 1)
                nm = month + 6
                end = dt.date(year + (nm - 1) // 12, (nm - 1) % 12 + 1, 1)
                spans.add((end - start).days)
        assert min(spans) == 181, f"minimum six-month span is {min(spans)}, not 181"
        assert max(spans) == 184
        assert 180 not in spans, "180 days is never six calendar months"

    def test_lower_bound_is_the_only_safe_fixed_threshold(self) -> None:
        """Any threshold above the minimum span rejects a lawful policy."""
        assert calendar_months_to_days(6) == 181
        assert calendar_months_to_days(1) == 28, "February is the shortest month"
        assert calendar_months_to_days(12) == 365

    def test_zero_and_negative_are_rejected(self) -> None:
        for bad in (0, -1):
            with pytest.raises(ValueError):
                calendar_months_to_days(bad)


class TestACEF036IsRegistered:
    def test_code_is_in_the_taxonomy(self) -> None:
        assert "ACEF-036" in EXTENDED_ERROR_DETAILS

    def test_code_is_info_not_a_failure(self) -> None:
        """A screen that cannot fully verify is a limitation, not a violation.

        The record may well satisfy the calendar requirement; the validator
        simply cannot confirm it. Failing on that would reject conformant data.
        """
        severity, category = resolve_error_meta("ACEF-036")
        assert severity == Severity.INFO
        assert category == ErrorCategory.PROFILE

    def test_detail_names_the_gap_and_the_anchor(self) -> None:
        detail = EXTENDED_ERROR_DETAILS["ACEF-036"]
        blob = f"{detail.problem} {detail.cause} {detail.fix}".lower()
        assert "calendar" in blob
        assert "anchor" in blob or "start_event" in blob
        assert "day" in blob


class TestTemplateUsesTheLowerBound:
    """The shipped rules must screen at 181, not 180."""

    @pytest.mark.parametrize("pid", ["article-19", "article-26.6"])
    def test_floor_rule_threshold_is_the_six_month_lower_bound(self, pid: str) -> None:
        prov = next(p for p in load_template("eu-ai-act-2024").provisions if p.provision_id == pid)
        floor = next(r for r in prov.evaluation if r.rule_id.endswith("-log-retention-floor"))
        assert floor.params["value"] == 181, (
            f"{pid} screens at {floor.params['value']} days; six calendar months is "
            "181 days at minimum, so 180 admits a policy four days short"
        )
        assert floor.params["op"] == "gte"

    @pytest.mark.parametrize("pid", ["article-19", "article-26.6"])
    def test_retention_block_keeps_the_unit_bearing_period(self, pid: str) -> None:
        """The day-count is the screen; months remain the stated obligation."""
        prov = next(p for p in load_template("eu-ai-act-2024").provisions if p.provision_id == pid)
        assert prov.retention is not None
        assert prov.retention.period is not None
        assert (prov.retention.period.value, prov.retention.period.unit) == (6, "months"), (
            "the obligation must stay unit-bearing; reducing it to days in the "
            "retention block would lose the calendar semantics entirely"
        )
        assert prov.retention.anchor_event == "record_creation"

    @pytest.mark.parametrize("pid", ["article-19", "article-26.6"])
    def test_rule_message_discloses_that_the_screen_is_partial(self, pid: str) -> None:
        """A message claiming full verification would be a false assurance."""
        prov = next(p for p in load_template("eu-ai-act-2024").provisions if p.provision_id == pid)
        floor = next(r for r in prov.evaluation if r.rule_id.endswith("-log-retention-floor"))
        msg = floor.message.lower()
        assert "calendar" in msg or "181" in msg


class TestACEF036FiresThroughValidateBundle:
    """The disclosure must reach a real run, not just exist in the taxonomy."""

    @staticmethod
    def _validate(tmp_path, provisions: list[str], instant: str):
        from acef.package import Package
        from acef.validation.engine import validate_bundle

        pkg = Package(producer={"name": "t", "version": "1"})
        system = pkg.add_subject("ai_system", name="S", version="1", risk_classification="high-risk")
        pkg.add_profile("eu-ai-act-2024", provisions=provisions)
        pkg.record(
            "event_log",
            provisions=provisions,
            payload={
                "event_type": "logging_spec",
                "retention_policy_summary": {
                    "min_days": 400,
                    "start_event": "record_creation",
                    "legal_basis": "EU AI Act Art. 19(1)",
                },
            },
            obligation_role="provider",
            entity_refs={"subject_refs": [system.id]},
            timestamp="2028-09-01T00:00:00Z",
        )
        out = tmp_path / "b"
        pkg.export(str(out))
        return validate_bundle(out, profiles=["eu-ai-act-2024"], evaluation_instant=instant)

    def _codes(self, assessment) -> list[str]:
        return [d.get("code") for d in assessment.structural_errors]

    def test_month_denominated_provision_discloses_the_screen(self, tmp_path) -> None:
        codes = self._codes(self._validate(tmp_path, ["article-19"], "2028-09-15T12:00:00Z"))
        assert "ACEF-036" in codes, f"no calendar-screen disclosure; got {codes}"

    def test_year_denominated_provision_does_not_disclose(self, tmp_path) -> None:
        """article-11 is a fixed period in YEARS — no calendar-month ambiguity."""
        codes = self._codes(self._validate(tmp_path, ["article-11"], "2028-09-15T12:00:00Z"))
        assert "ACEF-036" not in codes

    def test_disclosure_names_the_anchor_and_the_bound(self, tmp_path) -> None:
        assessment = self._validate(tmp_path, ["article-19"], "2028-09-15T12:00:00Z")
        msg = next(d["message"] for d in assessment.structural_errors if d.get("code") == "ACEF-036")
        assert "record_creation" in msg, "must name the anchor that was not checked"
        assert "181" in msg and "6 months" in msg

    def test_disclosure_is_non_gating(self, tmp_path) -> None:
        """Info severity: it annotates the result, it never gates it.

        A 400-day policy clears the 181-day screen. The disclosure says the
        CALENDAR requirement was not fully verified — it must not convert that
        into a failed rule or a not-satisfied provision.
        """
        assessment = self._validate(tmp_path, ["article-19"], "2028-09-15T12:00:00Z")
        floor = [r for r in assessment.results if r.rule_id == "art19-log-retention-floor"]
        assert floor, "the floor rule did not evaluate at all"
        assert floor[0].outcome == "passed", f"a 400-day policy must clear the 181-day screen; got {floor[0].outcome}"
        assert all(
            s.provision_outcome != "not-satisfied"
            for s in assessment.provision_summary
            if s.provision_id == "article-19"
        )


class TestBoolIsNotADayCount:
    """bool subclasses int in Python — a rule comparing True is not a day screen."""

    def test_months_provision_without_a_day_screen_does_not_disclose(self) -> None:
        """china-cac's cac-log-retention states 6 months but has NO day threshold.

        Its only int-valued rule compares against ``True``. Because
        ``isinstance(True, int)`` is True, a naive check mistook that for a
        day-count screen and emitted ACEF-036 on a provision that screens
        nothing — a disclosure about a screen that does not exist.
        """
        from acef.validation.engine import validate_bundle

        assessment = validate_bundle(
            "tests/conformance/golden-bundles/china-cac-labeling",
            profiles=["china-cac-labeling-2025"],
            evaluation_instant="2026-03-15T12:00:00Z",
        )
        codes = [d.get("code") for d in assessment.structural_errors]
        assert "ACEF-036" not in codes, (
            "ACEF-036 fired on a provision with no day-count screen; a rule "
            "comparing against a boolean is not a day threshold"
        )


class TestCalendarMinimumCoversTheGregorianCycle:
    """roborev on d04da7d (Low): a two-year sample misses century behaviour.

    Century years divisible by 100 but not 400 are common years, so 48 months
    starting 2097-03 spans 1460 days while every start inside 2027-2028 gives
    1461. A window that narrow returns a minimum one day too HIGH, which would
    reject a lawful policy — the exact failure direction the lower bound exists
    to avoid.
    """

    def test_forty_eight_months_accounts_for_a_non_leap_century(self) -> None:
        assert calendar_months_to_days(48) == 1460, "48 months can span 1460 days across a non-leap century year (2100)"

    def test_minimum_is_never_above_any_real_span(self) -> None:
        """Exhaustive over a full 400-year cycle for several month counts."""
        for months in (1, 6, 12, 48, 60):
            bound = calendar_months_to_days(months)
            for year in range(2000, 2400):
                for month in range(1, 13):
                    total = month - 1 + months
                    span = (dt.date(year + total // 12, total % 12 + 1, 1) - dt.date(year, month, 1)).days
                    assert bound <= span, (
                        f"{months} months: bound {bound} exceeds a real span of {span} starting {year}-{month:02d}"
                    )


class TestAdvisoryDiagnosticsRespectApplicability:
    """roborev on d04da7d (Medium): ACEF-036 fired before applicability filtering.

    A bundle whose only subject is minimal-risk was told an Article 19 retention
    screen occurred, even though that high-risk-only provision produced zero
    rule results. An advisory about how a provision was evaluated must not be
    emitted when it was not evaluated at all.
    """

    @staticmethod
    def _run(tmp_path, risk_classification: str):
        from acef.package import Package
        from acef.validation.engine import validate_bundle

        pkg = Package(producer={"name": "t", "version": "1"})
        subject = pkg.add_subject("ai_system", name="S", version="1", risk_classification=risk_classification)
        pkg.add_profile("eu-ai-act-2024", provisions=["article-19"])
        pkg.record(
            "event_log",
            provisions=["article-19"],
            payload={
                "event_type": "logging_spec",
                "retention_policy_summary": {
                    "min_days": 400,
                    "start_event": "record_creation",
                    "legal_basis": "EU AI Act Art. 19(1)",
                },
            },
            obligation_role="provider",
            entity_refs={"subject_refs": [subject.id]},
            timestamp="2028-09-01T00:00:00Z",
        )
        out = tmp_path / risk_classification
        pkg.export(str(out))
        assessment = validate_bundle(out, profiles=["eu-ai-act-2024"], evaluation_instant="2028-09-15T12:00:00Z")
        return [d.get("code") for d in assessment.structural_errors], len(assessment.results)

    def test_no_advisory_when_the_provision_applies_to_no_subject(self, tmp_path) -> None:
        codes, n_results = self._run(tmp_path, "minimal-risk")
        assert n_results == 0, "article-19 is high-risk only; nothing should evaluate"
        assert "ACEF-036" not in codes, "reported a calendar screen for a provision that never ran"

    def test_advisory_still_fires_when_the_provision_does_apply(self, tmp_path) -> None:
        codes, n_results = self._run(tmp_path, "high-risk")
        assert n_results > 0
        assert "ACEF-036" in codes, "gating must not suppress the genuine case"
