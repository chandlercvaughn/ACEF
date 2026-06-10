"""Unit tests for the EU Art. 73 incident-reporting crosswalk template.

Feature F-M3-TEMPLATE-ART73 / assertion VAL-TMPL-001.

Covers:
- the template loads through the existing template registry
  (``acef.templates.registry.load_template``);
- it encodes the Art. 73 provisions with per-provision effective dates and
  the `pending-final-adoption` Digital-Omnibus status (RFC-0002 §5.7, Q7);
- it requires ``public_incident_id``, the EU trigger array, ``widespread``,
  ``death_involved``, ``coordinated_disclosure.regulatory_timeline[]``, and
  ``notification_timeline[]`` via DSL ``field_present`` / ``exists_where`` rules;
- the encoded reporting-clock metadata computes the SHORTEST applicable
  deadline: ``death_involved`` → 10 days; ``3.49.b`` (critical-infrastructure)
  OR ``widespread`` → 2 days; otherwise (incl. non-fatal ``3.49.a``) → 15 days;
  the shortest clock wins for compound incidents.

The DSL operators in ``src/acef/validation/operators.py`` are pass/fail
predicates and cannot themselves *compute* a derived deadline. Per RFC-0002
§5.7 the clock is therefore carried as structured, byte-stable template
metadata (on the Art. 73 reporting provision's ``tiered_requirements``); this
test reads that metadata and evaluates the shortest-applicable-clock algorithm
against representative incident facts, asserting each branch's deadline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acef.templates.models import Template
from acef.templates.registry import (
    compute_template_digest,
    list_templates,
    load_template,
)

TEMPLATE_ID = "eu-ai-act-art73-2026"

# Per RFC-0002 §5.7 / Q7: Annex III high-risk reporting applies 2027-12-02 and
# Annex I applies 2028-08-02, both conditioned on Digital-Omnibus adoption
# (status `pending-final-adoption`); the as-enacted in-force date is 2026-08-02.
ANNEX_III_EFFECTIVE_DATE = "2027-12-02"
ANNEX_I_EFFECTIVE_DATE = "2028-08-02"
AS_ENACTED_EFFECTIVE_DATE = "2026-08-02"

DEATH_CLOCK_DAYS = 10
CRITICAL_OR_WIDESPREAD_CLOCK_DAYS = 2
DEFAULT_CLOCK_DAYS = 15


# ── Pure clock algorithm (the shortest-applicable-clock evaluator) ──


def _shortest_applicable_clock(clock_spec: dict[str, Any], facts: dict[str, Any]) -> int:
    """Compute the shortest applicable Art. 73 deadline (days) from facts.

    ``clock_spec`` is the template's ``reporting_clock`` metadata. ``facts``
    carries the EU trigger facts (``serious_incident_triggers``, ``widespread``,
    ``death_involved``) sourced from ``card_source.eu_ai_act_facts`` (confidential)
    or ``taxonomy_crosswalk.eu_ai_act`` (public). The smallest applicable clock
    wins for compound incidents.
    """
    triggers = set(facts.get("serious_incident_triggers", []))
    widespread = bool(facts.get("widespread", False))
    death_involved = bool(facts.get("death_involved", False))

    default_days = int(clock_spec["default_days"])
    candidates: list[int] = [default_days]

    for rule in clock_spec["rules"]:
        when = rule["when"]
        matched = False
        if when.get("death_involved") is True and death_involved:
            matched = True
        if when.get("widespread") is True and widespread:
            matched = True
        for trig in when.get("any_trigger", []):
            if trig in triggers:
                matched = True
        if matched:
            candidates.append(int(rule["days"]))

    return min(candidates)


# ── Fixtures ──


@pytest.fixture(scope="module")
def template() -> Template:
    return load_template(TEMPLATE_ID)


@pytest.fixture(scope="module")
def raw_template() -> dict[str, Any]:
    path = Path("src/acef/templates") / f"{TEMPLATE_ID}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _art73_provision(template: Template) -> Any:
    for prov in template.provisions:
        if prov.provision_id == "article-73":
            return prov
    raise AssertionError("article-73 provision not found in template")


def _clock_spec(template: Template) -> dict[str, Any]:
    prov = _art73_provision(template)
    assert prov.tiered_requirements is not None, "article-73 provision carries no tiered_requirements"
    clock = prov.tiered_requirements.get("reporting_clock")
    assert clock is not None, "article-73 provision carries no reporting_clock metadata"
    return clock


# ── Discovery / load ──


class TestTemplateLoads:
    def test_template_listed_in_registry(self) -> None:
        assert TEMPLATE_ID in list_templates()

    def test_template_loads_via_registry(self, template: Template) -> None:
        assert isinstance(template, Template)
        assert template.template_id == TEMPLATE_ID

    def test_template_digest_is_stable(self) -> None:
        # Byte-stability (§5.10): the digest is deterministic across calls.
        assert compute_template_digest(TEMPLATE_ID) == compute_template_digest(TEMPLATE_ID)

    def test_template_is_binding_eu_law(self, template: Template) -> None:
        assert template.jurisdiction == "EU"
        assert template.legal_force == "binding"
        assert template.instrument_type == "law"


# ── Per-provision effective dates + status (§5.7 / Q7) ──


class TestPerProvisionEffectiveDates:
    def test_article_73_provision_present(self, template: Template) -> None:
        prov = _art73_provision(template)
        assert prov.provision_id == "article-73"

    def test_article_3_49_trigger_provision_present(self, template: Template) -> None:
        ids = {p.provision_id for p in template.provisions}
        assert "article-3-49" in ids

    def test_per_provision_effective_dates_present(self, template: Template) -> None:
        # Each provision carries its own effective_date rather than relying on
        # a single default (§5.7: per-provision effective dates with status).
        dates = {p.provision_id: p.effective_date for p in template.provisions}
        assert dates["article-73"] is not None

    def test_annex_dates_with_pending_status(self, template: Template) -> None:
        # The Annex III / Annex I dates carry `pending-final-adoption` status
        # pending the Digital Omnibus (§5.7 / Appendix E Q7).
        statuses: set[str] = set()
        annex_dates: set[str] = set()
        for prov in template.provisions:
            tr = prov.tiered_requirements or {}
            adoption = tr.get("adoption")
            if adoption is not None:
                statuses.add(adoption.get("status", ""))
                # Both deferred Annex dates are carried in dedicated fields so a
                # validator can distinguish the Annex III vs Annex I postponement.
                annex_dates.add(adoption.get("annex_iii_effective_date", ""))
                annex_dates.add(adoption.get("annex_i_effective_date", ""))
        # At least one provision must record the pending-final-adoption status
        # and BOTH deferred Annex dates.
        assert "pending-final-adoption" in statuses
        assert ANNEX_III_EFFECTIVE_DATE in annex_dates
        assert ANNEX_I_EFFECTIVE_DATE in annex_dates


# ── Required-field DSL rules (field_present / exists_where) ──


class TestRequiredFieldRules:
    def _all_rules(self, template: Template) -> list[Any]:
        rules: list[Any] = []
        for prov in template.provisions:
            rules.extend(prov.evaluation)
        return rules

    def _fields_for_operator(self, template: Template, operator: str) -> set[str]:
        fields: set[str] = set()
        for rule in self._all_rules(template):
            if rule.rule == operator:
                fld = rule.params.get("field")
                if fld:
                    fields.add(fld)
        return fields

    def test_requires_public_incident_id(self, template: Template) -> None:
        fields = self._fields_for_operator(template, "field_present")
        assert "/payload/public_incident_id" in fields

    def test_requires_trigger_array(self, template: Template) -> None:
        fields = self._fields_for_operator(template, "field_present")
        assert "/payload/taxonomy_crosswalk/eu_ai_act/serious_incident_triggers" in fields

    def test_requires_widespread_and_death_facts(self, template: Template) -> None:
        fields = self._fields_for_operator(template, "field_present")
        assert "/payload/taxonomy_crosswalk/eu_ai_act/widespread" in fields
        assert "/payload/taxonomy_crosswalk/eu_ai_act/death_involved" in fields

    def test_requires_regulatory_and_notification_timeline(self, template: Template) -> None:
        present = self._fields_for_operator(template, "field_present")
        exists = {r.params.get("field") for r in self._all_rules(template) if r.rule == "exists_where"}
        all_fields = present | {f for f in exists if f}
        assert "/payload/coordinated_disclosure/regulatory_timeline" in all_fields
        assert "/payload/notification_timeline" in all_fields

    def test_all_operators_are_known(self, template: Template) -> None:
        known = {
            "has_record_type",
            "field_present",
            "field_value",
            "evidence_freshness",
            "attachment_exists",
            "entity_linked",
            "exists_where",
            "attachment_kind_exists",
            "bundle_signed",
            "record_attested",
        }
        for rule in self._all_rules(template):
            assert rule.rule in known, f"unknown operator {rule.rule!r}"

    def test_rule_ids_unique(self, template: Template) -> None:
        ids = [r.rule_id for r in self._all_rules(template)]
        assert len(ids) == len(set(ids))


# ── The shortest-applicable-clock metadata + evaluation ──


class TestReportingClockMetadata:
    def test_clock_spec_present(self, template: Template) -> None:
        spec = _clock_spec(template)
        assert spec["default_days"] == DEFAULT_CLOCK_DAYS
        # The clock keys on death_involved, 3.49.b, and widespread.
        rule_days = {r["days"] for r in spec["rules"]}
        assert DEATH_CLOCK_DAYS in rule_days
        assert CRITICAL_OR_WIDESPREAD_CLOCK_DAYS in rule_days

    def test_clock_source_paths_documented(self, template: Template) -> None:
        # The template documents BOTH fact-source paths (§5.7): confidential
        # card_source vs public taxonomy_crosswalk.
        spec = _clock_spec(template)
        sources = spec["fact_sources"]
        assert "card_source.eu_ai_act_facts" in sources["confidential"]
        assert "taxonomy_crosswalk.eu_ai_act" in sources["public"]


class TestShortestApplicableClock:
    """Each Art. 73 clock branch computed from representative incident facts."""

    def test_branch_death_with_other_triggers_is_10_days(self, template: Template) -> None:
        # (a) death_involved: true (+ a non-fatal trigger) → 10 days.
        spec = _clock_spec(template)
        facts = {
            "serious_incident_triggers": ["3.49.a", "3.49.d"],
            "widespread": False,
            "death_involved": True,
        }
        assert _shortest_applicable_clock(spec, facts) == DEATH_CLOCK_DAYS

    def test_branch_critical_infrastructure_only_is_2_days(self, template: Template) -> None:
        # (b) 3.49.b only → 2 days.
        spec = _clock_spec(template)
        facts = {
            "serious_incident_triggers": ["3.49.b"],
            "widespread": False,
            "death_involved": False,
        }
        assert _shortest_applicable_clock(spec, facts) == CRITICAL_OR_WIDESPREAD_CLOCK_DAYS

    def test_branch_widespread_only_is_2_days(self, template: Template) -> None:
        # (b') widespread only → 2 days.
        spec = _clock_spec(template)
        facts = {
            "serious_incident_triggers": ["3.49.c"],
            "widespread": True,
            "death_involved": False,
        }
        assert _shortest_applicable_clock(spec, facts) == CRITICAL_OR_WIDESPREAD_CLOCK_DAYS

    def test_branch_plain_non_fatal_3_49_a_is_15_days(self, template: Template) -> None:
        # (c) plain 3.49.a non-fatal serious-health-harm → 15 days.
        spec = _clock_spec(template)
        facts = {
            "serious_incident_triggers": ["3.49.a"],
            "widespread": False,
            "death_involved": False,
        }
        assert _shortest_applicable_clock(spec, facts) == DEFAULT_CLOCK_DAYS

    def test_branch_compound_death_and_critical_is_2_days(self, template: Template) -> None:
        # (d) COMPOUND death + 3.49.b → 2 days (shortest wins: min(10, 2)).
        spec = _clock_spec(template)
        facts = {
            "serious_incident_triggers": ["3.49.a", "3.49.b"],
            "widespread": False,
            "death_involved": True,
        }
        assert _shortest_applicable_clock(spec, facts) == CRITICAL_OR_WIDESPREAD_CLOCK_DAYS

    def test_branch_compound_death_and_widespread_is_2_days(self, template: Template) -> None:
        # (e) COMPOUND death + widespread → 2 days (shortest wins: min(10, 2)).
        spec = _clock_spec(template)
        facts = {
            "serious_incident_triggers": ["3.49.a"],
            "widespread": True,
            "death_involved": True,
        }
        assert _shortest_applicable_clock(spec, facts) == CRITICAL_OR_WIDESPREAD_CLOCK_DAYS

    def test_branch_no_triggers_falls_back_to_15_days(self, template: Template) -> None:
        # Defensive: an empty/unknown trigger set still yields the 15-day default.
        spec = _clock_spec(template)
        facts: dict[str, Any] = {
            "serious_incident_triggers": [],
            "widespread": False,
            "death_involved": False,
        }
        assert _shortest_applicable_clock(spec, facts) == DEFAULT_CLOCK_DAYS

    def test_branch_3_49_d_non_fatal_is_15_days(self, template: Template) -> None:
        # 3.49.d (fundamental-rights harm) alone, non-fatal → 15 days.
        spec = _clock_spec(template)
        facts = {
            "serious_incident_triggers": ["3.49.d"],
            "widespread": False,
            "death_involved": False,
        }
        assert _shortest_applicable_clock(spec, facts) == DEFAULT_CLOCK_DAYS


# ── Determinism (§5.10) ──


class TestDeterminism:
    def test_template_round_trip_is_byte_stable(self, raw_template: dict[str, Any]) -> None:
        # The on-disk JSON parses and the canonical digest is reproducible — no
        # wall-clock, no random ordering (§5.10).
        first = compute_template_digest(TEMPLATE_ID)
        second = compute_template_digest(TEMPLATE_ID)
        assert first == second
        assert raw_template["template_id"] == TEMPLATE_ID
