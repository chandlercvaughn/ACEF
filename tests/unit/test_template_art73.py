"""Unit tests for the EU Art. 73 incident-reporting crosswalk template.

Feature F-M3-TEMPLATE-ART73 / assertion VAL-TMPL-001.

Honesty correction (roborev, codex). The ACEF generic rule DSL CANNOT express
the three load-bearing Art. 73 enforcement checks:

1. **existential dual-source** — "at least ONE valid evidence path exists" with
   the trigger facts present on EITHER ``incident_card.taxonomy_crosswalk.eu_ai_act``
   (public) OR ``incident_report.card_source.eu_ai_act_facts`` (confidential);
2. **regulatory_timeline framework-match** — "some ``regulatory_timeline[]`` entry
   has ``framework == 'eu-ai-act-art73'``" (an order-insensitive array-element scan
   by a field predicate);
3. **shortest-clock + ACEF-084** — "the stated deadline matches the shortest
   applicable clock (death→10 / 3.49.b|widespread→2 / else→15)".

``field_present`` is a UNIVERSAL operator (PASS vacuously on zero records), so a
pair of ``field_present`` rules — one targeting ``incident_card`` and one targeting
``incident_report`` — is NOT a real OR: an EMPTY bundle (no incident evidence at
all) passes BOTH vacuously (false green), and ``field_present`` accepts an empty
``regulatory_timeline: []``. ``exists_where`` resolves a single RFC-6901 pointer per
record and ``jsonpointer`` has no array-wildcard, so no operator can scan
order-insensitive array entries by a ``framework`` predicate, and no operator can
COMPUTE a derived deadline. Encoding (1)/(2) as vacuous ``field_present`` pairs is
worse than nothing — it gives a false green.

Per RFC-0002 §5.7 (line 270/278) the matching-entry / deadline-consistency /
shortest-clock enforcement is therefore DELEGATED to the validator
(F-M3-VALIDATOR-RULES, assertion VAL-CLOCK-001), which raises ACEF-084 on mismatch.
The template (a) DECLARES the structured shortest-clock metadata the validator
reads, (b) keeps ONLY the DSL rules that are CORRECTLY expressible as per-record
conditionals, and (c) DOCUMENTS the validator-delegated checks explicitly so the
delegation is a pinned, honest contract — not a silent hole.

This test:
- asserts the template loads through the registry and is binding EU law;
- asserts the per-provision effective dates + ``pending-final-adoption`` status;
- reads the ``reporting_clock`` metadata and evaluates the shortest-applicable-clock
  algorithm against representative incident facts, asserting each branch's deadline
  (VAL-TMPL-001's core evidence);
- asserts the retained DSL rules behave CORRECTLY (no vacuous-OR false green, no
  hard-coded array index, ``notification_timeline`` targets ``incident_report``);
- pins the template's documentation of the three validator-delegated Art. 73 checks.

It does NOT re-implement the Art. 73 ACEF-084 enforcement (that is the validator's
job, F-M3-VALIDATOR-RULES).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acef.models.records import EntityRefs, RecordEnvelope
from acef.templates.models import Template
from acef.templates.registry import (
    compute_template_digest,
    list_templates,
    load_template,
)
from acef.validation.operators import OPERATOR_REGISTRY

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


# ── Retained DSL rules: only what the generic DSL can CORRECTLY enforce ──


class TestRetainedDslRules:
    """The template retains ONLY DSL rules that are correct per-record conditionals.

    The vacuous-truth ``field_present`` pairs that *appeared* to enforce the
    existential dual-source OR and the ``regulatory_timeline`` framework-match are
    REMOVED — they gave a false green (an empty bundle passed them all). The
    surviving rules are honest: each validates a field on the record type that
    actually carries it, with no cross-applying, no index-0 logic, and no false
    existential claim.
    """

    def _all_rules(self, template: Template) -> list[Any]:
        rules: list[Any] = []
        for prov in template.provisions:
            rules.extend(prov.evaluation)
        return rules

    def _fail_rules(self, template: Template) -> list[Any]:
        return [r for r in self._all_rules(template) if r.severity == "fail"]

    def _fields_for_record_type(self, template: Template, record_type: str) -> set[str]:
        fields: set[str] = set()
        for rule in self._all_rules(template):
            if rule.params.get("record_type") == record_type:
                fld = rule.params.get("field")
                if fld:
                    fields.add(fld)
        return fields

    def test_notification_timeline_targets_incident_report_only(self, template: Template) -> None:
        # notification_timeline[] is a top-level field on incident_report
        # (incident_report.schema.json), NOT on the CLOSED incident_card schema.
        # A field_present rule over incident_report is a CORRECT per-record
        # conditional (IF a report exists, it carries notification_timeline) — it
        # does NOT participate in the (removed) vacuous dual-source OR.
        card_fields = self._fields_for_record_type(template, "incident_card")
        report_fields = self._fields_for_record_type(template, "incident_report")
        assert "/payload/notification_timeline" not in card_fields, (
            "incident_card is a closed schema with no notification_timeline field"
        )
        assert "/payload/notification_timeline" in report_fields

    def test_no_vacuous_dual_source_field_present_pairs(self, template: Template) -> None:
        # The DSL-inexpressible existential dual-source OR (trigger array / widespread
        # / death_involved / public_incident_id / regulatory_timeline on EITHER the
        # public card OR the confidential card_source) is REMOVED, not encoded as a
        # vacuous field_present pair. None of those broken fields may survive as a
        # field_present rule on either path.
        banned_field_present_fields = {
            "/payload/public_incident_id",
            "/payload/card_source/public_incident_id",
            "/payload/taxonomy_crosswalk/eu_ai_act/serious_incident_triggers",
            "/payload/card_source/eu_ai_act_facts/serious_incident_triggers",
            "/payload/taxonomy_crosswalk/eu_ai_act/widespread",
            "/payload/card_source/eu_ai_act_facts/widespread",
            "/payload/taxonomy_crosswalk/eu_ai_act/death_involved",
            "/payload/card_source/eu_ai_act_facts/death_involved",
            "/payload/coordinated_disclosure/regulatory_timeline",
            "/payload/card_source/coordinated_disclosure/regulatory_timeline",
        }
        for rule in self._all_rules(template):
            if rule.rule == "field_present":
                fld = rule.params.get("field", "")
                assert fld not in banned_field_present_fields, (
                    f"rule {rule.rule_id!r} re-introduces a vacuous-truth field_present over "
                    f"{fld!r}; the existential dual-source OR is DSL-inexpressible and is "
                    "delegated to F-M3-VALIDATOR-RULES (ACEF-084), not encoded vacuously"
                )

    def test_no_rule_hard_codes_regulatory_timeline_index(self, template: Template) -> None:
        # No retained rule may key on a hard-coded array index (e.g. /0/...): such a
        # rule wrongly rejects a valid multi-jurisdiction timeline whose EU entry is
        # not first (order-insensitive array, §5.10).
        for rule in self._all_rules(template):
            fld = rule.params.get("field", "")
            assert "/regulatory_timeline/0/" not in fld, (
                f"rule {rule.rule_id!r} hard-codes regulatory_timeline index 0 — order-insensitive array (§5.10)"
            )

    def test_no_rule_keys_on_wrong_timeline_field(self, template: Template) -> None:
        # regulatory_timeline[] entries key on `framework`, never `jurisdiction`
        # (coordinated_disclosure.schema.json).
        for rule in self._all_rules(template):
            fld = rule.params.get("field", "")
            assert "/regulatory_timeline" not in fld or "/jurisdiction" not in fld, (
                f"rule {rule.rule_id!r} references regulatory_timeline[].jurisdiction; the schema field is `framework`"
            )

    def test_no_hard_record_count_blocks_confidential_path(self, template: Template) -> None:
        # A confidential, reserved-id Art.73 filing has NO public incident_card
        # (§5.7 critical path). No `has_record_type incident_card` fail-rule may
        # demand one, or it would reject the load-bearing confidential path.
        for rule in self._all_rules(template):
            if rule.rule == "has_record_type" and rule.params.get("type") == "incident_card":
                assert rule.severity != "fail", (
                    f"rule {rule.rule_id!r} hard-requires a public incident_card at "
                    "fail severity, blocking the confidential card_source Art.73 path (§5.7)"
                )

    def test_all_operators_are_known(self, template: Template) -> None:
        known = set(OPERATOR_REGISTRY.keys())
        for rule in self._all_rules(template):
            assert rule.rule in known, f"unknown operator {rule.rule!r}"

    def test_rule_ids_unique(self, template: Template) -> None:
        ids = [r.rule_id for r in self._all_rules(template)]
        assert len(ids) == len(set(ids))

    def test_retained_rules_have_messages(self, template: Template) -> None:
        for rule in self._all_rules(template):
            assert rule.message.strip(), f"rule {rule.rule_id!r} has an empty message"


# ── The retained rules behave correctly through the REAL DSL operators ──


def _make_record(record_type: str, payload: dict[str, Any]) -> RecordEnvelope:
    return RecordEnvelope(
        record_type=record_type,
        payload=payload,
        entity_refs=EntityRefs(),
        timestamp="2025-06-01T00:00:00Z",
    )


_VALID_AIIC_ID = "AIIC-ACME-2026-0123456789ABCDEFGHJKMNPQRS"


def _confidential_report() -> RecordEnvelope:
    """A RESERVED-id confidential Art.73 incident_report with NO public card.

    Carries the card_source overlay (the §5.7 confidential/source-backed path) and
    a top-level notification_timeline[] (the only field the retained DSL rules
    enforce on incident_report).
    """
    return _make_record(
        "incident_report",
        {
            "incident_type": "safety",
            "severity": "critical",
            "description": "confidential serious incident",
            "card_source": {
                "public_incident_id": _VALID_AIIC_ID,
                "id_grade": "self-asserted",
                "id_state": "RESERVED",
                "eu_ai_act_facts": {
                    "edition": "reg-2024-1689",
                    "serious_incident_triggers": ["3.49.a"],
                    "widespread": False,
                    "death_involved": True,
                },
                "coordinated_disclosure": {
                    "status": "private",
                    "regulatory_timeline": [
                        {
                            "framework": "eu-ai-act-art73",
                            "clock_model": "awareness_days",
                            "awareness_date": "2026-09-01T00:00:00Z",
                        }
                    ],
                },
            },
            "notification_timeline": [
                {"recipient": "national authority", "notification_date": "2026-09-05T00:00:00Z"},
            ],
        },
    )


class TestRetainedRuleEvaluation:
    """Evaluate the retained fail-severity rules through the real DSL operators.

    Rules are evaluated via :data:`OPERATOR_REGISTRY` — the same operator functions
    the validation engine uses — not a re-implementation.
    """

    def _failed_fail_rule_ids(self, template: Template, records: list[RecordEnvelope]) -> list[str]:
        return self._failed_rule_ids(template, records, "fail")

    def _failed_rule_ids(self, template: Template, records: list[RecordEnvelope], severity: str) -> list[str]:
        failed: list[str] = []
        for prov in template.provisions:
            for rule in prov.evaluation:
                if rule.severity != severity:
                    continue
                op = OPERATOR_REGISTRY[rule.rule]
                passed, _ = op(rule.params, records)
                if not passed:
                    failed.append(rule.rule_id)
        return failed

    def test_incident_report_without_notification_timeline_is_advisory_not_fail(self, template: Template) -> None:
        # Task #35: notification_timeline[] is a POST-FILING record (the
        # awareness->report->authority-notification chain) an exporter cannot populate
        # without fabricating a notification_date, so its presence check is ADVISORY
        # (warning), NOT fail-blocking — the BINDING Art.73 obligation is the delegated
        # ACEF-084 shortest-clock/dual-source check. A report missing notification_timeline
        # therefore trips NO fail-severity rule (it MUST NOT block the confidential §5.7
        # path), but DOES still trip the notification_timeline WARNING.
        report = _make_record(
            "incident_report",
            {
                "incident_type": "safety",
                "severity": "critical",
                "description": "report with no notification_timeline",
                "card_source": {"public_incident_id": _VALID_AIIC_ID, "id_grade": "self-asserted"},
            },
        )
        assert self._failed_fail_rule_ids(template, [report]) == [], (
            "a missing notification_timeline must NOT trip a fail-severity rule (it is advisory)"
        )
        assert "art73-notification-timeline-present" in self._failed_rule_ids(template, [report], "warning"), (
            "a missing notification_timeline must still trip the advisory WARNING rule"
        )

    def test_confidential_report_with_notification_timeline_passes_retained_rules(self, template: Template) -> None:
        # A complete confidential report (with notification_timeline) satisfies the
        # retained fail-severity rules — the retained rules do NOT block the §5.7
        # confidential path. (The existential dual-source / ACEF-084 enforcement is
        # the validator's job, not these rules.)
        assert self._failed_fail_rule_ids(template, [_confidential_report()]) == []


# ── Validator-delegated Art. 73 enforcement is DOCUMENTED (pinned contract) ──


class TestDelegatedEnforcementDocumented:
    """The three DSL-inexpressible Art. 73 checks are documented as delegated.

    This pins the honest delegation: the template states WHICH checks the validator
    (F-M3-VALIDATOR-RULES) performs and WHY the DSL cannot, so the delegation is a
    visible contract rather than a silent hole.
    """

    def _delegation_note(self, raw_template: dict[str, Any]) -> str:
        prov = next(p for p in raw_template["provisions"] if p["provision_id"] == "article-73")
        note = prov.get("validator_delegated_enforcement")
        assert note is not None, "article-73 provision must document validator_delegated_enforcement"
        return json.dumps(note)

    def test_delegation_block_present_and_pins_acef_084(self, raw_template: dict[str, Any]) -> None:
        prov = next(p for p in raw_template["provisions"] if p["provision_id"] == "article-73")
        block = prov.get("validator_delegated_enforcement")
        assert block is not None
        # The block names the owning feature and the error code.
        text = json.dumps(block)
        assert "F-M3-VALIDATOR-RULES" in text
        assert "ACEF-084" in text
        assert "§5.7" in text or "5.7" in text

    def test_delegation_block_lists_three_checks(self, raw_template: dict[str, Any]) -> None:
        prov = next(p for p in raw_template["provisions"] if p["provision_id"] == "article-73")
        block = prov["validator_delegated_enforcement"]
        checks = block["checks"]
        # All three DSL-inexpressible checks are enumerated.
        ids = {c["id"] for c in checks}
        assert {
            "existential-dual-source",
            "regulatory-timeline-framework-match",
            "shortest-clock-deadline-consistency",
        } <= ids
        # Each check states it is enforced by the validator, not the template DSL,
        # and explains why the DSL cannot express it.
        for check in checks:
            assert check["enforced_by"] == "F-M3-VALIDATOR-RULES"
            assert check["dsl_expressible"] is False
            assert check["reason"].strip()

    def test_delegation_block_names_both_fact_source_paths(self, raw_template: dict[str, Any]) -> None:
        note = self._delegation_note(raw_template)
        # The §5.7 dual fact-source rule is documented as the validator's input.
        assert "card_source.eu_ai_act_facts" in note
        assert "taxonomy_crosswalk.eu_ai_act" in note


# ── The shortest-applicable-clock metadata + evaluation (VAL-TMPL-001 core) ──


class TestReportingClockMetadata:
    def test_clock_spec_present(self, template: Template) -> None:
        spec = _clock_spec(template)
        assert spec["default_days"] == DEFAULT_CLOCK_DAYS
        # The clock keys on death_involved, 3.49.b, and widespread.
        rule_days = {r["days"] for r in spec["rules"]}
        assert DEATH_CLOCK_DAYS in rule_days
        assert CRITICAL_OR_WIDESPREAD_CLOCK_DAYS in rule_days

    def test_clock_selection_is_shortest_applicable(self, template: Template) -> None:
        spec = _clock_spec(template)
        assert spec["selection"] == "shortest-applicable"

    def test_clock_error_on_mismatch_is_acef_084(self, template: Template) -> None:
        # The clock metadata names the error the validator raises on a mismatch.
        spec = _clock_spec(template)
        assert spec["error_on_mismatch"] == "ACEF-084"

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
        # 3.49.d (property/environment harm) alone, non-fatal → 15 days.
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
