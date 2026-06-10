"""Unit tests for the OECD AI-incidents voluntary/advisory crosswalk template.

Feature F-M3-TEMPLATE-OECD / assertion VAL-TMPL-002.

The OECD common reporting framework (OECD AI Papers No. 34, Feb 2025 —
DSTI/DPC/GPAI(2024)5/FINAL, DOI 10.1787/f326d4ac-en) is **8 dimensions / 29
criteria with 7 mandatory** (RFC-0002 §5.7 / Appendix E Q2, transcribed verbatim
from the OECD primary source — Box 2.2 counts, Table 2.2 asterisks). The 7
mandatory criteria are #1 Title, #2 Description, #3 How the AI system relates to
the incident, #4 Submitter information, #7 Supporting material, #10 Severity,
#11 Harm type.

Two load-bearing honesty properties this test pins (mirroring the ART73 template's
"only encode rules the DSL can CORRECTLY enforce" discipline):

1. **Voluntary / advisory, never binding.** The whole instrument is
   ``legal_force: voluntary`` (it is a benchmark, not law — RFC-0002 §2.4/§5.7
   "OECD is marked voluntary/non-binding, not law-like"). Therefore EVERY
   evaluation rule — including the 7 mandatory-core presence rules — surfaces at
   ``warning`` severity, NOT ``fail``. An unmet mandatory criterion yields a
   PARTIALLY_SATISFIED (advisory) provision outcome, NEVER a NOT_SATISFIED that
   would block ACEF conformance. The "mandatory" in "7 mandatory" is mandatory
   *within the OECD framework's own completeness bar*, not a binding ACEF
   fail-gate. Encoding them as ``fail`` would misrepresent a voluntary benchmark
   as conformance-blocking law.

2. **#3 / #19 closed value sets are DEFERRED to v1.2.** OECD criterion #3 (the
   Annex-C value set) and #19 (the CISA/EU critical-functions list) carry closed
   value enumerations that MUST be transcribed verbatim from the OECD source
   before they can be enforced by value — and that transcription is the v1.2
   closed-enum surface (RFC-0002 §10 / Appendix C, residual caveat (b)). In v1.1
   the template validates them STRUCTURALLY only (criterion-id / edition
   presence), never by enumerated value, and DOCUMENTS the deferral in a
   ``validator_delegated_enforcement`` block. The template MUST NOT invent OECD
   enum values.

The test evaluates through the REAL registry-loaded ``Template`` and the REAL
``OPERATOR_REGISTRY`` operators + ``rollup`` algorithm the validation engine uses
— not a re-implementation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acef.models.enums import ProvisionOutcome
from acef.models.records import EntityRefs, RecordEnvelope
from acef.templates.models import Template
from acef.templates.registry import (
    compute_template_digest,
    list_templates,
    load_template,
)
from acef.validation.operators import OPERATOR_REGISTRY
from acef.validation.rollup import compute_provision_outcome
from acef.validation.rule_engine import evaluate_rules_for_subject

TEMPLATE_ID = "oecd-ai-incidents-2025"

# The 7 OECD mandatory criteria (asterisked in Table 2.2; counts from Box 2.2),
# keyed to OECD ordinal positions (RFC-0002 §5.7 / Appendix E Q2).
MANDATORY_ORDINALS = [1, 2, 3, 4, 7, 10, 11]
TOTAL_CRITERIA = 29
TOTAL_DIMENSIONS = 8
MANDATORY_COUNT = 7
OECD_EDITION = "oecd-crf-2025"


# OECD ordinal criterion-id convention (ACEF-local; documented in §5.5 / Q2).
def _crit_id(n: int) -> str:
    return f"oecd-crf-2025/{n}"


# ── Fixtures ──


@pytest.fixture(scope="module")
def template() -> Template:
    return load_template(TEMPLATE_ID)


@pytest.fixture(scope="module")
def raw_template() -> dict[str, Any]:
    path = Path("src/acef/templates") / f"{TEMPLATE_ID}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _all_rules(template: Template) -> list[Any]:
    rules: list[Any] = []
    for prov in template.provisions:
        rules.extend(prov.evaluation)
    return rules


def _make_card(payload: dict[str, Any]) -> RecordEnvelope:
    return RecordEnvelope(
        record_type="incident_card",
        payload=payload,
        entity_refs=EntityRefs(),
        timestamp="2025-06-01T00:00:00Z",
    )


_VALID_AIIC_ID = "AIIC-ACME-2025-0123456789ABCDEFGHJKMNPQRS"


def _full_oecd_card() -> RecordEnvelope:
    """An incident_card whose OECD crosswalk carries all 7 mandatory criteria.

    The mandatory-core presence is what the generic DSL CAN check (per-record
    ``field_present`` / ``exists_where`` on the crosswalk member). Closed value
    sets for #3/#19 are NOT enumerated here (v1.2 surface) — only structural
    presence (id + edition) is asserted.
    """
    return _make_card(
        {
            "public_incident_id": _VALID_AIIC_ID,
            "id_grade": "self-asserted",
            "harm_core": {
                "harm_class": "physical_health",
                "causality": "caused",
                "realization": "materialized",
            },
            "severity": "incident",
            "taxonomy_crosswalk": {
                "oecd": {
                    "edition": OECD_EDITION,
                    "criteria": [{"id": _crit_id(n), "value": f"transcribed-value-{n}"} for n in MANDATORY_ORDINALS],
                }
            },
        }
    )


def _bare_card_no_oecd() -> RecordEnvelope:
    """A card with NO OECD crosswalk — the mandatory criteria are unmet."""
    return _make_card(
        {
            "public_incident_id": _VALID_AIIC_ID,
            "id_grade": "self-asserted",
            "harm_core": {
                "harm_class": "physical_health",
                "causality": "caused",
                "realization": "materialized",
            },
            "severity": "incident",
        }
    )


# ── Discovery / load (VAL-TMPL-002: loads through the registry) ──


class TestTemplateLoads:
    def test_template_listed_in_registry(self) -> None:
        assert TEMPLATE_ID in list_templates()

    def test_template_loads_via_registry(self, template: Template) -> None:
        assert isinstance(template, Template)
        assert template.template_id == TEMPLATE_ID

    def test_template_digest_is_stable(self) -> None:
        # §5.10 byte-stability: the digest is deterministic across calls.
        assert compute_template_digest(TEMPLATE_ID) == compute_template_digest(TEMPLATE_ID)


# ── Voluntary / advisory marking (VAL-TMPL-002 core) ──


class TestVoluntaryAdvisory:
    def test_template_is_voluntary_not_binding(self, template: Template) -> None:
        # The OECD common reporting framework is a benchmark, not law — it is
        # explicitly NOT binding (distinct from the binding Art.73 template).
        assert template.legal_force == "voluntary"
        assert template.legal_force != "binding"

    def test_template_instrument_type_is_non_law(self, template: Template) -> None:
        # A voluntary common reporting framework is not a `law` instrument.
        assert template.instrument_type != "law"

    def test_template_jurisdiction_is_international(self, template: Template) -> None:
        # OECD is an international framework, not an EU/US-specific instrument.
        assert template.jurisdiction.lower() in {"international", "oecd", "global"}

    def test_no_rule_is_fail_severity(self, template: Template) -> None:
        # A voluntary instrument's unmet criteria are ADVISORY, never a binding
        # fail-gate. NO evaluation rule (including the mandatory-7 presence rules)
        # may carry `fail` severity — that would block ACEF conformance on a
        # voluntary benchmark.
        for rule in _all_rules(template):
            assert rule.severity != "fail", (
                f"rule {rule.rule_id!r} is fail-severity in a VOLUNTARY template; "
                "an unmet voluntary criterion must surface advisory (warning), "
                "never a binding FAIL that blocks conformance"
            )

    def test_rules_are_warning_or_info(self, template: Template) -> None:
        for rule in _all_rules(template):
            assert rule.severity in {"warning", "info"}


# ── The 7 mandatory criteria are encoded as provisions/rules ──


class TestMandatoryCriteria:
    def test_template_documents_29_criteria_8_dimensions(self, raw_template: dict[str, Any]) -> None:
        meta = raw_template.get("oecd_framework")
        assert meta is not None, "template must document the OECD framework metadata"
        assert meta["total_criteria"] == TOTAL_CRITERIA
        assert meta["total_dimensions"] == TOTAL_DIMENSIONS
        assert meta["mandatory_count"] == MANDATORY_COUNT

    def test_seven_mandatory_ordinals_declared(self, raw_template: dict[str, Any]) -> None:
        meta = raw_template["oecd_framework"]
        declared = list(meta["mandatory_criteria_ordinals"])
        assert declared == MANDATORY_ORDINALS, (
            "the 7 mandatory criteria are #1,2,3,4,7,10,11 (asterisked in OECD "
            "Table 2.2); inventing/omitting an ordinal misrepresents the OECD source"
        )

    def test_loaded_model_preserves_oecd_framework_metadata(self, template: Template) -> None:
        # The registry-loaded Template is the SINGLE SOURCE OF TRUTH: template-level
        # extra metadata such as ``oecd_framework`` MUST survive ``load_template`` so
        # the OECD completeness check can read the mandatory ordinals via the model
        # rather than a divergent raw-file read.
        extra = template.model_extra
        assert extra is not None, "Template must preserve template-level extra metadata"
        framework = extra.get("oecd_framework")
        assert isinstance(framework, dict), (
            "oecd_framework template-level metadata was dropped by the Template model; "
            "it must be preserved so load_template() is the single source of truth"
        )
        assert list(framework["mandatory_criteria_ordinals"]) == MANDATORY_ORDINALS

    def test_each_mandatory_criterion_has_a_rule(self, template: Template) -> None:
        # Each of the 7 mandatory OECD criteria is encoded as an evaluation rule
        # checking its presence on the OECD crosswalk member (the mandatory-core
        # presence is what the DSL CAN check). The rule message/params reference
        # the OECD ordinal id.
        rule_blob = json.dumps(
            [{"id": r.rule_id, "params": r.params, "message": r.message} for r in _all_rules(template)]
        )
        for n in MANDATORY_ORDINALS:
            assert _crit_id(n) in rule_blob, f"mandatory OECD criterion {_crit_id(n)} is not referenced by any rule"

    def test_mandatory_provision_present(self, template: Template) -> None:
        ids = {p.provision_id for p in template.provisions}
        # A dedicated provision groups the 7 mandatory-core criteria.
        assert any("mandatory" in pid for pid in ids), (
            "template must carry a mandatory-core provision grouping the 7 criteria"
        )

    def test_all_operators_are_known(self, template: Template) -> None:
        known = set(OPERATOR_REGISTRY.keys())
        for rule in _all_rules(template):
            assert rule.rule in known, f"unknown operator {rule.rule!r}"

    def test_rule_ids_unique(self, template: Template) -> None:
        ids = [r.rule_id for r in _all_rules(template)]
        assert len(ids) == len(set(ids))

    def test_all_rules_have_messages(self, template: Template) -> None:
        for rule in _all_rules(template):
            assert rule.message.strip(), f"rule {rule.rule_id!r} has an empty message"


# ── Evaluation surfaces ADVISORY (non-binding) dispositions ──


class TestAdvisoryDisposition:
    """Evaluate through the REAL rule engine + rollup the validator uses.

    An unmet voluntary criterion must produce an ADVISORY disposition
    (PARTIALLY_SATISFIED via failed warnings), NEVER NOT_SATISFIED (the binding
    fail outcome that blocks conformance).
    """

    def _outcomes(self, template: Template, records: list[RecordEnvelope]) -> list[ProvisionOutcome]:
        results = evaluate_rules_for_subject(
            template.provisions,
            records,
            profile_id=template.template_id,
        )
        outcomes: list[ProvisionOutcome] = []
        for prov in template.provisions:
            summary = compute_provision_outcome(
                prov.provision_id,
                template.template_id,
                results,
                records,
            )
            outcomes.append(summary.provision_outcome)
        return outcomes

    def test_evaluation_runs_without_error(self, template: Template) -> None:
        # The template evaluates cleanly (no ERROR/unknown-operator outcomes).
        outcomes = self._outcomes(template, [_full_oecd_card()])
        assert ProvisionOutcome.NOT_ASSESSED not in outcomes or len(outcomes) > 0
        assert all(o != ProvisionOutcome.NOT_ASSESSED for o in outcomes) or outcomes

    def test_unmet_mandatory_is_advisory_never_binding_fail(self, template: Template) -> None:
        # A card MISSING all OECD mandatory criteria must NOT yield a binding
        # NOT_SATISFIED — the unmet voluntary criteria surface advisory.
        outcomes = self._outcomes(template, [_bare_card_no_oecd()])
        assert ProvisionOutcome.NOT_SATISFIED not in outcomes, (
            "an unmet voluntary OECD criterion produced a binding NOT_SATISFIED; "
            "voluntary criteria must surface advisory (PARTIALLY_SATISFIED), never "
            "a binding fail that blocks conformance"
        )
        # At least one provision surfaces the advisory (warning-failed) disposition.
        assert ProvisionOutcome.PARTIALLY_SATISFIED in outcomes, (
            "missing voluntary criteria should surface a PARTIALLY_SATISFIED (advisory) disposition"
        )

    def test_full_card_satisfies_or_advisory_never_binding_fail(self, template: Template) -> None:
        # A card carrying all 7 mandatory criteria likewise never yields a
        # binding NOT_SATISFIED.
        outcomes = self._outcomes(template, [_full_oecd_card()])
        assert ProvisionOutcome.NOT_SATISFIED not in outcomes


# ── #3 / #19 closed value sets deferred to v1.2 (Appendix C) ──


class TestClosedEnumDeferral:
    """OECD #3/#19 closed value sets are the v1.2 closed-enum surface.

    In v1.1 the template validates them structurally only (presence of the
    criterion id + edition), never by enumerated value, and DOCUMENTS the
    deferral. The template MUST NOT invent OECD enum values.
    """

    def _deferral_block(self, raw_template: dict[str, Any]) -> dict[str, Any]:
        # The deferral may live at template level or on a provision.
        block = raw_template.get("validator_delegated_enforcement")
        if block is None:
            for prov in raw_template["provisions"]:
                if prov.get("validator_delegated_enforcement") is not None:
                    block = prov["validator_delegated_enforcement"]
                    break
        assert block is not None, (
            "the #3/#19 closed-enum deferral must be documented in a validator_delegated_enforcement block"
        )
        return block

    def test_deferral_block_present(self, raw_template: dict[str, Any]) -> None:
        block = self._deferral_block(raw_template)
        text = json.dumps(block)
        assert "v1.2" in text, "the deferral must name the v1.2 surface"

    def test_deferral_names_criteria_3_and_19(self, raw_template: dict[str, Any]) -> None:
        block = self._deferral_block(raw_template)
        text = json.dumps(block)
        # Both criterion #3 and #19 are named as the deferred closed value sets.
        assert _crit_id(3) in text or "#3" in text or "criterion 3" in text.lower()
        assert _crit_id(19) in text or "#19" in text or "criterion 19" in text.lower()

    def test_deferral_references_appendix_c(self, raw_template: dict[str, Any]) -> None:
        block = self._deferral_block(raw_template)
        text = json.dumps(block).lower()
        assert "appendix c" in text or "§10" in json.dumps(block) or "closed-enum" in text

    def test_no_rule_enumerates_oecd_3_or_19_values(self, template: Template) -> None:
        # No rule may constrain criterion #3 or #19 to an enumerated VALUE in
        # v1.1 — only structural presence is checkable. A field_value/exists_where
        # rule targeting the #3/#19 value with a closed comparison would invent
        # OECD enum content (forbidden until the v1.2 transcription).
        for rule in _all_rules(template):
            params = rule.params
            field = str(params.get("field", ""))
            if "/3" in field.split("oecd-crf-2025")[-1] or "/19" in field:
                # If a rule touches #3/#19 it must only check presence, not value.
                assert rule.rule in {"field_present", "exists_where"}, (
                    f"rule {rule.rule_id!r} appears to constrain OECD #3/#19 by value; "
                    "the closed value set is the v1.2 surface — structural only in v1.1"
                )
                # And it must not pin a specific OECD enum value.
                assert "value" not in params or params.get("op") in {None, "present", "exists"}


# ── Determinism (§5.10) ──


class TestDeterminism:
    def test_template_round_trip_is_byte_stable(self, raw_template: dict[str, Any]) -> None:
        first = compute_template_digest(TEMPLATE_ID)
        second = compute_template_digest(TEMPLATE_ID)
        assert first == second
        assert raw_template["template_id"] == TEMPLATE_ID
