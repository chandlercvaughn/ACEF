"""Tests for acef.render incident-evidence rendering (F-M9-RENDER).

The AssessmentBundle renderers (test_render.py) surface validation RESULTS and
incident ERROR diagnostics (ACEF-081..088). This file covers the COVERAGE MUST
of F-M9-RENDER (VAL-COVERAGE-RENDER-001): rendering incident EVIDENCE CONTENT —
``public_incident_id`` (+ ``id_grade``), ``harm_core``, the ``severity_vector``
rendered WITH its band (reusing :func:`acef.validation.incident_rules.band`), and
the ``taxonomy_crosswalk`` — from ``incident_card`` / ``incident_report`` records.

It also includes the Part-A audit regression: the Markdown evidence-ref list MUST
NOT silently drop refs beyond the first five (it now notes the overflow, matching
the console structural-errors truncation discipline).
"""

from __future__ import annotations

from acef.models.assessment import (
    Assessor,
    EvidenceBundleRef,
    RuleResult,
)
from acef.models.enums import RuleOutcome, RuleSeverity
from acef.render import (
    render_incident_evidence_console,
    render_incident_evidence_markdown,
    render_markdown,
)
from acef.validation.incident_rules import band

# A canonical critical-severity incident card payload exercising every rendered
# field: public_incident_id (+ id_grade), harm_core, severity_vector, and a
# multi-member taxonomy_crosswalk.
_CRITICAL_VECTOR = "ACEF-SEV:1.0/HT:P/HG:H/RV:I/SC:C/BR:P"
_PUBLIC_ID = "AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS"


def _incident_card_record(
    *,
    record_id: str = "urn:acef:rec:00000000-0000-0000-0000-0000000000aa",
    public_incident_id: str = _PUBLIC_ID,
    id_grade: str | None = "self-asserted",
    severity_vector: str | None = _CRITICAL_VECTOR,
    harm_core: dict | None = None,
    taxonomy_crosswalk: dict | None = None,
) -> dict:
    """Build a minimal incident_card record envelope (dict) for rendering."""
    payload: dict = {"public_incident_id": public_incident_id}
    if id_grade is not None:
        payload["id_grade"] = id_grade
    if severity_vector is not None:
        payload["severity_vector"] = severity_vector
    payload["harm_core"] = (
        harm_core
        if harm_core is not None
        else {
            "realization": "harm_event",
            "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
            "harm_class": "physical_safety",
        }
    )
    payload["taxonomy_crosswalk"] = (
        taxonomy_crosswalk
        if taxonomy_crosswalk is not None
        else {
            "eu_ai_act": {"edition": "reg-2024-1689", "serious_incident_triggers": ["3.49.a"]},
            "nist_ai_600_1": {"edition": "2024-07-final", "categories": ["Information Security"]},
        }
    )
    return {"record_id": record_id, "record_type": "incident_card", "payload": payload}


class TestRenderIncidentEvidenceMarkdown:
    """render_incident_evidence_markdown surfaces incident evidence content."""

    def test_renders_public_incident_id_and_grade(self) -> None:
        md = render_incident_evidence_markdown([_incident_card_record()])
        assert _PUBLIC_ID in md
        assert "self-asserted" in md

    def test_renders_harm_core(self) -> None:
        md = render_incident_evidence_markdown([_incident_card_record()])
        # harm_core fields surface in the rendered output.
        assert "physical_safety" in md
        assert "harm_event" in md

    def test_renders_severity_vector_with_band(self) -> None:
        md = render_incident_evidence_markdown([_incident_card_record()])
        # The vector itself AND the band derived from it (reusing incident_rules.band).
        expected_band = band(_CRITICAL_VECTOR)
        assert expected_band == "critical"
        assert _CRITICAL_VECTOR in md
        assert expected_band in md

    def test_renders_taxonomy_crosswalk_framework_labels(self) -> None:
        md = render_incident_evidence_markdown([_incident_card_record()])
        # Each present crosswalk framework member is labelled.
        assert "eu_ai_act" in md
        assert "nist_ai_600_1" in md
        # Version-pin editions surface so a populated member is verifiable evidence.
        assert "reg-2024-1689" in md
        assert "2024-07-final" in md

    def test_section_heading_present(self) -> None:
        md = render_incident_evidence_markdown([_incident_card_record()])
        assert "## Incident Evidence" in md

    def test_empty_input_yields_empty_output(self) -> None:
        assert render_incident_evidence_markdown([]) == ""

    def test_non_incident_record_skipped(self) -> None:
        other = {
            "record_id": "urn:acef:rec:00000000-0000-0000-0000-0000000000bb",
            "record_type": "risk_register",
            "payload": {"foo": "bar"},
        }
        assert render_incident_evidence_markdown([other]) == ""

    def test_missing_optional_severity_vector_does_not_crash(self) -> None:
        rec = _incident_card_record(severity_vector=None)
        md = render_incident_evidence_markdown([rec])
        # Still renders the id + harm_core; no band line, no crash.
        assert _PUBLIC_ID in md
        assert "physical_safety" in md

    def test_missing_optional_id_grade_does_not_crash(self) -> None:
        rec = _incident_card_record(id_grade=None)
        md = render_incident_evidence_markdown([rec])
        assert _PUBLIC_ID in md
        assert "self-asserted" not in md

    def test_unparseable_severity_vector_renders_vector_without_band(self) -> None:
        rec = _incident_card_record(severity_vector="ACEF-SEV:1.0/bogus")
        md = render_incident_evidence_markdown([rec])
        # The raw vector still surfaces, but no derived band (band() returns None).
        assert "ACEF-SEV:1.0/bogus" in md
        assert _PUBLIC_ID in md

    def test_incident_report_record_rendered(self) -> None:
        # incident_report (source-backed) is also an incident-evidence type.
        rec = {
            "record_id": "urn:acef:rec:00000000-0000-0000-0000-0000000000cc",
            "record_type": "incident_report",
            "payload": {
                "public_incident_id": _PUBLIC_ID,
                "harm_core": {
                    "realization": "harm_event",
                    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
                    "harm_class": "physical_safety",
                },
            },
        }
        md = render_incident_evidence_markdown([rec])
        assert _PUBLIC_ID in md
        assert "physical_safety" in md

    def test_card_source_public_incident_id_rendered(self) -> None:
        # A source-backed incident_report carries the id under card_source.
        rec = {
            "record_id": "urn:acef:rec:00000000-0000-0000-0000-0000000000dd",
            "record_type": "incident_report",
            "payload": {
                "card_source": {
                    "public_incident_id": _PUBLIC_ID,
                    "severity_vector": _CRITICAL_VECTOR,
                },
                "harm_core": {
                    "realization": "harm_event",
                    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
                    "harm_class": "physical_safety",
                },
            },
        }
        md = render_incident_evidence_markdown([rec])
        assert _PUBLIC_ID in md
        assert band(_CRITICAL_VECTOR) in md

    def test_non_dict_records_ignored(self) -> None:
        assert render_incident_evidence_markdown(["not-a-dict", 42, None]) == ""  # type: ignore[list-item]

    def test_deterministic_across_runs(self) -> None:
        recs = [_incident_card_record()]
        assert render_incident_evidence_markdown(recs) == render_incident_evidence_markdown(recs)


class TestRenderIncidentEvidenceConsole:
    """render_incident_evidence_console surfaces incident evidence concisely."""

    def test_renders_core_fields(self) -> None:
        out = render_incident_evidence_console([_incident_card_record()])
        assert _PUBLIC_ID in out
        assert "physical_safety" in out
        assert band(_CRITICAL_VECTOR) in out

    def test_empty_input_yields_empty_output(self) -> None:
        assert render_incident_evidence_console([]) == ""

    def test_non_incident_record_skipped(self) -> None:
        other = {"record_id": "x", "record_type": "risk_register", "payload": {}}
        assert render_incident_evidence_console([other]) == ""


class TestMarkdownEvidenceTruncationAudit:
    """Part-A audit regression: Markdown evidence-ref list must not silently drop.

    Before the fix, render_markdown sliced ``result.evidence_refs[:5]`` and emitted
    NO overflow note — a compliance report silently hid evidence references 6..N.
    The console structural-errors path already noted ``... and N more``; the
    Markdown evidence path now matches that discipline.
    """

    def test_overflow_note_when_more_than_five_evidence_refs(self) -> None:
        from acef.models.assessment import AssessmentBundle

        refs = [f"urn:acef:rec:{i:032d}" for i in range(8)]
        assessment = AssessmentBundle(
            assessor=Assessor(name="acef-validator", version="1.0.0"),
            evidence_bundle_ref=EvidenceBundleRef(package_id="urn:acef:pkg:x"),
            evaluation_instant="2025-06-01T00:00:00Z",
            results=[
                RuleResult(
                    rule_id="rule-many-ev",
                    provision_id="article-9",
                    profile_id="eu-ai-act",
                    rule_severity=RuleSeverity.FAIL,
                    outcome=RuleOutcome.FAILED,
                    message="many refs",
                    evidence_refs=refs,
                ),
            ],
        )
        md = render_markdown(assessment)
        # First five are shown, and the overflow is explicitly disclosed.
        assert refs[0] in md
        assert refs[4] in md
        assert "and 3 more" in md

    def test_no_overflow_note_when_five_or_fewer(self) -> None:
        from acef.models.assessment import AssessmentBundle

        refs = [f"urn:acef:rec:{i:032d}" for i in range(3)]
        assessment = AssessmentBundle(
            assessor=Assessor(name="acef-validator", version="1.0.0"),
            evidence_bundle_ref=EvidenceBundleRef(package_id="urn:acef:pkg:x"),
            evaluation_instant="2025-06-01T00:00:00Z",
            results=[
                RuleResult(
                    rule_id="rule-few-ev",
                    provision_id="article-9",
                    profile_id="eu-ai-act",
                    rule_severity=RuleSeverity.FAIL,
                    outcome=RuleOutcome.FAILED,
                    message="few refs",
                    evidence_refs=refs,
                ),
            ],
        )
        md = render_markdown(assessment)
        assert "more" not in md.split("## Rule Details")[1].split("## ")[0]
