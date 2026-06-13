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


class TestSourceBackedIncidentReportResolution:
    """roborev: a SOURCE-BACKED incident_report carries the authoritative evidence
    under ``payload.card_source.*`` (the shape ``Package.report_incident()`` emits),
    NOT at the payload root. The renderer MUST resolve public_incident_id / id_grade /
    severity_vector / harm_core from ``card_source`` for ``incident_report`` records,
    falling back to the root only when the source field is absent — and keep the
    PUBLIC ``incident_card`` (root fields) root-first (no regression).
    """

    # The real builder's canonical inputs (mirrors test_package_incident_incbuilder).
    _BUILDER_VECTOR = "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I"
    _BUILDER_HARM_CLASS = "physical_health"
    _BUILDER_HARM_CORE = {
        "realization": "harm_event",
        "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
        "harm_class": _BUILDER_HARM_CLASS,
    }

    @staticmethod
    def _real_report_incident_record() -> dict:
        """Emit an ACTUAL source-backed incident_report via the builder.

        Uses an attached RedactionPolicy so the regulator-only one-call path emits
        (matching F-M8-INCIDENT-BUILDER's construction). Returns the emitted record
        as a plain ``{record_type, payload}`` dict the renderer consumes.
        """
        from acef.package import Package
        from acef.redaction import RedactionPolicy

        pkg = Package(
            producer={"name": "test", "version": "1.0"},
            redaction_policy=RedactionPolicy(version="1.0.0"),
        )
        env = pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(TestSourceBackedIncidentReportResolution._BUILDER_HARM_CORE),
            incident_type="operational_failure",
            description="Confidential Art.73 serious-incident report.",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
            severity_vector=TestSourceBackedIncidentReportResolution._BUILDER_VECTOR,
        )
        return {"record_type": env.record_type, "payload": env.payload}

    def test_real_report_incident_markdown_surfaces_card_source_evidence(self) -> None:
        """RED (pre-fix): the real builder output stores public_incident_id /
        severity_vector / harm_core under ``card_source``; the renderer read
        ``payload.harm_core`` (root) → harm evidence OMITTED entirely.

        Pre-fix rendered Markdown was::

            ### AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS
            - **Public Incident ID:** `...`
            - **ID Grade:** self-asserted
            - **Severity Vector:** `...` (band: **major**)

        — NO "Harm Core" bullet, NO ``physical_health``/``harm_event`` lines.
        """
        rec = self._real_report_incident_record()
        # Precondition: the builder really puts harm_core under card_source, not root.
        assert "harm_core" not in rec["payload"]
        assert rec["payload"]["card_source"]["harm_core"]["harm_class"] == self._BUILDER_HARM_CLASS

        md = render_incident_evidence_markdown([rec])
        # public_incident_id resolves from card_source.
        assert _PUBLIC_ID in md
        # harm_core (Medium 2) — these were OMITTED pre-fix.
        assert "Harm Core" in md
        assert self._BUILDER_HARM_CLASS in md
        assert "harm_event" in md
        # severity band derived from the card_source.severity_vector via incident_rules.band.
        expected_band = band(self._BUILDER_VECTOR)
        assert expected_band == "major"
        assert self._BUILDER_VECTOR in md
        assert expected_band in md

    def test_real_report_incident_console_surfaces_card_source_harm_class(self) -> None:
        """RED (pre-fix): the console twin read ``payload.harm_core.harm_class``
        (root) → the "Harm class" line was OMITTED for real source-backed reports."""
        rec = self._real_report_incident_record()
        out = render_incident_evidence_console([rec])
        assert _PUBLIC_ID in out
        # Harm class line — OMITTED pre-fix (read root, found nothing).
        assert self._BUILDER_HARM_CLASS in out
        assert band(self._BUILDER_VECTOR) in out

    def test_divergent_root_id_does_not_mask_card_source_for_incident_report(self) -> None:
        """RED (pre-fix, Medium 1): an incident_report with BOTH a stray ROOT
        public_incident_id/severity_vector AND the authoritative card_source values
        rendered the ROOT (wrong) value, masking the real source-backed evidence.

        Record-type-aware resolution: for incident_report, card_source WINS.
        """
        stray_root_id = "AIIC-FORGED-2099-ZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        stray_root_vector = "ACEF-SEV:1.0/HT:P/HG:H/RV:I/SC:C/BR:P"  # critical (diverges)
        assert band(stray_root_vector) == "critical"  # the WRONG band, if root won.
        rec = {
            "record_type": "incident_report",
            "payload": {
                # Stray ROOT values that MUST NOT win for an incident_report.
                "public_incident_id": stray_root_id,
                "id_grade": "verified",
                "severity_vector": stray_root_vector,
                "harm_core": {"harm_class": "financial_loss", "realization": "near_miss"},
                # The authoritative card_source values.
                "card_source": {
                    "public_incident_id": _PUBLIC_ID,
                    "id_grade": "self-asserted",
                    "severity_vector": self._BUILDER_VECTOR,
                    "harm_core": dict(self._BUILDER_HARM_CORE),
                },
            },
        }
        md = render_incident_evidence_markdown([rec])
        # The authoritative card_source values surface...
        assert _PUBLIC_ID in md
        assert "self-asserted" in md
        assert self._BUILDER_VECTOR in md
        assert band(self._BUILDER_VECTOR) in md  # "major"
        assert self._BUILDER_HARM_CLASS in md
        # ...and the stray ROOT values do NOT mask them.
        assert stray_root_id not in md
        assert stray_root_vector not in md
        assert "financial_loss" not in md
        assert "critical" not in md

        # Console twin: same record-type-aware resolution.
        out = render_incident_evidence_console([rec])
        assert _PUBLIC_ID in out
        assert stray_root_id not in out
        assert self._BUILDER_HARM_CLASS in out
        assert "financial_loss" not in out

    def test_incident_report_falls_back_to_root_when_card_source_field_absent(self) -> None:
        """An incident_report whose card_source lacks a field falls back to the ROOT
        value for that field (the legacy public-shaped incident_report still renders).
        """
        rec = {
            "record_type": "incident_report",
            "payload": {
                "public_incident_id": _PUBLIC_ID,  # only at root
                "harm_core": dict(self._BUILDER_HARM_CORE),  # only at root
                "card_source": {
                    # card_source present but WITHOUT public_incident_id / harm_core.
                    "severity_vector": self._BUILDER_VECTOR,
                },
            },
        }
        md = render_incident_evidence_markdown([rec])
        assert _PUBLIC_ID in md  # fell back to root
        assert self._BUILDER_HARM_CLASS in md  # fell back to root
        assert band(self._BUILDER_VECTOR) in md  # resolved from card_source

    def test_public_incident_card_still_root_first_no_regression(self) -> None:
        """A PUBLIC incident_card carries its evidence at the payload ROOT; the
        record-type-aware rule keeps root-first for incident_card (no regression)."""
        rec = _incident_card_record()
        md = render_incident_evidence_markdown([rec])
        assert _PUBLIC_ID in md
        assert "self-asserted" in md
        assert "physical_safety" in md  # the public card's root harm_class
        assert _CRITICAL_VECTOR in md
        assert band(_CRITICAL_VECTOR) in md  # "critical"
        out = render_incident_evidence_console([rec])
        assert _PUBLIC_ID in out
        assert "physical_safety" in out
        assert band(_CRITICAL_VECTOR) in out

    def test_public_incident_card_root_wins_over_stray_card_source(self) -> None:
        """Even when a public incident_card carries a stray card_source, ROOT wins
        for incident_card (root-first), unchanged from the public-card contract."""
        rec = _incident_card_record()
        rec["payload"]["card_source"] = {
            "public_incident_id": "AIIC-STRAY-2099-ZZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "severity_vector": "ACEF-SEV:1.0/HT:P/HG:L/RV:N/SC:I/BR:S",
        }
        md = render_incident_evidence_markdown([rec])
        assert _PUBLIC_ID in md
        assert "AIIC-STRAY-2099-ZZZZZZZZZZZZZZZZZZZZZZZZZZ" not in md
        assert _CRITICAL_VECTOR in md


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
