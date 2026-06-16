"""ACEF render module — human-readable compliance reports.

Generates Markdown and console-formatted compliance reports from Assessment Bundles.
"""

from __future__ import annotations

from typing import Any

from acef.errors import incident_error_detail
from acef.models.assessment import AssessmentBundle
from acef.models.enums import ProvisionOutcome, RuleOutcome
from acef.validation.incident_rules import band

# Outcome display mapping
_OUTCOME_SYMBOLS = {
    ProvisionOutcome.SATISFIED: "[PASS]",
    ProvisionOutcome.NOT_SATISFIED: "[FAIL]",
    ProvisionOutcome.PARTIALLY_SATISFIED: "[PARTIAL]",
    ProvisionOutcome.GAP_ACKNOWLEDGED: "[GAP]",
    ProvisionOutcome.SKIPPED: "[SKIP]",
    ProvisionOutcome.NOT_ASSESSED: "[N/A]",
}

_RULE_OUTCOME_SYMBOLS = {
    RuleOutcome.PASSED: "[PASS]",
    RuleOutcome.FAILED: "[FAIL]",
    RuleOutcome.SKIPPED: "[SKIP]",
    RuleOutcome.ERROR: "[ERR]",
}


def render_markdown(assessment: AssessmentBundle) -> str:
    """Render an Assessment Bundle as a Markdown compliance report.

    Args:
        assessment: The AssessmentBundle to render.

    Returns:
        Markdown-formatted report string.
    """
    lines: list[str] = []

    lines.append("# ACEF Compliance Assessment Report")
    lines.append("")
    lines.append(f"**Assessment ID:** `{assessment.assessment_id}`")
    lines.append(f"**Timestamp:** {assessment.timestamp}")
    lines.append(f"**Evaluation Instant:** {assessment.evaluation_instant}")
    lines.append(f"**Assessor:** {assessment.assessor.name} v{assessment.assessor.version}")
    lines.append("")

    if assessment.evidence_bundle_ref.package_id:
        lines.append(f"**Evidence Bundle:** `{assessment.evidence_bundle_ref.package_id}`")
        if assessment.evidence_bundle_ref.content_hash:
            lines.append(f"**Bundle Digest:** `{assessment.evidence_bundle_ref.content_hash}`")
        lines.append("")

    # Profiles evaluated
    if assessment.profiles_evaluated:
        lines.append("## Profiles Evaluated")
        lines.append("")
        for profile in assessment.profiles_evaluated:
            lines.append(f"- {profile}")
        lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(assessment.summary())
    lines.append("")

    # Provision Summaries
    if assessment.provision_summary:
        lines.append("## Provision Results")
        lines.append("")
        lines.append("| Provision | Profile | Outcome | Fails | Warnings | Skipped |")
        lines.append("|-----------|---------|---------|-------|----------|---------|")
        for ps in assessment.provision_summary:
            symbol = _OUTCOME_SYMBOLS.get(ps.provision_outcome, "[?]")
            lines.append(
                f"| {ps.provision_id} | {ps.profile_id} | {symbol} {ps.provision_outcome.value} "
                f"| {ps.fail_count} | {ps.warning_count} | {ps.skipped_count} |"
            )
        lines.append("")

    # Rule Details
    if assessment.results:
        lines.append("## Rule Details")
        lines.append("")
        for result in assessment.results:
            symbol = _RULE_OUTCOME_SYMBOLS.get(result.outcome, "[?]")
            severity_label = f"[{result.rule_severity.value.upper()}]"
            lines.append(f"### {result.rule_id}")
            lines.append(f"- **Provision:** {result.provision_id}")
            lines.append(f"- **Severity:** {severity_label}")
            lines.append(f"- **Outcome:** {symbol} {result.outcome.value}")
            if result.message:
                lines.append(f"- **Message:** {result.message}")
            if result.evidence_refs:
                shown = result.evidence_refs[:5]
                rendered = ", ".join(f"`{r}`" for r in shown)
                # Disclose any truncation rather than silently dropping evidence
                # references beyond the first five — silently hiding evidence in a
                # compliance report is a correctness defect (Part-A audit). This
                # mirrors the console structural-errors "... and N more" discipline.
                overflow = len(result.evidence_refs) - len(shown)
                if overflow > 0:
                    rendered += f" … and {overflow} more"
                lines.append(f"- **Evidence:** {rendered}")
            lines.append("")

    # Structural Errors
    if assessment.structural_errors:
        lines.append("## Structural Errors")
        lines.append("")
        for error in assessment.structural_errors:
            code = error.get("code", "")
            msg = error.get("message", "")
            severity = error.get("severity", "")
            path = error.get("path", "")
            lines.append(f"- **{code}** [{severity}]: {msg}")
            if path:
                lines.append(f"  - Path: `{path}`")
            # RFC-0002 §7 incident band (ACEF-081..088): surface the FULL structured
            # diagnostic — Problem + Cause + FIX-HINT — so a filer sees exactly what
            # failed, why, and what to correct (VAL-DX-003). incident_error_detail
            # returns None for a v0.4 code, so no fix block is emitted for non-incident
            # codes.
            detail = incident_error_detail(code)
            if detail is not None:
                lines.append(f"  - Problem: {detail.problem}")
                lines.append(f"  - Cause: {detail.cause}")
                lines.append(f"  - Fix: {detail.fix}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by ACEF Reference Validator*")

    return "\n".join(lines)


def render_console(assessment: AssessmentBundle) -> str:
    """Render a concise console-formatted summary.

    Args:
        assessment: The AssessmentBundle to render.

    Returns:
        Console-formatted string with ANSI-compatible markers.
    """
    lines: list[str] = []

    lines.append("ACEF Compliance Assessment")
    lines.append("=" * 40)
    lines.append(f"Bundle: {assessment.evidence_bundle_ref.package_id}")
    lines.append(f"Evaluated: {assessment.evaluation_instant}")
    lines.append("")

    # Summary
    lines.append(assessment.summary())
    lines.append("")

    # Provision table
    if assessment.provision_summary:
        lines.append("Provisions:")
        for ps in assessment.provision_summary:
            symbol = _OUTCOME_SYMBOLS.get(ps.provision_outcome, "[?]")
            lines.append(f"  {symbol:10s} {ps.provision_id} ({ps.profile_id})")

    # Failed rules
    failed_rules = [r for r in assessment.results if r.outcome == RuleOutcome.FAILED]
    if failed_rules:
        lines.append("")
        lines.append(f"Failed Rules ({len(failed_rules)}):")
        for r in failed_rules:
            lines.append(f"  [{r.rule_severity.value.upper():7s}] {r.rule_id}: {r.message or 'No message'}")

    # Errors
    if assessment.structural_errors:
        lines.append("")
        lines.append(f"Structural Errors ({len(assessment.structural_errors)}):")
        for error in assessment.structural_errors[:10]:
            code = error.get("code", "")
            lines.append(f"  {code}: {error.get('message', '')}")
            # Surface the RFC-0002 §7 incident diagnostic (ACEF-081..088) — Problem +
            # Cause + Fix — so a filer sees what failed, why, and the remediation in
            # the concise console output too (VAL-DX-003), consistent with the
            # Markdown renderer.
            detail = incident_error_detail(code)
            if detail is not None:
                lines.append(f"    Problem: {detail.problem}")
                lines.append(f"    Cause: {detail.cause}")
                lines.append(f"    Fix: {detail.fix}")
        if len(assessment.structural_errors) > 10:
            lines.append(f"  ... and {len(assessment.structural_errors) - 10} more")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Incident-evidence rendering (RFC-0002 §5.2 acef.render) — VAL-COVERAGE-RENDER-001
# ---------------------------------------------------------------------------
#
# The AssessmentBundle renderers above surface validation RESULTS (and the §7
# incident ERROR diagnostics ACEF-081..088). They do NOT carry incident EVIDENCE
# CONTENT — an Assessment Bundle holds outcomes, not the incident_card /
# incident_report payloads themselves.
#
# These functions render that evidence content from the raw record envelopes
# (plain dicts: ``{record_type, payload}``) the caller (CLI inspect, a later
# feature) holds: for each ``incident_card`` / ``incident_report`` record they
# surface the public_incident_id (+ id_grade), the harm_core, the severity_vector
# rendered WITH its band (reusing the shipped band() projection — never
# recomputed), and the taxonomy_crosswalk framework members.
#
# Discipline:
# - Presentation only. ``render`` surfaces whatever fields are present on the
#   record AS-IS; it never re-derives confidentiality and never invents fields.
# - Robust: a record missing an optional field renders gracefully (no crash); a
#   non-incident (or non-dict) record is skipped; an empty input yields "".
# - Deterministic: records render in given order; crosswalk members and harm_core
#   fields render in a fixed key order; no wall-clock / random values are read.

_INCIDENT_RECORD_TYPES: frozenset[str] = frozenset({"incident_card", "incident_report"})

# Fixed render order for taxonomy_crosswalk framework members (§5.5). Ordering is
# deterministic and stable regardless of dict insertion order.
_CROSSWALK_MEMBER_ORDER: tuple[str, ...] = (
    "eu_ai_act",
    "oecd",
    "nist_ai_600_1",
    "cset",
    "mit_causal",
    "mit_domain",
    "aiid",
    "stix",
)

# Fixed render order for harm_core scalar/sub-object fields (§5.2).
_HARM_CORE_FIELD_ORDER: tuple[str, ...] = (
    "harm_class",
    "realization",
    "causality",
    "tangibility",
)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _incident_payload(record: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Return ``(record_type, payload)`` for an incident record, else ``None``.

    Non-dict records, non-incident record_types, and records without a dict
    payload return ``None`` (the record is skipped). The ``record_type`` is
    returned because incident-field resolution is record-type aware: a
    source-backed ``incident_report`` carries the authoritative evidence under
    ``card_source`` whereas a public ``incident_card`` carries it at the payload
    root (see :func:`_resolve_incident_field`).
    """
    if not isinstance(record, dict):
        return None
    record_type = record.get("record_type")
    if record_type not in _INCIDENT_RECORD_TYPES:
        return None
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    return record_type, payload


def _resolve_incident_field(payload: dict[str, Any], record_type: str, field: str) -> Any:
    """Resolve an incident field RECORD-TYPE AWARE-ly (roborev Medium 1/2).

    The authoritative location of ``public_incident_id`` / ``id_grade`` /
    ``severity_vector`` / ``harm_core`` depends on the record type:

    - A SOURCE-BACKED ``incident_report`` (the shape ``Package.report_incident``
      emits) carries them under ``payload.card_source`` — the regulator-filing
      evidence. ``card_source`` is preferred; a stray/divergent ROOT value must
      NOT mask the real source-backed evidence. Falls back to the root only when
      the ``card_source`` field is absent (a legacy public-shaped report).
    - A PUBLIC ``incident_card`` carries them at the payload ROOT (the public
      surface). Root is preferred; ``card_source`` is a fallback only.

    Never invents absent fields (returns ``None`` when present in neither).
    """
    card_source = _as_dict(payload.get("card_source"))
    if record_type == "incident_report":
        # Source-backed: card_source is authoritative, root is the fallback.
        value = card_source.get(field)
        if value is not None:
            return value
        return payload.get(field)
    # Public incident_card: root-first, card_source fallback.
    value = payload.get(field)
    if value is not None:
        return value
    return card_source.get(field)


def _crosswalk_edition(member: dict[str, Any]) -> str | None:
    """Return a member's version-pin (``edition`` or, for mit_domain, the
    ``taxonomy_version`` label), or None when absent (§5.5)."""
    edition = member.get("edition")
    if isinstance(edition, str) and edition:
        return edition
    tv = member.get("taxonomy_version")
    return tv if isinstance(tv, str) and tv else None


def _render_harm_core_markdown(harm_core: dict[str, Any]) -> list[str]:
    """Render harm_core sub-fields as Markdown bullet lines (fixed key order)."""
    lines: list[str] = []
    for field in _HARM_CORE_FIELD_ORDER:
        if field not in harm_core:
            continue
        value = harm_core[field]
        if field == "causality" and isinstance(value, dict):
            entity = value.get("entity", "")
            intent = value.get("intent", "")
            timing = value.get("timing", "")
            lines.append(f"  - **causality:** entity={entity}, intent={intent}, timing={timing}")
        else:
            lines.append(f"  - **{field}:** {value}")
    return lines


def _ordered_crosswalk_members(crosswalk: dict[str, Any]) -> list[str]:
    """Return present crosswalk member keys in the fixed order, with any extra
    (e.g. ``x-*`` vendor namespace) members appended in sorted order for
    determinism."""
    present = [m for m in _CROSSWALK_MEMBER_ORDER if m in crosswalk]
    extras = sorted(k for k in crosswalk if k not in _CROSSWALK_MEMBER_ORDER)
    return present + extras


def render_incident_evidence_markdown(records: list[dict[str, Any]]) -> str:
    """Render incident EVIDENCE content from record envelopes as Markdown.

    For each ``incident_card`` / ``incident_report`` record in ``records``,
    surfaces the public_incident_id (+ id_grade), harm_core, the severity_vector
    WITH its derived band (reusing :func:`acef.validation.incident_rules.band` —
    never recomputed), and the taxonomy_crosswalk framework members (each with its
    version-pin edition). Non-incident / non-dict records are skipped. An empty
    input — or an input with no incident records — yields ``""`` (no heading).

    Args:
        records: Record envelopes (plain dicts ``{record_type, payload, ...}``).

    Returns:
        Markdown-formatted incident-evidence section, or ``""`` when there is no
        incident evidence to render.
    """
    blocks: list[list[str]] = []
    for record in records:
        resolved = _incident_payload(record)
        if resolved is None:
            continue
        record_type, payload = resolved
        block: list[str] = []

        public_id = _resolve_incident_field(payload, record_type, "public_incident_id")
        id_grade = _resolve_incident_field(payload, record_type, "id_grade")
        heading = f"### {public_id}" if isinstance(public_id, str) and public_id else "### (no public_incident_id)"
        block.append(heading)
        if isinstance(public_id, str) and public_id:
            block.append(f"- **Public Incident ID:** `{public_id}`")
        if isinstance(id_grade, str) and id_grade:
            block.append(f"- **ID Grade:** {id_grade}")

        # severity_vector + band (reuse the shipped band() projection).
        severity_vector = _resolve_incident_field(payload, record_type, "severity_vector")
        if isinstance(severity_vector, str) and severity_vector:
            band_value = band(severity_vector)
            if band_value is not None:
                block.append(f"- **Severity Vector:** `{severity_vector}` (band: **{band_value}**)")
            else:
                # A present-but-unparseable vector: surface it verbatim with no
                # derived band rather than crashing (band() returns None).
                block.append(f"- **Severity Vector:** `{severity_vector}` (band: unparseable)")

        # harm_core — record-type aware (card_source for a source-backed report).
        harm_core = _as_dict(_resolve_incident_field(payload, record_type, "harm_core"))
        if harm_core:
            block.append("- **Harm Core:**")
            block.extend(_render_harm_core_markdown(harm_core))

        # taxonomy_crosswalk — record-type aware, like the sibling fields above: a
        # source-backed incident_report carries it under card_source, a public
        # incident_card at the root.
        crosswalk = _as_dict(_resolve_incident_field(payload, record_type, "taxonomy_crosswalk"))
        member_keys = _ordered_crosswalk_members(crosswalk)
        if member_keys:
            block.append("- **Taxonomy Crosswalk:**")
            for key in member_keys:
                member = _as_dict(crosswalk.get(key))
                edition = _crosswalk_edition(member)
                if edition is not None:
                    block.append(f"  - **{key}** (edition: {edition})")
                else:
                    block.append(f"  - **{key}**")

        blocks.append(block)

    if not blocks:
        return ""

    lines: list[str] = ["## Incident Evidence", ""]
    for block in blocks:
        lines.extend(block)
        lines.append("")
    return "\n".join(lines).rstrip("\n")


def render_incident_evidence_console(records: list[dict[str, Any]]) -> str:
    """Render incident EVIDENCE content from record envelopes for the console.

    Concise console twin of :func:`render_incident_evidence_markdown`: one block
    per ``incident_card`` / ``incident_report`` record carrying the
    public_incident_id, the severity band (reusing
    :func:`acef.validation.incident_rules.band`), the harm_class, and the present
    crosswalk framework members. Non-incident / non-dict records are skipped; an
    empty input yields ``""``.

    Args:
        records: Record envelopes (plain dicts ``{record_type, payload, ...}``).

    Returns:
        Console-formatted incident-evidence section, or ``""`` when there is no
        incident evidence to render.
    """
    blocks: list[list[str]] = []
    for record in records:
        resolved = _incident_payload(record)
        if resolved is None:
            continue
        record_type, payload = resolved
        block: list[str] = []

        public_id = _resolve_incident_field(payload, record_type, "public_incident_id")
        block.append(f"Incident: {public_id}" if isinstance(public_id, str) and public_id else "Incident: (no id)")

        severity_vector = _resolve_incident_field(payload, record_type, "severity_vector")
        if isinstance(severity_vector, str) and severity_vector:
            band_value = band(severity_vector)
            block.append(f"  Severity: {band_value if band_value is not None else 'unparseable'} ({severity_vector})")

        # harm_core — record-type aware (card_source for a source-backed report).
        harm_core = _as_dict(_resolve_incident_field(payload, record_type, "harm_core"))
        harm_class = harm_core.get("harm_class")
        if isinstance(harm_class, str) and harm_class:
            block.append(f"  Harm class: {harm_class}")

        # taxonomy_crosswalk — record-type aware (card_source for a source-backed
        # report, root for a public card), matching the markdown twin.
        crosswalk = _as_dict(_resolve_incident_field(payload, record_type, "taxonomy_crosswalk"))
        member_keys = _ordered_crosswalk_members(crosswalk)
        if member_keys:
            block.append(f"  Crosswalk: {', '.join(member_keys)}")

        blocks.append(block)

    if not blocks:
        return ""

    lines: list[str] = ["Incident Evidence", "=" * 40]
    for block in blocks:
        lines.extend(block)
    return "\n".join(lines)
