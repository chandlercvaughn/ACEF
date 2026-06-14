"""ACEF CLI formatters — Rich-based pretty output."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from acef.models.assessment import AssessmentBundle
from acef.models.enums import ProvisionOutcome, RuleOutcome

console = Console()

_OUTCOME_STYLES = {
    ProvisionOutcome.SATISFIED: ("PASS", "green"),
    ProvisionOutcome.NOT_SATISFIED: ("FAIL", "red bold"),
    ProvisionOutcome.PARTIALLY_SATISFIED: ("PARTIAL", "yellow"),
    ProvisionOutcome.GAP_ACKNOWLEDGED: ("GAP", "cyan"),
    ProvisionOutcome.SKIPPED: ("SKIP", "dim"),
    ProvisionOutcome.NOT_ASSESSED: ("N/A", "dim"),
}

_RULE_OUTCOME_STYLES = {
    RuleOutcome.PASSED: ("PASS", "green"),
    RuleOutcome.FAILED: ("FAIL", "red"),
    RuleOutcome.SKIPPED: ("SKIP", "dim"),
    RuleOutcome.ERROR: ("ERR", "red bold"),
}


def print_assessment(assessment: AssessmentBundle) -> None:
    """Print a pretty-formatted assessment to console."""
    # Header
    console.print()
    console.print(
        Panel.fit(
            f"[bold]ACEF Compliance Assessment[/bold]\n"
            f"Bundle: {assessment.evidence_bundle_ref.package_id}\n"
            f"Evaluated: {assessment.evaluation_instant}",
            border_style="blue",
        )
    )

    # Summary
    console.print(f"\n[bold]{assessment.summary()}[/bold]\n")

    # Provision table
    if assessment.provision_summary:
        table = Table(title="Provision Results", show_lines=True)
        table.add_column("Provision", style="cyan")
        table.add_column("Profile")
        table.add_column("Outcome", justify="center")
        table.add_column("Fails", justify="right")
        table.add_column("Warnings", justify="right")

        for ps in assessment.provision_summary:
            label, style = _OUTCOME_STYLES.get(ps.provision_outcome, ("?", "white"))
            table.add_row(
                ps.provision_id,
                ps.profile_id,
                Text(label, style=style),
                str(ps.fail_count),
                str(ps.warning_count),
            )

        console.print(table)

    # Failed rules
    failed = [r for r in assessment.results if r.outcome == RuleOutcome.FAILED]
    if failed:
        console.print(f"\n[red bold]Failed Rules ({len(failed)}):[/red bold]")
        for r in failed:
            # rule_severity is normally a RuleSeverity enum, but assessments
            # that have been round-tripped through JSON may carry a plain
            # string here. Coerce defensively so the pretty printer never
            # raises AttributeError on a string severity.
            sev_obj = r.rule_severity
            severity = (sev_obj.value if hasattr(sev_obj, "value") else str(sev_obj)).upper()
            console.print(f"  [{severity:7s}] {r.rule_id}: {r.message or ''}")

    # Structural errors
    if assessment.structural_errors:
        console.print(f"\n[red]Structural Errors ({len(assessment.structural_errors)}):[/red]")
        for err in assessment.structural_errors[:10]:
            console.print(f"  {err.get('code', '')}: {err.get('message', '')}")
        if len(assessment.structural_errors) > 10:
            console.print(f"  ... and {len(assessment.structural_errors) - 10} more")


def _as_dict(value: Any) -> dict[str, Any]:
    """Coerce a possibly-malformed manifest value to a dict for tolerant display."""
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    """Coerce a possibly-malformed manifest value to a list for tolerant display."""
    return value if isinstance(value, list) else []


def print_bundle_info(manifest_data: dict[str, Any]) -> None:
    """Print bundle inspection output."""
    # ``inspect`` is a tolerant summary view: a malformed-but-JSON-object manifest
    # may carry a non-object metadata / producer / non-array sections (schema
    # conformance is ``validate``'s job). Coerce non-objects/arrays via
    # _as_dict/_as_list so each access degrades to a placeholder instead of
    # raising a raw AttributeError/TypeError.
    metadata = manifest_data.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    producer = metadata.get("producer", {})
    if not isinstance(producer, dict):
        producer = {}

    console.print()
    console.print(
        Panel.fit(
            f"[bold]ACEF Evidence Bundle[/bold]\n"
            f"Package ID: {metadata.get('package_id', 'N/A')}\n"
            f"Timestamp: {metadata.get('timestamp', 'N/A')}\n"
            f"Producer: {producer.get('name', 'N/A')} "
            f"v{producer.get('version', 'N/A')}",
            border_style="blue",
        )
    )

    # Subjects
    subjects = _as_list(manifest_data.get("subjects", []))
    if subjects:
        table = Table(title="Subjects")
        table.add_column("Name", style="cyan")
        table.add_column("Type")
        table.add_column("Risk Classification")
        table.add_column("Phase")

        for raw_sub in subjects:
            sub = _as_dict(raw_sub)
            table.add_row(
                str(sub.get("name", "")),
                str(sub.get("subject_type", "")),
                str(sub.get("risk_classification", "")),
                str(sub.get("lifecycle_phase", "")),
            )
        console.print(table)

    # Entity counts
    entities = _as_dict(manifest_data.get("entities", {}))
    console.print(
        f"\nEntities: "
        f"{len(_as_list(entities.get('components', [])))} components, "
        f"{len(_as_list(entities.get('datasets', [])))} datasets, "
        f"{len(_as_list(entities.get('actors', [])))} actors, "
        f"{len(_as_list(entities.get('relationships', [])))} relationships"
    )

    # Record files
    record_files = _as_list(manifest_data.get("record_files", []))
    if record_files:
        table = Table(title="Record Files")
        table.add_column("Type", style="cyan")
        table.add_column("Path")
        table.add_column("Count", justify="right")

        total_records = 0
        for raw_rf in record_files:
            rf = _as_dict(raw_rf)
            count = rf.get("count", 0)
            count_int = count if isinstance(count, int) and not isinstance(count, bool) else 0
            table.add_row(str(rf.get("record_type", "")), str(rf.get("path", "")), str(count_int))
            total_records += count_int
        console.print(table)
        console.print(f"Total records: {total_records}")

    # Profiles
    profiles = _as_list(manifest_data.get("profiles", []))
    if profiles:
        profile_ids = ", ".join(str(_as_dict(p).get("profile_id", "")) for p in profiles)
        console.print(f"\nProfiles: {profile_ids}")
