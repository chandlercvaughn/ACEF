"""ACEF CLI — scaffold command: generate template stubs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from acef.templates.registry import list_templates, load_template

if TYPE_CHECKING:
    from acef.templates.models import Template


def _scaffold_to_dict(template: Template) -> dict[str, Any]:
    """Build a machine-readable scaffold of a template's provisions."""
    return {
        "template_id": template.template_id,
        "template_name": template.template_name,
        "version": template.version,
        "jurisdiction": template.jurisdiction,
        "provisions": [
            {
                "provision_id": p.provision_id,
                "provision_name": p.provision_name,
                "required_evidence_types": list(p.required_evidence_types or []),
                "minimum_evidence_count": dict(p.minimum_evidence_count or {}),
                "rules": [
                    {
                        "rule_id": r.rule_id,
                        "severity": r.severity if isinstance(r.severity, str) else r.severity.value,
                        "rule": r.rule,
                    }
                    for r in (p.evaluation or [])
                ],
            }
            for p in template.provisions
        ],
    }


@click.command("scaffold")
@click.argument("profile_id")
@click.option(
    "--output",
    "-o",
    default=None,
    help="Write the scaffold to this file path. If omitted, output goes to stdout.",
)
@click.option(
    "--format",
    "fmt",
    default="summary",
    type=click.Choice(["json", "summary"]),
    help="Output format. `summary` is human-readable; `json` is machine-readable.",
)
def scaffold_cmd(profile_id: str, output: str | None, fmt: str) -> None:
    """Generate evidence stubs for a regulation profile.

    Shows what records are needed and generates payload templates.
    Both ``--output`` and ``--format`` are now honored (previously they
    were accepted but ignored).
    """
    try:
        template = load_template(profile_id)
    except Exception as e:
        click.echo(f"Error loading template: {e}", err=True)
        available = list_templates()
        if available:
            click.echo(f"Available templates: {', '.join(available)}", err=True)
        raise SystemExit(1)

    if fmt == "json":
        rendered = json.dumps(_scaffold_to_dict(template), indent=2, sort_keys=True)
    else:
        lines: list[str] = []
        lines.append(f"Scaffold for: {template.template_name} ({template.template_id})")
        lines.append(f"Version: {template.version}")
        lines.append(f"Jurisdiction: {template.jurisdiction}")
        lines.append("")
        for provision in template.provisions:
            lines.append(f"  {provision.provision_id}: {provision.provision_name}")
            if provision.required_evidence_types:
                for rt in provision.required_evidence_types:
                    min_count = provision.minimum_evidence_count.get(rt, 1)
                    lines.append(f"    - {rt} (min: {min_count})")
            if provision.evaluation:
                for rule in provision.evaluation:
                    lines.append(f"    Rule: {rule.rule_id} [{rule.severity}] {rule.rule}")
            lines.append("")
        rendered = "\n".join(lines)

    if output:
        try:
            Path(output).write_text(rendered, encoding="utf-8")
        except OSError as exc:
            click.echo(f"Error writing scaffold to {output}: {exc}", err=True)
            raise SystemExit(1) from exc
        click.echo(f"Scaffold written to: {output}", err=True)
    else:
        click.echo(rendered)
