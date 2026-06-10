"""ACEF CLI — validate command: validate a bundle with pretty output."""

from __future__ import annotations

import json
import sys

import click

from acef.assessment_builder import validate
from acef.cli.formatters import print_assessment
from acef.models.enums import ProvisionOutcome, RuleOutcome


@click.command("validate")
@click.argument("path")
@click.option("--profile", "-p", multiple=True, help="Profile IDs to validate against")
@click.option("--output", "-o", default=None, help="Write assessment JSON to file")
@click.option("--format", "fmt", default="pretty", type=click.Choice(["pretty", "json", "markdown"]))
def validate_cmd(path: str, profile: tuple[str, ...], output: str | None, fmt: str) -> None:
    """Validate an ACEF Evidence Bundle at PATH.

    Optionally specify --profile to evaluate against regulation mapping templates.
    """
    profiles = list(profile) if profile else None
    assessment = validate(path, profiles=profiles)

    if fmt == "json":
        click.echo(json.dumps(assessment.to_dict(), indent=2))
    elif fmt == "markdown":
        from acef.render import render_markdown

        click.echo(render_markdown(assessment))
    else:
        print_assessment(assessment)

    if output:
        from acef.assessment_builder import export_assessment

        export_assessment(assessment, output)
        # Send the "Assessment written to:" status line to STDERR. This
        # keeps stdout exclusively machine-readable in --format json mode
        # so `acef validate ... -f json -o out | jq` succeeds.
        click.echo(f"Assessment written to: {output}", err=True)

    # Exit code based on results
    has_fatal = any(e.get("severity") == "fatal" for e in assessment.structural_errors)
    has_not_satisfied = any(
        ps.provision_outcome == ProvisionOutcome.NOT_SATISFIED for ps in assessment.provision_summary
    )
    # Rule ERROR outcomes indicate the evaluator could not finish — surface
    # them via non-zero exit so CI does not report green on broken engines.
    has_rule_error = any(r.outcome == RuleOutcome.ERROR for r in assessment.results)

    if has_fatal:
        sys.exit(2)
    elif has_not_satisfied or has_rule_error:
        sys.exit(1)
    else:
        sys.exit(0)
