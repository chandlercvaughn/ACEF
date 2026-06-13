"""ACEF CLI — validate command: validate a bundle with pretty output."""

from __future__ import annotations

import json
import sys
import tarfile
import tempfile
from contextlib import ExitStack
from pathlib import Path

import click

from acef.assessment_builder import validate
from acef.cli.formatters import print_assessment
from acef.models.enums import ProvisionOutcome, RuleOutcome


def _is_archive(path: Path) -> bool:
    """Return True if ``path`` is an ``.acef.tar.gz`` archive file."""
    return path.is_file() and (path.suffix == ".gz" or str(path).endswith(".tar.gz"))


def extract_archive_raw(archive_path: Path, stack: ExitStack) -> Path:
    """Safely extract an ``.acef.tar.gz`` archive VERBATIM and return its bundle
    root directory.

    Reuses the loader's vetted safety primitives (``_validate_tar_safety`` +
    ``_safe_tar_extract``) — the SAME safe-extract path ``load()`` uses — so the
    CLI never introduces a second, unsafe extractor. The temp directory is
    registered on ``stack`` and cleaned up when the caller's ``with`` block exits,
    AFTER validation has run against the extracted files.

    Crucially this extracts the archive bytes EXACTLY as received: it does NOT
    round-trip through ``load()`` + ``Package.export()``, which would regenerate
    ``hashes/content-hashes.json`` / ``hashes/merkle-tree.json`` from the loaded
    records and SILENTLY HEAL any tampering (e.g. a stripped Merkle tree or a
    content-hash mismatch) before the validator ever ran. Validating the raw
    extracted directory makes ``validate`` detect archive tampering with the same
    integrity verdict (ACEF-010 hash mismatch, ACEF-011 missing/invalid Merkle
    tree, etc.) it produces for the equivalent directory bundle.

    Mirrors ``doctor``'s archive handling and ``loader._load_archive``'s bundle-root
    resolution.
    """
    from acef.loader import _safe_tar_extract, _validate_tar_safety

    tmpdir = Path(stack.enter_context(tempfile.TemporaryDirectory()))
    with tarfile.open(str(archive_path), "r:gz") as tar:
        _validate_tar_safety(tar)
        _safe_tar_extract(tar, tmpdir)

    # Find the bundle root: a single nested directory is the canonical archive
    # layout; otherwise the temp dir itself is the bundle root.
    extracted = list(tmpdir.iterdir())
    if len(extracted) == 1 and extracted[0].is_dir():
        return extracted[0]
    return tmpdir


@click.command("validate")
@click.argument("path")
@click.option("--profile", "-p", multiple=True, help="Profile IDs to validate against")
@click.option("--output", "-o", default=None, help="Write assessment JSON to file")
@click.option("--format", "fmt", default="pretty", type=click.Choice(["pretty", "json", "markdown"]))
def validate_cmd(path: str, profile: tuple[str, ...], output: str | None, fmt: str) -> None:
    """Validate an ACEF Evidence Bundle at PATH.

    Accepts a directory bundle or an ``.acef.tar.gz`` archive. Optionally specify
    --profile to evaluate against regulation mapping templates.

    Archive inputs are validated AS RECEIVED: the archive is safely extracted
    verbatim and the SAME validation pipeline runs against the extracted bytes.
    The integrity files inside the archive are checked as-is, so a tampered
    archive (e.g. stripped ``merkle-tree.json`` or a content-hash mismatch) is
    rejected — it is NOT round-tripped through load→export, which would heal the
    tampering before validation.
    """
    profiles = list(profile) if profile else None
    bundle_path = Path(path)

    with ExitStack() as stack:
        if _is_archive(bundle_path):
            # Resolve the archive to a RAW-extracted directory and validate that.
            # Passing the extracted directory (not the archive path) to
            # ``validate`` bypasses its archive branch's load→export round-trip,
            # which heals tampering. See ``extract_archive_raw``.
            target: str | Path = extract_archive_raw(bundle_path, stack)
        else:
            target = path

        assessment = validate(target, profiles=profiles)

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
