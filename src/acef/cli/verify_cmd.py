"""ACEF CLI -- ``verify`` command: lightweight bundle verification for CI.

``verify`` is the CI-friendly counterpart to ``validate``:

* ``validate``  -- full assessment (loads regulation profiles, evaluates DSL
  rules, computes provision outcomes). Used when a full conformance report
  is needed.
* ``verify``    -- lightweight: schema + integrity + signatures + cross-record
  rules. No profile loading, no provision rollup. Used in CI on every bundle
  to catch structural defects fast.

Both share the same Phase 1-3 validator pipeline; ``verify`` simply skips
Phase 4 (profile rule evaluation) and uses an exit-code policy tuned for CI
on the existing test corpus.

Baseline diagnostic downgrade
-----------------------------
``verify`` supports an RFC-gated table of *baseline diagnostics* — specific
``(code, path-shape)`` pairs still reported to stderr but tolerated by the exit
code, for genuinely-frozen legacy bytes that a tightened schema retroactively
flags. The table is currently EMPTY: the sole historical entry (``ACEF-002`` at
``/audit_trail/<int>/actor_ref``) existed only because the v0.3-era goldens
carried ``audit_trail[0].actor_ref = ""``; F1 regenerated those goldens with a
schema-valid deterministic producer actor_ref, so the SDK no longer emits that
diagnostic and the downgrade is obsolete. Removing it means a FRESH bundle with
an invalid audit-trail actor_ref correctly FAILS verification (it no longer
slips through CI). Any future baseline entry requires a spec-author RFC.
"""

from __future__ import annotations

import json
import re
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Any

import click

from acef.loader import extract_archive_raw
from acef.validation.engine import validate_bundle

# Baseline downgrade table.
#
# Each entry: ``(code, path_regex)`` -- if the diagnostic matches both, it is
# downgraded from fatal/error to "baseline" (reported but does not affect the
# exit code). Path is matched against the diagnostic's ``path`` field
# (JSON-pointer-like).
#
# Extending this table requires a spec-author RFC. Adding entries silently is
# a regression of the verify contract.
# Currently EMPTY: the SDK emits schema-valid bundles (F1), so no diagnostic needs
# downgrading. A FRESH invalid audit-trail actor_ref now correctly fails verify.
_BASELINE_DIAGNOSTICS: tuple[tuple[str, re.Pattern[str]], ...] = ()


def _is_baseline(diag: dict[str, Any]) -> bool:
    """Return True if ``diag`` matches a known frozen-bundle baseline.

    A baseline diagnostic is reported but does not fail the CI exit code.
    """
    code = diag.get("code", "")
    path = diag.get("path", "") or ""
    for baseline_code, baseline_path_re in _BASELINE_DIAGNOSTICS:
        if code == baseline_code and baseline_path_re.match(path):
            return True
    return False


def _classify(diag: dict[str, Any]) -> str:
    """Return classification: "baseline", "fatal", "error", "warning", "info"."""
    if _is_baseline(diag):
        return "baseline"
    severity = diag.get("severity", "error")
    if severity == "fatal":
        return "fatal"
    if severity == "error":
        return "error"
    if severity == "warning":
        return "warning"
    return "info"


def _print_pretty(
    bundle_path: str,
    tallies: dict[str, int],
    diagnostics: list[dict[str, Any]],
    quiet: bool,
) -> None:
    """Print a human-readable verification report."""
    if not quiet:
        click.echo(f"Verifying: {bundle_path}", err=True)
    # Only emit any per-diagnostic detail if there is something to report.
    if not diagnostics:
        if not quiet:
            click.echo("OK -- no diagnostics", err=True)
        return

    for d in diagnostics:
        cls = _classify(d)
        code = d.get("code", "?")
        sev = d.get("severity", "?")
        msg = d.get("message", "")
        path = d.get("path", "")
        prefix = {
            "fatal": "FATAL",
            "error": "ERROR",
            "warning": "WARN ",
            "info": "INFO ",
            "baseline": "BASE ",
        }.get(cls, sev.upper())
        path_str = f" [{path}]" if path else ""
        # ACEF-NNN codes appear in stderr so VAL-CLI-003's
        # "code substring on stdout or stderr" check finds them.
        click.echo(f"{prefix} {code}{path_str}: {msg}", err=True)

    if not quiet:
        summary_parts = []
        for kind in ("fatal", "error", "warning", "baseline", "info"):
            count = tallies.get(kind, 0)
            if count:
                summary_parts.append(f"{kind}={count}")
        click.echo("Summary: " + (", ".join(summary_parts) or "clean"), err=True)


def _print_json(
    bundle_path: str,
    exit_code: int,
    tallies: dict[str, int],
    diagnostics: list[dict[str, Any]],
) -> None:
    """Print a machine-readable verification report on stdout.

    ACEF-NNN codes are preserved verbatim in the ``code`` field of each
    diagnostic, satisfying VAL-CLI-003's "code substring" requirement on
    stdout for ``--format json``.
    """
    classified = []
    for d in diagnostics:
        out = dict(d)
        out["classification"] = _classify(d)
        classified.append(out)

    report = {
        "path": bundle_path,
        "exit_code": exit_code,
        "tallies": tallies,
        "diagnostics": classified,
    }
    click.echo(json.dumps(report, indent=2))


def _compute_exit_code(tallies: dict[str, int]) -> int:
    """Map non-baseline tallies to a CI exit code.

    * 0 -- no non-baseline fatal/error
    * 1 -- one or more non-baseline errors
    * 2 -- one or more non-baseline fatals
    """
    if tallies.get("fatal", 0) > 0:
        return 2
    if tallies.get("error", 0) > 0:
        return 1
    return 0


@click.command("verify")
@click.argument("path")
@click.option(
    "--format",
    "fmt",
    default="pretty",
    type=click.Choice(["pretty", "json"]),
    help="Output format. ``pretty`` writes to stderr; ``json`` writes a structured report to stdout.",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Suppress non-diagnostic output (banner, summary).",
)
def verify_cmd(path: str, fmt: str, quiet: bool) -> None:
    """Verify an ACEF Evidence Bundle at PATH.

    Accepts a directory bundle or an ``.acef.tar.gz`` archive. Runs schema
    validation, integrity verification, reference checking, and (for v1.1
    bundles) cross-record rules, banned-language lint, and vendor-namespace lint
    hooks. Does NOT load regulation profiles or compute provision outcomes --
    use ``acef validate`` for that.

    Archive inputs are verified AS RECEIVED: the archive is safely extracted
    verbatim and the SAME validator runs against the extracted bytes, so a
    tampered archive (e.g. stripped ``merkle-tree.json`` or a content-hash
    mismatch) is rejected with the matching integrity code. The archive is NOT
    round-tripped through load→export, which would heal the tampering.

    Exit codes:

      * 0 -- no fresh fatal/error diagnostics (baseline diagnostics tolerated)
      * 1 -- one or more fresh error diagnostics
      * 2 -- one or more fresh fatal diagnostics

    Known baseline diagnostics (legacy frozen-bundle compatibility) are
    reported but do not affect the exit code.
    """
    bundle_path = Path(path)
    if not bundle_path.exists():
        click.echo(f"ERROR: bundle path does not exist: {path}", err=True)
        sys.exit(2)

    is_archive = bundle_path.is_file() and (bundle_path.suffix == ".gz" or str(bundle_path).endswith(".tar.gz"))
    if not bundle_path.is_dir() and not is_archive:
        click.echo(
            f"ERROR: bundle path is not a directory or .acef.tar.gz archive: {path}",
            err=True,
        )
        sys.exit(2)

    with ExitStack() as stack:
        if is_archive:
            # Resolve the archive to a RAW-extracted directory and verify that.
            # The shared ``loader.extract_archive_raw`` context manager extracts
            # the bytes verbatim (no load→export round-trip), so the integrity
            # check sees the archive's real on-disk state and detects tampering.
            # Entering it on ``stack`` keeps the temp dir alive until this
            # ``with`` block exits, after the validator has run.
            try:
                target = stack.enter_context(extract_archive_raw(bundle_path))
            except Exception as e:  # noqa: BLE001 — surface any extraction fault as a clean exit, never crash
                click.echo(f"ERROR: archive could not be extracted: {e}", err=True)
                sys.exit(2)
            report_path = str(bundle_path)
        else:
            target = bundle_path
            report_path = str(bundle_path)

        # ``profiles=None`` skips Phase 4 (rule evaluation). The other phases
        # still run and populate ``structural_errors``.
        assessment = validate_bundle(str(target), profiles=None)
        diagnostics: list[dict[str, Any]] = list(assessment.structural_errors)

        # Tally by classification.
        tallies: dict[str, int] = {
            "fatal": 0,
            "error": 0,
            "warning": 0,
            "baseline": 0,
            "info": 0,
        }
        for d in diagnostics:
            tallies[_classify(d)] = tallies.get(_classify(d), 0) + 1

        exit_code = _compute_exit_code(tallies)

        if fmt == "json":
            _print_json(report_path, exit_code, tallies, diagnostics)
        else:
            _print_pretty(report_path, tallies, diagnostics, quiet)

    sys.exit(exit_code)
