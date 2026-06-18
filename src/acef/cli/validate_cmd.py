"""ACEF CLI — validate command: validate a bundle with pretty output."""

from __future__ import annotations

import json
import sys

import click

from acef.assessment_builder import validate
from acef.cli.formatters import print_assessment
from acef.errors import ACEFFormatError
from acef.models.enums import ProvisionOutcome, RuleOutcome


@click.command("validate")
@click.argument("path")
@click.option("--profile", "-p", multiple=True, help="Profile IDs to validate against")
@click.option("--output", "-o", default=None, help="Write assessment JSON to file")
@click.option("--format", "fmt", default="pretty", type=click.Choice(["pretty", "json", "markdown"]))
@click.option(
    "--trust-anchor",
    "trust_anchor",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help=(
        "Path to a PEM- or DER-encoded X.509 trust-anchor certificate (repeatable). "
        "When supplied, an x5c signature chain MUST terminate at one of these anchors "
        "per spec §3.1.3; chains that do not surface ACEF-012. Omit for self-attested "
        "trust (no anchor enforcement)."
    ),
)
@click.option(
    "--expected-producer",
    "expected_producer",
    default=None,
    help=(
        "Expected signer identity (spec Appendix D.3): the EXACT full leaf certificate "
        "subject DN (RFC 4514), e.g. 'CN=acme,O=ACME Corp'. With --trust-anchor, an ANCHORED "
        "signature whose subject does not match surfaces ACEF-012 (valid signature, wrong "
        "signer). A bare CN is NOT accepted. Omit to report the binding without enforcing identity."
    ),
)
def validate_cmd(
    path: str,
    profile: tuple[str, ...],
    output: str | None,
    fmt: str,
    trust_anchor: tuple[str, ...],
    expected_producer: str | None,
) -> None:
    """Validate an ACEF Evidence Bundle at PATH.

    Accepts a directory bundle or an ``.acef.tar.gz`` archive. Optionally specify
    --profile to evaluate against regulation mapping templates.

    Archive inputs are validated AS RECEIVED: the public ``validate`` API
    safely extracts the archive bytes verbatim (via the shared
    ``loader.extract_archive_raw`` primitive) and runs the SAME validation
    pipeline against the extracted bytes. The integrity files inside the archive
    are checked as-is, so a tampered archive (e.g. stripped ``merkle-tree.json``
    or a content-hash mismatch) is rejected — it is NOT round-tripped through
    load→export, which would heal the tampering before validation.
    """
    profiles = list(profile) if profile else None

    # Load operator-supplied trust anchors (spec §3.1.3). ``click.Path(exists=True)``
    # already rejected a nonexistent path; ``load_trust_anchors`` rejects a file
    # whose bytes are not a PEM/DER certificate with a structured ACEF-012 error,
    # which we surface as a clean message + exit 2 rather than a raw traceback
    # (the same failure contract the rest of this command honors).
    trust_anchors = None
    if trust_anchor:
        from acef.errors import ACEFSigningError
        from acef.signing import load_trust_anchors

        try:
            trust_anchors = load_trust_anchors(trust_anchor)
        except ACEFSigningError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(2)

    # Delegate directly to the public ``validate`` API. Its archive branch now
    # performs the raw safe-extraction (no load→export healing), so the CLI no
    # longer duplicates extraction logic — directory and archive inputs share
    # one code path with identical integrity verdicts.
    #
    # A missing or malformed ARCHIVE (``extract_archive_raw`` raises
    # ``ACEFFormatError`` ACEF-050 — "Archive not found" for a nonexistent path,
    # "Malformed or corrupt archive: ... not a gzip file" for a non-gzip
    # ``*.tar.gz``) must surface as a CLEAN error + the SAME non-zero exit code a
    # missing/malformed DIRECTORY produces, not an uncaught traceback. A
    # missing/malformed DIRECTORY returns an ``AssessmentBundle`` carrying a FATAL
    # structural error (ACEF-002 / ACEF-050) → ``has_fatal`` → exit 2 below; we
    # mirror that exit code (2) here so directory and archive inputs are
    # SYMMETRIC. ``--format json`` emits a structured error object (the same
    # ``structural_errors`` shape a fatal directory assessment carries) so a
    # ``| jq`` consumer never receives a traceback on stdout.
    try:
        assessment = validate(path, profiles=profiles, trust_anchors=trust_anchors, expected_producer=expected_producer)
    except ACEFFormatError as exc:
        code = exc.code or "ACEF-050"
        # ``str(exc)`` is ``"[ACEF-050] <message>"`` (the ``ACEFError.__str__``
        # prefixes the code) — appropriate for the HUMAN text/stderr path, where an
        # inline ``[ACEF-050]`` reads naturally. ``exc.message`` is the SAME text
        # WITHOUT the ``[CODE]`` prefix — the right form for the machine-readable
        # JSON ``ValidationDiagnostic``, whose separate ``code`` field already
        # carries the code. Embedding the prefix in the JSON ``message`` too would
        # DUPLICATE the code (engine-emitted diagnostics carry a bare message, e.g.
        # ``"acef-manifest.json not found"``, with no embedded ``[CODE]``).
        text_message = str(exc)
        json_message = exc.message
        if fmt == "json":
            # Emit a NORMAL AssessmentBundle — the SAME type+serialization the
            # success path uses (``assessment.to_dict()`` below) — so a
            # ``--format json`` consumer always receives the standard validate
            # payload shape, never an ad-hoc partial object. The error is carried
            # as a ``ValidationDiagnostic`` in ``structural_errors``, exactly as
            # ``validation.engine`` records a structural failure (e.g.
            # ``ValidationDiagnostic("ACEF-002", ...).to_dict()``). The diagnostic
            # DERIVES its severity + category from the error registry for ``code``
            # (ACEF-050 → fatal/format; a non-fatal ACEFFormatError code such as
            # ACEF-052 → error/format) — it does NOT hard-code ``"fatal"`` or omit
            # ``category``, which would misrepresent non-fatal format codes.
            from acef.errors import ValidationDiagnostic
            from acef.models.assessment import AssessmentBundle

            error_assessment = AssessmentBundle()
            error_assessment.structural_errors.append(ValidationDiagnostic(code, json_message, path=path).to_dict())
            click.echo(json.dumps(error_assessment.to_dict(), indent=2))
        else:
            click.echo(f"Error: {text_message}", err=True)
        # Match the missing/malformed-DIRECTORY exit code (FATAL → 2) so archive
        # and directory inputs return the same code for the equivalent failure.
        # Exit code and the diagnostic's registry severity are separate concerns:
        # the CLI exits 2 for the archive-failure (mirroring the directory FATAL
        # exit) even when the diagnostic's registry severity is non-fatal — the
        # JSON BODY carries the diagnostic's TRUE registry severity/category.
        sys.exit(2)

    if fmt == "json":
        click.echo(json.dumps(assessment.to_dict(), indent=2))
    elif fmt == "markdown":
        from acef.render import render_markdown

        click.echo(render_markdown(assessment))
    else:
        print_assessment(assessment)

    if output:
        from acef.assessment_builder import export_assessment
        from acef.errors import ACEFError

        # An unwritable ``--output`` path (parent is a file, read-only FS, etc.)
        # must surface as a clean error + non-zero exit, NOT an uncaught OSError
        # traceback — which would corrupt a ``--format json`` consumer reading
        # stdout (audit: arg-handling defect).
        try:
            export_assessment(assessment, output)
        except (OSError, ACEFError) as exc:
            click.echo(f"Error: Cannot write assessment to {output}: {exc}", err=True)
            sys.exit(2)
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
