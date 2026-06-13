"""ACEF CLI — export command: export directory/archive."""

from __future__ import annotations

from typing import TYPE_CHECKING

import click

from acef.errors import ACEFError
from acef.loader import load

if TYPE_CHECKING:
    from acef.package import Package


@click.command("export")
@click.argument("input_path")
@click.argument("output_path")
@click.option(
    "--format",
    "fmt",
    default=None,
    type=click.Choice(["directory", "archive"]),
    help="Output format. If omitted, inferred from output_path suffix (.tar.gz → archive, anything else → directory).",
)
@click.option("--sign", "key_path", default=None, help="Path to PEM private key for signing")
def export_cmd(input_path: str, output_path: str, fmt: str | None, key_path: str | None) -> None:
    """Export an ACEF bundle from INPUT_PATH to OUTPUT_PATH.

    Can convert between directory and archive formats. When ``--format`` is
    omitted the format is inferred from ``output_path``; when explicitly
    provided it is strictly honored regardless of the path suffix.

    Exit codes: 0 on success; 1 on a clean failure (input not a loadable bundle,
    signing key unreadable, or the export write failing). A bad input path,
    a non-bundle file, or an unreadable ``--sign`` key are surfaced as a
    structured ``Error:`` message on stderr — never an uncaught Python traceback.
    """
    # Load the input bundle. ``load`` raises ACEFError subclasses (e.g.
    # ACEFFormatError ACEF-050) when the path is missing or is not a directory /
    # .acef.tar.gz archive; surface that as a clean error + exit 1 rather than
    # letting the traceback escape (audit: arg-handling defect — export leaked an
    # uncaught ACEFFormatError with empty user output for a bad input path).
    try:
        pkg = load(input_path)
    except ACEFError as exc:
        click.echo(f"Error: Cannot load bundle from {input_path}: {exc}", err=True)
        raise SystemExit(1) from exc
    except OSError as exc:
        click.echo(f"Error: Cannot read input {input_path}: {exc}", err=True)
        raise SystemExit(1) from exc

    if key_path:
        # ``sign`` raises ACEFExportError (ACEF-050) when the key path is missing
        # or unreadable. Same clean-error contract: a bad ``--sign`` key must not
        # crash the CLI with a traceback (audit: arg-handling defect).
        try:
            pkg.sign(key_path)
        except ACEFError as exc:
            click.echo(f"Error: Cannot sign with key {key_path}: {exc}", err=True)
            raise SystemExit(1) from exc
        except OSError as exc:
            click.echo(f"Error: Cannot read signing key {key_path}: {exc}", err=True)
            raise SystemExit(1) from exc

    # If the caller did not specify --format, infer it from the output
    # path suffix (backward-compatible behavior). If they did specify
    # one, honor it strictly so passing --format directory cannot
    # silently produce an archive.
    if fmt is None:
        fmt = "archive" if output_path.endswith(".tar.gz") else "directory"

    if fmt == "archive":
        if not output_path.endswith(".tar.gz"):
            output_path += ".acef.tar.gz"
        _do_export(pkg, output_path)
        click.echo(f"Exported archive: {output_path}")
    elif fmt == "directory":
        # Strip any .tar.gz suffix that would otherwise mislead Package.export
        # into producing an archive.
        if output_path.endswith(".acef.tar.gz"):
            output_path = output_path[: -len(".acef.tar.gz")]
        elif output_path.endswith(".tar.gz"):
            output_path = output_path[: -len(".tar.gz")]
        _do_export(pkg, output_path)
        click.echo(f"Exported directory: {output_path}")
    else:
        # click.Choice should make this unreachable; keep defensive.
        raise click.UsageError(f"Unknown --format value: {fmt!r}")


def _do_export(pkg: Package, output_path: str) -> None:
    """Export ``pkg`` to ``output_path``, converting export faults into a clean
    CLI error + exit 1.

    ``Package.export`` performs the JWS signing pass when a signing key was
    registered (so an unreadable ``--sign`` key surfaces here as
    ``ACEFExportError``), and raises on any write/serialization fault. Both must
    reach the user as a structured ``Error:`` message rather than an uncaught
    traceback (audit: arg-handling defect — a bad ``--sign`` key crashed export).
    """
    try:
        pkg.export(output_path)
    except ACEFError as exc:
        click.echo(f"Error: Failed to export bundle to {output_path}: {exc}", err=True)
        raise SystemExit(1) from exc
    except OSError as exc:
        click.echo(f"Error: Cannot write bundle to {output_path}: {exc}", err=True)
        raise SystemExit(1) from exc
