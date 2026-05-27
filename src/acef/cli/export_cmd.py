"""ACEF CLI — export command: export directory/archive."""

from __future__ import annotations

import click

from acef.loader import load


@click.command("export")
@click.argument("input_path")
@click.argument("output_path")
@click.option(
    "--format",
    "fmt",
    default=None,
    type=click.Choice(["directory", "archive"]),
    help="Output format. If omitted, inferred from output_path suffix "
    "(.tar.gz → archive, anything else → directory).",
)
@click.option("--sign", "key_path", default=None, help="Path to PEM private key for signing")
def export_cmd(input_path: str, output_path: str, fmt: str | None, key_path: str | None) -> None:
    """Export an ACEF bundle from INPUT_PATH to OUTPUT_PATH.

    Can convert between directory and archive formats. When ``--format`` is
    omitted the format is inferred from ``output_path``; when explicitly
    provided it is strictly honored regardless of the path suffix.
    """
    pkg = load(input_path)

    if key_path:
        pkg.sign(key_path)

    # If the caller did not specify --format, infer it from the output
    # path suffix (backward-compatible behavior). If they did specify
    # one, honor it strictly so passing --format directory cannot
    # silently produce an archive.
    if fmt is None:
        fmt = "archive" if output_path.endswith(".tar.gz") else "directory"

    if fmt == "archive":
        if not output_path.endswith(".tar.gz"):
            output_path += ".acef.tar.gz"
        pkg.export(output_path)
        click.echo(f"Exported archive: {output_path}")
    elif fmt == "directory":
        # Strip any .tar.gz suffix that would otherwise mislead Package.export
        # into producing an archive.
        if output_path.endswith(".acef.tar.gz"):
            output_path = output_path[: -len(".acef.tar.gz")]
        elif output_path.endswith(".tar.gz"):
            output_path = output_path[: -len(".tar.gz")]
        pkg.export(output_path)
        click.echo(f"Exported directory: {output_path}")
    else:
        # click.Choice should make this unreachable; keep defensive.
        raise click.UsageError(f"Unknown --format value: {fmt!r}")
