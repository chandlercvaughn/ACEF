"""ACEF CLI — main entry point with Click group."""

from __future__ import annotations

import io
import sys

import click

from acef._version import __version__


def _force_utf8_streams() -> None:
    """Reconfigure stdout/stderr to UTF-8 so non-ASCII bundle contents print.

    Spec §3.1.1 requires UTF-8 NFC throughout. On systems with LANG=C or
    LANG=POSIX, Python's default stdout encoding may fall back to ASCII
    and raise UnicodeEncodeError when Rich/click prints non-ASCII subject
    names. Reconfiguring once at CLI entry ensures output is consistent
    across locales.
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name)
        # Newer Python (3.7+) exposes reconfigure() on text streams.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="strict")
            except (io.UnsupportedOperation, ValueError):
                # Some streams (e.g., pytest captures) don't support reconfigure.
                pass


_force_utf8_streams()


@click.group()
@click.version_option(version=__version__, prog_name="acef")
def cli() -> None:
    """ACEF — AI Compliance Evidence Format CLI.

    Tools for creating, validating, and inspecting ACEF Evidence Bundles.
    """
    pass


# Import and register subcommands. These imports are intentionally placed after
# _force_utf8_streams() runs (above) so that any module-level console/encoding
# setup in the subcommand modules observes the reconfigured UTF-8 streams.
# E402 is suppressed for this deliberate ordering (spec §3.1.1 UTF-8 NFC output).
from acef.cli.doctor_cmd import doctor_cmd  # noqa: E402
from acef.cli.export_cmd import export_cmd  # noqa: E402
from acef.cli.init_cmd import init_cmd  # noqa: E402
from acef.cli.inspect_cmd import inspect_cmd  # noqa: E402
from acef.cli.record_cmd import record_cmd  # noqa: E402
from acef.cli.scaffold_cmd import scaffold_cmd  # noqa: E402
from acef.cli.validate_cmd import validate_cmd  # noqa: E402
from acef.cli.verify_cmd import verify_cmd  # noqa: E402

cli.add_command(init_cmd, "init")
cli.add_command(validate_cmd, "validate")
cli.add_command(verify_cmd, "verify")
cli.add_command(export_cmd, "export")
cli.add_command(inspect_cmd, "inspect")
cli.add_command(record_cmd, "record")
cli.add_command(scaffold_cmd, "scaffold")
cli.add_command(doctor_cmd, "doctor")


if __name__ == "__main__":
    cli()
