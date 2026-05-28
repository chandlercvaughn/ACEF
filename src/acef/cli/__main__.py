"""Allow ``python -m acef.cli`` invocation as a fallback when the
installed ``acef`` console_script entrypoint is unavailable.

The standalone entrypoint declared in ``pyproject.toml`` is the preferred
invocation surface; this module dispatches to the same Click group.
"""

from __future__ import annotations

from acef.cli.main import cli

if __name__ == "__main__":
    cli()
