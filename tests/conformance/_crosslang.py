"""Shared cross-language conformance gating (PhD-review finding 32).

The cross-language parity tests previously called ``pytest.skip`` when the
TypeScript SDK artifacts were absent — so a fresh clone or a CI runner that did
not ``npm run build:test`` saw the whole cross-language tier SILENTLY SKIPPED
while the suite still reported all-green, hiding an unproven parity claim.

``require_ts_cli`` makes that absence a LOUD FAILURE by default (parity unproven
== red), with a single explicit opt-out: set ``ACEF_SKIP_CROSSLANG=1`` to skip
on a machine where TypeScript is deliberately not built (parity then NOT
verified). The default — including CI — fails, surfacing the gap.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

_OPT_OUT_ENV = "ACEF_SKIP_CROSSLANG"


def crosslang_opted_out() -> bool:
    return os.environ.get(_OPT_OUT_ENV) == "1"


def require_ts_cli(cli_path: Path, *, what: str) -> None:
    """FAIL (not silently skip) when a required TS driver is absent.

    Honors the explicit ``ACEF_SKIP_CROSSLANG=1`` opt-out, which downgrades the
    failure to a clearly-labelled skip so a local-only Python developer can run
    without the TS toolchain — at the cost of NOT verifying parity.
    """
    if cli_path.exists():
        return
    if crosslang_opted_out():
        pytest.skip(f"{what} absent and {_OPT_OUT_ENV}=1 set — cross-language parity NOT verified (opted out).")
    pytest.fail(
        f"{what} absent at {cli_path}: cross-language parity is UNPROVEN. Build the TS drivers "
        "(`cd packages/sdk-typescript && npm install && npm run build && npm run build:test`), or set "
        f"{_OPT_OUT_ENV}=1 to explicitly opt out (parity then NOT verified). A silent skip previously "
        "hid this conformance gap on fresh clones / CI."
    )
