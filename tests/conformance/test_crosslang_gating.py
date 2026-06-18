"""Tests for the cross-language gating helper (PhD-review finding 32).

Verifies that an absent TS driver is a LOUD FAILURE by default (not a silent
skip), and that the explicit ACEF_SKIP_CROSSLANG=1 opt-out downgrades it to a
labelled skip.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conformance._crosslang import require_ts_cli


def test_absent_driver_fails_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACEF_SKIP_CROSSLANG", raising=False)
    # pytest.fail raises Failed (an OutcomeException / BaseException subclass).
    with pytest.raises(pytest.fail.Exception) as exc:
        require_ts_cli(Path("/nonexistent/ts-cli.js"), what="TS test-cli")
    assert "UNPROVEN" in str(exc.value), "absent TS driver must fail loudly, not skip silently"


def test_present_driver_passes(tmp_path: Path) -> None:
    cli = tmp_path / "present-cli.js"
    cli.write_text("// stub", encoding="utf-8")
    # No exception => the gate lets the test proceed.
    require_ts_cli(cli, what="TS test-cli")


def test_opt_out_downgrades_to_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACEF_SKIP_CROSSLANG", "1")
    # pytest.skip raises Skipped — NOT Failed — distinguished by the message.
    with pytest.raises(pytest.skip.Exception) as exc:
        require_ts_cli(Path("/nonexistent/ts-cli.js"), what="TS test-cli")
    assert "opted out" in str(exc.value)
