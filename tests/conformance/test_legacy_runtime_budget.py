"""Legacy conformance runtime budget gate (VAL-REGRESSION-LEGACY-BUDGET-001).

Verifies that the combined wall-clock of ``tests/conformance/`` excluding
``test_freddy_*`` does not exceed the pre-v0.4 baseline by more than 10%.

The baseline is recorded in ``tests/conformance/baseline-runtime.json`` and
was captured by F-M1-REGRESSION-SUITE at the start of WS8.

This test is inherently timing-sensitive. Mitigations:
  - Generous 10% headroom (per the contract assertion).
  - Skipped entirely when ``ACEF_SKIP_RUNTIME_BUDGET=1`` (machine-load
    aware: local dev should set this to avoid spurious failures from
    background processes).
  - Uses the *minimum* of three back-to-back runs as the measurement,
    which is more robust to transient load than median or mean.

The authoritative enforcement environment is CI. F-M1-TIER-INFRA owns the
CI scheduling.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

_THIS_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parents[2]
_BASELINE_PATH = _THIS_FILE.parent / "baseline-runtime.json"


def _load_baseline() -> dict:
    return json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))


@pytest.mark.legacy_budget
@pytest.mark.regression
def test_legacy_runtime_budget_baseline_file_exists() -> None:
    """Baseline file precondition: must exist with the expected schema."""
    assert _BASELINE_PATH.exists(), (
        f"Baseline runtime file missing at {_BASELINE_PATH}. It must be committed alongside the legacy-budget test."
    )
    data = _load_baseline()
    assert "wall_clock_seconds" in data
    assert "baseline_for_budget_check" in data["wall_clock_seconds"]
    assert "budget" in data
    assert "max_allowed_seconds" in data["budget"]
    assert data["budget"]["headroom_pct"] == 10


@pytest.mark.legacy_budget
@pytest.mark.regression
@pytest.mark.skipif(
    os.environ.get("ACEF_SKIP_RUNTIME_BUDGET") == "1",
    reason="ACEF_SKIP_RUNTIME_BUDGET=1 set (local dev opt-out).",
)
def test_val_regression_legacy_budget_001_runtime_within_10_percent() -> None:
    """VAL-REGRESSION-LEGACY-BUDGET-001: Combined wall-clock of
    ``tests/conformance/`` excluding ``test_freddy_*`` does NOT exceed the
    pre-v0.4 baseline by more than 10%.

    Measurement: three back-to-back invocations of the same pytest selection
    used to capture the baseline. The minimum of the three is compared to
    the budget. Minimum-of-N (rather than mean) is the standard technique
    for timing benchmarks because it filters transient noise (GC pauses,
    background processes) which only ADD time.

    The test is skipped when ``ACEF_SKIP_RUNTIME_BUDGET=1`` is set, to
    accommodate noisy local development machines. CI is the authoritative
    enforcement environment (see F-M1-TIER-INFRA).
    """
    baseline = _load_baseline()
    max_allowed = float(baseline["budget"]["max_allowed_seconds"])

    # Build the pytest invocation that mirrors the baseline-capture command
    # exactly. We deliberately drop -v (verbose) and use -q + --no-header
    # for the minimal output footprint, and -p no:cacheprovider so .pytest_cache
    # state does not skew the timing run-to-run.
    pytest_argv = [
        sys.executable,
        "-m",
        "pytest",
        "tests/conformance/",
        "--ignore-glob=*test_freddy_*",
        # Also ignore this very test to avoid self-recursion (pytest would
        # otherwise descend into the budget test, which would loop).
        f"--ignore={_THIS_FILE.relative_to(_PROJECT_ROOT)}",
        "-q",
        "--no-header",
        "-p",
        "no:cacheprovider",
        "--override-ini=addopts=",  # neutralize the -v in pyproject.toml
    ]

    runs: list[float] = []
    for _ in range(3):
        start = time.perf_counter()
        result = subprocess.run(
            pytest_argv,
            cwd=_PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        elapsed = time.perf_counter() - start
        runs.append(elapsed)
        # If the suite itself fails, the budget test is meaningless. Surface
        # that as a failure with full output for diagnosis.
        if result.returncode != 0:
            pytest.fail(
                f"Inner pytest run failed (exit {result.returncode}) -- runtime "
                f"budget cannot be measured on a broken suite.\n"
                f"--- stdout (tail) ---\n{result.stdout[-2000:]}\n"
                f"--- stderr (tail) ---\n{result.stderr[-2000:]}"
            )

    best = min(runs)
    assert best <= max_allowed, (
        f"Legacy conformance suite runtime regression detected.\n"
        f"  baseline (s)            : {baseline['wall_clock_seconds']['baseline_for_budget_check']}\n"
        f"  max allowed (s, +10%)   : {max_allowed}\n"
        f"  observed runs (s)       : {[round(r, 3) for r in runs]}\n"
        f"  best of three (s)       : {round(best, 3)}\n"
        f"Either v1.1 work has added per-bundle overhead, or the baseline\n"
        f"needs re-capture for a new platform. See VAL-REGRESSION-LEGACY-BUDGET-001."
    )
