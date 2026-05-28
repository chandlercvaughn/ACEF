#!/usr/bin/env python3
"""CI gate: enforce per-sub-tier wall-clock budgets for the plumbing tier.

Owned by F-M1-TIER-INFRA (VAL-TIER-003).

Tier budgets (per the operation contract):
  * plumbing    <=60s
  * conformance <=40s   (sub-tier of plumbing)
  * regression  <=20s   (sub-tier of plumbing)

Behavior
--------
For each tier in the chosen set, this script invokes::

    python -m pytest -m <tier> --tb=no -q --timeout=60 -p no:cacheprovider

with ``ACEF_SKIP_RUNTIME_BUDGET=1`` set in the environment so that the
self-referential ``test_legacy_runtime_budget`` benchmark does not consume
the budget it is itself trying to measure. The script measures wall-clock
duration of each invocation with ``time.perf_counter`` and compares it to
the tier budget. The gate fails (exit 1) if any of:

* pytest exits non-zero for a tier (test failure under the gate);
* wall-clock duration exceeds the tier budget.

A single non-zero exit indicates ALL violations (the script does not
short-circuit; it prints every tier's outcome).

Flags
-----
``--tier {plumbing,conformance,regression,all}``
    Tier to gate. ``all`` (default) runs plumbing, conformance, and regression
    in that order.

``--no-skip-runtime-budget``
    Do NOT set ``ACEF_SKIP_RUNTIME_BUDGET=1`` (used only by maintainers
    investigating the legacy-budget benchmark itself).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]

# Tier -> (wall-clock budget seconds, per-test --timeout)
_TIER_BUDGETS: dict[str, tuple[int, int]] = {
    "plumbing": (60, 60),
    "conformance": (40, 60),
    "regression": (20, 60),
}


def _run_tier(tier: str, skip_runtime_budget: bool) -> tuple[bool, float, int]:
    """Invoke pytest for a single tier.

    Returns ``(within_budget_and_passing, wall_clock_seconds, exit_code)``.
    """
    budget_seconds, per_test_timeout = _TIER_BUDGETS[tier]
    env = os.environ.copy()
    if skip_runtime_budget:
        env["ACEF_SKIP_RUNTIME_BUDGET"] = "1"

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-m",
        tier,
        "--tb=no",
        "-q",
        f"--timeout={per_test_timeout}",
        "-p",
        "no:cacheprovider",
    ]

    print(f"\n--- tier={tier} budget<={budget_seconds}s ---")
    print(f"$ {' '.join(cmd)}")

    start = time.perf_counter()
    proc = subprocess.run(  # noqa: S603 (controlled args)
        cmd,
        cwd=str(_REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    elapsed = time.perf_counter() - start

    # Show the trailing summary line(s) for human-readable CI logs.
    tail = proc.stdout.strip().splitlines()[-3:]
    for line in tail:
        print(line)
    print(f"wall-clock: {elapsed:.2f}s (budget {budget_seconds}s)")

    within_budget = elapsed <= budget_seconds
    passing = proc.returncode == 0
    if not passing:
        print(
            f"FAIL: pytest exit code {proc.returncode} for tier '{tier}'. "
            "Wall-clock budget is not the only requirement; tests must pass.",
            file=sys.stderr,
        )
        # Surface the full stderr to help debugging in CI.
        if proc.stderr.strip():
            print("--- pytest stderr ---", file=sys.stderr)
            print(proc.stderr, file=sys.stderr)
    if not within_budget:
        print(
            f"FAIL: tier '{tier}' wall-clock {elapsed:.2f}s exceeds budget {budget_seconds}s (VAL-TIER-003).",
            file=sys.stderr,
        )

    return (within_budget and passing, elapsed, proc.returncode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ACEF plumbing-tier wall-clock budget gate (F-M1-TIER-INFRA).")
    parser.add_argument(
        "--tier",
        choices=["plumbing", "conformance", "regression", "all"],
        default="all",
        help="Which tier (or 'all') to gate. Default: all.",
    )
    parser.add_argument(
        "--no-skip-runtime-budget",
        action="store_true",
        help=(
            "Do NOT set ACEF_SKIP_RUNTIME_BUDGET=1 in the pytest environment. "
            "Default behavior is to skip the legacy-budget self-benchmark."
        ),
    )
    args = parser.parse_args(argv)

    tiers = ["plumbing", "conformance", "regression"] if args.tier == "all" else [args.tier]

    all_ok = True
    summary: list[tuple[str, float, int, bool]] = []
    for tier in tiers:
        ok, elapsed, exit_code = _run_tier(tier=tier, skip_runtime_budget=not args.no_skip_runtime_budget)
        summary.append((tier, elapsed, exit_code, ok))
        all_ok = all_ok and ok

    print("\n=== plumbing-budget gate summary ===")
    for tier, elapsed, exit_code, ok in summary:
        verdict = "PASS" if ok else "FAIL"
        budget = _TIER_BUDGETS[tier][0]
        print(f"  {tier:<12} {elapsed:6.2f}s / {budget}s  (pytest exit {exit_code})  {verdict}")

    if not all_ok:
        return 1
    print("PASS: all tier wall-clock budgets respected and pytest exited 0.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
