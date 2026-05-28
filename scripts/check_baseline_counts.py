#!/usr/bin/env python3
"""CI gate: enforce test-count non-regression against ``tests/baseline-counts.json``.

Owned by F-M1-TIER-INFRA (VAL-TIER-001, VAL-TIER-004).

Behavior
--------
1. Run ``pytest --collect-only --quiet`` from the repository root.
2. Parse the trailing ``"N tests collected"`` line.
3. Compare the observed total to ``counts.total`` in
   ``tests/baseline-counts.json``.

Exit codes
----------
* ``0`` — observed count is >= baseline (growth allowed; regression denied).
* ``1`` — observed count is < baseline (CI fails; an approved RFC is required
  to update the baseline file).
* ``2`` — baseline file or pytest invocation could not be parsed.

Flags
-----
``--baseline-override INT``
    Override the baseline value loaded from the JSON file. Used by
    ``tests/unit/test_baseline_counts_gate.py`` to assert that a synthetic
    regression triggers a non-zero exit without mutating the on-disk file.

``--counts-file PATH``
    Path to the baseline counts JSON. Defaults to
    ``<repo>/tests/baseline-counts.json``.

``--observed-override INT``
    Override the observed test count without running pytest. Used by
    ``tests/unit/test_baseline_counts_gate.py`` to deterministically simulate
    a regression scenario in unit tests (avoids the nested-pytest cost).

Growth-allowed policy
---------------------
``observed >= baseline`` -> PASS. Test growth is normal and welcomed. Shrinkage
indicates either (a) a test was accidentally deleted/skipped, (b) a marker
filter regressed, or (c) collection broke. All three demand human review.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_COUNTS_PATH = _REPO_ROOT / "tests" / "baseline-counts.json"

# Matches the pytest collection summary line, e.g.:
#   "1267 tests collected in 0.23s"
#   "112/1267 tests collected (1155 deselected) in 0.18s"
_COLLECTED_RE = re.compile(r"(?P<count>\d+)\s+tests?\s+collected", re.IGNORECASE)


def _load_baseline(counts_path: Path) -> int:
    if not counts_path.exists():
        print(f"ERROR: baseline counts file not found: {counts_path}", file=sys.stderr)
        sys.exit(2)
    try:
        data = json.loads(counts_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: baseline counts file is not valid JSON: {exc}", file=sys.stderr)
        sys.exit(2)
    try:
        total = int(data["counts"]["total"])
    except (KeyError, TypeError, ValueError) as exc:
        print(
            f"ERROR: baseline counts file missing 'counts.total' int: {exc}",
            file=sys.stderr,
        )
        sys.exit(2)
    return total


def _collect_pytest_total() -> int:
    """Invoke pytest in collect-only mode and parse the test count.

    Walks output lines from last to first because pytest may emit warning
    summaries containing other digits before the final tally.
    """
    proc = subprocess.run(  # noqa: S603 (controlled args)
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "--quiet",
            "-p",
            "no:cacheprovider",
        ],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 5):  # 5 = no tests collected (still parseable)
        print(
            "ERROR: pytest --collect-only failed (exit "
            f"{proc.returncode}):\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}",
            file=sys.stderr,
        )
        sys.exit(2)

    for line in reversed(proc.stdout.splitlines()):
        match = _COLLECTED_RE.search(line)
        if match:
            return int(match.group("count"))
    print(
        f"ERROR: could not parse '<N> tests collected' line from pytest output:\n{proc.stdout}",
        file=sys.stderr,
    )
    sys.exit(2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ACEF test-count non-regression gate (F-M1-TIER-INFRA).")
    parser.add_argument(
        "--counts-file",
        type=Path,
        default=_DEFAULT_COUNTS_PATH,
        help="Path to baseline-counts.json (default: tests/baseline-counts.json).",
    )
    parser.add_argument(
        "--baseline-override",
        type=int,
        default=None,
        help=(
            "Override the baseline value loaded from the JSON file. "
            "Used by VAL-TIER-004 unit tests to simulate regressions."
        ),
    )
    parser.add_argument(
        "--observed-override",
        type=int,
        default=None,
        help=(
            "Override the observed pytest count instead of running pytest. "
            "Used by VAL-TIER-004 unit tests for deterministic gate behavior."
        ),
    )
    args = parser.parse_args(argv)

    if args.baseline_override is not None:
        baseline = args.baseline_override
        baseline_source = f"override={baseline}"
    else:
        baseline = _load_baseline(args.counts_file)
        baseline_source = str(args.counts_file)

    if args.observed_override is not None:
        observed = args.observed_override
        observed_source = f"override={observed}"
    else:
        observed = _collect_pytest_total()
        observed_source = "pytest --collect-only"

    delta = observed - baseline
    print(f"baseline:  {baseline}  (source: {baseline_source})")
    print(f"observed:  {observed}  (source: {observed_source})")
    print(f"delta:     {delta:+d}")

    if observed < baseline:
        print(
            "FAIL: observed test count is BELOW baseline. Test growth is "
            "welcomed; regression is not. If a test was intentionally "
            "removed/renamed, update tests/baseline-counts.json via an "
            "approved RFC (see contract VAL-TIER-001).",
            file=sys.stderr,
        )
        return 1

    print("PASS: observed >= baseline (growth allowed, regression denied).")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
