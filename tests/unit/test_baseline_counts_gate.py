"""Unit tests for the baseline-counts CI gate (VAL-TIER-001, VAL-TIER-004).

Owned by F-M1-TIER-INFRA. These tests exercise
``scripts/check_baseline_counts.py`` by invoking it as a subprocess with the
override flags, which lets us deterministically simulate "a test was
deliberately skipped" without actually deleting tests or running the full
pytest suite recursively.

Assertions covered:
  * VAL-TIER-001: ``tests/baseline-counts.json`` exists and parses.
  * VAL-TIER-004: synthetic deficit (observed < baseline) yields non-zero
    exit; surplus (observed >= baseline) yields exit 0.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BASELINE_PATH = _REPO_ROOT / "tests" / "baseline-counts.json"
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "check_baseline_counts.py"


def _run_gate(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the gate script as a subprocess and return the completed proc."""
    return subprocess.run(  # noqa: S603 (controlled args)
        [sys.executable, str(_SCRIPT_PATH), *args],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )


# ---------------------------------------------------------------------------
# VAL-TIER-001: baseline file present, parses, contains expected keys
# ---------------------------------------------------------------------------


def test_val_tier_001_baseline_counts_file_exists_and_parses() -> None:
    """VAL-TIER-001: ``tests/baseline-counts.json`` exists at HEAD with the
    authoritative schema (counts.total, counts.by_directory, counts.by_marker).
    """
    assert _BASELINE_PATH.exists(), (
        f"baseline-counts.json missing at {_BASELINE_PATH}. F-M1-TIER-INFRA must commit this file."
    )
    data = json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))
    assert "counts" in data, "missing top-level 'counts' object"
    counts = data["counts"]
    assert "total" in counts and isinstance(counts["total"], int) and counts["total"] > 0
    assert "by_directory" in counts and isinstance(counts["by_directory"], dict)
    assert "by_marker" in counts and isinstance(counts["by_marker"], dict)
    for d in ("tests/unit/", "tests/conformance/", "tests/integration/"):
        assert d in counts["by_directory"], f"by_directory missing key {d!r}"
    for m in ("plumbing", "conformance", "regression"):
        assert m in counts["by_marker"], f"by_marker missing key {m!r}"
    # Provenance fields required by the contract.
    assert "captured_at" in data
    assert "captured_at_commit" in data
    assert data.get("ownership") == "F-M1-TIER-INFRA"


def test_val_tier_001_baseline_counts_script_exists_and_is_executable() -> None:
    """The CI gate script must exist and run without syntax errors."""
    assert _SCRIPT_PATH.exists(), f"gate script missing at {_SCRIPT_PATH}"
    proc = _run_gate("--help")
    assert proc.returncode == 0, f"--help failed: {proc.stderr}"
    assert "baseline" in proc.stdout.lower()


# ---------------------------------------------------------------------------
# VAL-TIER-004: synthetic regression triggers non-zero exit
# ---------------------------------------------------------------------------


def test_val_tier_004_surplus_passes() -> None:
    """observed >= baseline => exit 0 (growth allowed)."""
    proc = _run_gate(
        "--baseline-override",
        "100",
        "--observed-override",
        "200",
    )
    assert proc.returncode == 0, f"surplus case must pass; stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert "PASS" in proc.stdout


def test_val_tier_004_equal_passes() -> None:
    """observed == baseline => exit 0 (no regression)."""
    proc = _run_gate(
        "--baseline-override",
        "1267",
        "--observed-override",
        "1267",
    )
    assert proc.returncode == 0


def test_val_tier_004_deficit_fails() -> None:
    """observed < baseline => exit 1.

    Simulates a deliberately-skipped test by overriding the observed pytest
    count to a value below the baseline. The CI gate MUST reject this without
    modifying any on-disk files.
    """
    proc = _run_gate(
        "--baseline-override",
        "1000",
        "--observed-override",
        "999",
    )
    assert proc.returncode == 1, (
        f"deficit case must exit 1; got {proc.returncode}. stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    assert "FAIL" in proc.stderr or "FAIL" in proc.stdout


def test_val_tier_004_large_deficit_fails() -> None:
    """A drop of even a single test triggers the gate."""
    proc = _run_gate(
        "--baseline-override",
        "99999",
        "--observed-override",
        "1",
    )
    assert proc.returncode == 1


def test_val_tier_004_missing_counts_file_errors() -> None:
    """If the on-disk baseline file is missing, the gate exits 2 (loud)."""
    proc = _run_gate(
        "--counts-file",
        str(_REPO_ROOT / "does-not-exist.json"),
        "--observed-override",
        "100",
    )
    assert proc.returncode == 2


# ---------------------------------------------------------------------------
# Sanity: the live baseline must match the live pytest collection count
# (catches accidental baseline drift introduced by an unrelated PR)
# ---------------------------------------------------------------------------


def test_baseline_counts_matches_live_collection_or_grows() -> None:
    """The live ``pytest --collect-only`` total MUST be >= recorded baseline.

    If this test fails it indicates either:
      (a) a real test was removed/skipped without an RFC, OR
      (b) the baseline-counts.json was committed at a higher number than
          actually exists at HEAD (mistake).
    Either way the file needs human attention.
    """
    if not _BASELINE_PATH.exists():  # pragma: no cover (covered above)
        pytest.skip("baseline file missing")
    data = json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))
    baseline = int(data["counts"]["total"])
    proc = _run_gate()
    assert proc.returncode == 0, (
        f"live count regressed below baseline {baseline}: stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
