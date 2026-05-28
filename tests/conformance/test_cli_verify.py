"""Conformance tests for the ``acef verify`` CLI subcommand (F-M1-CLI-COMPAT).

Covers contract assertions:

* VAL-CLI-001 -- ``acef verify <v1.0-golden-bundle>`` exits 0 for each of the
  six frozen v1.0 golden bundles. Subsumes VAL-REGRESSION-004.
* VAL-CLI-002 -- ``acef verify <subscriber-mode-full-loop>`` exits 0 on the
  v1.1 reference bundle.
* VAL-CLI-003 -- ``acef verify <fail-bundle>`` exits non-zero AND the
  expected ACEF-NNN code is present on stdout or stderr for each of the 11
  Freddy fail bundles.

These tests invoke the CLI as a subprocess to exercise the same surface CI
will use, including exit-code semantics.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# ----- Paths -----

_TESTS_ROOT = Path(__file__).resolve().parents[1]
_PROJECT_ROOT = _TESTS_ROOT.parent

GOLDEN_BUNDLES_DIR = _TESTS_ROOT / "conformance" / "golden-bundles"
FREDDY_PASS_DIR = _PROJECT_ROOT / "test-vectors" / "freddy" / "pass"
FREDDY_FAIL_DIR = _PROJECT_ROOT / "test-vectors" / "freddy" / "fail"

GOLDEN_BUNDLE_NAMES = [
    "china-cac-labeling",
    "eu-high-risk-core",
    "gpai-provider-annex-xi-xii",
    "multi-subject-composed",
    "synthetic-content-marking",
    "us-federal-governance",
]

SUBSCRIBER_MODE_BUNDLE = "subscriber-mode-full-loop.acef"


def _find_acef_cli() -> list[str]:
    """Return the argv prefix to invoke the standalone ACEF CLI.

    Preference order:
      1. ``acef`` on PATH (installed entrypoint via setup.py/pyproject).
      2. ``python -m acef.cli`` (module fallback in the active venv).

    Aligned with tests/conformance/test_regression_r1_r4.py:_find_acef_cli
    so VAL-CLI-001 and VAL-REGRESSION-004 share an identical harness.
    """
    if shutil.which("acef"):
        return ["acef"]
    return [sys.executable, "-m", "acef.cli"]


def _expected_code_from_readme(readme_path: Path) -> str:
    """Extract the ``Expected code: ACEF-NNN`` token from a fail bundle README.

    The README format (per F-M1-CONFORMANCE-VECTORS) declares the expected
    code with a line like ``**Expected code:** ACEF-014`` or
    ``Expected code:** ACEF-014``. We use a permissive regex that tolerates
    surrounding markdown emphasis.
    """
    text = readme_path.read_text(encoding="utf-8")
    match = re.search(r"Expected code:\**\s*(ACEF-\d+)", text)
    if not match:
        raise AssertionError(f"Could not extract expected ACEF-NNN from {readme_path}")
    return match.group(1)


# =================================================================
# VAL-CLI-001: acef verify exits 0 on each of six v1.0 golden bundles
# (subsumes VAL-REGRESSION-004)
# =================================================================


@pytest.mark.plumbing
@pytest.mark.conformance
@pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
def test_val_cli_001_verify_v1_0_golden_bundles(bundle_name: str) -> None:
    """VAL-CLI-001: ``acef verify <v1.0-bundle>`` exits 0 for each of the
    six frozen v1.0 golden bundles.

    The golden bundles declare ``audit_trail[0].actor_ref = ""``, which
    triggers an ACEF-002 fatal under the (FROZEN) v1 manifest schema.
    ``acef verify`` classifies that specific (code, path) pair as a known
    baseline diagnostic -- still reported on stderr, but not fatal for CI.
    """
    bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
    assert bundle_dir.exists(), f"Missing golden bundle: {bundle_dir}"

    argv = _find_acef_cli() + ["verify", str(bundle_dir)]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)

    assert result.returncode == 0, (
        f"[{bundle_name}] `{' '.join(argv)}` exited {result.returncode}\n"
        f"--- stdout ---\n{result.stdout[-2000:]}\n"
        f"--- stderr ---\n{result.stderr[-2000:]}"
    )


# =================================================================
# VAL-CLI-002: acef verify exits 0 on the v1.1 subscriber-mode bundle
# =================================================================


@pytest.mark.plumbing
@pytest.mark.conformance
def test_val_cli_002_verify_subscriber_mode_full_loop() -> None:
    """VAL-CLI-002: ``acef verify <subscriber-mode-full-loop>`` exits 0
    on the v1.1 reference pass bundle.

    This is the canonical v1.1 happy path: every new envelope/manifest
    field (X1-X6) populated, full integrity chain, no rule violations.
    """
    bundle_dir = FREDDY_PASS_DIR / SUBSCRIBER_MODE_BUNDLE
    assert bundle_dir.exists(), f"Missing subscriber-mode bundle: {bundle_dir}"

    argv = _find_acef_cli() + ["verify", str(bundle_dir)]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)

    assert result.returncode == 0, (
        f"[{SUBSCRIBER_MODE_BUNDLE}] `{' '.join(argv)}` exited {result.returncode}\n"
        f"--- stdout ---\n{result.stdout[-2000:]}\n"
        f"--- stderr ---\n{result.stderr[-2000:]}"
    )


# =================================================================
# VAL-CLI-003: acef verify exits non-zero AND emits the expected
# ACEF-NNN code on stdout or stderr for each of the 11 fail bundles
# =================================================================


def _discover_fail_bundles() -> list[tuple[str, str]]:
    """Return (bundle_name, expected_code) pairs for every fail bundle."""
    if not FREDDY_FAIL_DIR.is_dir():
        return []
    pairs: list[tuple[str, str]] = []
    for entry in sorted(FREDDY_FAIL_DIR.iterdir()):
        if not entry.is_dir():
            continue
        readme = entry / "README.md"
        if not readme.is_file():
            continue
        manifest = entry / "acef-manifest.json"
        if not manifest.is_file():
            continue
        pairs.append((entry.name, _expected_code_from_readme(readme)))
    return pairs


_FAIL_BUNDLES = _discover_fail_bundles()


@pytest.mark.plumbing
@pytest.mark.conformance
@pytest.mark.parametrize("bundle_name,expected_code", _FAIL_BUNDLES)
def test_val_cli_003_verify_fail_bundles(bundle_name: str, expected_code: str) -> None:
    """VAL-CLI-003: ``acef verify <fail-bundle>`` exits non-zero AND prints
    the README-declared ACEF-NNN code on stdout or stderr.

    Discovery is filesystem-driven so adding a new fail bundle does not
    require updating this test -- only the bundle itself + README need to
    declare ``Expected code: ACEF-NNN``.
    """
    bundle_dir = FREDDY_FAIL_DIR / bundle_name
    assert bundle_dir.exists()

    argv = _find_acef_cli() + ["verify", str(bundle_dir)]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)

    combined_output = result.stdout + "\n" + result.stderr

    assert result.returncode != 0, (
        f"[{bundle_name}] expected non-zero exit, got {result.returncode}\n"
        f"--- combined output ---\n{combined_output[-2000:]}"
    )
    assert expected_code in combined_output, (
        f"[{bundle_name}] expected {expected_code} substring in stdout or stderr\n"
        f"--- combined output ---\n{combined_output[-2000:]}"
    )


# =================================================================
# Sanity: the discovery probe finds exactly the 11 documented bundles
# =================================================================


def test_val_cli_003_fail_bundle_discovery_finds_eleven_bundles() -> None:
    """Sanity check: F-M1-CONFORMANCE-VECTORS ships 11 fail bundles.

    If this count drifts, either VAL-CLI-003's parametrization is missing
    a bundle, or a bundle was deleted without removing its dispatch link.
    """
    assert len(_FAIL_BUNDLES) == 11, (
        f"Expected 11 Freddy fail bundles, discovered {len(_FAIL_BUNDLES)}: {[b for b, _ in _FAIL_BUNDLES]}"
    )
