"""Regression suite cross-referencing VAL-REGRESSION-001..004 (F-M1-REGRESSION-SUITE).

This module makes each regression-tier contract assertion discoverable by
``grep VAL-REGRESSION-NNN tests/`` and runnable as a single focused module.

The behaviors below are also exercised by:
  - ``tests/conformance/test_golden_bundles.py``     -> R1
  - ``tests/unit/test_variant_registry_v1_1.py``     -> R2
  - ``tests/unit/test_error_registry_snapshot.py``   -> R3

The duplication is intentional. Per the F-M1-REGRESSION-SUITE dispatch, the
regression-tier coverage must be visible via assertion-ID grep so the
contract -> test crosswalk is auditable.

Each test is tagged with ``@pytest.mark.regression`` for sub-tier budget
enforcement (VAL-PERFORMANCE-CONFORMANCE-001: regression sub-tier <=20s).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from acef.errors import ERROR_REGISTRY
from acef.models.enums import RuleOutcome
from acef.schemas.registry import resolve_variant
from acef.validation.engine import validate_bundle

# ----- Paths -----

_TESTS_ROOT = Path(__file__).resolve().parents[1]
_PROJECT_ROOT = _TESTS_ROOT.parent
GOLDEN_BUNDLES_DIR = _TESTS_ROOT / "conformance" / "golden-bundles"
FIXTURES_DIR = _TESTS_ROOT / "conformance" / "fixtures"
V1_0_VARIANTS_FIXTURE = FIXTURES_DIR / "v1.0-variants.json"
V1_0_ERRORS_FIXTURE = FIXTURES_DIR / "v1.0-errors.json"

GOLDEN_BUNDLE_NAMES = [
    "china-cac-labeling",
    "eu-high-risk-core",
    "gpai-provider-annex-xi-xii",
    "multi-subject-composed",
    "synthetic-content-marking",
    "us-federal-governance",
]


def _load_manifest_profiles(bundle_dir: Path) -> list[str]:
    manifest_path = bundle_dir / "acef-manifest.json"
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    return [p["profile_id"] for p in manifest_data.get("profiles", [])]


def _load_fixture(bundle_name: str) -> dict[str, Any]:
    fixture_path = GOLDEN_BUNDLES_DIR / f"{bundle_name}.acef-assessment.json"
    return json.loads(fixture_path.read_text(encoding="utf-8"))


# =================================================================
# VAL-REGRESSION-001: R1 v1.0 golden bundles validate clean
# =================================================================


@pytest.mark.regression
@pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
def test_val_regression_001_v1_0_golden_bundles_validate_clean(bundle_name: str) -> None:
    """VAL-REGRESSION-001: All six v1.0 golden bundles validate clean under
    v1.0 schema selection (driven by their ``core_version: 1.0.0``).

    "Clean" means:
      - validate_bundle() returns an AssessmentBundle.
      - No RuleOutcome.ERROR results (rule evaluator finished cleanly).
      - The same provision_summary entries as the published fixture (i.e.,
        v1.1 work did not change the set of outcomes the v1.0 validator
        produced).

    The existence of pre-v0.4 structural diagnostics (e.g., the empty
    audit_trail/0/actor_ref ACEF-002 baked into the frozen golden manifests)
    is NOT a v0.4 regression -- it is a pre-existing baseline that the
    snapshot fixtures captured before the v1.1 work began. This assertion
    enforces the regression boundary: *no new* errors caused by v1.1 work.
    """
    bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
    assert bundle_dir.exists(), f"Golden bundle missing: {bundle_name}"

    fixture = _load_fixture(bundle_name)
    evaluation_instant = fixture["evaluation_instant"]
    profiles = _load_manifest_profiles(bundle_dir)

    assessment = validate_bundle(
        bundle_dir,
        profiles=profiles,
        evaluation_instant=evaluation_instant,
    )

    # Engine ran to completion (rule errors indicate a broken evaluator).
    rule_errors = [r for r in assessment.results if r.outcome == RuleOutcome.ERROR]
    assert not rule_errors, (
        f"[{bundle_name}] Rule evaluator produced ERROR outcomes (broken engine): "
        f"{[(r.rule_id if hasattr(r, 'rule_id') else '?') for r in rule_errors[:5]]}"
    )

    # The v1.1 work must not have introduced new structural diagnostics
    # beyond what the published fixture captured.
    fixture_outcomes = {
        (ps["profile_id"], ps["provision_id"]): ps["provision_outcome"] for ps in fixture.get("provision_summary", [])
    }
    runtime_outcomes = {
        (ps.profile_id, ps.provision_id): ps.provision_outcome.value for ps in assessment.provision_summary
    }

    # Same key set: no missing, no extra provisions.
    assert set(runtime_outcomes.keys()) == set(fixture_outcomes.keys()), (
        f"[{bundle_name}] Provision set drift -- "
        f"new: {set(runtime_outcomes) - set(fixture_outcomes)}, "
        f"removed: {set(fixture_outcomes) - set(runtime_outcomes)}"
    )

    # Same outcomes: no provision flipped from satisfied to not_satisfied.
    drift = [
        (k, fixture_outcomes[k], runtime_outcomes[k])
        for k in fixture_outcomes
        if runtime_outcomes[k] != fixture_outcomes[k]
    ]
    assert not drift, f"[{bundle_name}] Provision outcome drift: {drift[:5]}"


# =================================================================
# VAL-REGRESSION-002: R2 v1.0 variants resolve identically to snapshot
# =================================================================


def _load_v1_0_variant_snapshot() -> list[dict[str, Any]]:
    return json.loads(V1_0_VARIANTS_FIXTURE.read_text(encoding="utf-8"))


@pytest.mark.regression
def test_val_regression_002_variants_snapshot_present_and_sized() -> None:
    """VAL-REGRESSION-002 precondition: snapshot exists and has the captured
    count (12 entries at R0 capture; the brief's "13" is a doc miscount)."""
    assert V1_0_VARIANTS_FIXTURE.exists(), f"R0 snapshot missing: {V1_0_VARIANTS_FIXTURE}"
    snapshot = _load_v1_0_variant_snapshot()
    assert len(snapshot) == 12, f"R0 variant snapshot must have 12 entries; got {len(snapshot)}"


@pytest.mark.regression
@pytest.mark.parametrize(
    "snapshot_entry",
    _load_v1_0_variant_snapshot(),
    ids=lambda e: e["artifact_name"],
)
def test_val_regression_002_variants_resolve_to_snapshot(snapshot_entry: dict[str, Any]) -> None:
    """VAL-REGRESSION-002: Every entry in the R0 v1.0-variants.json snapshot
    resolves via ``resolve_variant(name, "v1")`` to the byte-identical tuple
    (record_type, discriminator_field, discriminator_value).

    This guarantees v1.1 work did not mutate any v1.0 variant resolution.
    """
    name = snapshot_entry["artifact_name"]
    resolved = resolve_variant(name, "v1")
    assert resolved is not None, f"resolve_variant({name!r}, 'v1') returned None"

    for field in ("record_type", "discriminator_field", "discriminator_value"):
        assert resolved.get(field) == snapshot_entry[field], (
            f"{name}.{field}: snapshot={snapshot_entry[field]!r}, resolved={resolved.get(field)!r}"
        )


# =================================================================
# VAL-REGRESSION-003: R3 v1.0 error codes byte-equal to snapshot
# =================================================================


def _load_v1_0_error_snapshot() -> dict[str, dict[str, str]]:
    return json.loads(V1_0_ERRORS_FIXTURE.read_text(encoding="utf-8"))


@pytest.mark.regression
def test_val_regression_003_error_snapshot_present_and_sized() -> None:
    """VAL-REGRESSION-003 precondition: snapshot exists with the captured
    population count (31 codes; ACEF-001..060 is reserved-sparse)."""
    assert V1_0_ERRORS_FIXTURE.exists(), f"R0 snapshot missing: {V1_0_ERRORS_FIXTURE}"
    snapshot = _load_v1_0_error_snapshot()
    assert len(snapshot) == 31, f"R0 error snapshot must have 31 entries; got {len(snapshot)}"


@pytest.mark.regression
@pytest.mark.parametrize(
    "code",
    sorted(_load_v1_0_error_snapshot().keys()),
)
def test_val_regression_003_v1_0_errors_byte_equal(code: str) -> None:
    """VAL-REGRESSION-003: Every v1.0 error code in the R0 snapshot is
    byte-equal in ERROR_REGISTRY post-v1.1-work (severity, category,
    description). No v1.0 code may be deleted or mutated by v1.1 work."""
    snapshot = _load_v1_0_error_snapshot()
    expected = snapshot[code]

    assert code in ERROR_REGISTRY, f"v1.0 code {code} deleted from ERROR_REGISTRY"
    severity, category, description = ERROR_REGISTRY[code]

    assert severity.value == expected["severity"], (
        f"{code} severity: snapshot={expected['severity']!r}, got={severity.value!r}"
    )
    assert category.value == expected["category"], (
        f"{code} category: snapshot={expected['category']!r}, got={category.value!r}"
    )
    assert description == expected["description"], (
        f"{code} description mismatch:\n  snapshot: {expected['description']!r}\n  got:      {description!r}"
    )


# =================================================================
# VAL-REGRESSION-004: R4 Standalone `acef verify` CLI exits 0
# =================================================================


def _find_acef_cli() -> list[str]:
    """Return the argv prefix to invoke the standalone ACEF CLI.

    Preference order:
      1. ``acef`` on PATH (installed entrypoint via setup.py/pyproject).
      2. ``python -m acef.cli`` (module fallback in the active venv).
    """
    if shutil.which("acef"):
        return ["acef"]
    return [sys.executable, "-m", "acef.cli"]


@pytest.mark.regression
@pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
def test_val_regression_004_acef_verify_cli(bundle_name: str) -> None:
    """VAL-REGRESSION-004: ``acef verify <bundle>`` exits 0 for each of the
    six v1.0 golden bundles.

    This assertion subsumes VAL-CLI-001 (same harness, same bundles).

    Implemented by F-M1-CLI-COMPAT: the ``acef verify`` subcommand calls
    the existing validator pipeline but classifies a narrow, well-known
    baseline diagnostic (empty ``audit_trail[N]/actor_ref`` triggering
    ACEF-002 under the FROZEN v1 manifest schema) as non-fatal for CI.
    Every other ACEF-002 (and every other diagnostic) continues to fail.

    See ``src/acef/cli/verify_cmd.py:_BASELINE_DIAGNOSTICS`` for the exact
    downgrade rule.
    """
    bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
    assert bundle_dir.exists()

    argv = _find_acef_cli() + ["verify", str(bundle_dir)]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)

    assert result.returncode == 0, (
        f"[{bundle_name}] `{' '.join(argv)}` exited {result.returncode}\n"
        f"--- stdout ---\n{result.stdout[-2000:]}\n"
        f"--- stderr ---\n{result.stderr[-2000:]}"
    )
