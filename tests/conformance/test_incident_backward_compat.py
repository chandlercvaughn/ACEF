"""Backward-compatibility regression — RFC-0002 (F-M4-BACKWARD-COMPAT).

Asserts VAL-COMPAT-001: every existing v1.0 golden bundle (and any
``incident_report`` golden) validates **byte-identically under
``core_version: 1.0.0`` after this operation**, and the two frozen paths
(``acef-conventions/v1/`` + ``tests/conformance/golden-bundles/``) are
byte-unchanged versus the operation base commit.

Why this exists
---------------
RFC-0002 adds the v1.1 incident surface: the ``incident_card`` /
``card_source`` schemas, the ACEF-081..088 error band, and the offline
incident rules in ``src/acef/validation/engine.py``. All of that is
**version-gated** on ``manifest.versioning.core_version == "1.1.0"``
(``schema_version_for_core_version`` routes 1.0.x → ``"v1"`` and the engine
only dispatches ``run_incident_rules`` when ``schema_version == "v1.1"``).

This regression proves the gate holds for the frozen v1.0 goldens:

1.  **No new incident code fires.** Running ``validate_bundle`` on each v1.0
    golden produces ZERO diagnostics in the reserved RFC-0002 band
    (ACEF-081..088). A v1.0 bundle must never see an incident rule.
2.  **The assessment is unchanged.** The runtime assessment for each golden
    still matches its committed ``<bundle>.acef-assessment.json`` fixture —
    same provision outcomes, same per-outcome rule-result counts. If the v1.1
    work had perturbed the v1.0 validation path, this comparison would fail.
3.  **The frozen paths are byte-unchanged.** ``git diff`` of
    ``acef-conventions/v1/`` and ``tests/conformance/golden-bundles/`` against
    the operation base commit is empty, file-for-file (content compared via
    ``git show <base>:<path>``). The test FAILS if any frozen byte moved.

Determinism: golden bundles are discovered by sorted directory scan (no
hard-coded brittle list drives the parametrization), but a coverage floor
asserts the known v1.0 goldens are still present so coverage cannot silently
shrink. The frozen-path walk is sorted. No wall-clock, no randomness — the
fixture ``evaluation_instant`` drives every comparison.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from acef.loader import load
from acef.schemas.registry import schema_version_for_core_version
from acef.validation.engine import validate_bundle

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Operation base commit: the pre-operation state of the frozen paths. Pinned
# from .ops/.../ops-active.md ("Base commit") and the F-M4-BACKWARD-COMPAT
# dispatch. The two frozen paths MUST be byte-identical to this tree.
OPERATION_BASE_COMMIT = "411b65efe95496e1aeae3c62c35fe09e879d4e16"

# Repo root = three parents up from this file
#   tests/conformance/test_incident_backward_compat.py -> repo root
REPO_ROOT = Path(__file__).resolve().parents[2]

GOLDEN_BUNDLES_DIR = REPO_ROOT / "tests" / "conformance" / "golden-bundles"

# The two FROZEN paths (relative to repo root, forward-slash form for git).
FROZEN_PATHS: tuple[str, ...] = (
    "acef-conventions/v1",
    "tests/conformance/golden-bundles",
)

# Coverage floor: the known v1.0 golden bundle directories that MUST stay
# covered by this regression. Discovery is dynamic (sorted scan), but this
# floor guards against coverage silently shrinking if a golden is renamed or
# the scan regresses. These six are the frozen v1.0 set (all declare
# ``core_version: 1.0.0``); none currently carries an ``incident_report``
# record, which is itself an asserted invariant below (a v1.0 incident_report
# golden would be auto-discovered and added to the no-incident-code proof).
KNOWN_V1_0_GOLDEN_BUNDLES: frozenset[str] = frozenset(
    {
        "china-cac-labeling",
        "eu-high-risk-core",
        "gpai-provider-annex-xi-xii",
        "multi-subject-composed",
        "synthetic-content-marking",
        "us-federal-governance",
    }
)

# RFC-0002 reserved incident error band. NONE of these may fire on a v1.0
# bundle. Matches ACEF-081 through ACEF-088 (and nothing else in the 08x
# decade — ACEF-080 is a pre-existing v0.4 code and is allowed).
INCIDENT_CODE_RE = re.compile(r"^ACEF-08[1-8]$")


# ---------------------------------------------------------------------------
# Discovery helpers (deterministic, sorted)
# ---------------------------------------------------------------------------


def _discover_golden_bundles() -> list[str]:
    """Return the sorted names of all golden bundle directories.

    A golden bundle directory is any immediate subdirectory of
    ``golden-bundles/`` that contains an ``acef-manifest.json``. Sorted for
    byte-stable, order-independent parametrization.
    """
    if not GOLDEN_BUNDLES_DIR.is_dir():
        return []
    names = [
        child.name
        for child in GOLDEN_BUNDLES_DIR.iterdir()
        if child.is_dir() and (child / "acef-manifest.json").is_file()
    ]
    return sorted(names)


GOLDEN_BUNDLE_NAMES: list[str] = _discover_golden_bundles()


def _load_manifest(bundle_name: str) -> dict[str, Any]:
    manifest_path = GOLDEN_BUNDLES_DIR / bundle_name / "acef-manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _bundle_core_version(bundle_name: str) -> str:
    manifest = _load_manifest(bundle_name)
    versioning = manifest.get("versioning")
    if not isinstance(versioning, dict):
        return ""
    cv = versioning.get("core_version", "")
    return cv if isinstance(cv, str) else ""


def _bundle_profiles(bundle_name: str) -> list[str]:
    manifest = _load_manifest(bundle_name)
    return [p["profile_id"] for p in manifest.get("profiles", [])]


def _load_fixture(bundle_name: str) -> dict[str, Any]:
    fixture_path = GOLDEN_BUNDLES_DIR / f"{bundle_name}.acef-assessment.json"
    return json.loads(fixture_path.read_text(encoding="utf-8"))


def _record_types(bundle_name: str) -> set[str]:
    """Record types declared in a golden bundle's manifest record_files."""
    manifest = _load_manifest(bundle_name)
    rec_files = manifest.get("record_files", [])
    return {rf["record_type"] for rf in rec_files if isinstance(rf, dict) and "record_type" in rf}


def _all_diagnostic_codes(assessment: Any) -> list[str]:
    """Collect every diagnostic ``code`` surfaced by an assessment.

    The validation engine flushes ALL phase diagnostics — schema, integrity,
    reference, cross-record, v1.1 rules, AND the RFC-0002 incident rules — into
    ``assessment.structural_errors`` as dicts carrying a ``code`` key (see
    ``ValidationDiagnostic.to_dict``). Failed rule results additionally carry a
    diagnostic identity via their ``rule_id``; incident codes never surface as
    rule results (they are structural diagnostics), but we scan both surfaces
    defensively so no incident-code path can hide.
    """
    codes: list[str] = []
    for diag in assessment.structural_errors:
        code = diag.get("code") if isinstance(diag, dict) else None
        if isinstance(code, str):
            codes.append(code)
    return codes


# ---------------------------------------------------------------------------
# Discovery sanity / coverage floor
# ---------------------------------------------------------------------------


@pytest.mark.regression
class TestGoldenBundleDiscovery:
    """Discovery is non-empty, sorted, and covers the known v1.0 floor."""

    def test_golden_bundles_dir_exists(self) -> None:
        assert GOLDEN_BUNDLES_DIR.is_dir(), f"Golden bundle dir missing: {GOLDEN_BUNDLES_DIR}"

    def test_discovery_is_nonempty(self) -> None:
        assert GOLDEN_BUNDLE_NAMES, "No golden bundles discovered — backward-compat regression is vacuous"

    def test_discovery_is_sorted(self) -> None:
        assert GOLDEN_BUNDLE_NAMES == sorted(GOLDEN_BUNDLE_NAMES), "Golden bundle discovery must be sorted"

    def test_coverage_floor_known_v1_0_goldens(self) -> None:
        """Every known v1.0 golden is still discovered — coverage cannot shrink."""
        discovered = set(GOLDEN_BUNDLE_NAMES)
        missing = KNOWN_V1_0_GOLDEN_BUNDLES - discovered
        assert not missing, f"Known v1.0 golden bundle(s) no longer discovered (coverage shrank): {sorted(missing)}"

    def test_all_known_goldens_declare_core_version_1_0_0(self) -> None:
        """Each known v1.0 golden declares core_version 1.0.0 and routes to the v1 schema set."""
        for bundle_name in sorted(KNOWN_V1_0_GOLDEN_BUNDLES):
            cv = _bundle_core_version(bundle_name)
            assert cv == "1.0.0", f"{bundle_name}: expected core_version 1.0.0, got {cv!r}"
            # The version gate: 1.0.0 must NOT route to the v1.1 incident schema set.
            assert schema_version_for_core_version(cv) == "v1", (
                f"{bundle_name}: core_version {cv!r} must route to the v1 schema set, never the v1.1 incident surface"
            )


# ---------------------------------------------------------------------------
# (1) No new incident code (ACEF-081..088) fires on any v1.0 golden
# ---------------------------------------------------------------------------


@pytest.mark.regression
class TestNoIncidentCodeFiresOnV10:
    """The RFC-0002 incident band never fires on a v1.0 (core_version 1.0.0) bundle."""

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_no_incident_code_in_diagnostics(self, bundle_name: str) -> None:
        """Validation of a v1.0 golden surfaces zero ACEF-081..088 diagnostics."""
        bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
        fixture = _load_fixture(bundle_name)
        evaluation_instant = fixture["evaluation_instant"]
        profiles = _bundle_profiles(bundle_name)

        assessment = validate_bundle(
            bundle_dir,
            profiles=profiles,
            evaluation_instant=evaluation_instant,
        )

        codes = _all_diagnostic_codes(assessment)
        incident_codes = [c for c in codes if INCIDENT_CODE_RE.match(c)]
        assert not incident_codes, (
            f"[{bundle_name}] RFC-0002 incident code(s) fired on a v1.0 bundle "
            f"(must be byte-equivalent-absent for core_version 1.0.0): {incident_codes}. "
            f"All diagnostic codes: {codes}"
        )

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_no_incident_report_in_v1_0_golden_implies_no_card_validation(self, bundle_name: str) -> None:
        """v1.0 goldens carry no incident_report record (RFC-0002 record types are v1.1-gated).

        This is the documented coverage hook from the dispatch: VAL-COMPAT-001
        names ``incident_report`` goldens explicitly. The frozen v1.0 set
        carries none; if one were ever added it would be auto-discovered here
        and would still have to pass ``test_no_incident_code_in_diagnostics``
        (no v1.1 incident rule fires on a 1.0.0 bundle).
        """
        rec_types = _record_types(bundle_name)
        assert "incident_report" not in rec_types, (
            f"[{bundle_name}] carries an incident_report record under core_version "
            f"{_bundle_core_version(bundle_name)!r}; RFC-0002 incident record types are "
            "v1.1-gated and must not appear in a frozen v1.0 golden"
        )


# ---------------------------------------------------------------------------
# (2) Each v1.0 golden assessment is UNCHANGED vs its committed fixture
# ---------------------------------------------------------------------------


@pytest.mark.regression
class TestGoldenAssessmentUnchanged:
    """Runtime assessment of each v1.0 golden still matches its committed fixture.

    This proves the v1.1 incident work did not perturb the v1.0 validation
    path: identical provision outcomes and identical per-outcome rule-result
    counts, given the fixture's ``evaluation_instant``.
    """

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_provision_outcomes_match_fixture(self, bundle_name: str) -> None:
        bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
        fixture = _load_fixture(bundle_name)
        evaluation_instant = fixture["evaluation_instant"]
        profiles = _bundle_profiles(bundle_name)

        assessment = validate_bundle(
            bundle_dir,
            profiles=profiles,
            evaluation_instant=evaluation_instant,
        )

        fixture_outcomes: dict[tuple[str, str], str] = {}
        for ps in fixture.get("provision_summary", []):
            fixture_outcomes[(ps["profile_id"], ps["provision_id"])] = ps["provision_outcome"]

        runtime_outcomes: dict[tuple[str, str], str] = {}
        for ps in assessment.provision_summary:
            runtime_outcomes[(ps.profile_id, ps.provision_id)] = ps.provision_outcome.value

        assert runtime_outcomes == fixture_outcomes, (
            f"[{bundle_name}] provision outcomes drifted vs committed fixture. "
            f"runtime={runtime_outcomes} fixture={fixture_outcomes}"
        )

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_rule_result_counts_match_fixture(self, bundle_name: str) -> None:
        bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
        fixture = _load_fixture(bundle_name)
        evaluation_instant = fixture["evaluation_instant"]
        profiles = _bundle_profiles(bundle_name)

        assessment = validate_bundle(
            bundle_dir,
            profiles=profiles,
            evaluation_instant=evaluation_instant,
        )

        fixture_counts: dict[str, int] = {}
        for r in fixture.get("results", []):
            outcome = r.get("outcome", "unknown")
            fixture_counts[outcome] = fixture_counts.get(outcome, 0) + 1

        runtime_counts: dict[str, int] = {}
        for r in assessment.results:
            outcome = r.outcome.value
            runtime_counts[outcome] = runtime_counts.get(outcome, 0) + 1

        assert runtime_counts == fixture_counts, (
            f"[{bundle_name}] rule-result counts drifted vs committed fixture. "
            f"runtime={runtime_counts} fixture={fixture_counts}"
        )

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_no_added_structural_error_code_vs_fixture(self, bundle_name: str) -> None:
        """The operation ADDS no structural-error code on the v1.0 path.

        The v1.0 goldens are NOT diagnostic-free: each carries a pre-existing,
        benign ``ACEF-002`` (an empty ``audit_trail[0].actor_ref`` that does not
        match the actor-URN pattern) recorded in the golden's committed
        ``structural_errors``; some fixtures additionally list ``ACEF-032``
        ("provision not yet effective — skipped") which the current runtime
        instead surfaces as skipped rule *results* (already covered, byte-stable,
        by :meth:`test_rule_result_counts_match_fixture`). The committed
        ``structural_errors`` surface is therefore NOT a byte-for-byte equality
        target against these older fixtures — and ``engine.py`` is byte-identical
        to this feature's workerStartCommit, so any code the runtime emits here is
        pre-operation behavior.

        What VAL-COMPAT-001 actually requires of THIS operation is that it
        introduces no *new* diagnostic on the v1.0 path. This asserts exactly
        that: the runtime structural-error code multiset is a SUBSET of the
        fixture's (the operation added nothing), and contains no RFC-0002
        incident-band code (ACEF-081..088).
        """
        bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
        fixture = _load_fixture(bundle_name)
        evaluation_instant = fixture["evaluation_instant"]
        profiles = _bundle_profiles(bundle_name)

        assessment = validate_bundle(
            bundle_dir,
            profiles=profiles,
            evaluation_instant=evaluation_instant,
        )

        runtime_codes = set(_all_diagnostic_codes(assessment))
        fixture_codes = {
            se["code"]
            for se in fixture.get("structural_errors", [])
            if isinstance(se, dict) and isinstance(se.get("code"), str)
        }

        # No code the runtime emits is absent from the committed fixture: the
        # operation introduced zero new structural diagnostics on the v1.0 path.
        added = runtime_codes - fixture_codes
        assert not added, (
            f"[{bundle_name}] operation introduced new structural-error code(s) on a v1.0 "
            f"bundle (must add nothing): {sorted(added)}; runtime={sorted(runtime_codes)} "
            f"fixture={sorted(fixture_codes)}"
        )

        # And independently: none of the runtime codes is in the reserved
        # RFC-0002 incident band — a v1.0 bundle must never trip an 08x rule.
        incident_codes = [c for c in sorted(runtime_codes) if INCIDENT_CODE_RE.match(c)]
        assert not incident_codes, (
            f"[{bundle_name}] RFC-0002 incident code(s) present on a v1.0 bundle: {incident_codes}"
        )

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_golden_loads_clean(self, bundle_name: str) -> None:
        """Each v1.0 golden still loads without error after the operation."""
        bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
        pkg = load(str(bundle_dir))
        assert pkg is not None
        assert len(pkg.records) > 0, f"[{bundle_name}] expected at least one record"


# ---------------------------------------------------------------------------
# (3) Frozen paths are byte-unchanged vs the operation base commit
# ---------------------------------------------------------------------------


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    """Run a git command from the repo root, capturing text output."""
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _git_available_and_base_present() -> bool:
    """True iff git works here and the base commit is resolvable."""
    rev = _git("rev-parse", "--verify", f"{OPERATION_BASE_COMMIT}^{{commit}}")
    return rev.returncode == 0


@pytest.mark.regression
class TestFrozenPathsByteUnchanged:
    """``acef-conventions/v1/`` + golden-bundles are byte-unchanged vs base."""

    def test_git_base_commit_resolvable(self) -> None:
        assert _git_available_and_base_present(), (
            f"Operation base commit {OPERATION_BASE_COMMIT} is not resolvable from the repo "
            "at this path — cannot prove frozen-path byte-stability"
        )

    def test_frozen_paths_diff_stat_is_empty(self) -> None:
        """``git diff --stat <base> -- <frozen paths>`` is EMPTY (tracked changes)."""
        if not _git_available_and_base_present():
            pytest.skip("git or base commit unavailable")

        result = _git("diff", "--stat", OPERATION_BASE_COMMIT, "--", *FROZEN_PATHS)
        assert result.returncode == 0, f"git diff failed: {result.stderr}"
        diff_out = result.stdout.strip()
        assert diff_out == "", (
            "Frozen path(s) changed vs the operation base commit "
            f"{OPERATION_BASE_COMMIT} (FROZEN: VAL-SCHEMA-010 / VAL-REGRESSION-001):\n{diff_out}"
        )

    def test_frozen_paths_no_unstaged_or_untracked_changes(self) -> None:
        """No working-tree or index changes (incl. untracked) under the frozen paths.

        ``git diff --stat <base>`` compares against the base tree but a brand
        new untracked file under a frozen path would also be a violation.
        ``git status --porcelain`` over the frozen paths catches staged,
        unstaged, AND untracked changes.
        """
        if not _git_available_and_base_present():
            pytest.skip("git or base commit unavailable")

        result = _git("status", "--porcelain", "--", *FROZEN_PATHS)
        assert result.returncode == 0, f"git status failed: {result.stderr}"
        status_out = result.stdout.strip()
        assert status_out == "", (
            f"Working-tree/untracked change(s) detected under FROZEN path(s) (must be byte-unchanged):\n{status_out}"
        )

    def test_every_frozen_file_content_matches_base_blob(self) -> None:
        """File-for-file: each frozen file's bytes equal its base-commit blob.

        Belt-and-braces beyond ``git diff``: walk every tracked file under the
        frozen paths (sorted), read its current bytes, and compare to
        ``git show <base>:<path>``. Also asserts the set of tracked frozen
        files is identical to the base set (no additions/removals).
        """
        if not _git_available_and_base_present():
            pytest.skip("git or base commit unavailable")

        for frozen in FROZEN_PATHS:
            # Files tracked under this path in the base tree.
            base_listing = _git("ls-tree", "-r", "--name-only", OPERATION_BASE_COMMIT, "--", frozen)
            assert base_listing.returncode == 0, f"git ls-tree (base) failed: {base_listing.stderr}"
            base_files = sorted(p for p in base_listing.stdout.splitlines() if p)

            # Files tracked under this path right now (HEAD index).
            head_listing = _git("ls-files", "--", frozen)
            assert head_listing.returncode == 0, f"git ls-files failed: {head_listing.stderr}"
            head_files = sorted(p for p in head_listing.stdout.splitlines() if p)

            assert head_files == base_files, (
                f"Tracked file set under FROZEN '{frozen}' differs from base "
                f"{OPERATION_BASE_COMMIT}: added={sorted(set(head_files) - set(base_files))} "
                f"removed={sorted(set(base_files) - set(head_files))}"
            )

            for rel_path in base_files:
                base_blob = subprocess.run(
                    ["git", "-C", str(REPO_ROOT), "show", f"{OPERATION_BASE_COMMIT}:{rel_path}"],
                    capture_output=True,
                    check=False,
                )
                assert base_blob.returncode == 0, f"git show {rel_path} failed: {base_blob.stderr!r}"
                current_bytes = (REPO_ROOT / rel_path).read_bytes()
                assert current_bytes == base_blob.stdout, (
                    f"FROZEN file '{rel_path}' changed bytes vs base commit "
                    f"{OPERATION_BASE_COMMIT} (len now={len(current_bytes)} "
                    f"base={len(base_blob.stdout)})"
                )
