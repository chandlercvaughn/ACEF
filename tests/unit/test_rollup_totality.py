"""Executable counterpart to spec Appendix C (roll-up determinism proof).

PhD-review finding 10: the 7-step `provision_outcome` roll-up's totality,
determinism, and order-independence were argued only in prose. This module
proves them empirically by exhaustively evaluating the real implementation
(`compute_provision_outcome`) against the Appendix C reference function ``rho``
over the full cross-product of small rule-result multisets, with and without an
evidence gap:

  * Totality   — the implementation returns a valid ``ProvisionOutcome`` for
                 every input (never raises, never returns ``None``).
  * Agreement  — the implementation equals the proved reference function ``rho``
                 on every input (so the spec model and the code are the same
                 function).
  * Order-independence — permuting the rule list never changes the outcome.
"""

from __future__ import annotations

import itertools

import pytest

from acef.models.assessment import RuleResult
from acef.models.enums import ProvisionOutcome, RuleOutcome, RuleSeverity
from acef.models.records import RecordEnvelope
from acef.validation.rollup import compute_provision_outcome

# The 12 rule "cell" types: every (outcome, severity) pair.
_OUTCOMES = (RuleOutcome.PASSED, RuleOutcome.FAILED, RuleOutcome.SKIPPED, RuleOutcome.ERROR)
_SEVERITIES = (RuleSeverity.FAIL, RuleSeverity.WARNING, RuleSeverity.INFO)
_CELLS = tuple(itertools.product(_OUTCOMES, _SEVERITIES))


def _rho(cells: tuple[tuple[RuleOutcome, RuleSeverity], ...], gap: bool) -> ProvisionOutcome:
    """Appendix C reference function ρ — first-match-wins over P1…P6, else satisfied."""
    if len(cells) == 0:  # P1: no-rules guard
        return ProvisionOutcome.NOT_ASSESSED
    if any(o == RuleOutcome.FAILED and s == RuleSeverity.FAIL for o, s in cells):  # P2
        return ProvisionOutcome.NOT_SATISFIED
    if any(o == RuleOutcome.ERROR for o, _ in cells):  # P3
        return ProvisionOutcome.NOT_ASSESSED
    if all(o == RuleOutcome.SKIPPED for o, _ in cells):  # P4 (len>=1 guaranteed)
        return ProvisionOutcome.SKIPPED
    if gap:  # P5
        return ProvisionOutcome.GAP_ACKNOWLEDGED
    if any(o == RuleOutcome.FAILED and s == RuleSeverity.WARNING for o, s in cells):  # P6
        return ProvisionOutcome.PARTIALLY_SATISFIED
    return ProvisionOutcome.SATISFIED  # P7


def _impl(cells: tuple[tuple[RuleOutcome, RuleSeverity], ...], gap: bool) -> ProvisionOutcome:
    results = [
        RuleResult(
            rule_id=f"r{i}",
            provision_id="prov-1",
            profile_id="test-profile",
            rule_severity=sev,
            outcome=out,
            evidence_refs=[],
        )
        for i, (out, sev) in enumerate(cells)
    ]
    records = []
    if gap:
        # Package-wide gap (empty subject_refs) so it applies regardless of scope.
        records.append(RecordEnvelope(record_type="evidence_gap", provisions_addressed=["prov-1"], payload={}))
    return compute_provision_outcome("prov-1", "test-profile", results, records).provision_outcome


# All multisets of size 0..3 over the 12 cell types (1+12+144+1728 = 1885 tuples),
# crossed with gap on/off = 3770 inputs — exhaustive over every predicate combination.
_ALL_INPUTS = [
    (cells, gap) for size in range(4) for cells in itertools.product(_CELLS, repeat=size) for gap in (False, True)
]


class TestRollupTotalityAndAgreement:
    def test_input_space_is_exhaustive(self) -> None:
        assert len(_ALL_INPUTS) == (1 + 12 + 144 + 1728) * 2 == 3770

    def test_implementation_is_total_and_matches_appendix_c(self) -> None:
        valid = set(ProvisionOutcome)
        for cells, gap in _ALL_INPUTS:
            got = _impl(cells, gap)
            # Totality: always a valid outcome, never None / never raised.
            assert got in valid, f"non-total: {got!r} for cells={cells} gap={gap}"
            # Agreement with the proved reference function.
            assert got == _rho(cells, gap), (
                f"impl disagrees with Appendix C ρ for cells={cells} gap={gap}: impl={got} rho={_rho(cells, gap)}"
            )

    def test_info_severity_failure_is_non_gating(self) -> None:
        # A failed info-severity rule (nothing else firing) must roll up to satisfied.
        cells = ((RuleOutcome.PASSED, RuleSeverity.FAIL), (RuleOutcome.FAILED, RuleSeverity.INFO))
        assert _impl(cells, gap=False) == ProvisionOutcome.SATISFIED

    @pytest.mark.parametrize(
        "cells",
        [
            ((RuleOutcome.FAILED, RuleSeverity.FAIL), (RuleOutcome.PASSED, RuleSeverity.WARNING)),
            ((RuleOutcome.PASSED, RuleSeverity.FAIL), (RuleOutcome.SKIPPED, RuleSeverity.WARNING)),
            ((RuleOutcome.ERROR, RuleSeverity.WARNING), (RuleOutcome.PASSED, RuleSeverity.FAIL)),
        ],
    )
    def test_order_independence(self, cells: tuple[tuple[RuleOutcome, RuleSeverity], ...]) -> None:
        # Confluence: every permutation yields the same outcome.
        outcomes = {_impl(perm, gap=False) for perm in itertools.permutations(cells)}
        assert len(outcomes) == 1, f"outcome depends on rule order: {outcomes}"
