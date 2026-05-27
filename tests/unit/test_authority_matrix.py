"""Unit tests for the §14.5 disposition authority matrix.

Covers VAL-VALIDATION-LOAD-AUTHORITY-MATRIX-001 at the data-table level.
The full 5×4 = 20 (authority_class × actor_type) grid is parametrized;
each cell asserts that `lookup()` returns the expected granted/denied
value from contract.md lines 41-47.
"""

from __future__ import annotations

import pytest

from acef.models.enums import ActorRole, AuthorityClass
from acef.validation.authority_matrix import (
    ACTOR_TYPES,
    AUTHORITY_CLASSES,
    all_cells,
    lookup,
)

# The expected truth table — duplicated from contract.md lines 41-47 so the
# implementation cannot quietly drift without the test failing.
_EXPECTED: dict[tuple[str, str], bool] = {
    # priority: all granted
    (AuthorityClass.PRIORITY.value, ActorRole.DEPLOYER.value): True,
    (AuthorityClass.PRIORITY.value, ActorRole.PROVIDER.value): True,
    (AuthorityClass.PRIORITY.value, ActorRole.AUDITOR.value): True,
    (AuthorityClass.PRIORITY.value, ActorRole.REGULATOR.value): True,
    # severity_advisory: all granted
    (AuthorityClass.SEVERITY_ADVISORY.value, ActorRole.DEPLOYER.value): True,
    (AuthorityClass.SEVERITY_ADVISORY.value, ActorRole.PROVIDER.value): True,
    (AuthorityClass.SEVERITY_ADVISORY.value, ActorRole.AUDITOR.value): True,
    (AuthorityClass.SEVERITY_ADVISORY.value, ActorRole.REGULATOR.value): True,
    # accepted_risk_request: customer only
    (AuthorityClass.ACCEPTED_RISK_REQUEST.value, ActorRole.DEPLOYER.value): True,
    (AuthorityClass.ACCEPTED_RISK_REQUEST.value, ActorRole.PROVIDER.value): False,
    (AuthorityClass.ACCEPTED_RISK_REQUEST.value, ActorRole.AUDITOR.value): False,
    (AuthorityClass.ACCEPTED_RISK_REQUEST.value, ActorRole.REGULATOR.value): False,
    # false_positive_assertion: customer + auditor
    (AuthorityClass.FALSE_POSITIVE_ASSERTION.value, ActorRole.DEPLOYER.value): True,
    (AuthorityClass.FALSE_POSITIVE_ASSERTION.value, ActorRole.PROVIDER.value): False,
    (AuthorityClass.FALSE_POSITIVE_ASSERTION.value, ActorRole.AUDITOR.value): True,
    (AuthorityClass.FALSE_POSITIVE_ASSERTION.value, ActorRole.REGULATOR.value): False,
    # evidence_dispute: auditor + regulator only
    (AuthorityClass.EVIDENCE_DISPUTE.value, ActorRole.DEPLOYER.value): False,
    (AuthorityClass.EVIDENCE_DISPUTE.value, ActorRole.PROVIDER.value): False,
    (AuthorityClass.EVIDENCE_DISPUTE.value, ActorRole.AUDITOR.value): True,
    (AuthorityClass.EVIDENCE_DISPUTE.value, ActorRole.REGULATOR.value): True,
}


def test_matrix_size_is_5_by_4() -> None:
    """Sanity guard: 5 authority classes × 4 actor types = 20 cells."""
    assert len(AUTHORITY_CLASSES) == 5
    assert len(ACTOR_TYPES) == 4
    assert len(all_cells()) == 20
    assert len(_EXPECTED) == 20


@pytest.mark.parametrize(
    "authority_class,actor_type,expected",
    [(ac, at, expected) for (ac, at), expected in _EXPECTED.items()],
    ids=[f"{ac}-{at}-{'granted' if exp else 'denied'}" for (ac, at), exp in _EXPECTED.items()],
)
def test_matrix_cell(authority_class: str, actor_type: str, expected: bool) -> None:
    """VAL-VALIDATION-LOAD-AUTHORITY-MATRIX-001: every cell matches contract.md."""
    assert lookup(authority_class, actor_type) is expected


def test_all_cells_matches_expected_truth_table() -> None:
    """all_cells() must enumerate the same 20 (ac, at, granted) triples
    that the expected truth table declares, in *some* order.
    """
    enumerated = {(ac, at): granted for ac, at, granted in all_cells()}
    assert enumerated == _EXPECTED


def test_unknown_authority_class_returns_denied() -> None:
    """Defensive default: an unknown authority_class cannot be presumed
    granted (security-relevant invariant).
    """
    assert lookup("made_up_class", ActorRole.DEPLOYER.value) is False


def test_unknown_actor_type_returns_denied() -> None:
    """Outside-matrix actor types (importer, distributor, data_subject)
    are not granted any §14.5 authority.
    """
    for outside in (
        ActorRole.IMPORTER.value,
        ActorRole.DISTRIBUTOR.value,
        ActorRole.DATA_SUBJECT.value,
    ):
        for ac in AUTHORITY_CLASSES:
            assert lookup(ac, outside) is False, f"actor_type={outside!r} must NOT be granted authority_class={ac!r}"


def test_empty_string_inputs_return_denied() -> None:
    """Null-safety: empty strings yield denied (lookups on malformed data
    must not succeed).
    """
    assert lookup("", "") is False
    assert lookup("", ActorRole.AUDITOR.value) is False
    assert lookup(AuthorityClass.PRIORITY.value, "") is False
