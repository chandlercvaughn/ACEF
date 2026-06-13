"""Disposition authority matrix (ACEF authority model).

NORMATIVE BASIS (audit cross-record-authority-2): the ACEF-080 error *code*
is normative (ACEF-Spec-Outline-v0.1.md §3.6 error taxonomy — "Bundle
declares analysis_mode ... mode-gated rule violation"). The 5×4 authority
MATRIX itself, however, has NO normative home in the ACEF spec or RFC-0002
(grep confirms neither document defines `authority_class` or an authority
matrix, and the spec has no section 14). The grid below derives from the ACEF
authority model defined by the acef-v0.4-freddy-adoption operation, whose
contract.md inlines it at lines 41-47. We document that provenance honestly
rather than citing a fabricated spec section.

Each row is an `authority_class` from :class:`acef.models.enums.AuthorityClass`;
each column is an actor type. Cells declare whether a `disposition_record`
(record_type `risk_treatment` with `treatment_subtype: external_disposition`)
carrying `authority_check.authority_granted: true` is acceptable for that
(authority_class × actor_type) pair.

A cell value of ``True`` means *granted is allowed*; the bundle is clean for
that pair. ``False`` means *granted is denied*; encountering
`authority_granted: true` in such a pair MUST emit ACEF-080 (per
VAL-VALIDATION-LOAD-AUTHORITY-MATRIX-001) so that disposition records cannot
silently bypass the authority model.

Actor-type columns map to :class:`acef.models.enums.ActorRole` values:

- "customer"  → not a v1.0 enum value. The brief uses "customer" / "provider"
  in a Freddy-specific sense; ACEF's ActorRole has `DEPLOYER` (the v1.0
  counterpart of "customer" — the org running the AI system), `PROVIDER`,
  `AUDITOR`, `REGULATOR`. We map the contract's "Customer Actor" column to
  the `deployer` role, which is ACEF's canonical name for the customer-side
  actor in EU AI Act terminology.
- "provider" → `provider`
- "auditor"  → `auditor`
- "regulator"→ `regulator`

Other ActorRole values (`importer`, `distributor`, `data_subject`) are not in
the authority matrix; encountering such an actor on a disposition record with
authority_granted: true is treated as a denied (matrix-not-found) result and
emits ACEF-080.
"""

from __future__ import annotations

from typing import Final

from acef.models.enums import ActorRole, AuthorityClass

# The four matrix columns, in contract-order. Each is a canonical ActorRole
# value (string form, matching what appears in serialized records).
ACTOR_TYPES: Final[tuple[str, ...]] = (
    ActorRole.DEPLOYER.value,  # "customer" column
    ActorRole.PROVIDER.value,  # "provider" column
    ActorRole.AUDITOR.value,  # "auditor" column
    ActorRole.REGULATOR.value,  # "regulator" column
)

# The five authority_class rows. Each is an AuthorityClass value (string
# form).
AUTHORITY_CLASSES: Final[tuple[str, ...]] = (
    AuthorityClass.PRIORITY.value,
    AuthorityClass.SEVERITY_ADVISORY.value,
    AuthorityClass.ACCEPTED_RISK_REQUEST.value,
    AuthorityClass.FALSE_POSITIVE_ASSERTION.value,
    AuthorityClass.EVIDENCE_DISPUTE.value,
)

# The 5×4 matrix. Each entry is a dict keyed by actor-type string, with
# True if granted to that actor is allowed under the ACEF authority model,
# False if denied.
#
# Source: the acef-v0.4-freddy-adoption operation contract.md lines 41-47
# (the operation's inlined authority grid — NOT a normative ACEF spec /
# RFC-0002 clause; see module docstring). Each cell documented inline:
_MATRIX: Final[dict[str, dict[str, bool]]] = {
    AuthorityClass.PRIORITY.value: {
        # priority disagreements may be raised by any party — all granted
        ActorRole.DEPLOYER.value: True,
        ActorRole.PROVIDER.value: True,
        ActorRole.AUDITOR.value: True,
        ActorRole.REGULATOR.value: True,
    },
    AuthorityClass.SEVERITY_ADVISORY.value: {
        # severity advisories likewise — all granted
        ActorRole.DEPLOYER.value: True,
        ActorRole.PROVIDER.value: True,
        ActorRole.AUDITOR.value: True,
        ActorRole.REGULATOR.value: True,
    },
    AuthorityClass.ACCEPTED_RISK_REQUEST.value: {
        # accepting residual risk is the customer's prerogative; provider,
        # auditor, regulator cannot accept risk on the customer's behalf
        ActorRole.DEPLOYER.value: True,
        ActorRole.PROVIDER.value: False,
        ActorRole.AUDITOR.value: False,
        ActorRole.REGULATOR.value: False,
    },
    AuthorityClass.FALSE_POSITIVE_ASSERTION.value: {
        # false-positive call sits with the customer (they own ground-truth
        # context) and auditor (independent verification); provider self-
        # certifying a false positive on their own finding is denied;
        # regulator does not assert false positives
        ActorRole.DEPLOYER.value: True,
        ActorRole.PROVIDER.value: False,
        ActorRole.AUDITOR.value: True,
        ActorRole.REGULATOR.value: False,
    },
    AuthorityClass.EVIDENCE_DISPUTE.value: {
        # evidence integrity disputes route to independent parties only —
        # the customer and provider are interested parties and cannot grant
        # themselves the authority to overrule evidence
        ActorRole.DEPLOYER.value: False,
        ActorRole.PROVIDER.value: False,
        ActorRole.AUDITOR.value: True,
        ActorRole.REGULATOR.value: True,
    },
}


def lookup(authority_class: str, actor_type: str) -> bool:
    """Return True iff `authority_granted: true` is allowed for the pair.

    Args:
        authority_class: One of the five values from
            :class:`AuthorityClass` (string form).
        actor_type: One of the four matrix columns (string form). Other
            ActorRole values (importer, distributor, data_subject) are
            outside the matrix and return ``False``.

    Returns:
        True if the cell is "granted"; False if "denied" OR if either
        argument is outside the authority matrix (defensive default — an
        unrecognized pair cannot be presumed granted).
    """
    row = _MATRIX.get(authority_class)
    if row is None:
        return False
    return row.get(actor_type, False)


def all_cells() -> list[tuple[str, str, bool]]:
    """Enumerate every (authority_class, actor_type, granted) triple.

    Used by VAL-VALIDATION-LOAD-AUTHORITY-MATRIX-001's parametrized tests to
    drive all 20 sub-tests off a single source of truth.
    """
    out: list[tuple[str, str, bool]] = []
    for ac in AUTHORITY_CLASSES:
        for at in ACTOR_TYPES:
            out.append((ac, at, _MATRIX[ac][at]))
    return out
