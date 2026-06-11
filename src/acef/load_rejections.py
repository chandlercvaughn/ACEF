"""Load-time rejection checks per VAL-LOAD-001..004.

Runs as a post-parse, pre-Package-construction hook inside :func:`acef.load`.
Inspects the raw manifest dict and the raw record dicts (not the
:class:`RecordEnvelope` objects) so the rejection-checking logic does not
depend on payload-typed Pydantic models that might themselves reject the
forbidden values via ``Literal`` constraints.

Three rules are enforced here. Rules 1 and 2 are mirrored in
:mod:`acef.validation.cross_record`; rule 3 is delegated to it outright —
either way :func:`validate_bundle` emits the same ACEF-NNN code via
diagnostic for the same input (VAL-LOAD-005).

- **VAL-LOAD-001 / 002**: ``harness_attestation.verifier.verifier_class``
  in ``{"persona", "llm"}`` → raise ``LoadRejection(code="ACEF-070")``.
  Per brief §3.6, persona and LLM verifiers lack the determinism needed
  to attest state transitions; the existing
  :class:`acef.models.agent_reliability.HarnessVerifier` ``Literal`` enum
  already excludes them, but the loader rejects them with a structured
  ``LoadRejection`` (rather than letting Pydantic raise a generic
  ``ValidationError``) so callers can match on ``exc.code``.

- **VAL-LOAD-003**: a ``risk_treatment`` record with
  ``payload.treatment_subtype == "external_disposition"`` and
  ``payload.internal_state_unchanged: false`` →
  ``LoadRejection(code="ACEF-076")``. Per brief §V3: external dispositions
  are advisory and MUST NOT mutate internal evidence state.

- **VAL-LOAD-004**: a disposition record with
  ``payload.authority_check.authority_granted: true`` violating the §14.5
  matrix → ``LoadRejection(code="ACEF-080")``. The check FAILS CLOSED
  (audit findings cross-record-authority-5/6): a granted disposition with
  a missing / non-string / empty / unrecognized ``authority_class`` is
  rejected, and absent an explicit ``authority_check.actor_ref`` EVERY
  ``entity_refs.actor_refs`` URN is evaluated — ANY denied or undeclared
  actor rejects the load (an explicit ``actor_ref`` keeps single-actor
  semantics). The semantics are delegated wholesale to
  :func:`acef.validation.cross_record.enforce_disposition_authority` — the
  validator's canonical implementation — so :func:`acef.load` and
  :func:`acef.validation.engine.validate_bundle` reject the exact same
  inputs with the exact same messages (VAL-LOAD-005 parity by
  construction). The ONLY legitimate silent skip is a record that claims
  no authority (``authority_granted`` absent or not ``true``).

"""

from __future__ import annotations

from typing import Any

from acef.errors import LoadRejection

# The §14.5 disposition-authority semantics (VAL-LOAD-004) are delegated to
# the validator's canonical implementation so load() and validate_bundle()
# cannot drift (roborev on 1a665671 found the loader mirror had retained
# both authority bypasses fixed in cross_record). No import cycle:
# cross_record imports only acef.errors + acef.validation.authority_matrix;
# the validator engine imports acef.loader strictly inside functions.
from acef.validation.cross_record import enforce_disposition_authority

# verifier_class values that are forbidden in harness_attestation records.
# Per brief §3.6, persona and LLM verifiers are non-deterministic and cannot
# attest state transitions. The :class:`HarnessVerifier` Pydantic model's
# ``Literal`` enum already excludes them; this constant exists so the loader
# can emit the structured ACEF-070 LoadRejection instead of letting Pydantic
# raise a generic ValidationError.
_BANNED_VERIFIER_CLASSES: frozenset[str] = frozenset({"persona", "llm"})


def _payload(rec: dict[str, Any]) -> dict[str, Any]:
    """Return the ``payload`` dict of a record, or {} if absent/non-dict."""
    p = rec.get("payload")
    return p if isinstance(p, dict) else {}


def _is_disposition_record(rec: dict[str, Any]) -> bool:
    """True iff record is a ``risk_treatment`` with
    ``payload.treatment_subtype == "external_disposition"``.

    Mirrors :func:`acef.validation.cross_record._is_disposition_record` and
    :func:`acef.validation.v1_1_rules._is_disposition_record` — kept as a
    duplicate (not imported) because both counterparts are module-private.
    Used here only to gate the VAL-LOAD-003 (ACEF-076) check; the
    VAL-LOAD-004 (ACEF-080) path delegates to
    :func:`~acef.validation.cross_record.enforce_disposition_authority`,
    which applies its own canonical predicate. Whenever the predicate
    changes in one place it MUST be updated in all three.
    """
    if rec.get("record_type") != "risk_treatment":
        return False
    return _payload(rec).get("treatment_subtype") == "external_disposition"


def check_load_rejections(
    manifest_data: dict[str, Any],
    records: list[dict[str, Any]],
) -> None:
    """Run all load-rejection checks; raise ``LoadRejection`` on the first hit.

    Order of checks (first violation wins — this is "rejection", not
    "diagnostic collection"):

    1. harness_attestation verifier_class ∈ {persona, llm} → ACEF-070
    2. disposition_record internal_state_unchanged: false → ACEF-076
    3. disposition_record §14.5 matrix violation → ACEF-080 (FAIL CLOSED;
       delegated to the validator's canonical
       :func:`acef.validation.cross_record.enforce_disposition_authority`)

    Args:
        manifest_data: Parsed acef-manifest.json content (dict).
        records: List of raw record dicts (post-JSONL-parse, pre-envelope).

    Raises:
        LoadRejection: With ``code`` set to the specific ACEF-NNN that
            named the rule violated.
    """
    for rec in records:
        if not isinstance(rec, dict):
            continue
        record_id = rec.get("record_id", "")
        record_type = rec.get("record_type", "")

        # ---- VAL-LOAD-001 / 002: harness_attestation verifier_class ----
        if record_type == "harness_attestation":
            payload = _payload(rec)
            verifier = payload.get("verifier")
            if isinstance(verifier, dict):
                vc = verifier.get("verifier_class")
                if isinstance(vc, str) and vc in _BANNED_VERIFIER_CLASSES:
                    raise LoadRejection(
                        (
                            f"harness_attestation {record_id!r} uses banned "
                            f"verifier_class={vc!r}: persona and LLM "
                            "verifiers lack the determinism required to "
                            "attest state transitions per brief §3.6. "
                            "Permitted classes: contract_gate, "
                            "read_back_verifier, cryptographic_verifier, "
                            "harness_internal."
                        ),
                        code="ACEF-070",
                    )

        # ---- VAL-LOAD-003 / 004: disposition record checks ----
        if _is_disposition_record(rec):
            payload = _payload(rec)

            # VAL-LOAD-003: internal_state_unchanged must be true (or absent
            # and defaulted to true by downstream code; we only reject the
            # explicit false case). Per brief §V3, external dispositions are
            # advisory; setting internal_state_unchanged=false would let an
            # external party rewrite internal evidence state.
            if payload.get("internal_state_unchanged") is False:
                raise LoadRejection(
                    (
                        f"disposition_record {record_id!r} sets "
                        "internal_state_unchanged=false: external "
                        "dispositions are advisory per brief §V3 and MUST "
                        "NOT mutate internal evidence state."
                    ),
                    code="ACEF-076",
                )

            # VAL-LOAD-004: §14.5 authority matrix — FAIL CLOSED. Delegated
            # wholesale to the validator's canonical implementation
            # (acef.validation.cross_record.enforce_disposition_authority;
            # audit findings cross-record-authority-5/6) so load() and
            # validate_bundle() reject the exact same inputs with the exact
            # same ACEF-080 messages (VAL-LOAD-005 parity by construction):
            #
            # - authority_granted: true with a missing / non-string / empty
            #   / unrecognized authority_class → ACEF-080 (never a silent
            #   skip — roborev on 1a665671 found this bypass alive here
            #   after it was fixed validator-side);
            # - absent authority_check.actor_ref → EVERY non-empty string
            #   in entity_refs.actor_refs[] is evaluated; ANY denied or
            #   undeclared actor rejects (permitted-first ordering cannot
            #   hide a denied actor); an explicit actor_ref keeps
            #   single-actor semantics;
            # - a granted disposition naming no resolvable actor → ACEF-080;
            # - NO authority claim (authority_granted absent / not true) →
            #   no rejection (legitimate skip, gated inside the helper).
            #
            # Per-record invocation preserves the loader's first-violation-
            # wins ordering across records and check types; the rejection
            # raises on the FIRST diagnostic the helper emits.
            authority_diags = enforce_disposition_authority(manifest_data, [rec])
            if authority_diags:
                first = authority_diags[0]
                raise LoadRejection(first.message, code=first.code)


__all__ = ["check_load_rejections"]
