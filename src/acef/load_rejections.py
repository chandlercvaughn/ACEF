"""Load-time rejection checks per VAL-LOAD-001..004.

Runs as a post-parse, pre-Package-construction hook inside :func:`acef.load`.
Inspects the raw manifest dict and the raw record dicts (not the
:class:`RecordEnvelope` objects) so the rejection-checking logic does not
depend on payload-typed Pydantic models that might themselves reject the
forbidden values via ``Literal`` constraints.

Three rules are enforced here. Each is also mirrored in
:mod:`acef.validation.cross_record` so :func:`validate_bundle` emits the
same ACEF-NNN code via diagnostic for the same input (VAL-LOAD-005).

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
  matrix → ``LoadRejection(code="ACEF-080")``. The matrix lookup is
  delegated to :func:`acef.validation.authority_matrix.lookup`.

The hook is also exported for re-use by
:mod:`acef.validation.cross_record` (one source of truth, one canonical
predicate implementation).
"""

from __future__ import annotations

from typing import Any

from acef.errors import LoadRejection
from acef.validation.authority_matrix import lookup as _matrix_lookup

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
    duplicate (not imported) only because the loader's rejection path runs
    BEFORE the validator module is imported (cross-tier import discipline).
    Whenever the predicate changes in one place it MUST be updated in all
    three.
    """
    if rec.get("record_type") != "risk_treatment":
        return False
    return _payload(rec).get("treatment_subtype") == "external_disposition"


def _actor_role_map(manifest: dict[str, Any]) -> dict[str, str]:
    """Build actor_id → role mapping from ``manifest.entities.actors``."""
    out: dict[str, str] = {}
    entities = manifest.get("entities")
    if not isinstance(entities, dict):
        return out
    actors = entities.get("actors")
    if not isinstance(actors, list):
        return out
    for actor in actors:
        if not isinstance(actor, dict):
            continue
        actor_id = actor.get("actor_id")
        role = actor.get("role")
        if isinstance(actor_id, str) and isinstance(role, str):
            out[actor_id] = role
    return out


def _resolve_disposition_actor_role(
    rec: dict[str, Any],
    actor_role_map: dict[str, str],
) -> tuple[str | None, str | None]:
    """Return (actor_ref, actor_role) for a disposition record.

    Reads ``payload.authority_check.actor_ref`` first; falls back to the
    first ``entity_refs.actor_refs`` URN. Returns (None, None) if no
    resolvable actor can be found.
    """
    payload = _payload(rec)
    auth = payload.get("authority_check") if isinstance(payload, dict) else None
    actor_ref: str | None = None
    if isinstance(auth, dict):
        ar = auth.get("actor_ref")
        if isinstance(ar, str) and ar:
            actor_ref = ar
    if actor_ref is None:
        er = rec.get("entity_refs")
        if isinstance(er, dict):
            actors = er.get("actor_refs")
            if isinstance(actors, list) and actors:
                first = actors[0]
                if isinstance(first, str) and first:
                    actor_ref = first
    if actor_ref is None:
        return (None, None)
    return (actor_ref, actor_role_map.get(actor_ref))


def check_load_rejections(
    manifest_data: dict[str, Any],
    records: list[dict[str, Any]],
) -> None:
    """Run all load-rejection checks; raise ``LoadRejection`` on the first hit.

    Order of checks (first violation wins — this is "rejection", not
    "diagnostic collection"):

    1. harness_attestation verifier_class ∈ {persona, llm} → ACEF-070
    2. disposition_record internal_state_unchanged: false → ACEF-076
    3. disposition_record §14.5 matrix violation → ACEF-080

    Args:
        manifest_data: Parsed acef-manifest.json content (dict).
        records: List of raw record dicts (post-JSONL-parse, pre-envelope).

    Raises:
        LoadRejection: With ``code`` set to the specific ACEF-NNN that
            named the rule violated.
    """
    actor_role_map = _actor_role_map(manifest_data)

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

            # VAL-LOAD-004: §14.5 authority matrix. Only the
            # authority_granted=true case can violate the matrix; granted
            # =false is always permitted (denying authority on anyone is OK).
            auth = payload.get("authority_check")
            if isinstance(auth, dict) and auth.get("authority_granted") is True:
                ac = auth.get("authority_class")
                if isinstance(ac, str) and ac:
                    actor_ref, role = _resolve_disposition_actor_role(rec, actor_role_map)
                    if role is None:
                        # Unknown / unresolvable actor with a granted
                        # disposition is itself a §14.5 violation (the
                        # matrix lookup defaults to denied for unknown
                        # actor types).
                        raise LoadRejection(
                            (
                                f"disposition_record {record_id!r} grants "
                                f"authority_class={ac!r} but the "
                                f"authorizing actor ({actor_ref!r}) is "
                                "not declared in manifest.entities.actors. "
                                "Per §14.5, authority grants require a "
                                "mapped actor with an explicit role."
                            ),
                            code="ACEF-080",
                        )
                    if not _matrix_lookup(ac, role):
                        raise LoadRejection(
                            (
                                f"disposition_record {record_id!r} grants "
                                f"authority_class={ac!r} to actor "
                                f"{actor_ref!r} (role={role!r}), but the "
                                "§14.5 authority matrix denies that "
                                "(authority_class × actor_role) pair."
                            ),
                            code="ACEF-080",
                        )


__all__ = ["check_load_rejections"]
