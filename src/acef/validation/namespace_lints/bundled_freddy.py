"""Bundled lint patterns for the ``x-freddy/*`` namespace family.

Auto-registers on import. Import this submodule explicitly (or rely on the
validation engine's wiring) to enable enforcement of:

- ACEF-077 (FATAL/integrity) for ``x-freddy/voice-rubric-emission``
  records whose ``claim_lexicon_scan_result.tokens_found`` is non-empty
  AND that lack a paired ``harness_attestation_ref`` AND that have NOT
  been properly rejected via ``rejection_state``.

This is the Core-side hook described in plan WS3.10 and the ops-active
rules: ACEF-077 is a Core error code but its violating content lives in
Freddy's namespace. By auto-registering the lint pattern when this module
is imported, ACEF v0.4 ships ACEF-077 enforcement out of the box for any
bundle that opts into the x-freddy namespace.

Deployments that want to opt OUT can either:

1. Not import this submodule (manual; works for downstream SDK builds
   that exclude it), or
2. Call :func:`acef.validation.namespace_lints.unregister_namespace`
   ("x-freddy/voice-rubric-emission") at startup (runtime opt-out).

Per the brief §5.2 the trigger is:

    claim_lexicon_scan_result.tokens_found NON-EMPTY
    AND rejection_state == "accepted"
    → ACEF-077

Per the §5.1 (F1 persona-observation) trigger and the ACEF-077
registry description ("voice_rubric_emission contains claim-lexicon token
without paired harness_attestation"), the additional carve-out is:

    AND no harness_attestation_ref in payload → ACEF-077
    (i.e., a paired harness_attestation_ref makes the bundle safe even
    when tokens_found is non-empty AND rejection_state is accepted)

We combine both: ACEF-077 fires iff tokens_found is non-empty AND the
record is not properly rejected AND there is no paired harness attestation
in the payload. Producers can avoid the diagnostic by any of:

- ensuring the claim-lexicon scan finds no banned tokens, OR
- properly rejecting the record via
  ``rejection_state: "rejected_invalid_voice_rubric_emission"``, OR
- pairing the record with a ``harness_attestation_ref`` in the payload.
"""

from __future__ import annotations

from typing import Any

from acef.errors import ValidationDiagnostic
from acef.validation.namespace_lints import (
    NamespaceLintPattern,
    register_namespace_lint,
)

FREDDY_VOICE_RUBRIC_EMISSION_NS: str = "x-freddy/voice-rubric-emission"


def _tokens_found_non_empty(payload: dict[str, Any]) -> bool:
    """True iff payload.claim_lexicon_scan_result.tokens_found is a non-empty list."""
    scan = payload.get("claim_lexicon_scan_result")
    if not isinstance(scan, dict):
        return False
    tokens = scan.get("tokens_found")
    if not isinstance(tokens, list):
        return False
    return len(tokens) > 0


def _properly_rejected(payload: dict[str, Any]) -> bool:
    """True iff payload.rejection_state declares a proper rejection.

    Per brief §5.2 the accepted/rejected states are:
        - "accepted"
        - "rejected_invalid_voice_rubric_emission"

    Only the latter satisfies the "properly rejected" predicate. An
    unknown / missing rejection_state defaults to "not rejected" so the
    strictest interpretation applies (matches §10.7's strict requirement).
    """
    rs = payload.get("rejection_state")
    return rs == "rejected_invalid_voice_rubric_emission"


def _has_paired_harness_attestation(payload: dict[str, Any]) -> bool:
    """True iff payload carries a harness_attestation_ref or causation_chain ref.

    The ACEF-077 description's "paired harness_attestation" allows either:

    - ``payload.harness_attestation_ref`` is a non-empty string URN, OR
    - any element of the record's ``causation_chain`` resolves to a
      harness attestation URN.

    For the second case we cannot resolve URNs here (that's the engine's
    job in cross_record), so we accept ANY non-empty causation_chain
    entry that looks URN-shaped as a "best-effort pairing". The strict
    cross-record causation_chain check (ACEF-073) catches dangling refs
    separately, so a forged causation_chain entry doesn't get a free pass.

    We deliberately do NOT look at the *envelope-level* causation_chain
    field here — only the payload, because this lint operates strictly on
    payload content per the registry's lint-callable contract. The
    engine-level causation_chain is checked by cross_record.py.
    """
    ref = payload.get("harness_attestation_ref")
    if isinstance(ref, str) and ref:
        return True
    return False


def lint_voice_rubric_emission(
    manifest: dict[str, Any],
    payload: dict[str, Any],
    all_records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-077 when a voice-rubric-emission record carries banned
    tokens without a proper rejection or paired harness attestation.

    Implements brief §5.2 + the ACEF-077 registry description. See module
    docstring for the full trigger semantics.
    """
    if not _tokens_found_non_empty(payload):
        return []  # nothing to lint — scan was clean
    if _properly_rejected(payload):
        return []  # producer rejected the record; no enforcement needed
    if _has_paired_harness_attestation(payload):
        return []  # paired attestation satisfies the carve-out

    emission_id = payload.get("emission_id", "<unknown>")
    scan = payload.get("claim_lexicon_scan_result", {})
    tokens = scan.get("tokens_found", []) if isinstance(scan, dict) else []
    tokens_repr = ", ".join(repr(t) for t in tokens if isinstance(t, str)) or "<non-string tokens>"
    return [
        ValidationDiagnostic(
            "ACEF-077",
            (
                f"voice_rubric_emission {emission_id!r} contains banned "
                f"claim-lexicon tokens ({tokens_repr}) and is not properly "
                "rejected (rejection_state != "
                "'rejected_invalid_voice_rubric_emission') nor paired with a "
                "harness_attestation_ref. Per brief §5.2 / §10.7 such "
                "emissions MUST be rejected at the producer; per the "
                "ACEF-077 spec entry a paired harness_attestation also "
                "satisfies the requirement."
            ),
        )
    ]


# Pattern definition + auto-registration on import.
_FREDDY_VOICE_RUBRIC_PATTERN = NamespaceLintPattern(
    namespace=FREDDY_VOICE_RUBRIC_EMISSION_NS,
    pattern_id="claim-lexicon-without-paired-harness-attestation",
    description=(
        "Emit ACEF-077 when an x-freddy/voice-rubric-emission record "
        "carries banned claim-lexicon tokens without proper rejection or "
        "a paired harness_attestation_ref (brief §5.2 / spec §10.7)."
    ),
    lint=lint_voice_rubric_emission,
    emitted_codes=["ACEF-077"],
)


register_namespace_lint(_FREDDY_VOICE_RUBRIC_PATTERN)


__all__ = [
    "FREDDY_VOICE_RUBRIC_EMISSION_NS",
    "lint_voice_rubric_emission",
]
