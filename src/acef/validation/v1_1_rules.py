"""ACEF v1.1 validator rules — banned-language, state-class taxonomy, mode-gates.

Closes the v1.1 validator triplet alongside :mod:`acef.validation.cross_record`.
Only invoked when the resolved schema version is ``v1.1`` (regression-safety
per VAL-REGRESSION-001 — v1.0 bundles do NOT pass through these checks).

Assertions fulfilled by this module:

- **VAL-VALIDATION-008**: An Assessment Bundle with
  ``coverage_cell.claim_language`` containing a banned substring fails with
  ACEF-079 (NOT ACEF-053 — codex policy carved out ACEF-079 for this
  specific case so vendor-extension diagnostics don't subsume Core
  banned-copy enforcement).
- **VAL-VALIDATION-009**: A record with ``state_class`` outside the seven
  hard-coded taxonomy entries emits ACEF-076. A record whose taxonomy
  entry has ``fake_green_test_required: true`` but lacks
  ``fake_green_test_ref`` also emits ACEF-076 (per ACEF-076 description:
  "state_class record lacks fake-green test reference").
- **VAL-VALIDATION-010**: A bundle whose ``analysis_mode`` forbids a record
  type that nevertheless appears in the bundle emits ACEF-080. The
  per-mode forbidden tables (plan WS3.9) are:

      subscriber            : (none)
      public_artifact       : delivery_verdict, disposition_record (i.e.,
                              risk_treatment with treatment_subtype=
                              external_disposition)
      canary                : delivery_verdict; transparency_disclosure
                              with variant=verification_badge whose
                              page_state != "unsupported"; any other
                              transparency_disclosure whose
                              confidentiality is "public"
      unattributed_artifact : same as public_artifact PLUS any record
                              with a non-null `attribution` field
                              (payload.attribution OR top-level
                              attribution_advisory)

Each function returns a list of :class:`ValidationDiagnostic` instances.
The engine merges them into the AssessmentBundle.structural_errors list.

VAL-VALIDATION-011 (subscriber required record types) already lives in
:func:`acef.validation.cross_record.enforce_mode_gates`; this module does
not duplicate that check.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path
from typing import Any

from acef.errors import ValidationDiagnostic

# ---------------------------------------------------------------------------
# Banned claim-language tokens
# ---------------------------------------------------------------------------

# The closed, normative banned claim-lexicon for ``coverage_cell.claim_language``.
# Taken VERBATIM from the spec ACEF-079 error-taxonomy row
# (planning/ACEF-Spec-Outline-v0.1.md §3.6, line 1282): "coverage_cell.claim_language
# contains a banned claim-lexicon token (`compliant`, `certified`,
# `AI Act-approved`, `guaranteed`)". The list is CLOSED at exactly these four
# tokens; additions require a spec amendment. (Audit cross-record-authority-1:
# the non-normative `lawful` token was removed — it false-rejected conformant
# bundles citing a GDPR "lawful basis" / disclosing something is "unlawful".)
BANNED_CLAIM_LANGUAGE_TOKENS: tuple[str, ...] = (
    "compliant",
    "certified",
    "AI Act-approved",
    "guaranteed",
)


def _compile_banned_token_patterns(
    tokens: tuple[str, ...],
) -> tuple[tuple[str, re.Pattern[str]], ...]:
    r"""Compile each banned token to a case-insensitive HYPHEN-AWARE matcher.

    Audit cross-record-authority-4: the original naive substring scan
    (``token in lowered``) false-rejected legitimate words that merely
    CONTAIN a banned token (e.g. ``noncompliant`` contains ``compliant``).
    The first fix anchored each token between word boundaries
    (``\b<token>\b``), which stopped pure-substring matches.

    But ``\b`` treats ``-`` as a word boundary, so ``\bcompliant\b`` STILL
    matched "compliant" inside legitimate hyphenated compounds like
    ``non-compliant`` / ``self-certified`` / ``AI Act-approved-process`` — a
    residual false ACEF-079 (roborev follow-up). We therefore replace the
    ``\b`` anchors with explicit edge LOOKAROUNDS that treat a hyphenated
    compound as a single lexical unit:

        (?<![\w-]) <token> (?![\w-])

    A banned token matches ONLY when it is NOT adjacent to a word-character
    OR a hyphen on either edge. So:

    * ``non-compliant`` / ``self-certified`` / ``certified-evidence`` →
      hyphen on one edge → NOT matched (the compound is one token).
    * ``AI Act-approved-process`` → trailing ``-`` after the multi-word
      token → NOT matched.
    * ``noncompliant`` / ``recertified`` → word-char on the edge → NOT
      matched (the original substring guard preserved).
    * standalone ``compliant`` / ``compliant.`` / ``(certified)`` →
      whitespace or punctuation on the edge (neither ``\w`` nor ``-``) →
      MATCHED. Punctuation is a real boundary.

    The token is :func:`re.escape`-d so multi-word / hyphenated tokens
    (``AI Act-approved``) match literally; the internal hyphen of the token
    itself is part of the escaped literal and is unaffected by the edge
    lookarounds. Matching is case-insensitive (``re.IGNORECASE``) to preserve
    the prior "COMPLIANT" == "compliant" behavior, and ``re.UNICODE`` (the
    Python-3 default for ``str`` patterns) makes ``\w`` Unicode-aware.
    """
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for token in tokens:
        pattern = re.compile(
            r"(?<![\w-])" + re.escape(token) + r"(?![\w-])",
            re.IGNORECASE | re.UNICODE,
        )
        compiled.append((token, pattern))
    return tuple(compiled)


# Pre-compiled (token, word-boundary-pattern) pairs — built once at import.
_BANNED_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = _compile_banned_token_patterns(
    BANNED_CLAIM_LANGUAGE_TOKENS
)


# ---------------------------------------------------------------------------
# Forbidden-record-type tables per analysis_mode (plan WS3.9)
# ---------------------------------------------------------------------------

# Simple forbidden record-type lists keyed by analysis_mode. The
# ``risk_treatment`` row is matched by record_type alone, then the
# treatment_subtype check (for disposition_record) is applied separately
# below so we can name the variant accurately in the diagnostic.
_FORBIDDEN_RECORD_TYPES_BY_MODE: dict[str, tuple[str, ...]] = {
    "subscriber": (),
    "public_artifact": ("delivery_verdict",),
    "canary": ("delivery_verdict",),
    "unattributed_artifact": ("delivery_verdict",),
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _records_iter(
    records: list[dict[str, Any]],
) -> Iterator[tuple[int, dict[str, Any]]]:
    for idx, r in enumerate(records):
        if isinstance(r, dict):
            yield idx, r


def _record_id_of(rec: dict[str, Any]) -> str:
    rid = rec.get("record_id", "")
    return rid if isinstance(rid, str) else ""


def _record_type_of(rec: dict[str, Any]) -> str:
    rt = rec.get("record_type", "")
    return rt if isinstance(rt, str) else ""


def _payload_of(rec: dict[str, Any]) -> dict[str, Any]:
    p = rec.get("payload")
    return p if isinstance(p, dict) else {}


def _is_disposition_record(rec: dict[str, Any]) -> bool:
    """risk_treatment with treatment_subtype=external_disposition (V3)."""
    if _record_type_of(rec) != "risk_treatment":
        return False
    return _payload_of(rec).get("treatment_subtype") == "external_disposition"


def _is_verification_badge_record(rec: dict[str, Any]) -> bool:
    """transparency_disclosure with variant=verification_badge (V4)."""
    if _record_type_of(rec) != "transparency_disclosure":
        return False
    return _payload_of(rec).get("variant") == "verification_badge"


def _has_non_null_attribution(rec: dict[str, Any]) -> bool:
    """True iff the record carries any non-null attribution information.

    Per plan WS3.9 unattributed_artifact mode forbids any record with a
    non-null ``attribution`` field. The field can appear at the payload
    level (``payload.attribution``) or as the dedicated
    ``attribution_advisory`` block used by persona_observation records.
    """
    payload = _payload_of(rec)
    if payload.get("attribution") not in (None, "", {}, []):
        return True
    aa = payload.get("attribution_advisory")
    if isinstance(aa, dict) and aa:
        # An ``attribution_advisory`` block is itself an attribution claim.
        return True
    # Top-level (envelope-level) attribution field, in case producers
    # promoted it out of payload.
    top = rec.get("attribution")
    if top not in (None, "", {}, []):
        return True
    return False


# ---------------------------------------------------------------------------
# State-class taxonomy loader (cached)
# ---------------------------------------------------------------------------


def _state_class_taxonomy_path() -> Path:
    """Resolve the v1.1 taxonomy JSON path relative to the installed package."""
    # ``acef-conventions/v1.1/state-class-taxonomy.json`` is project-relative
    # at repo root. Walk up from this file to find it. We climb until we
    # locate ``acef-conventions`` because the package is installed in
    # editable mode during dev (path = ``src/acef/validation/v1_1_rules.py``)
    # and from a wheel in production (where ``acef-conventions/`` is
    # shipped as package data).
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "acef-conventions" / "v1.1" / "state-class-taxonomy.json"
        if candidate.is_file():
            return candidate
    # Fall back to a path that will fail open clearly if missing.
    return Path("acef-conventions/v1.1/state-class-taxonomy.json")


@lru_cache(maxsize=1)
def load_state_class_taxonomy() -> dict[str, dict[str, Any]]:
    """Return a dict keyed by state_class_id → entry dict.

    Reads ``acef-conventions/v1.1/state-class-taxonomy.json`` once per
    process. Defensive parsing: a malformed file produces an empty dict
    (every state_class then fails as "unknown" — the strictest, safest
    fallback).
    """
    path = _state_class_taxonomy_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    entries = data.get("state_classes")
    if not isinstance(entries, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if isinstance(entry, dict):
            sid = entry.get("state_class_id")
            if isinstance(sid, str) and sid:
                out[sid] = entry
    return out


# ---------------------------------------------------------------------------
# VAL-VALIDATION-008: banned claim_language lint
# ---------------------------------------------------------------------------


def lint_coverage_cell_claim_language(
    assessment_bundle: dict[str, Any],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-079 for each coverage_cell.claim_language banned-token hit.

    Per VAL-VALIDATION-008: scan the Assessment Bundle's ``coverage_cells``
    array. For each cell, run a case-insensitive HYPHEN-AWARE whole-token scan
    over the closed normative banned-token list (the four tokens of the spec
    ACEF-079 row). Each violating (cell_id, token) pair emits a distinct
    ACEF-079 diagnostic so producers see every offending token.

    Hyphen-aware (not substring, not bare ``\\b``) matching per audit
    cross-record-authority-4 + roborev follow-up: a banned token fires only as
    a standalone token bounded by non-word/non-hyphen edges. Legitimate words
    that merely contain a banned token as a substring (``noncompliant``) and
    legitimate hyphenated compounds that embed one (``non-compliant`` /
    ``self-certified``) are NOT false-rejected; punctuation-delimited
    standalone tokens (``compliant.``) still fire.

    NOT ACEF-053 — codex policy explicitly carved out ACEF-079 to keep the
    Core banned-copy outcome independent of vendor-extension diagnostics.
    """
    if not isinstance(assessment_bundle, dict):
        return []
    cells = assessment_bundle.get("coverage_cells")
    if not isinstance(cells, list):
        return []

    diags: list[ValidationDiagnostic] = []
    for idx, cell in enumerate(cells):
        if not isinstance(cell, dict):
            continue
        claim = cell.get("claim_language")
        if not isinstance(claim, str) or not claim:
            continue
        cell_id = cell.get("cell_id")
        if not isinstance(cell_id, str) or not cell_id:
            cell_id = f"<coverage_cells[{idx}]>"
        for token, pattern in _BANNED_TOKEN_PATTERNS:
            if pattern.search(claim):
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-079",
                        (
                            f"coverage_cell {cell_id!r} has claim_language "
                            f"containing the banned claim-lexicon token "
                            f"{token!r} as a whole word. Per the ACEF-079 "
                            "error-taxonomy row (spec §3.6), the constrained "
                            "coverage_cell.claim_language vocabulary MUST NOT "
                            "include this token."
                        ),
                    )
                )
    return diags


# ---------------------------------------------------------------------------
# VAL-VALIDATION-009: state_class taxonomy enforcement
# ---------------------------------------------------------------------------


def enforce_state_class_taxonomy(
    records: list[dict[str, Any]],
    taxonomy: dict[str, dict[str, Any]] | None = None,
) -> list[ValidationDiagnostic]:
    """Emit ACEF-076 when a record's state_class violates the taxonomy.

    Two failure modes both emit ACEF-076 (per the ACEF-076 description:
    "state_class record lacks fake-green test reference" — the validator
    treats both "unknown state_class" and "known state_class missing the
    required fake_green_test_ref" as the same code, because the latter is
    semantically a fake-green binding failure and the former cannot have a
    valid fake-green binding by construction).

    1. ``state_class`` is not in the 7-entry taxonomy.
    2. ``state_class`` is in the taxonomy, the entry's
       ``fake_green_test_required`` is true, AND the record's
       ``payload.fake_green_test_ref`` is missing or empty.

    Both ``harness_attestation`` records (where state_class lives in the
    payload) and any future record type that grows a ``state_class`` field
    are checked uniformly. Records without a ``state_class`` field are
    ignored (the field is conditional, not absolute-required).
    """
    if taxonomy is None:
        taxonomy = load_state_class_taxonomy()

    diags: list[ValidationDiagnostic] = []
    for _idx, rec in _records_iter(records):
        payload = _payload_of(rec)
        sc = payload.get("state_class")
        if sc is None:
            # Some producers might put state_class at the envelope level
            # (forward-compat); accept both.
            sc = rec.get("state_class")
        if not isinstance(sc, str) or not sc:
            continue
        rec_id = _record_id_of(rec)
        entry = taxonomy.get(sc)
        if entry is None:
            diags.append(
                ValidationDiagnostic(
                    "ACEF-076",
                    (
                        f"Record {rec_id!r} declares state_class={sc!r}, "
                        "which is not in the v1.1 state-class taxonomy. "
                        "The taxonomy is closed in v0.4; see "
                        "acef-conventions/v1.1/state-class-taxonomy.json "
                        "for the allowed values (step, finding, "
                        "coverage_cell, regression, delivery, badge, "
                        "attestation)."
                    ),
                )
            )
            continue
        # Known state_class — check fake_green_test_required.
        if not entry.get("fake_green_test_required"):
            continue
        ref = payload.get("fake_green_test_ref")
        if isinstance(ref, str) and ref:
            continue
        diags.append(
            ValidationDiagnostic(
                "ACEF-076",
                (
                    f"Record {rec_id!r} declares state_class={sc!r}, which "
                    "requires a fake_green_test_ref per the v1.1 "
                    "state-class taxonomy, but the field is missing or "
                    "empty. Per brief §3.6 / SPEC-FRD §24.5, every "
                    "fake-green-required state_class MUST cite the "
                    "fake-green test URN that proves the state cannot be "
                    "reached without the bound evidence."
                ),
            )
        )
    return diags


# ---------------------------------------------------------------------------
# VAL-VALIDATION-010: mode-gated forbidden record types
# ---------------------------------------------------------------------------


def enforce_mode_gated_forbidden_types(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    """Emit ACEF-080 for each record forbidden by the bundle's analysis_mode.

    Implements plan WS3.9. The forbidden-record-type table:

    +-----------------------+-------------------------------------------+
    | mode                  | forbidden                                  |
    +=======================+===========================================+
    | subscriber            | (none)                                     |
    +-----------------------+-------------------------------------------+
    | public_artifact       | delivery_verdict; risk_treatment whose     |
    |                       | treatment_subtype=external_disposition     |
    |                       | (i.e., disposition_record / V3 variant);   |
    |                       | finding_record carrying accepted_risk_ref  |
    +-----------------------+-------------------------------------------+
    | canary                | delivery_verdict;                          |
    |                       | transparency_disclosure with               |
    |                       |   variant=verification_badge AND           |
    |                       |   page_state != "unsupported"              |
    |                       | (badge_state MUST be unsupported in canary)|
    |                       | other transparency_disclosure records      |
    |                       |   whose confidentiality is "public"        |
    +-----------------------+-------------------------------------------+
    | unattributed_artifact | same as public_artifact PLUS any record    |
    |                       | with a non-null attribution field          |
    +-----------------------+-------------------------------------------+

    A bundle without an ``analysis_mode`` does not trigger this check —
    mode-gates only apply when the producer declares a mode.

    Normative basis (audit cross-record-authority-2): the ACEF-080 *code*
    is normative (spec §3.6 error taxonomy — "contains forbidden record
    types for that mode"). The per-mode forbidden-record-type TABLE above,
    however, has no normative home in the ACEF spec or RFC-0002; it derives
    from the ACEF mode-gate model defined by the acef-v0.4-freddy-adoption
    operation plan (WS3.9). Diagnostics cite the code's real home plus that
    model, never a fabricated spec section.
    """
    if not isinstance(manifest, dict):
        return []
    mode = manifest.get("analysis_mode")
    if not isinstance(mode, str) or mode not in _FORBIDDEN_RECORD_TYPES_BY_MODE:
        return []

    diags: list[ValidationDiagnostic] = []
    forbidden_simple = _FORBIDDEN_RECORD_TYPES_BY_MODE[mode]

    for _idx, rec in _records_iter(records):
        rec_id = _record_id_of(rec)
        rt = _record_type_of(rec)
        if not rt:
            continue

        # Rule (a): simple forbidden record types.
        if rt in forbidden_simple:
            diags.append(
                ValidationDiagnostic(
                    "ACEF-080",
                    (
                        f"Bundle declares analysis_mode={mode!r} but contains "
                        f"a forbidden record_type {rt!r} on record "
                        f"{rec_id!r}. Per the ACEF-080 mode-gate rule (spec "
                        f"§3.6; per-mode table: ACEF mode-gate model), "
                        f"{mode!r} mode disallows this record type."
                    ),
                )
            )
            continue

        # Rule (b): disposition_record variant under public_artifact /
        # unattributed_artifact.
        if mode in ("public_artifact", "unattributed_artifact") and _is_disposition_record(rec):
            diags.append(
                ValidationDiagnostic(
                    "ACEF-080",
                    (
                        f"Bundle declares analysis_mode={mode!r} but contains "
                        f"a disposition_record (risk_treatment variant "
                        f"V3, treatment_subtype=external_disposition) on "
                        f"record {rec_id!r}. Per the ACEF-080 mode-gate rule "
                        f"(spec §3.6; per-mode table: ACEF mode-gate model), "
                        f"{mode!r} mode disallows disposition_record."
                    ),
                )
            )
            continue

        # Rule (c): canary-specific badge_state and transparency rules.
        if mode == "canary":
            if _is_verification_badge_record(rec):
                page_state = _payload_of(rec).get("page_state")
                if page_state != "unsupported":
                    diags.append(
                        ValidationDiagnostic(
                            "ACEF-080",
                            (
                                f"Bundle declares analysis_mode='canary' but "
                                f"badge_state record {rec_id!r} has "
                                f"page_state={page_state!r}. Per the ACEF-080 "
                                "mode-gate rule (spec §3.6; per-mode table: "
                                "ACEF mode-gate model), canary-mode "
                                "badge_state records MUST have "
                                "page_state='unsupported'."
                            ),
                        )
                    )
                continue
            if rt == "transparency_disclosure":
                conf = rec.get("confidentiality")
                if conf == "public":
                    diags.append(
                        ValidationDiagnostic(
                            "ACEF-080",
                            (
                                f"Bundle declares analysis_mode='canary' but "
                                f"transparency_disclosure record {rec_id!r} "
                                "has confidentiality='public'. Per the "
                                "ACEF-080 mode-gate rule (spec §3.6; per-mode "
                                "table: ACEF mode-gate model), canary mode "
                                "forbids public transparency_disclosure "
                                "records (non-badge_state disclosures MUST be "
                                "private in canary)."
                            ),
                        )
                    )
                continue

        # Rule (d): unattributed_artifact forbids any record with a
        # non-null attribution field.
        if mode == "unattributed_artifact" and _has_non_null_attribution(rec):
            diags.append(
                ValidationDiagnostic(
                    "ACEF-080",
                    (
                        f"Bundle declares analysis_mode='unattributed_artifact' "
                        f"but record {rec_id!r} (record_type={rt!r}) carries a "
                        "non-null attribution field. Per the ACEF-080 mode-"
                        "gate rule (spec §3.6; per-mode table: ACEF mode-gate "
                        "model), unattributed_artifact mode forbids any "
                        "attribution information."
                    ),
                )
            )
            continue

        # Rule (e): accepted_risk_ref is forbidden under public_artifact (and the stricter
        # unattributed_artifact). The frozen manifest analysis_mode schema contract:
        # "'public_artifact' forbids delivery_verdict / disposition_record / accepted_risk_ref
        # ...". accepted_risk_ref is a finding_record FIELD (an external risk-acceptance
        # pointer), NOT a record type, so it is gated here rather than via the forbidden-type
        # table (F3 — previously unenforced, so the schema promised an ACEF-080 the validator
        # never emitted). The FIELD's PRESENCE is forbidden (roborev on 8905e06): an empty or
        # whitespace accepted_risk_ref is still the forbidden field, so any non-null value
        # trips ACEF-080 (the schema validates the value TYPE; the mode-gate forbids presence).
        if mode in ("public_artifact", "unattributed_artifact") and rt == "finding_record":
            payload = _payload_of(rec)
            if "accepted_risk_ref" in payload and payload["accepted_risk_ref"] is not None:
                accepted_risk_ref = payload["accepted_risk_ref"]
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-080",
                        (
                            f"Bundle declares analysis_mode={mode!r} but finding_record "
                            f"{rec_id!r} carries accepted_risk_ref={accepted_risk_ref!r}. Per "
                            "the ACEF-080 mode-gate rule (the frozen analysis_mode schema "
                            f"contract), {mode!r} mode forbids the accepted_risk_ref field (an "
                            "external risk-acceptance pointer)."
                        ),
                    )
                )
                continue

        # NOTE (F3 / roborev on 8905e06): the frozen analysis_mode schema description also
        # says public_artifact "caps persona_observation.attribution_advisory.confidence at
        # low/medium". But ``persona_observation`` is NOT a registered v1.1 record type (it is
        # absent from RECORD_TYPES; a record bearing it is rejected as ACEF-003 unknown type
        # before this mode-gate runs), and there is no attribution_advisory schema in v1.1.
        # The cap is therefore UNENFORCEABLE on any valid v1.1 bundle — implementing a rule
        # for a phantom record type would be dead code that the test suite could only exercise
        # via the helper, never a real bundle path. The cap is a v1.2 concern (it requires
        # registering the persona_observation record type + attribution_advisory schema
        # first); no rule is emitted here until that type exists.
    return diags


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def run_v1_1_rules(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    assessment_bundle: dict[str, Any] | None = None,
) -> list[ValidationDiagnostic]:
    """Run all v1.1 rule families and return a merged diagnostic list.

    Called by the engine ONLY when ``schema_version == "v1.1"`` (v1.0
    bundles must be byte-equivalent to pre-v0.4 validator behavior per
    VAL-REGRESSION-001).

    Args:
        manifest: Parsed acef-manifest.json content.
        records: All record dicts loaded from the bundle's JSONL files.
        assessment_bundle: Optional pre-existing Assessment Bundle dict
            (for re-validation of an emitted assessment). When None, the
            banned-language lint is a no-op (there is nothing to lint).
            The engine passes the sibling ``<bundle>.acef-assessment.json``
            or in-bundle ``acef-assessment.json`` if present.
    """
    diags: list[ValidationDiagnostic] = []
    if assessment_bundle is not None:
        diags.extend(lint_coverage_cell_claim_language(assessment_bundle))
    diags.extend(enforce_state_class_taxonomy(records))
    diags.extend(enforce_mode_gated_forbidden_types(manifest, records))
    return diags
