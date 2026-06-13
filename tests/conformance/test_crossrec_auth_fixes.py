"""F-M6-CROSSREC — cross-record authority diagnostic/lexicon fixes.

RED-first tests for audit findings cross-record-authority-1/2/3/4/7
(contract assertions VAL-FIX-AUTH-001/002/003/004/007).

- AUTH-001: BANNED_CLAIM_LANGUAGE_TOKENS must equal the normative ACEF-079
  four-token list (spec §3.6 line 1282: ``compliant``, ``certified``,
  ``AI Act-approved``, ``guaranteed``). The non-normative ``lawful`` token
  must be removed so conformant bundles using it are not false-rejected.
- AUTH-004: the banned-token scan must use WORD-BOUNDARY matching so a
  banned token only fires as a whole word, never embedded in a legitimate
  larger word (e.g. ``noncompliant`` containing ``compliant`` as a
  substring must NOT be matched; a stand-alone ``compliant`` must).
- AUTH-002: authority-matrix / mode-gate / tenant / disposition diagnostic
  strings must NOT cite non-existent spec sections (§6.4 / §6.6 / §14.5).
  They must cite the actual governing source (the ACEF-NNN error-code row
  in §3.6, the real §3.1.3 integrity section, or "ACEF authority model"
  for rules with no normative spec home).
- AUTH-003: namespace lints contribute ONLY to ``structural_errors`` and
  never to ``results[].outcome`` / ``provision_summary[].provision_outcome``
  (the §3.7 line-1386 extension-outcome boundary).
- AUTH-007: the ``_has_paired_harness_attestation`` docstring must describe
  the ACTUAL behavior (only ``payload.harness_attestation_ref`` is honored;
  ``causation_chain`` is intentionally NOT trusted here).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import acef.validation.authority_matrix as authority_matrix
import acef.validation.cross_record as cross_record
import acef.validation.namespace_lints.bundled_freddy as bundled_freddy
import acef.validation.v1_1_rules as v1_1_rules
from acef.models.urns import URNType
from acef.package import Package
from acef.validation.engine import validate_bundle
from acef.validation.v1_1_rules import (
    BANNED_CLAIM_LANGUAGE_TOKENS,
    lint_coverage_cell_claim_language,
)
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
)

# The normative ACEF-079 banned-lexicon tuple, taken VERBATIM from the spec
# §3.6 error-taxonomy row (planning/ACEF-Spec-Outline-v0.1.md line 1282).
# Closed at four tokens — ``lawful`` is NOT present.
SPEC_ACEF_079_TOKENS: tuple[str, ...] = (
    "compliant",
    "certified",
    "AI Act-approved",
    "guaranteed",
)

# Section-citation patterns that DO NOT exist in the normative spec
# (§6.4 = "Conformance Program", §6.6 = "Golden Bundle Specifications",
# there is no §14). Any diagnostic citing these for tenant/mode/authority
# rules is misleading and must be removed.
_FABRICATED_CITATION = re.compile(r"§\s?6\.4|§\s?6\.6|§\s?14(?:\.\d+)?")


def _coverage_cell(claim_language: str) -> dict:
    return {
        "cell_id": "urn:acef:cell:00000000-0000-0000-0000-000000000001",
        "subject_ref": "urn:acef:sub:00000000-0000-0000-0000-000000000001",
        "dimensions": {
            "scenario_class": "tool_use",
            "surface_class": "chat",
            "time_window_start": "2026-01-01T00:00:00Z",
            "time_window_end": "2026-01-02T00:00:00Z",
        },
        "bound_evidence_refs": ["urn:acef:rec:00000000-0000-0000-0000-000000000099"],
        "freshness_state": "fresh",
        "freshness_policy_ref": "urn:acef:pol:00000000-0000-0000-0000-000000000001",
        "claim_language": claim_language,
        "coverage_outcome": "covered",
    }


def _assessment_bundle(claim_language: str) -> dict:
    return {
        "versioning": {"core_version": "1.1.0", "assessment_version": "1.1.0"},
        "assessment_id": "urn:acef:asx:00000000-0000-0000-0000-000000000001",
        "timestamp": "2026-01-02T00:00:00Z",
        "evaluation_instant": "2026-01-02T00:00:00Z",
        "assessor": {"name": "acef-validator", "version": "0.1.0"},
        "evidence_bundle_ref": {
            "content_hash": "sha256:" + "0" * 64,
            "package_id": "urn:acef:pkg:11111111-1111-1111-1111-111111111111",
        },
        "profiles_evaluated": [],
        "template_digests": {},
        "results": [],
        "provision_summary": [],
        "structural_errors": [],
        "integrity": None,
        "coverage_cells": [_coverage_cell(claim_language)],
    }


def _codes_for(claim_language: str) -> list[str]:
    return [d.code for d in lint_coverage_cell_claim_language(_assessment_bundle(claim_language))]


# ---------------------------------------------------------------------------
# AUTH-001: the banned-token list must match the normative four-token spec
# ---------------------------------------------------------------------------


def test_banned_list_equals_normative_four_token_spec_list() -> None:
    """BANNED_CLAIM_LANGUAGE_TOKENS == the spec ACEF-079 four-token tuple.

    Pins the constant to the NORMATIVE source rather than tautologically
    parametrizing over itself. ``lawful`` (the non-normative fifth token)
    must be absent.
    """
    assert tuple(BANNED_CLAIM_LANGUAGE_TOKENS) == SPEC_ACEF_079_TOKENS
    assert "lawful" not in BANNED_CLAIM_LANGUAGE_TOKENS


def test_lawful_basis_claim_is_not_false_rejected() -> None:
    """A coverage_cell citing a GDPR 'lawful basis' must NOT emit ACEF-079.

    Terminology the RFC itself uses pervasively; the non-normative
    ``lawful`` token false-rejected it.
    """
    assert "ACEF-079" not in _codes_for("Processing relies on a documented lawful basis under GDPR Art. 6.")


def test_unlawful_disclosure_is_not_false_rejected() -> None:
    """A coverage_cell honestly disclosing something is 'unlawful' must NOT
    emit ACEF-079 (``lawful`` is removed; even if present, ``unlawful`` is a
    different word under word-boundary matching).
    """
    assert "ACEF-079" not in _codes_for("This processing path is unlawful and was disabled.")


# ---------------------------------------------------------------------------
# AUTH-004: word-boundary matching for the remaining banned tokens
# ---------------------------------------------------------------------------


def test_stand_alone_banned_token_still_fires() -> None:
    """Each remaining banned token, as a whole word, still emits ACEF-079."""
    for token in SPEC_ACEF_079_TOKENS:
        found = _codes_for(f"This system is {token} for the named scope.")
        assert "ACEF-079" in found, f"whole-word {token!r} must still fire ACEF-079; got {found!r}"


def test_banned_token_embedded_in_larger_word_does_not_fire() -> None:
    """A banned token that appears only as a SUBSTRING of a larger
    legitimate word must NOT emit ACEF-079 (word-boundary matching).

    ``noncompliant`` contains ``compliant``; ``recertified`` contains
    ``certified``; ``guaranteedness`` contains ``guaranteed`` — none is the
    banned whole word, so none may be flagged.
    """
    for phrase in (
        "The artifact was flagged noncompliant by the auditor.",
        "Equipment was recertified after the audit cycle.",
        "We make no claim of guaranteedness about the result.",
    ):
        found = _codes_for(phrase)
        assert "ACEF-079" not in found, f"substring-only match must NOT fire for {phrase!r}; got {found!r}"


def test_hyphenated_compound_with_banned_token_does_not_fire() -> None:
    """A hyphenated compound is a single token under word-boundary rules;
    a banned word adjacent to a hyphen with surrounding word chars must not
    over-match. ``self-certifiedX``-style runs are not the banned word.
    """
    # 'precertified-evidence' — 'certified' is embedded in 'precertified'
    assert "ACEF-079" not in _codes_for("See the precertifiedstate-evidence bundle.")


def test_banned_token_at_phrase_boundary_with_punctuation_fires() -> None:
    """A banned whole word delimited by punctuation still fires (word
    boundaries treat punctuation as a delimiter)."""
    assert "ACEF-079" in _codes_for("Status: compliant.")
    assert "ACEF-079" in _codes_for("(certified)")


def test_multiword_banned_token_matches_whole_phrase() -> None:
    """The multi-word ``AI Act-approved`` token matches as a phrase."""
    assert "ACEF-079" in _codes_for("This output is AI Act-approved for deployment.")
    # An unrelated sentence merely containing 'approved' must NOT fire (the
    # banned token is the full phrase 'AI Act-approved', not 'approved').
    assert "ACEF-079" not in _codes_for("The change was approved by the review board.")


# ---------------------------------------------------------------------------
# AUTH-004 (roborev follow-up): hyphenated-compound false-positive
#
# ``\b<token>\b`` treats ``-`` as a word boundary, so ``\bcompliant\b`` STILL
# matches "compliant" embedded in legitimate hyphenated compounds like
# "non-compliant" / "self-certified" → a false ACEF-079. The fix replaces the
# ``\b`` anchors with edge LOOKAROUNDS that treat a hyphenated compound as a
# single lexical unit: ``(?<![\w-])<token>(?![\w-])`` — a banned token matches
# only when NOT adjacent to a word-char OR a hyphen. Punctuation (``.`` ``,``
# ``(`` ``)`` ``:`` whitespace) is a REAL boundary and must still fire.
# ---------------------------------------------------------------------------


def test_hyphen_prefixed_compound_does_not_false_flag() -> None:
    """A banned token that is the SUFFIX of a hyphenated compound must NOT
    fire ACEF-079 — the compound is one lexical unit, not the bare word.

    These all currently FALSE-flag under ``\\b<token>\\b`` (hyphen is a word
    boundary) and must stop after switching to hyphen-aware lookarounds.
    """
    for phrase in (
        "This system is non-compliant with the rule.",
        "The model is non-certified for this scope.",
    ):
        found = _codes_for(phrase)
        assert "ACEF-079" not in found, f"hyphenated compound must NOT fire ACEF-079 for {phrase!r}; got {found!r}"


def test_hyphen_suffixed_compound_does_not_false_flag() -> None:
    """A banned token that is the PREFIX of a hyphenated compound must NOT
    fire ACEF-079 (the hyphen ties the word into a larger unit).
    """
    for phrase in (
        "The vendor self-certified the result.",
        "Documented under a certified-evidence chain.",
    ):
        found = _codes_for(phrase)
        assert "ACEF-079" not in found, f"hyphen-suffixed compound must NOT fire ACEF-079 for {phrase!r}; got {found!r}"


def test_multiword_token_inside_longer_hyphenated_run_does_not_fire() -> None:
    """The multi-word ``AI Act-approved`` token, when itself extended by a
    trailing hyphen into a longer compound (``AI Act-approved-process``), is
    a different lexical unit and must NOT fire.
    """
    found = _codes_for("This uses an AI Act-approved-process internally.")
    assert "ACEF-079" not in found, f"hyphen-extended multiword compound must NOT fire ACEF-079; got {found!r}"


def test_bare_banned_word_still_fires_after_hyphen_fix() -> None:
    """The standalone banned word, surrounded by whitespace, still fires —
    the hyphen-aware lookarounds must not weaken whole-word enforcement.
    """
    assert "ACEF-079" in _codes_for("This system is compliant for the named scope.")


def test_punctuation_adjacent_banned_word_still_fires_after_hyphen_fix() -> None:
    """Punctuation (``.`` ``,`` ``:`` parentheses) is a REAL boundary, not a
    hyphen/word-char, so a banned word abutting punctuation still fires.
    """
    for phrase in (
        "Status: compliant.",
        "Result is compliant, per the audit.",
        "(certified)",
    ):
        assert "ACEF-079" in _codes_for(phrase), f"punctuation-adjacent banned word must still fire for {phrase!r}"


# ---------------------------------------------------------------------------
# AUTH-002: diagnostics must not cite non-existent spec sections
# ---------------------------------------------------------------------------


def _all_v1_1_diag_messages() -> list[str]:
    """Drive every cross-record / v1_1_rules diagnostic family to collect the
    user-facing messages for citation auditing.

    Builds inputs that trigger tenant-uniformity (ACEF-075), cross-tenant
    refs (ACEF-020), mode-gates (ACEF-080), forbidden-types (ACEF-080) and
    disposition-authority (ACEF-080) diagnostics.
    """
    messages: list[str] = []

    # Tenant uniformity: two distinct tenant_labels with analysis_mode set.
    manifest = base_manifest(analysis_mode="subscriber")
    recs = [
        base_record(record_id="urn:acef:rec:t1", tenant_label="tenant-a"),
        base_record(record_id="urn:acef:rec:t2", tenant_label="tenant-b"),
    ]
    messages += [d.message for d in cross_record.enforce_tenant_uniformity(manifest, recs)]

    # Cross-tenant entity reference (ACEF-020).
    refs_recs = [
        base_record(
            record_id="urn:acef:rec:o1",
            tenant_label="tenant-a",
            entity_refs={"dataset_refs": ["urn:acef:ds:shared"]},
        ),
        base_record(
            record_id="urn:acef:rec:o2",
            tenant_label="tenant-b",
            entity_refs={"dataset_refs": ["urn:acef:ds:shared"]},
        ),
    ]
    etmap = cross_record.build_entity_tenant_map(refs_recs)
    messages += [d.message for d in cross_record.enforce_cross_tenant_refs(refs_recs, etmap)]

    # Subscriber mode-gates: missing required record types (ACEF-080).
    messages += [d.message for d in cross_record.enforce_mode_gates(base_manifest(analysis_mode="subscriber"), [])]

    # Disposition authority: provider grants accepted_risk_request (DENIED).
    disp_manifest = base_manifest(
        analysis_mode="subscriber",
        entities_actors=[{"actor_id": "urn:acef:act:prov", "role": "provider"}],
    )
    disp_rec = base_record(
        record_id="urn:acef:rec:disp",
        record_type="risk_treatment",
        entity_refs={"actor_refs": ["urn:acef:act:prov"]},
        payload={
            "treatment_subtype": "external_disposition",
            "authority_check": {
                "authority_granted": True,
                "authority_class": "accepted_risk_request",
                "actor_ref": "urn:acef:act:prov",
            },
        },
    )
    messages += [d.message for d in cross_record.enforce_disposition_authority(disp_manifest, [disp_rec])]

    # Forbidden record types under public_artifact (ACEF-080).
    fr_manifest = base_manifest(analysis_mode="public_artifact")
    fr_rec = base_record(record_id="urn:acef:rec:dv", record_type="delivery_verdict")
    messages += [d.message for d in v1_1_rules.enforce_mode_gated_forbidden_types(fr_manifest, [fr_rec])]

    # Banned claim-language diagnostic message.
    messages += [d.message for d in lint_coverage_cell_claim_language(_assessment_bundle("System is compliant."))]

    assert messages, "expected at least one diagnostic message to audit"
    return messages


def test_no_diagnostic_cites_a_nonexistent_spec_section() -> None:
    """No user-facing diagnostic may cite §6.4 / §6.6 / §14.x — those spec
    sections do not contain the cited tenant/mode/authority rules.
    """
    offenders = [m for m in _all_v1_1_diag_messages() if _FABRICATED_CITATION.search(m)]
    assert offenders == [], f"diagnostics cite non-existent spec sections: {offenders!r}"


def test_authority_matrix_docstring_does_not_cite_nonexistent_section() -> None:
    """The authority_matrix module docstring must not present §14.5 as a
    normative spec clause (no §14 exists)."""
    doc = authority_matrix.__doc__ or ""
    assert not _FABRICATED_CITATION.search(doc), f"authority_matrix docstring cites a non-existent section:\n{doc}"


def test_cross_record_module_docstring_does_not_cite_nonexistent_section() -> None:
    """The cross_record module docstring must not cite §14.5 etc."""
    doc = cross_record.__doc__ or ""
    assert not _FABRICATED_CITATION.search(doc), f"cross_record docstring cites a non-existent section:\n{doc}"


def test_v1_1_rules_module_docstring_does_not_cite_nonexistent_section() -> None:
    """The v1_1_rules module docstring must not cite §6.6 mode tables as a
    normative spec clause."""
    doc = v1_1_rules.__doc__ or ""
    assert not _FABRICATED_CITATION.search(doc), f"v1_1_rules docstring cites a non-existent section:\n{doc}"


# ---------------------------------------------------------------------------
# AUTH-002 (roborev follow-up): the ACEF-020 cross-tenant-reference diagnostic
# must cite a source consistent with the code it EMITS.
#
# ``enforce_cross_tenant_refs`` emits ``ACEF-020`` (the dangling/cross-tenant
# entity-REFERENCE code) but the message body cited "the ACEF-075 tenant-
# uniformity model". ACEF-075 is a DIFFERENT condition — tenant_label MISMATCH
# across records, not a cross-tenant entity reference — so the emitted code and
# the cited code disagree. The diagnostic must cite the governing source for
# ACEF-020 (the cross-tenant entity-reference rule), not the unrelated ACEF-075
# taxonomy row.
# ---------------------------------------------------------------------------


def _cross_tenant_diag() -> object:
    """Drive the single ACEF-020 cross-tenant-reference diagnostic."""
    refs_recs = [
        base_record(
            record_id="urn:acef:rec:o1",
            tenant_label="tenant-a",
            entity_refs={"dataset_refs": ["urn:acef:ds:shared"]},
        ),
        base_record(
            record_id="urn:acef:rec:o2",
            tenant_label="tenant-b",
            entity_refs={"dataset_refs": ["urn:acef:ds:shared"]},
        ),
    ]
    etmap = cross_record.build_entity_tenant_map(refs_recs)
    diags = cross_record.enforce_cross_tenant_refs(refs_recs, etmap)
    assert diags, "expected at least one cross-tenant ACEF-020 diagnostic"
    return diags[0]


def test_cross_tenant_reference_emits_acef_020() -> None:
    """Pin the emitted code: the cross-tenant entity-reference rule emits
    ACEF-020 (not ACEF-075)."""
    diag = _cross_tenant_diag()
    assert diag.code == "ACEF-020"


def test_cross_tenant_reference_citation_matches_emitted_code() -> None:
    """The ACEF-020 diagnostic must NOT cite the unrelated ACEF-075 taxonomy
    row. ACEF-075 = tenant_label MISMATCH across records; the cross-tenant
    entity-reference condition is governed by ACEF-020 (REFERENCE integrity).
    The user-facing message must cite a source consistent with ACEF-020.
    """
    diag = _cross_tenant_diag()
    msg = diag.message
    assert "ACEF-075" not in msg, (
        f"ACEF-020 cross-tenant-reference diagnostic must NOT cite the unrelated ACEF-075 row; got: {msg!r}"
    )
    # It should reference the actual governing rule for ACEF-020 (the
    # cross-tenant entity-reference rule / reference-integrity model).
    assert "ACEF-020" in msg, f"ACEF-020 diagnostic should cite its own code as the governing rule; got: {msg!r}"


# ---------------------------------------------------------------------------
# AUTH-003: namespace lints contribute ONLY to structural_errors
# ---------------------------------------------------------------------------

FREDDY_NS = "x-freddy/voice-rubric-emission"


def _voice_rubric_payload() -> dict:
    return {
        "emission_id": "urn:freddy:emi:00000000-0000-0000-0000-000000000001",
        "rubric_id": "urn:freddy:rub:00000000-0000-0000-0000-000000000001",
        "rubric_version": "1.0.0",
        "redaction_attestation_ref": "urn:acef:rec:99000000-0000-0000-0000-000000000099",
        "styled_prose_digest": "sha256:" + "0" * 63 + "1",
        "claim_lexicon_scan_result": {
            "tokens_found": ["compliant"],
            "scan_timestamp": "2026-01-01T00:00:00Z",
            "scanner_version": "1.0.0",
        },
        "rejection_state": "accepted",
    }


# A v1.1 subject + EU AI Act profile bundle that produces NON-EMPTY rule
# results and provision summaries, so the namespace-lint boundary can be
# proven against REAL conformance OUTCOMES (not vacuously over empty lists).
#
# The bundle is built through the PRODUCTION Package exporter (Package →
# add_subject → add_profile → record → export) so the manifest, profile
# declaration (template_version + applicable_provisions), and per-record_type
# record_files are schema-correct exactly as a real producer would emit them.
# A hand-built manifest previously injected UNRELATED ACEF-002/004/025
# structural diagnostics (non-schema ``provisions`` profile key; a
# mixed-record_type JSONL file mislabeled all ``risk_register``), which meant
# the namespace-lint boundary was NOT proven cleanly. Building via the
# exporter yields a schema-clean bundle whose ONLY structural delta between
# the with-/without-x-freddy runs is the ACEF-077 namespace lint
# (roborev cross-record-authority Low).
#
# Determinism: a fixed clock + a per-URN-type counting urn_generator are
# injected so BOTH runs mint identical subject/record/package URNs. This is
# load-bearing — the §3.7 result projection includes ``subject_scope``, so
# without a stable subject URN the two runs would carry different (random)
# subject ids and the "outcomes identical" comparison would be a false
# negative. The injection follows the VAL-SDK-007 determinism contract.
#
# Tolerated baseline: the exporter's package-creation audit-trail entry has
# no actor_ref, which serializes to an empty string and fails the actor-URN
# pattern → exactly one ACEF-002 at ``/audit_trail/0/actor_ref``. That single
# exporter-intrinsic diagnostic is identical across both runs and is NOT the
# x-freddy lint; the test tolerates it explicitly and asserts no OTHER
# structural codes (ACEF-004/014/025) appear.
_BOUNDARY_CLOCK_INSTANT = datetime(2026, 1, 1, tzinfo=UTC)


def _boundary_urn_generator() -> Callable[[URNType], str]:
    """A deterministic URN generator: a per-type 1-based counter so each
    URN type (pkg/sub/rec/…) gets stable, repeatable ids across runs."""
    counters: dict[URNType, int] = {}

    def _gen(urn_type: URNType) -> str:
        nxt = counters.get(urn_type, 0) + 1
        counters[urn_type] = nxt
        return f"urn:acef:{urn_type.value}:{nxt:08d}-0000-0000-0000-000000000000"

    return _gen


def _build_boundary_package(*, with_freddy: bool) -> Package:
    """Build a v1.1 boundary Package via the production exporter API.

    The two core records (risk_register + risk_treatment) satisfy enough of
    EU AI Act article-9 to yield non-empty results[]/provision_summary[].
    When ``with_freddy`` is set, an ``x-freddy/voice-rubric-emission``
    extension record carrying a banned claim-lexicon token (and neither a
    proper rejection nor a paired harness attestation) is appended — the sole
    trigger for the ACEF-077 namespace lint.
    """
    pkg = Package(
        producer={"name": "crossrec-boundary-test", "version": "1.0.0"},
        clock=lambda: _BOUNDARY_CLOCK_INSTANT,
        urn_generator=_boundary_urn_generator(),
    )
    # core_version 1.1.0 routes validation through the v1.1 schema + rule
    # families — the gate that activates the namespace-lint phase. A v1.0
    # bundle would never run the lint (and ACEF-077 could not fire), so the
    # boundary must be proven on a v1.1 bundle.
    pkg.versioning.core_version = "1.1.0"
    system = pkg.add_subject(
        "ai_system",
        name="Boundary System",
        risk_classification="high-risk",
        modalities=["text"],
    )
    pkg.add_profile("eu-ai-act-2024", provisions=["article-9"])
    pkg.record(
        "risk_register",
        provisions=["article-9"],
        payload={
            "risk_id": "R-1",
            "description": "Risk A",
            "category": "safety",
            "likelihood": "likely",
            "severity": "major",
            "risk_level": "high",
        },
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    pkg.record(
        "risk_treatment",
        provisions=["article-9"],
        payload={
            "risk_id": "R-1",
            "treatment_type": "mitigate",
            "control_description": "Treatment A",
            "implementation_status": "implemented",
        },
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    if with_freddy:
        pkg.record(FREDDY_NS, payload=_voice_rubric_payload())
    return pkg


def _run_boundary_bundle(bundle_dir: Path, *, with_freddy: bool) -> object:
    """Export + validate a boundary bundle, optionally including the x-freddy
    namespace-lint-triggering record. Validates WITH the eu-ai-act-2024
    profile so results[]/provision_summary[] are non-empty."""
    _build_boundary_package(with_freddy=with_freddy).export(str(bundle_dir))
    return validate_bundle(
        bundle_dir,
        profiles=["eu-ai-act-2024"],
        evaluation_instant="2027-01-01T00:00:00Z",
    )


def test_namespace_lint_does_not_alter_conformance_outcomes(tmp_path: Path) -> None:
    """The x-freddy namespace lint contributes ONLY to structural_errors and
    NEVER to results[]/provision_summary[] — proven on a REAL profile that
    yields non-empty conformance outcomes (the §3.7 line-1386 boundary).

    Earlier this test validated WITHOUT profiles, so results/provision_summary
    were empty and the boundary assertions were vacuous. Now it validates a
    bundle WITH the eu-ai-act-2024 profile and compares the outcome lists with
    and without the x-freddy record:

      (a) the outcome lists are POPULATED (non-vacuous);
      (b) results[] and provision_summary[] are IDENTICAL with/without the
          x-freddy record (the lint touches structural_errors only);
      (c) the x-freddy record DOES add its ACEF-077 to structural_errors
          (and that addition does NOT exist in the no-freddy run).
    """
    no_freddy = _run_boundary_bundle(tmp_path / "no-freddy", with_freddy=False)
    with_freddy = _run_boundary_bundle(tmp_path / "with-freddy", with_freddy=True)

    # (a) Non-vacuous: the EU AI Act profile actually produced outcomes.
    assert no_freddy.results, "expected non-empty results[] — boundary must be proven on real outcomes"
    assert no_freddy.provision_summary, "expected non-empty provision_summary[] — non-vacuous boundary"
    assert with_freddy.results, "with-freddy run must also produce non-empty results[]"
    assert with_freddy.provision_summary, "with-freddy run must also produce non-empty provision_summary[]"

    # (b) The conformance OUTCOMES are identical with and without the lint
    #     trigger. Compare the §3.7-scoped projections directly (rule_id,
    #     provision_id, subject scope, outcome) — order-independent.
    def _result_key(r: object) -> tuple:
        return (r.rule_id, r.provision_id, tuple(sorted(r.subject_scope or [])), r.outcome)

    def _summary_key(s: object) -> tuple:
        return (s.provision_id, tuple(sorted(s.subject_scope or [])), s.provision_outcome)

    assert sorted(_result_key(r) for r in no_freddy.results) == sorted(_result_key(r) for r in with_freddy.results), (
        "results[] outcomes MUST be identical with and without the x-freddy record"
    )
    assert sorted(_summary_key(s) for s in no_freddy.provision_summary) == sorted(
        _summary_key(s) for s in with_freddy.provision_summary
    ), "provision_summary[] outcomes MUST be identical with and without the x-freddy record"

    # (c) The x-freddy record DOES add ACEF-077 to structural_errors, and that
    #     code is absent without the record — the lint's effect is confined to
    #     structural_errors.
    assert "ACEF-077" not in codes(no_freddy.structural_errors), "no-freddy run must not carry ACEF-077"
    assert "ACEF-077" in codes(with_freddy.structural_errors), "x-freddy record must add ACEF-077 to structural_errors"

    # (c-clean) The fixture is a SCHEMA-CLEAN bundle: its only tolerated
    #     structural baseline is the single exporter-intrinsic ACEF-002 on
    #     the package-creation audit-trail entry's empty actor_ref. NO
    #     unrelated structural diagnostics (ACEF-004 payload-schema /
    #     ACEF-025 record_files type-mismatch / ACEF-014 integrity) may be
    #     present — otherwise the boundary is not cleanly proven (the lint
    #     would no longer be the SOLE structural effect of the x-freddy
    #     record). roborev cross-record-authority Low.
    for _code in ("ACEF-004", "ACEF-014", "ACEF-025"):
        assert _code not in codes(no_freddy.structural_errors), (
            f"clean fixture must not carry spurious {_code}: {no_freddy.structural_errors!r}"
        )
    # The ONLY structural delta WITH the x-freddy record is ACEF-077.
    assert sorted(codes(with_freddy.structural_errors)) == sorted([*codes(no_freddy.structural_errors), "ACEF-077"]), (
        "the SOLE structural delta of the x-freddy record must be ACEF-077 — "
        f"no-freddy={no_freddy.structural_errors!r} with-freddy={with_freddy.structural_errors!r}"
    )

    # ACEF-077 must not leak into any serialized rule result or provision
    # summary in the with-freddy run.
    result_blobs = [str(r.to_dict() if hasattr(r, "to_dict") else r) for r in with_freddy.results]
    assert not any("ACEF-077" in b for b in result_blobs), f"ACEF-077 must NOT appear in results[]: {result_blobs!r}"
    summary_blobs = [str(s.to_dict() if hasattr(s, "to_dict") else s) for s in with_freddy.provision_summary]
    assert not any("ACEF-077" in b for b in summary_blobs), (
        f"ACEF-077 must NOT appear in provision_summary[]: {summary_blobs!r}"
    )


def test_namespace_lint_emitted_codes_are_documented() -> None:
    """The registered freddy pattern declares its emitted codes, and they
    are Core structural codes (ACEF-077) — the introspection contract that
    keeps the structural-errors boundary auditable.
    """
    pattern = bundled_freddy._FREDDY_VOICE_RUBRIC_PATTERN
    assert pattern.emitted_codes == ["ACEF-077"]


# ---------------------------------------------------------------------------
# AUTH-007: docstring matches actual behavior (no causation_chain trust)
# ---------------------------------------------------------------------------


def test_has_paired_harness_attestation_docstring_matches_behavior() -> None:
    """The docstring must NOT claim causation_chain pairing the code does
    not implement; it must state causation_chain is not trusted here.
    """
    doc = bundled_freddy._has_paired_harness_attestation.__doc__ or ""
    lowered = doc.lower()
    # Behavior: only payload.harness_attestation_ref satisfies the carve-out.
    assert "harness_attestation_ref" in doc
    # The stale claim that ANY causation_chain entry is accepted as a
    # "best-effort pairing" must be gone.
    assert "best-effort pairing" not in lowered, (
        "docstring still claims a best-effort causation_chain pairing the code does not implement"
    )
    # If causation_chain is mentioned at all, it must be to say it is NOT
    # trusted / checked separately — not that it satisfies the carve-out.
    if "causation_chain" in lowered:
        assert "not" in lowered, "causation_chain mention must clarify it is NOT trusted by this carve-out"


def test_has_paired_harness_attestation_only_honors_payload_ref() -> None:
    """Behavioral pin: a causation_chain alone does NOT satisfy the
    carve-out; only payload.harness_attestation_ref does.
    """
    # causation_chain present but no harness_attestation_ref → not paired.
    assert bundled_freddy._has_paired_harness_attestation({"causation_chain": ["urn:acef:rec:something"]}) is False
    # harness_attestation_ref present → paired.
    assert bundled_freddy._has_paired_harness_attestation({"harness_attestation_ref": "urn:acef:rec:att"}) is True
