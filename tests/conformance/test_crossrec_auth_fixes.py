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
from pathlib import Path

import acef.validation.authority_matrix as authority_matrix
import acef.validation.cross_record as cross_record
import acef.validation.namespace_lints.bundled_freddy as bundled_freddy
import acef.validation.v1_1_rules as v1_1_rules
from acef.validation.engine import validate_bundle
from acef.validation.v1_1_rules import (
    BANNED_CLAIM_LANGUAGE_TOKENS,
    lint_coverage_cell_claim_language,
)
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
    write_bundle,
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


def test_namespace_lint_diagnostic_only_in_structural_errors(tmp_path: Path) -> None:
    """A namespace-lint-triggering bundle places ACEF-077 in
    ``structural_errors`` ONLY — never in ``results[].outcome`` or
    ``provision_summary[].provision_outcome`` (the §3.7 line-1386 boundary).
    """
    bundle_dir = tmp_path / "freddy-boundary"
    write_bundle(
        bundle_dir,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:bd000000-0000-0000-0000-000000000001",
                record_type=FREDDY_NS,
                payload=_voice_rubric_payload(),
            ),
        ],
    )

    assessment = validate_bundle(bundle_dir)

    # The lint code lands in structural_errors.
    assert "ACEF-077" in codes(assessment.structural_errors)

    # It MUST NOT appear in any rule result outcome or provision summary
    # outcome — those are the §3.7-scoped values that must be identical with
    # or without x-* extensions.
    result_codes: list[str] = []
    for r in assessment.results:
        d = r.to_dict() if hasattr(r, "to_dict") else r
        # rule results carry a 'code' only via diagnostics; outcomes are an
        # enum string. Assert no ACEF-077 leaks into any serialized result.
        result_codes.append(str(d))
    assert not any("ACEF-077" in c for c in result_codes), f"ACEF-077 must NOT appear in results[]: {result_codes!r}"

    summary_blobs = [str(s.to_dict() if hasattr(s, "to_dict") else s) for s in assessment.provision_summary]
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
