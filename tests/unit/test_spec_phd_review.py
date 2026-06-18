"""Spec-hardening regressions from the adversarial PhD-committee review.

Each test pins a standards-engineering gap the review found so the spec text
cannot silently regress below the bar that survives PhD/standards-body scrutiny.
The tests assert on the normative spec document (and, where a fix is code-level,
on the implementation) rather than on prose tone.

Review finding ids referenced inline (workflow wf_13a76292-96d):
  14 — no RFC 2119 / BCP 14 normative-keyword section
  17 — document version identity internally inconsistent
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SPEC = _REPO_ROOT / "planning" / "ACEF-Spec-Outline-v0.1.md"


def _spec_text() -> str:
    return _SPEC.read_text(encoding="utf-8")


class TestFinding14NormativeLanguage:
    """The document uses 60+ load-bearing MUST/SHOULD/MAY but never defines them.
    A standards editor requires the BCP 14 (RFC 2119 + RFC 8174) boilerplate."""

    def test_bcp14_boilerplate_present(self) -> None:
        text = _spec_text()
        assert "BCP 14" in text, "spec must reference BCP 14 to define normative keywords"
        assert "RFC 2119" in text, "spec must cite RFC 2119"
        assert "RFC 8174" in text, "spec must cite RFC 8174 (all-caps-only interpretation)"
        # The RFC 8174 'when, and only when, they appear in all capitals' clause.
        assert "all capitals" in text or "all-capitals" in text, "spec must include the RFC 8174 all-capitals qualifier"

    def test_normative_keywords_enumerated(self) -> None:
        text = _spec_text()
        # The boilerplate must enumerate the key words it is defining.
        for kw in ("MUST NOT", "SHOULD", "RECOMMENDED", "MAY", "OPTIONAL"):
            assert kw in text, f"normative keyword {kw!r} must be defined/enumerated"


class TestFinding8And38Collation:
    """'lexicographic' is used for record/path/key ordering but the collation unit
    (byte / code-point / UTF-16 code-unit) is never defined, so byte-determinism is
    not entailed by the text. The impl uses UTF-16 code-unit order (RFC 8785)."""

    def test_collation_unit_is_defined_as_utf16(self) -> None:
        text = _spec_text()
        assert "UTF-16 code unit" in text or "UTF-16 code-unit" in text, (
            "spec must define the lexicographic collation unit as UTF-16 code units"
        )
        # It must reference RFC 8785's object-member ordering so the choice is anchored.
        assert "RFC 8785" in text
        # It must explicitly warn that this diverges from Unicode code-point order.
        assert "code point" in text.lower() or "code-point" in text.lower(), (
            "spec must contrast UTF-16 collation with code-point order (the divergence the impl handles)"
        )

    def test_collation_mentions_supplementary_plane_divergence(self) -> None:
        text = _spec_text().lower()
        assert "supplementary" in text or "u+10000" in text or "surrogate" in text, (
            "spec must name the non-BMP/surrogate case where the two collations diverge"
        )


class TestFinding9ArchiveDeterminism:
    """DEFLATE byte-output is not portable (zlib-version dependent); the spec's
    'byte-identical archives MUST' had an escape hatch downgrading it. Bundle
    identity must be defined over the UNPACKED tree, not the gzip wrapper."""

    def test_archive_bytes_are_not_a_conformance_requirement(self) -> None:
        text = _spec_text()
        # The old escape-hatch contradiction must be gone.
        assert "If an implementation cannot produce identical gzip output" not in text, (
            "spec still carries the gzip escape-hatch that downgrades a MUST"
        )

    def test_deflate_body_declared_out_of_conformance_and_hash_domain(self) -> None:
        text = _spec_text().lower()
        assert "deflate" in text, "spec must address DEFLATE portability explicitly"
        # The reframing: identity/conformance is over the unpacked bundle digest.
        assert "transport" in text, "gzip archive must be framed as a transport container"


class TestFinding13IntegerDomain:
    """The I-JSON safe-integer domain (RFC 7493, |n| <= 2^53-1) is enforced only at
    hash time; it must be stated as a record-content authoring constraint."""

    def test_safe_integer_domain_is_a_record_constraint(self) -> None:
        text = _spec_text()
        assert "RFC 7493" in text, "spec must cite RFC 7493 (I-JSON) for the integer domain"
        assert "2^53" in text or "9007199254740991" in text, "spec must state the safe-integer boundary numerically"
        # roborev Low on 94b1b34: the rule must keep BOTH the authoring/export
        # rejection AND the ACEF-051 hash-time backstop (not regress to hash-only),
        # and must cover the whole hash domain (manifest + artifacts), not just records.
        idx = text.find("Integer domain (I-JSON)")
        assert idx != -1, "spec lost the I-JSON integer-domain rule"
        rule = text[idx : idx + 900]
        assert "ACEF-051" in rule, "integer-domain rule must keep the ACEF-051 hash-time backstop"
        assert "reject" in rule.lower(), "integer-domain rule must require producer rejection (authoring/export)"
        assert "acef-manifest.json" in rule and "artifact" in rule.lower(), (
            "integer-domain rule must cover the whole hash domain (manifest + artifacts), not only records"
        )


class TestFinding15ConformanceClasses:
    """The offline-deterministic / source-backed / online-conformance classes drive
    ACEF-083 and the incident validation modes but lived only in RFC-0002 (no
    normative force). They must have a normative home in the core spec, and the §0
    'conformance class (§6.6)' reference must resolve to that section."""

    def test_classes_defined_in_core_spec(self) -> None:
        text = _spec_text()
        for cls in ("offline-deterministic", "source-backed", "online-conformance"):
            assert cls in text, f"core spec must normatively define the {cls!r} conformance class"

    def test_section_66_is_conformance_classes(self) -> None:
        text = _spec_text()
        assert "### 6.6 Conformance Classes" in text, "spec must add §6.6 Conformance Classes (the §0 reference target)"
        # The previously-numbered §6.6 (Golden Bundles) must be renumbered, not lost.
        assert "Golden Bundle Specifications" in text, "Golden Bundle Specifications section must still exist"
        # No duplicate §6.6 heading.
        assert text.count("### 6.6 ") == 1, "exactly one §6.6 heading must exist"

    def test_offline_class_is_the_baseline_and_online_is_optional(self) -> None:
        text = _spec_text()
        idx = text.find("### 6.6 Conformance Classes")
        assert idx != -1
        sec = text[idx : idx + 3200]
        assert "MUST" in sec, "the baseline (offline-deterministic) class must be a MUST for conformance"
        assert "OPTIONAL" in sec, "the online-conformance class must be marked OPTIONAL"

    def test_offline_class_inputs_pin_evaluation_instant_and_trust_anchors(self) -> None:
        """roborev on 1fd3128: the offline class cannot be 'bundle bytes alone' —
        §3.7 depends on evaluation_instant, and §3.1.3 requires x5c chain validation
        against trust anchors. Both must be declared explicit inputs of the class."""
        text = _spec_text()
        idx = text.find("offline-deterministic (baseline, MUST)")
        assert idx != -1, "spec lost the offline-deterministic baseline paragraph"
        para = text[idx : idx + 1600]
        assert "evaluation_instant" in para, "offline class must pin evaluation_instant as an input"
        assert "trust anchor" in para.lower(), "offline class must include x5c trust-anchor validation (§3.1.3)"
        assert "x5c" in para, "offline class must address x5c chain validation, not only JWS self-consistency"


class TestFindings16And19And37ErrorTaxonomy:
    """The error taxonomy was split-brained: ACEF-046 in §3.6 but out of the frozen
    registry, 081-088 only in code, Appendix B saying '001 through 060', the 024
    gap unexplained, and 053/077/079 overlapping. §3.6 must reconcile all of it."""

    def test_incident_codes_081_to_088_have_normative_rows(self) -> None:
        text = _spec_text()
        for n in range(81, 89):
            assert f"`ACEF-{n:03d}`" in text, f"§3.6 must list ACEF-{n:03d} (was code-only)"

    def test_registry_governance_note_present(self) -> None:
        text = _spec_text()
        idx = text.find("Error-registry governance")
        assert idx != -1, "§3.6 must add the registry-governance note (frozen / additive / extended layers)"
        note = text[idx : idx + 1600]
        assert "resolve_error_meta" in note, "governance note must cite the single source of truth"
        assert "ACEF-024" in note and "reserved" in note.lower(), (
            "governance note must explain the ACEF-024 reserved gap"
        )
        for code in ("ACEF-053", "ACEF-077", "ACEF-079"):
            assert code in note, f"governance note must state the {code} overlap partition"

    def test_appendix_b_no_longer_claims_001_to_060_as_the_whole_taxonomy(self) -> None:
        text = _spec_text()
        # The Appendix B error-taxonomy row must not present 001-060 as the full range.
        assert "(ACEF-001 through ACEF-060) with severity" not in text, (
            "Appendix B still presents ACEF-001..060 as the complete taxonomy"
        )

    def test_acef_046_attached_to_unknown_operator(self) -> None:
        # The code side of finding 37 (also pinned in test_rule_engine): an unknown
        # rule operator yields a machine-detectable ACEF-046.
        from acef.models.enums import RuleOutcome
        from acef.templates.models import EvaluationRule, Provision
        from acef.validation.rule_engine import evaluate_rules_for_subject

        prov = Provision(
            provision_id="p",
            provision_name="p",
            normative_text_ref="x",
            description="d",
            required_evidence_types=[],
            evaluation=[EvaluationRule(rule_id="r", rule="frobnicate", params={}, severity="fail", message="m")],
        )
        results = evaluate_rules_for_subject([prov], [], profile_id="prof")
        assert results[0].outcome == RuleOutcome.ERROR
        assert results[0].error_code == "ACEF-046"


class TestFindings26And30RelatedWork:
    """The nearest prior art (in-toto/SLSA/Sigstore/W3C VC/NIST OSCAL/OPA-Rego/XBRL)
    appeared ZERO times, so the novelty delta was unstated — a desk-reject trigger.
    §8 must name them and articulate ACEF's delta."""

    def test_adjacent_prior_art_is_named(self) -> None:
        text = _spec_text()
        for system in ("in-toto", "SLSA", "OSCAL", "Verifiable Credential", "Sigstore"):
            assert system in text, f"Related Work must name the adjacent prior-art system {system!r}"
        # OSCAL is the closest analog and must be discussed, not just listed.
        assert text.count("OSCAL") >= 1

    def test_related_work_articulates_a_delta(self) -> None:
        text = _spec_text()
        idx = text.find("Related Work")
        assert idx != -1, "spec must add a Related Work section/subsection"
        sec = text[idx : idx + 4000]
        # The section must state what is NEW vs the prior art (the contribution), not
        # merely list analogies.
        assert "delta" in sec.lower() or "novel" in sec.lower() or "differ" in sec.lower(), (
            "Related Work must articulate ACEF's delta vs the prior art, not just list it"
        )
        # And must honestly scope the research-contribution claim (evaluation-gated).
        assert "evaluat" in sec.lower(), "Related Work must honestly gate the research claim on evaluation"


class TestFindings1And4And5SecurityConsiderations:
    """The spec had no threat model / Security Considerations section (finding 1,
    critical). Appendix D must state an adversary model, the guarantees, the
    explicit non-goals (replay/freshness, x5c revocation, DNS-01 default, key-to-
    identity binding), and the Merkle second-preimage argument (finding 4/44)."""

    def _appendix_d(self) -> str:
        text = _spec_text()
        idx = text.find("## Appendix D")
        assert idx != -1, "spec must add Appendix D: Security Considerations"
        return text[idx:]

    def test_appendix_d_has_adversary_model_and_guarantees_and_nongoals(self) -> None:
        d = self._appendix_d().lower()
        assert "adversary model" in d or "threat model" in d, "Appendix D must state an adversary/threat model"
        assert "guarantee" in d, "Appendix D must state the guarantees"
        assert "non-goal" in d or "out of scope" in d or "out-of-scope" in d, "Appendix D must state explicit non-goals"

    def test_appendix_d_covers_the_named_security_findings(self) -> None:
        d = self._appendix_d().lower()
        # finding 5 (replay/freshness, no trusted timestamp) + finding 7 (revocation).
        assert "replay" in d or "freshness" in d, (
            "Appendix D must address replay/freshness (signing time self-asserted)"
        )
        assert "revocation" in d or "crl" in d or "ocsp" in d, (
            "Appendix D must address x5c revocation being out of scope"
        )
        # finding 2 (key-to-identity binding) framed as a security property.
        assert "producer" in d and ("self-attested" in d or "binding" in d), (
            "Appendix D must address signing-identity-to-producer binding"
        )

    def test_appendix_d_merkle_second_preimage_argument(self) -> None:
        d = self._appendix_d()
        dl = d.lower()
        assert "second-preimage" in dl or "second preimage" in dl, (
            "Appendix D must give the Merkle second-preimage argument"
        )
        # The argument hinges on leaf domain-separation (0x00) and that a path cannot
        # contain arbitrary digest bytes, so leaf/inner-node preimages cannot collide.
        assert "0x00" in d, "the Merkle argument must reference the 0x00 leaf domain-separator"
        assert "path" in dl, "the Merkle argument must rest on path-byte constraints"


class TestFindings25And27And28EvaluationMethodology:
    """There is no empirical evaluation (coverage study, inter-annotator agreement,
    measured cross-regulation reuse, soundness-vs-obligation-semantics). Appendix E
    must specify the methodology and HONESTLY mark it not-yet-performed — without
    fabricating any result."""

    def _appendix_e(self) -> str:
        text = _spec_text()
        idx = text.find("## Appendix E")
        assert idx != -1, "spec must add Appendix E: Evaluation Methodology"
        return text[idx:]

    def test_appendix_e_specifies_the_measures(self) -> None:
        e = self._appendix_e().lower()
        assert "coverage" in e, "Appendix E must specify a coverage study vs a human-audit baseline"
        assert "inter-annotator" in e or "inter-rater" in e, "Appendix E must specify inter-annotator agreement"
        assert "reuse" in e, "Appendix E must specify measured cross-regulation evidence reuse"

    def test_appendix_e_marks_evaluation_not_yet_performed(self) -> None:
        e = self._appendix_e().lower()
        assert "not yet" in e or "not-yet" in e or "not been performed" in e or "future work" in e, (
            "Appendix E must explicitly mark the evaluation as not yet performed (honesty)"
        )

    def test_appendix_e_distinguishes_engineering_from_research(self) -> None:
        e = self._appendix_e().lower()
        # The conformance suite / determinism proof is engineering verification, not
        # an evaluation of the contribution (self-referential) — this must be stated.
        assert "self-referential" in e or "regression suite" in e or "not an evaluation" in e, (
            "Appendix E must explain why self-conformance is not an evaluation of the contribution"
        )

    def test_no_fabricated_f1_or_accuracy_numbers_in_appendix_e(self) -> None:
        # Guard against fabricated metrics: Appendix E must not assert a measured
        # score for ACEF (e.g. 'f1 = 0.9x', 'NN% coverage') as if performed.
        e = self._appendix_e()
        assert not re.search(r"\bf1[ _-]?(score)?\s*[:=]\s*0\.\d", e.lower()), (
            "Appendix E must not fabricate an F1 score"
        )


class TestForwardCompatibleMinorSelection:
    """roborev on 4d1f0dd: the header must not declare higher 1.y minors invalid
    while the validator routes them to v1.1 — the spec must document the
    forward-compatible fallback and match the implementation."""

    def test_spec_documents_forward_compatible_fallback(self) -> None:
        text = _spec_text()
        assert "Forward-compatible minor selection" in text, "§6.2 must define the forward-compatible minor fallback"
        idx = text.find("Forward-compatible minor selection")
        para = text[idx : idx + 900]
        assert "ACEF-001" in para, "non-1 major must be rejected with ACEF-001"
        assert "additiv" in para.lower(), "the fallback's soundness rests on minor additivity (§3.1.4)"

    def test_implementation_matches_the_documented_fallback(self) -> None:
        from acef.schemas.registry import schema_version_for_core_version

        # 1.0.x -> v1, 1.1.x -> v1.1, higher 1.y -> v1.1 (forward-compat fallback).
        assert schema_version_for_core_version("1.0.0") == "v1"
        assert schema_version_for_core_version("1.1.0") == "v1.1"
        assert schema_version_for_core_version("1.2.0") == "v1.1", (
            "higher 1.y must fall back to the highest known minor"
        )
        # Non-1 major is rejected (ACEF-001), per the documented contract.
        from acef.errors import ACEFSchemaError

        with pytest.raises(ACEFSchemaError):
            schema_version_for_core_version("2.0.0")


class TestVersionModelAlignment:
    """roborev Medium on 9fc5db0: the header core_version model must match §6.2
    (semver 1.0.x/1.1.x ranges), not assert a conflicting exact-values-only set."""

    def test_header_and_section_62_use_the_same_version_ranges(self) -> None:
        text = _spec_text()
        head = "\n".join(text.splitlines()[:20])
        assert "1.0.x" in head and "1.1.x" in head, "header must use the §6.2 semver 1.0.x/1.1.x ranges"
        # §6.2 must still declare those same ranges (single version model).
        idx = text.find("### 6.2 Versioning Strategy")
        assert idx != -1, "spec lost §6.2"
        sec = text[idx : idx + 1500]
        assert "1.0.x" in sec and "1.1.x" in sec, "§6.2 must declare the 1.0.x/1.1.x ranges the header references"


class TestFinding18RollupPrecedence:
    """§3.7 stepwise algorithm and the §6.5 precedence string were reconciled only
    by a 'listed last for numbering continuity, applied first' apology. The order
    must equal the precedence by construction (no-rules guard is step 1)."""

    def test_no_numbering_apology_remains(self) -> None:
        text = _spec_text()
        for apology in ("numbering continuity", "listed last", "applied first"):
            assert apology not in text, f"roll-up precedence still carries the apology phrase {apology!r}"

    def test_algorithm_first_step_is_the_no_rules_guard(self) -> None:
        text = _spec_text()
        idx = text.find("precedence algorithm")
        assert idx != -1, "spec lost the precedence-algorithm anchor"
        window = text[idx : idx + 1600]
        # The first numbered step must be the no-rules → not-assessed guard.
        m = re.search(r"\n\s*1\.\s+(.{0,160})", window)
        assert m, "precedence algorithm lost its numbered step 1"
        step1 = m.group(1).lower()
        assert "no" in step1 and "rule" in step1 and "not-assessed" in step1, (
            f"step 1 must be the no-rules → not-assessed guard, got: {m.group(1)!r}"
        )

    def test_step6_matches_appendix_c_p6_no_all_fail_passed_conjunct(self) -> None:
        """roborev on f4d58a3: §3.7 step 6 must match the corrected Appendix C P6
        (skipped fail-severity rule is non-blocking). It must NOT require 'ALL
        fail-severity rules passed' as the partial-satisfaction condition."""
        text = _spec_text()
        idx = text.find("precedence algorithm")
        window = text[idx : idx + 1700]
        m = re.search(r"\n\s*6\.\s+(.{0,200})", window)
        assert m, "precedence algorithm lost step 6"
        step6 = m.group(1)
        assert (
            "ALL** fail-severity rules passed but" not in step6 and "ALL fail-severity rules passed but" not in step6
        ), f"step 6 still carries the contradictory 'ALL fail passed but' conjunct: {step6!r}"
        assert "warning" in step6.lower() and "failed" in step6.lower(), (
            "step 6 must key on a failed warning-severity rule"
        )

    def test_conformance_row_order_matches_algorithm(self) -> None:
        rows = [ln for ln in _spec_text().splitlines() if "**Provision roll-up**" in ln]
        assert rows, "spec lost the Provision roll-up conformance row"
        row = rows[0]
        # The conformance row must point at the §3.7 algorithm (single source of
        # truth), not restate a divergent standalone '>' chain, and must keep the
        # F22 fix (no phantom 'error' provision_outcome).
        assert "> error >" not in row
        assert "not-assessed" in row
        assert "3.7" in row or "§3.7" in row, "conformance row must reference the §3.7 algorithm as the source of truth"


class TestFinding10FormalProof:
    """The roll-up's totality/determinism/confluence were argued only in prose
    comments. Appendix C must give a semi-formal proof, and the empty-set DSL
    semantics must be pinned (existential FALSE / universal TRUE on the empty set)."""

    def test_appendix_c_proof_exists(self) -> None:
        text = _spec_text()
        assert "## Appendix C" in text, "spec must add Appendix C (roll-up determinism proof)"
        c = text[text.find("## Appendix C") :].lower()
        for term in ("totality", "determinism", "order-independence", "empty-set"):
            assert term in c, f"Appendix C must prove/cover {term!r}"

    def test_empty_set_operator_semantics_pinned(self) -> None:
        c = _spec_text()
        c = c[c.find("## Appendix C") :].lower()
        assert "existential" in c and "universal" in c, "Appendix C must classify operators existential vs universal"
        assert "vacuous" in c, "Appendix C must state vacuous truth for universal operators on the empty set"
        # roborev on 21e3349: entity_linked is UNIVERSAL (vacuous-pass), matching
        # §3.5 + op_entity_linked — it must appear in the universal line, not existential.
        universal_line = next((ln for ln in c.split("\n") if "universal" in ln and "—" in ln), "")
        existential_line = next((ln for ln in c.split("\n") if "existential" in ln and "—" in ln), "")
        assert "entity_linked" in universal_line, "Appendix C must list entity_linked as universal"
        assert "entity_linked" not in existential_line, "Appendix C must NOT list entity_linked as existential"


class TestFinding17VersionIdentity:
    """Filename v0.1, H1 'v0.3', body v1.1/v0.4 — a versioned standard cannot have
    three different answers to 'what version is this'."""

    def test_h1_title_has_no_conflicting_inline_version(self) -> None:
        first_line = _spec_text().splitlines()[0]
        # The H1 must not assert a bare doc version (e.g. 'v0.3') that conflicts
        # with the explicit version block; version lives in the status block below.
        assert not re.search(r"\bv0\.3\b", first_line), (
            f"H1 still carries the conflicting inline 'v0.3': {first_line!r}"
        )

    def test_explicit_document_revision_and_format_version_block(self) -> None:
        text = _spec_text()
        head = "\n".join(text.splitlines()[:20])
        # A single coherent statement: the DOCUMENT revision and the FORMAT version
        # it covers are stated separately and unambiguously.
        assert "Document revision" in head, "header must state an explicit Document revision"
        assert "Format version" in head, "header must state the ACEF Core format version covered"
        assert "core_version" in head, "header must pin the valid manifest.versioning.core_version values"
        assert "1.0.0" in head and "1.1.0" in head, "header must enumerate core_version 1.0.0 and 1.1.0"
