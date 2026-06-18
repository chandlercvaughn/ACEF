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
