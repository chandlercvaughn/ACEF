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
