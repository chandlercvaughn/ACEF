"""Repo-wide retention-provenance guards for GitHub issue #1.

The proximate defect was `"retention_years": 10` on `eu-ai-act-2024` `article-12`,
where Art. 12 of Regulation (EU) 2024/1689 states no retention period at all.

The SYSTEMIC defect is why it survived. The repo had already diagnosed this exact
class once — PhD-review finding 22, commit 2b82e0d, which corrected
`eu-ai-act-art73-2026.json` and wrote a guard for it. That guard hardcodes
`load_template("eu-ai-act-art73-2026")` as a string literal
(`tests/unit/test_validation_incident_rules.py:2742`), so it could not see the
identical defect sitting in `eu-ai-act-2024.json`. A guard scoped to one template
is how a fix fails to propagate.

Every guard here is therefore parametrized over ALL templates.

Structure follows `tests/unit/test_widespread_art73_framing.py`, the repo's prior
remediation of a legal mischaracterization: pin the claim to its article point
number, then assert the wrong framing cannot recur — allowing the legitimate
NEGATED phrasing, because corrected prose must still be able to discuss Art. 12
and retention in the same sentence.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from acef.templates.models import Template
from acef.templates.registry import list_templates, load_template

_ROOT = Path(__file__).resolve().parents[2]
_TEMPLATE_DIR = _ROOT / "src" / "acef" / "templates"

# EXPLICIT, mirroring tests/unit/test_templates.py:68. Deriving this from
# list_templates() would be circular: a registry regression that dropped a
# template would also drop it from the parametrization and pass silently.
# test_template_id_list_is_current below catches drift between the two.
ALL_TEMPLATE_IDS = [
    "china-cac-labeling-2025",
    "eu-ai-act-2024",
    "eu-ai-act-art73-2026",
    "eu-gpai-code-of-practice-2025",
    "eu-labelling-code-of-practice-2026",
    "iso-iec-23894-2023",
    "iso-iec-42001-2023",
    "nist-ai-600-1-gai-profile",
    "nist-ai-rmf-1.0",
    "oecd-ai-incidents-2025",
    "uk-ai-copyright-guidance-2026",
    "us-copyright-office-part3-2025",
    "us-omb-m-24-10",
]


def _load(template_id: str) -> Template:
    return load_template(template_id)


def test_template_id_list_is_current() -> None:
    """The explicit list must track the registry, or every guard below is partial."""
    assert sorted(list_templates()) == sorted(ALL_TEMPLATE_IDS)


@pytest.mark.parametrize("template_id", ALL_TEMPLATE_IDS)
def test_every_provision_declares_a_retention_determination(template_id: str) -> None:
    """No provision may be silent about retention.

    A missing block is indistinguishable from "nobody looked". `not_assessed` is
    the honest way to say the latter, and it is explicitly allowed — what is
    forbidden is saying nothing at all.
    """
    template = _load(template_id)
    missing = [p.provision_id for p in template.provisions if p.retention is None]
    assert not missing, (
        f"{template_id}: {len(missing)} provision(s) declare no retention "
        f"determination: {missing}. Use kind='not_assessed' if the instrument has "
        "not been assessed for retention duties — silence is not a determination."
    )


@pytest.mark.parametrize("template_id", ALL_TEMPLATE_IDS)
def test_no_retention_figure_lacks_provenance(template_id: str) -> None:
    """The issue #1 invariant, repo-wide: no bare number.

    The model enforces this at construction; this asserts it over the SHIPPED
    content, so a template committed with a bare figure fails here even if some
    future loader relaxes.
    """
    raw = json.loads((_TEMPLATE_DIR / f"{template_id}.json").read_text(encoding="utf-8"))
    offenders = [
        p.get("provision_id")
        for p in raw.get("provisions", [])
        if p.get("retention_years") is not None and not (p.get("retention") or {}).get("basis", "").strip()
    ]
    assert not offenders, (
        f"{template_id}: provisions {offenders} set retention_years with no "
        "retention.basis. This is the exact shape of issue #1."
    )


@pytest.mark.parametrize("template_id", ALL_TEMPLATE_IDS)
def test_inferred_retention_says_it_is_inferred(template_id: str) -> None:
    """An inference chain must be visible as one.

    `article-9`'s ten years is defensible — but only transitively, via Annex IV
    point 5 -> Art. 11 -> Art. 18(1)(a). A reader must be able to tell that from
    `article-11`, where Art. 18(1)(a) names the document class directly.
    """
    template = _load(template_id)
    offenders = [
        p.provision_id
        for p in template.provisions
        if p.retention is not None and p.retention.source == "inferred" and "INFERRED" not in p.retention.basis
    ]
    assert not offenders, (
        f"{template_id}: provisions {offenders} declare source='inferred' without the "
        "literal token INFERRED in the basis (the eu-ai-act-art73-2026.json "
        "convention from PhD-review finding 22)."
    )


@pytest.mark.parametrize("template_id", ALL_TEMPLATE_IDS)
def test_cited_retention_names_its_source(template_id: str) -> None:
    """`cited` with an empty normative_text_ref is the defect wearing a badge."""
    template = _load(template_id)
    offenders = [
        p.provision_id
        for p in template.provisions
        if p.retention is not None and p.retention.source == "cited" and not p.retention.normative_text_ref.strip()
    ]
    assert not offenders, f"{template_id}: provisions {offenders} declare source='cited' with no normative_text_ref."


# ── The misattribution guard ──
#
# Modelled on tests/unit/test_widespread_art73_framing.py: make the wrong framing
# unable to recur, while leaving the CORRECTED framing expressible.
#
# The instrument is `normative_text_ref`, not `basis`. `normative_text_ref` IS the
# attribution — the field that says which text a determination rests on — so
# naming Art. 12 there on a period-bearing determination is exactly the defect.
#
# A free-text scan of `basis` was tried first and rejected: it produced a false
# positive on article-19, whose basis correctly quotes Art. 19(1) — "shall keep
# the logs referred to in Article 12(1) ... of at least six months". Any accurate
# statement of the Art. 12 / Art. 19 split must reference Art. 12 alongside
# retention language, so a co-occurrence test cannot separate the correct framing
# from the wrong one. An allow-list of negated phrasings would have to enumerate
# every way of writing that sentence, and would silently rot.

_ART12_CITATION = re.compile(
    r"art(?:icle)?\.?\s*12\b(?!\s*\(1\)\s*logs)|(?<![\w-])article-12(?![\w-])",
    re.IGNORECASE,
)


@pytest.mark.parametrize("template_id", ALL_TEMPLATE_IDS)
def test_no_retention_period_is_sourced_to_article_12(template_id: str) -> None:
    """Art. 12 must never be the CITED SOURCE of a retention period.

    Art. 12 of Reg. (EU) 2024/1689 has exactly three paragraphs and contains no
    duration; "over the lifetime of the system" in Art. 12(1) qualifies the
    recording capability, not any keeping duty. Retention of those logs is
    governed by Art. 19(1) (provider) and Art. 26(6) (deployer), both "at least
    six months". Art. 18(1)'s ten years is a closed enumeration of five
    document classes that does not include logs.
    """
    template = _load(template_id)
    for prov in template.provisions:
        ret = prov.retention
        if ret is None:
            continue
        # Only a determination that actually asserts a PERIOD can misattribute one.
        # `none_stated` on article-12 legitimately cites Art. 12 — that is the
        # documented ABSENCE, and it is the correct outcome.
        if ret.kind not in ("fixed_period", "minimum_floor"):
            continue
        if _ART12_CITATION.search(ret.normative_text_ref):
            pytest.fail(
                f"{template_id}:{prov.provision_id} sources a {ret.kind} retention "
                f"period to Art. 12, which states none. Cite Art. 19(1) (provider) or "
                f"Art. 26(6) (deployer) for log retention, or Art. 18(1) for "
                f"documentation. Got normative_text_ref={ret.normative_text_ref!r}"
            )


def test_article_12_records_a_documented_absence_not_a_period() -> None:
    """The reported defect, pinned directly.

    `none_stated` + `cited` is the shape that lets an auditor distinguish "the
    instrument states no period" from "nobody looked" (`not_assessed`).
    """
    art12 = next(p for p in _load("eu-ai-act-2024").provisions if p.provision_id == "article-12")
    assert art12.retention is not None
    assert art12.retention.kind == "none_stated"
    assert art12.retention.period is None
    assert art12.retention.source == "cited"
    assert art12.retention_years is None, (
        "article-12 must not carry a retention_years figure — Art. 12 states no period"
    )


@pytest.mark.parametrize("template_id", ALL_TEMPLATE_IDS)
def test_every_exists_where_rule_declares_record_type(template_id: str) -> None:
    """`op_exists_where` indexes params["record_type"] directly.

    `src/acef/validation/operators.py:1402` reads it with `params["record_type"]`,
    so a rule omitting the key raises KeyError at VALIDATION time rather than
    emitting a diagnostic. All shipped exists_where rules carry it; this stops the
    new article-19 / article-26.6 rules from being written without it.
    """
    template = _load(template_id)
    offenders = [
        f"{p.provision_id}/{r.rule_id}"
        for p in template.provisions
        for r in p.evaluation
        if r.rule == "exists_where" and not str(r.params.get("record_type", "")).strip()
    ]
    assert not offenders, (
        f"{template_id}: exists_where rules {offenders} omit params['record_type']; "
        "operators.py:1402 indexes it directly, so this raises KeyError at validation "
        "time."
    )


# ── Evidence-side misattribution guard ──
#
# The template guard above tests `normative_text_ref` on PROVISIONS. Records
# carry their own retention provenance in `payload.retention_policy_summary`
# and on the envelope, and the same misattribution is expressible there —
# golden-bundles/eu-high-risk-core shipped {"legal_basis": "EU AI Act Art.
# 12(1)", "min_days": 3650} for exactly this reason (roborev on 0753d47).

_BUNDLE_ROOT = _ROOT / "tests" / "conformance" / "golden-bundles"


def _iter_record_retention() -> list[tuple[str, dict]]:
    """Every (source, retention_policy_summary) across the golden corpus."""
    found: list[tuple[str, dict]] = []
    for jsonl in sorted(_BUNDLE_ROOT.glob("*/records/*.jsonl")):
        for lineno, line in enumerate(jsonl.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            summary = (rec.get("payload") or {}).get("retention_policy_summary")
            if isinstance(summary, dict):
                rel = jsonl.relative_to(_ROOT)
                found.append((f"{rel}:{lineno}", summary))
    return found


def test_golden_corpus_has_retention_records_to_check() -> None:
    """Guard the guard: an empty sweep would pass vacuously forever."""
    assert _iter_record_retention(), "no retention_policy_summary found in any golden bundle"


def test_no_golden_record_attributes_retention_to_article_12() -> None:
    """Art. 12 states no retention period, so no record may cite it as one.

    Retention of Art. 12(1) logs is governed by Art. 19(1) for providers and
    Art. 26(6) for deployers, both "at least six months".
    """
    for source, summary in _iter_record_retention():
        basis = str(summary.get("legal_basis", ""))
        if _ART12_CITATION.search(basis):
            pytest.fail(
                f"{source} attributes a {summary.get('min_days')}-day retention to "
                f"Art. 12, which states none: legal_basis={basis!r}. Cite Art. 19(1) "
                f"(provider) or Art. 26(6) (deployer)."
            )
