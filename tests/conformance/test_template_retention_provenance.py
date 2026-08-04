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
# Modelled on tests/unit/test_widespread_art73_framing.py. Art. 12 must never be
# named as the SOURCE of a retention period. The allow-list below exists because
# the CORRECTED prose legitimately mentions Art. 12 and retention together —
# "Art. 12 states no retention period; see Art. 19" must pass while
# "retention per Art. 12" must fail.

_ART12 = re.compile(r"art(?:icle)?\.?\s*12\b|article-12", re.IGNORECASE)
_RETENTION_PERIOD = re.compile(
    r"\b(?:retention|retain|keep|kept)\b|\bmin_days\b|\bmin_retention_days\b",
    re.IGNORECASE,
)
# Phrases that NEGATE a retention duty under Art. 12. Longest first so a longer
# phrase is consumed before a shorter substring of it.
_ALLOWED_NEGATIONS = (
    "states no retention period",
    "sets no retention period",
    "no retention period is stated",
    "imposes no retention period",
    "does not state a retention period",
    "no retention period",
)


@pytest.mark.parametrize("template_id", ALL_TEMPLATE_IDS)
def test_no_retention_period_is_attributed_to_article_12(template_id: str) -> None:
    """Art. 12 may be discussed, but never cited AS a retention period.

    Art. 12 of Reg. (EU) 2024/1689 has exactly three paragraphs and contains no
    duration. Retention of the logs it requires is governed by Art. 19(1)
    (provider) and Art. 26(6) (deployer), both "at least six months".
    """
    template = _load(template_id)
    for prov in template.provisions:
        if prov.retention is None:
            continue
        ret = prov.retention
        # Only a determination that actually asserts a PERIOD can misattribute one.
        if ret.kind not in ("fixed_period", "minimum_floor"):
            continue
        for label, text in (
            ("normative_text_ref", ret.normative_text_ref),
            ("basis", ret.basis),
        ):
            stripped = text.lower()
            for neg in _ALLOWED_NEGATIONS:
                stripped = stripped.replace(neg, "")
            if _ART12.search(stripped) and _RETENTION_PERIOD.search(stripped):
                pytest.fail(
                    f"{template_id}:{prov.provision_id} {label} attributes a retention "
                    f"period to Art. 12, which states none. Retention of Art. 12(1) "
                    f"logs is governed by Art. 19(1) / Art. 26(6). Got: {text[:160]!r}"
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
