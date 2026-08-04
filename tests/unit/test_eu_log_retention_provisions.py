"""article-19 / article-26.6 — the six-month log-retention floor, made expressible.

roborev finding on fd291ff (High): `article-12`'s retention basis asserted that
"the at-least-six-months floor in Art. 19(1) (provider) and Art. 26(6) (deployer)
... modelled as the separate article-19 and article-26.6 provisions of this
template and enforced there" — while neither provision existed. The basis was
making a claim the template did not honour, which is the same class of defect
issue #1 reported.

Art. 19(1) binds the PROVIDER; Art. 26(6) first subparagraph binds the DEPLOYER.
Both read "for a period appropriate to the intended purpose of the high-risk AI
system, of at least six months". They are a FLOOR, unbounded above — not a fixed
period — which is why `retention_years` (an int) cannot express them at all.

Commencement is the amended Art. 113 third paragraph point (c), as replaced by
Regulation (EU) 2026/1744 Art. 1 point (40)(b): Chapter III Sections 1-3 apply
from 2 December 2027 for Annex III high-risk systems and 2 August 2028 for
Annex I. Arts 19 and 26 are both Chapter III Section 3. ACEF cannot express that
discriminator — `effective_date` is a single string and the `risk_classification`
enum lives in the frozen v1 manifest schema with no Annex I/III value — so the
EARLIER limb is stored and both limbs are carried declaratively.
"""

from __future__ import annotations

import pytest

from acef.templates.models import Provision, Template
from acef.templates.registry import load_template

_EU = "eu-ai-act-2024"
# Amended Art. 113 third para (c)(i) — Annex III high-risk.
_ANNEX_III_DATE = "2027-12-02"
# Amended Art. 113 third para (c)(ii) — Annex I high-risk.
_ANNEX_I_DATE = "2028-08-02"
# Chapter III Sections 1-3 provisions in this template, all governed by that limb.
_CHAPTER_III = [
    "article-9",
    "article-10",
    "article-11",
    "article-12",
    "article-13",
    "article-14",
    "article-15",
    "article-17",
    "article-19",
    "article-26.6",
]


@pytest.fixture(scope="module")
def template() -> Template:
    return load_template(_EU)


def _prov(template: Template, provision_id: str) -> Provision:
    for prov in template.provisions:
        if prov.provision_id == provision_id:
            return prov
    pytest.fail(f"provision {provision_id!r} not found in {_EU}")


class TestProvisionsExist:
    @pytest.mark.parametrize("pid", ["article-19", "article-26.6"])
    def test_provision_is_modelled(self, template: Template, pid: str) -> None:
        """article-12's basis names these; they must exist or the basis lies."""
        prov = _prov(template, pid)
        assert prov.provision_name.strip()
        assert "high-risk" in prov.applicable_to

    def test_article_12_basis_is_now_truthful(self, template: Template) -> None:
        """The claim that these are 'modelled and enforced' must be honoured."""
        art12 = _prov(template, "article-12")
        assert art12.retention is not None
        basis = art12.retention.basis
        assert "article-19" in basis and "article-26.6" in basis
        ids = {p.provision_id for p in template.provisions}
        assert {"article-19", "article-26.6"} <= ids, "article-12's basis references provisions that do not exist"


class TestRetentionShape:
    def test_article_19_is_a_provider_six_month_floor(self, template: Template) -> None:
        ret = _prov(template, "article-19").retention
        assert ret is not None
        assert ret.kind == "minimum_floor", "a floor is unbounded above, not a fixed period"
        assert ret.duty_holder == "provider"
        assert ret.period is not None
        assert (ret.period.value, ret.period.unit) == (6, "months")
        assert ret.source == "cited"
        assert "19" in ret.normative_text_ref

    def test_article_26_6_is_a_deployer_six_month_floor(self, template: Template) -> None:
        ret = _prov(template, "article-26.6").retention
        assert ret is not None
        assert ret.kind == "minimum_floor"
        assert ret.duty_holder == "deployer", (
            "Art. 26(6) binds the deployer; conflating it with the Art. 19 provider "
            "duty is the split the issue reporter flagged as missing"
        )
        assert ret.period is not None
        assert (ret.period.value, ret.period.unit) == (6, "months")

    @pytest.mark.parametrize("pid", ["article-19", "article-26.6"])
    def test_floor_carries_no_retention_years_scalar(self, template: Template, pid: str) -> None:
        """A floor in months is not representable as integer years."""
        prov = _prov(template, pid)
        assert prov.retention_years is None
        assert prov.retention_years_basis is None


class TestCommencement:
    @pytest.mark.parametrize("pid", _CHAPTER_III)
    def test_chapter_iii_provisions_use_the_amended_date(self, template: Template, pid: str) -> None:
        """Reg. (EU) 2026/1744 moved these; 2026-08-02 is stale as of 27 July 2026.

        Shipping the new provisions at the amended date while leaving the eight
        existing ones at the superseded one would put two contradictory readings
        of a single Art. 113 point inside one template.
        """
        assert _prov(template, pid).effective_date == _ANNEX_III_DATE

    @pytest.mark.parametrize("pid", ["article-50.2", "article-53"])
    def test_non_chapter_iii_dates_are_untouched(self, template: Template, pid: str) -> None:
        """Art. 50 is Chapter IV and Art. 53 is Chapter V — neither was amended."""
        assert _prov(template, pid).effective_date != _ANNEX_III_DATE

    @pytest.mark.parametrize("pid", ["article-19", "article-26.6"])
    def test_both_commencement_limbs_are_recorded(self, template: Template, pid: str) -> None:
        """effective_date holds one date; the other limb must not be lost.

        Storing only the earliest date without recording that it is the earliest
        of two is what makes a conservative projection indistinguishable from a
        definitive legal assertion.
        """
        tiered = _prov(template, pid).tiered_requirements
        assert tiered is not None, f"{pid} records no adoption block"
        adoption = tiered.get("adoption")
        assert adoption is not None, f"{pid}.tiered_requirements has no 'adoption' key"
        assert adoption.get("annex_iii_high_risk") == _ANNEX_III_DATE
        assert adoption.get("annex_i_high_risk") == _ANNEX_I_DATE
        assert "2026/1744" in adoption.get("basis", ""), (
            "the amending regulation must be cited, or the dates are unsourced — "
            "the exact defect this branch exists to fix"
        )


class TestEnforcementRules:
    @pytest.mark.parametrize("pid", ["article-19", "article-26.6"])
    def test_every_exists_where_rule_declares_record_type(self, template: Template, pid: str) -> None:
        """`op_exists_where` indexes params["record_type"] directly.

        `src/acef/validation/operators.py` reads it with `params["record_type"]`,
        so omitting the key raises KeyError at validation time rather than
        emitting a diagnostic.
        """
        offenders = [
            r.rule_id
            for r in _prov(template, pid).evaluation
            if r.rule == "exists_where" and not str(r.params.get("record_type", "")).strip()
        ]
        assert not offenders, f"{pid}: exists_where rules missing record_type: {offenders}"

    @pytest.mark.parametrize(("pid", "role"), [("article-19", "provider"), ("article-26.6", "deployer")])
    def test_rules_are_scoped_to_the_right_duty_holder(self, template: Template, pid: str, role: str) -> None:
        """A provider-scoped rule must not fire on a deployer's records."""
        scoped = [r for r in _prov(template, pid).evaluation if r.scope is not None]
        assert scoped, f"{pid} has no obligation-role-scoped rules"
        for rule in scoped:
            assert rule.scope is not None
            assert rule.scope.obligation_roles == [role], (
                f"{pid}/{rule.rule_id} is scoped to {rule.scope.obligation_roles}, expected [{role!r}]"
            )

    @pytest.mark.parametrize("pid", ["article-19", "article-26.6"])
    def test_the_floor_is_enforced_at_fail_severity(self, template: Template, pid: str) -> None:
        """The six-month floor is a binding duty, not advice."""
        floors = [
            r
            for r in _prov(template, pid).evaluation
            if r.rule == "exists_where" and r.params.get("op") == "gte" and r.params.get("value") == 180
        ]
        assert floors, f"{pid} has no rule enforcing a 180-day floor"
        assert any(r.severity == "fail" for r in floors), (
            f"{pid}: the retention floor is only advisory; Art. 19(1)/26(6) are binding"
        )

    @pytest.mark.parametrize("pid", ["article-19", "article-26.6"])
    def test_both_retention_surfaces_are_read(self, template: Template, pid: str) -> None:
        """ACEF expresses record retention in two places, and bundles use both.

        The envelope pointer `/retention/min_retention_days` and the payload
        pointer `/payload/retention_policy_summary/min_days` denote different
        objects. The repo's own canonical logging_spec record in
        golden-bundles/eu-high-risk-core carries envelope `retention: null` and
        states retention ONLY in the payload, so a rule set reading just the
        envelope would not fire on ACEF's own reference bundle.
        """
        fields = {str(r.params.get("field", "")) for r in _prov(template, pid).evaluation}
        assert any("/retention/min_retention_days" == f for f in fields), (
            f"{pid} does not read the envelope retention surface"
        )
        assert any("retention_policy_summary" in f for f in fields), (
            f"{pid} does not read the payload retention surface"
        )
