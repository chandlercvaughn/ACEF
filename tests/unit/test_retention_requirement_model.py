"""GitHub issue #1: a retention figure must carry its provenance, structurally.

`src/acef/templates/eu-ai-act-2024.json` shipped `"retention_years": 10` on eight
provisions with no basis. For `article-12` that is a false statement of law:
Art. 12 of Regulation (EU) 2024/1689 has exactly three paragraphs and states no
retention period at all. Logs are governed by Art. 19(1) (provider, "at least six
months") and Art. 26(6) (deployer, same floor); the 10-year figure belongs to
Art. 18(1), which anchors to placing on the market.

The repo already diagnosed this class of defect once — PhD-review finding 22,
commit 2b82e0d — but the guard it landed hardcodes
`load_template("eu-ai-act-art73-2026")`, so the fix never propagated. These tests
enforce the invariant at the MODEL layer, where no template can evade it.

Invariants under test (every violation message prefixed "ACEF-034: "):
  R1 kind in {fixed_period, minimum_floor} => period is not None
  R2 kind in {none_stated, not_assessed}   => period is None
  R3 kind == "not_assessed"                <=> source == "not_assessed"
  R4 source == "inferred"                  => literal token INFERRED in basis
  R5 source == "cited"                     => normative_text_ref non-empty
                                              AND INFERRED absent from basis
  R6 basis.strip() non-empty in every case
  P1 retention_years is not None => retention is not None
  P2 retention_years is not None => retention is a fixed_period in years of the
                                    same magnitude
  P3 retention_years is not None => retention_years_basis non-empty and equal to
                                    retention.basis
  P4 retention_years is None     => retention_years_basis is None
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from acef.templates.models import (
    Provision,
    RetentionPeriod,
    RetentionRequirement,
)


def _cited_10y() -> RetentionRequirement:
    """The Art. 18(1)(a) determination — directly cited, no inference."""
    return RetentionRequirement(
        kind="fixed_period",
        duty_holder="provider",
        period=RetentionPeriod(value=10, unit="years"),
        anchor_event="placed_on_market_or_put_into_service",
        source="cited",
        normative_text_ref="EU AI Act Art. 18(1)(a)",
        basis=(
            "Art. 18(1)(a) requires the provider to keep the technical documentation "
            "referred to in Article 11 at the disposal of national competent "
            "authorities for a period ending 10 years after the high-risk AI system "
            "has been placed on the market or put into service."
        ),
    )


class TestRetentionRequirementInvariants:
    """R1-R6: an unsourced or internally inconsistent figure must not construct."""

    def test_fixed_period_requires_a_period(self) -> None:
        """R1: a period-bearing kind without a period is incoherent."""
        with pytest.raises(ValidationError, match="ACEF-034"):
            RetentionRequirement(
                kind="fixed_period",
                period=None,
                source="cited",
                normative_text_ref="EU AI Act Art. 18(1)(a)",
                basis="Art. 18(1)(a) sets 10 years.",
            )

    def test_minimum_floor_requires_a_period(self) -> None:
        """R1, the Art. 19 shape: a floor with no magnitude asserts nothing."""
        with pytest.raises(ValidationError, match="ACEF-034"):
            RetentionRequirement(
                kind="minimum_floor",
                duty_holder="provider",
                period=None,
                source="cited",
                normative_text_ref="EU AI Act Art. 19(1)",
                basis="Art. 19(1) sets a floor of at least six months.",
            )

    def test_none_stated_must_not_carry_a_period(self) -> None:
        """R2: this is the article-12 shape. A period here re-introduces the bug."""
        with pytest.raises(ValidationError, match="ACEF-034"):
            RetentionRequirement(
                kind="none_stated",
                period=RetentionPeriod(value=10, unit="years"),
                source="cited",
                normative_text_ref="EU AI Act Art. 12(1)-(3)",
                basis="Art. 12 states no retention period.",
            )

    def test_not_assessed_must_not_carry_a_period(self) -> None:
        """R2: an unassessed provision cannot simultaneously know its period."""
        with pytest.raises(ValidationError, match="ACEF-034"):
            RetentionRequirement(
                kind="not_assessed",
                period=RetentionPeriod(value=7, unit="years"),
                source="not_assessed",
                basis="No retention determination has been made.",
            )

    def test_not_assessed_kind_requires_not_assessed_source(self) -> None:
        """R3 forward: claiming a citation while declaring nothing assessed."""
        with pytest.raises(ValidationError, match="ACEF-034"):
            RetentionRequirement(
                kind="not_assessed",
                source="cited",
                normative_text_ref="OMB M-24-10",
                basis="No retention determination has been made.",
            )

    def test_not_assessed_source_requires_not_assessed_kind(self) -> None:
        """R3 reverse: a concrete kind cannot rest on an absent determination."""
        with pytest.raises(ValidationError, match="ACEF-034"):
            RetentionRequirement(
                kind="fixed_period",
                period=RetentionPeriod(value=7, unit="years"),
                source="not_assessed",
                basis="No retention determination has been made.",
            )

    def test_inferred_source_requires_the_inferred_token_in_basis(self) -> None:
        """R4: the whole point of finding 22 — an inference must SAY it is one.

        This is the exact defect: article-9's 10 years is defensible via
        Annex IV -> Art. 11 -> Art. 18(1)(a), but a reader must be able to tell
        that chain from a directly cited figure.
        """
        with pytest.raises(ValidationError, match="ACEF-034"):
            RetentionRequirement(
                kind="fixed_period",
                period=RetentionPeriod(value=10, unit="years"),
                source="inferred",
                basis="Reaches Art. 18(1)(a) through Annex IV point 5 and Art. 11.",
            )

    def test_inferred_source_accepts_basis_carrying_the_token(self) -> None:
        """R4 positive: the art73 precedent wording is the model to follow."""
        req = RetentionRequirement(
            kind="fixed_period",
            duty_holder="provider",
            period=RetentionPeriod(value=10, unit="years"),
            anchor_event="placed_on_market_or_put_into_service",
            source="inferred",
            normative_text_ref="EU AI Act Art. 9",
            basis=(
                "INFERRED, not stated by Art. 9. Art. 9 sets no retention period; the "
                "risk-management documentation reaches the Art. 18(1)(a) 10-year "
                "period transitively via Annex IV point 5 and Art. 11."
            ),
        )
        assert req.source == "inferred"
        assert req.period is not None
        assert req.period.value == 10

    def test_cited_source_requires_a_normative_text_ref(self) -> None:
        """R5: 'cited' with nothing cited is the defect wearing a badge."""
        with pytest.raises(ValidationError, match="ACEF-034"):
            RetentionRequirement(
                kind="fixed_period",
                period=RetentionPeriod(value=10, unit="years"),
                source="cited",
                normative_text_ref="",
                basis="Art. 18(1)(a) sets 10 years.",
            )

    def test_cited_source_rejects_an_inferred_basis(self) -> None:
        """R5: a determination cannot be both directly cited and inferred."""
        with pytest.raises(ValidationError, match="ACEF-034"):
            RetentionRequirement(
                kind="fixed_period",
                period=RetentionPeriod(value=10, unit="years"),
                source="cited",
                normative_text_ref="EU AI Act Art. 18(1)(a)",
                basis="INFERRED from Annex IV and Art. 11.",
            )

    def test_blank_basis_is_rejected_for_every_kind(self) -> None:
        """R6: whitespace is not provenance."""
        for kind, source in (
            ("none_stated", "cited"),
            ("not_assessed", "not_assessed"),
        ):
            with pytest.raises(ValidationError, match="ACEF-034"):
                RetentionRequirement(
                    kind=kind,  # type: ignore[arg-type]
                    source=source,  # type: ignore[arg-type]
                    normative_text_ref="EU AI Act Art. 12(1)-(3)",
                    basis="   ",
                )

    def test_period_value_must_be_positive(self) -> None:
        """A zero-or-negative retention period is not a retention period."""
        with pytest.raises(ValidationError):
            RetentionPeriod(value=0, unit="years")

    def test_article_12_shape_constructs(self) -> None:
        """The corrected article-12: a documented ABSENCE, not a missing field.

        An auditor must be able to distinguish 'the instrument states no period'
        from 'nobody looked'. That is why `none_stated` is `cited`.
        """
        req = RetentionRequirement(
            kind="none_stated",
            duty_holder="provider",
            period=None,
            source="cited",
            normative_text_ref="EU AI Act Art. 12(1)-(3)",
            basis=(
                "Art. 12 states no retention period; it requires only that the system "
                "technically allow automatic recording of events over its lifetime. "
                "Retention of those logs is governed by Art. 19(1) for providers and "
                "Art. 26(6) for deployers, both 'at least six months'."
            ),
        )
        assert req.kind == "none_stated"
        assert req.period is None

    def test_article_19_shape_constructs(self) -> None:
        """The six-month floor the repo currently cannot express at all."""
        req = RetentionRequirement(
            kind="minimum_floor",
            duty_holder="provider",
            period=RetentionPeriod(value=6, unit="months"),
            anchor_event="record_creation",
            source="cited",
            normative_text_ref="EU AI Act Art. 19(1)",
            basis=(
                "Art. 19(1): providers shall keep the logs referred to in Article "
                "12(1), automatically generated by their high-risk AI systems, to the "
                "extent such logs are under their control, for a period appropriate to "
                "the intended purpose, of at least six months."
            ),
        )
        assert req.kind == "minimum_floor"
        assert req.duty_holder == "provider"
        assert req.period is not None
        assert (req.period.value, req.period.unit) == (6, "months")


class TestProvisionRetentionCoupling:
    """P1-P4: the legacy scalar and the structured block must not diverge."""

    def test_retention_years_without_retention_block_is_rejected(self) -> None:
        """P1: this is literally the shipped defect — a bare integer."""
        with pytest.raises(ValidationError, match="ACEF-034"):
            Provision(provision_id="article-12", retention_years=10)

    def test_retention_years_must_match_the_structured_period(self) -> None:
        """P2: a scalar disagreeing with its own provenance block."""
        with pytest.raises(ValidationError, match="ACEF-034"):
            Provision(
                provision_id="article-11",
                retention_years=7,
                retention_years_basis=_cited_10y().basis,
                retention=_cited_10y(),
            )

    def test_retention_years_rejects_a_non_fixed_period_block(self) -> None:
        """P2: a floor is not a fixed period; the scalar cannot represent it."""
        floor = RetentionRequirement(
            kind="minimum_floor",
            duty_holder="provider",
            period=RetentionPeriod(value=6, unit="months"),
            source="cited",
            normative_text_ref="EU AI Act Art. 19(1)",
            basis="Art. 19(1) sets a floor of at least six months.",
        )
        with pytest.raises(ValidationError, match="ACEF-034"):
            Provision(
                provision_id="article-19",
                retention_years=1,
                retention_years_basis=floor.basis,
                retention=floor,
            )

    def test_retention_years_basis_must_equal_retention_basis(self) -> None:
        """P3: two provenance strings that can drift are one too many."""
        with pytest.raises(ValidationError, match="ACEF-034"):
            Provision(
                provision_id="article-11",
                retention_years=10,
                retention_years_basis="Some other wording.",
                retention=_cited_10y(),
            )

    def test_retention_years_basis_without_retention_years_is_rejected(self) -> None:
        """P4: a dangling basis for a figure that no longer exists."""
        with pytest.raises(ValidationError, match="ACEF-034"):
            Provision(
                provision_id="article-12",
                retention_years=None,
                retention_years_basis="Art. 18(1)(a) sets 10 years.",
            )

    def test_consistent_provision_constructs(self) -> None:
        """The corrected article-11: scalar and block agree exactly."""
        req = _cited_10y()
        prov = Provision(
            provision_id="article-11",
            retention_years=10,
            retention_years_basis=req.basis,
            retention=req,
        )
        assert prov.retention is not None
        assert prov.retention.source == "cited"
        assert prov.retention_years == 10

    def test_provision_without_any_retention_is_still_valid(self) -> None:
        """Back-compat: the field is optional on the model.

        Templates are swept to populate it, and the repo-wide conformance guard
        enforces presence across all shipped templates. Making it mandatory here
        would break every third-party Provision constructed in code.
        """
        prov = Provision(provision_id="article-50.2")
        assert prov.retention is None
        assert prov.retention_years is None

    def test_retention_block_is_not_silently_dropped_at_load(self) -> None:
        """Provision declares no model_config, so pydantic defaults to extra='ignore'.

        Before `retention` was a declared field, adding it to a template JSON was a
        no-op that NO existing test could see: TestTemplateRoundTrip compares only
        template_id and provision COUNT. This pins the field as declared.
        """
        req = _cited_10y()
        prov = Provision(
            provision_id="article-11",
            retention_years=10,
            retention_years_basis=req.basis,
            retention=req,
        )
        dumped = prov.model_dump()
        assert "retention" in dumped, (
            "retention was dropped from model_dump() — it is not a declared field on "
            "Provision, so template JSON carrying it would be silently discarded"
        )
        assert dumped["retention"]["source"] == "cited"
