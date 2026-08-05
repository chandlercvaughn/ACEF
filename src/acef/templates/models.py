"""ACEF template data models — Template, Provision, EvaluationRule, Scope, Condition."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RuleScope(BaseModel):
    """Scope filter for DSL rules."""

    risk_classifications: list[str] = Field(default_factory=list)
    obligation_roles: list[str] = Field(default_factory=list)
    lifecycle_phases: list[str] = Field(default_factory=list)
    modalities: list[str] = Field(default_factory=list)


class RuleCondition(BaseModel):
    """Condition for when a DSL rule applies."""

    if_provision_effective: bool | None = None
    if_system_type: list[str] = Field(default_factory=list)


class EvaluationRule(BaseModel):
    """A single DSL evaluation rule within a provision."""

    rule_id: str
    rule: str  # operator name
    params: dict[str, Any] = Field(default_factory=dict)
    severity: str = "fail"  # fail | warning | info
    message: str = ""
    scope: RuleScope | None = None
    condition: RuleCondition | None = None


class SubProvision(BaseModel):
    """A sub-provision within a parent provision."""

    provision_id: str
    normative_text_ref: str = ""
    description: str = ""


# 100 years, expressed per unit. 36525 days = 100 Julian years incl. leap days.
_MAX_PERIOD_BY_UNIT = {"days": 36525, "months": 1200, "years": 100}


class RetentionPeriod(BaseModel):
    """A retention magnitude with its unit.

    Years alone cannot express the EU AI Act log floor: Art. 19(1) and Art. 26(6)
    both say "at least six months", which ``retention_years`` (an ``int``) can only
    round to 0 or 1. Carrying the unit is what makes the real obligation
    representable.
    """

    value: int = Field(ge=1)
    unit: Literal["days", "months", "years"]

    @model_validator(mode="after")
    def _check_ceiling(self) -> RetentionPeriod:
        """Cap the period at 100 years, expressed in this period's OWN unit.

        A unit-blind cap is wrong in both directions: it rejects 1201 days
        (~3.3 years, entirely ordinary) while admitting 1200 years. The ceiling
        exists so a month-denominated period cannot overflow
        ``datetime.date`` inside the calendar-minimum scan
        (validation.engine._MAX_RETENTION_MONTHS), and no real statutory
        retention approaches a century.
        """
        if self.value > _MAX_PERIOD_BY_UNIT[self.unit]:
            raise ValueError(
                f"ACEF-034: retention period {self.value} {self.unit} exceeds the "
                f"100-year ceiling ({_MAX_PERIOD_BY_UNIT[self.unit]} {self.unit})"
            )
        return self


class RetentionRequirement(BaseModel):
    """A retention determination together with its provenance.

    Issue #1: ``src/acef/templates/eu-ai-act-2024.json`` asserted
    ``"retention_years": 10`` on eight provisions with no source. For
    ``article-12`` that is a false statement of law — Art. 12 of Regulation (EU)
    2024/1689 states no retention period at all, and the schema documents the
    field as "Required retention period", so ACEF was publishing the figure as
    fact.

    ``kind`` distinguishes the four determinations that a bare integer conflates:
    a fixed period, a minimum floor (unbounded above), a documented ABSENCE of any
    stated period, and "nobody has assessed this yet". The last two are different
    facts and an auditor must be able to tell them apart.

    ``source`` is the provenance of the DETERMINATION, not only of a number:
    ``"cited"`` means the determination — a period, or its documented absence — is
    grounded in instrument text named in ``normative_text_ref``; ``"inferred"``
    means the figure is reached by an inference chain (e.g. Art. 9 documentation
    reaching the Art. 18(1)(a) ten years via Annex IV and Art. 11);
    ``"not_assessed"`` means no determination has been made.
    """

    kind: Literal["fixed_period", "minimum_floor", "none_stated", "not_assessed"]
    duty_holder: Literal["provider", "deployer", "authorised_representative", "importer", "any"] = "any"
    period: RetentionPeriod | None = None
    anchor_event: Literal[
        "placed_on_market_or_put_into_service",
        "put_into_service",
        "record_creation",
        "first_deployment",
        "first_use",
        "not_specified",
    ] = "not_specified"
    source: Literal["cited", "inferred", "not_assessed"]
    normative_text_ref: str = ""
    basis: str

    @model_validator(mode="after")
    def _check_provenance(self) -> RetentionRequirement:
        """Enforce R1-R6. Every message is prefixed ``ACEF-034:``."""
        if self.kind in ("fixed_period", "minimum_floor") and self.period is None:
            raise ValueError(
                f"ACEF-034: retention kind {self.kind!r} requires a period, but none "
                "was given — a period-bearing determination without a magnitude "
                "asserts nothing"
            )
        if self.kind in ("none_stated", "not_assessed") and self.period is not None:
            raise ValueError(
                f"ACEF-034: retention kind {self.kind!r} must not carry a period; got "
                f"{self.period.value} {self.period.unit}. A stated period contradicts "
                "the claim that none was stated or assessed"
            )
        if (self.kind == "not_assessed") != (self.source == "not_assessed"):
            raise ValueError(
                "ACEF-034: kind and source must agree on whether a determination "
                f"exists; got kind={self.kind!r} with source={self.source!r}"
            )
        if not self.basis.strip():
            raise ValueError(
                "ACEF-034: retention basis must be non-empty — a retention "
                "determination with no stated basis is not auditable, and a null "
                "basis is exactly what made issue #1 detectable"
            )
        if self.source == "inferred" and "INFERRED" not in self.basis:
            raise ValueError(
                "ACEF-034: source='inferred' requires the literal token INFERRED in "
                "the basis so a reader can distinguish a derived figure from a cited "
                "one (the eu-ai-act-art73-2026.json convention, PhD-review finding 22)"
            )
        if self.source == "cited":
            if not self.normative_text_ref.strip():
                raise ValueError(
                    "ACEF-034: source='cited' requires a non-empty normative_text_ref "
                    "— a citation that cites nothing is the original defect wearing a "
                    "badge"
                )
            if "INFERRED" in self.basis:
                raise ValueError(
                    "ACEF-034: source='cited' contradicts an INFERRED basis; a "
                    "determination is either grounded in the cited text or derived, "
                    "not both"
                )
        return self


class Provision(BaseModel):
    """A regulatory provision within a template."""

    provision_id: str
    provision_name: str = ""
    normative_text_ref: str = ""
    description: str = ""
    effective_date: str | None = None
    applicable_to: list[str] = Field(default_factory=list)
    sub_provisions: list[SubProvision] = Field(default_factory=list)
    required_evidence_types: list[str] = Field(default_factory=list)
    minimum_evidence_count: dict[str, int] = Field(default_factory=dict)
    evidence_freshness_max_days: int | None = None
    retention_years: int | None = None
    # Optional provenance for retention_years when it is an INFERRED default rather
    # than a cited figure (e.g. Art. 73 sets no incident-report retention, so the
    # 10-year value is inferred from Art. 18). Modeled so the qualification survives
    # load_template() and is accessible to SDK consumers (PhD-review finding 22).
    retention_years_basis: str | None = None
    # Structured supersession of the two fields above (issue #1). ``retention_years``
    # is an int-years scalar that cannot express the Art. 19(1) / Art. 26(6) "at
    # least six months" floor, cannot distinguish a floor from a fixed period,
    # cannot say WHO owes the duty or WHEN the clock starts, and — as shipped —
    # carried no source at all. The scalar is retained for backward compatibility
    # and is kept in lockstep with this block by the validator below.
    #
    # Declaring it as a real field is load-bearing: ``Provision`` sets no
    # ``model_config``, so pydantic's default ``extra="ignore"`` applies (unlike
    # ``Template``, which sets ``extra="allow"``). Before this field existed,
    # adding ``retention`` to a template JSON was silently discarded at load and no
    # existing test could observe it.
    retention: RetentionRequirement | None = None
    evaluation: list[EvaluationRule] = Field(default_factory=list)
    tiered_requirements: dict[str, Any] | None = None
    evaluation_scope: str | None = None  # "package" or None (per-subject default)

    @model_validator(mode="after")
    def _check_retention_coupling(self) -> Provision:
        """Enforce P1-P4: the legacy scalar must never diverge from the block."""
        if self.retention_years is None:
            if self.retention_years_basis is not None:
                raise ValueError(
                    "ACEF-034: retention_years_basis is set but retention_years is "
                    "None — a basis for a figure that does not exist. Move the "
                    "reasoning into retention.basis"
                )
            return self

        if self.retention is None:
            raise ValueError(
                f"ACEF-034: provision {self.provision_id!r} sets retention_years="
                f"{self.retention_years} with no retention block. A retention figure "
                "with no recorded source is not auditable — this is the defect "
                "reported in issue #1"
            )
        if self.retention.kind != "fixed_period":
            raise ValueError(
                f"ACEF-034: provision {self.provision_id!r} sets retention_years but "
                f"retention.kind is {self.retention.kind!r}; only 'fixed_period' is "
                "representable as an integer number of years"
            )
        period = self.retention.period
        if period is None or period.unit != "years" or period.value != self.retention_years:
            got = "None" if period is None else f"{period.value} {period.unit}"
            raise ValueError(
                f"ACEF-034: provision {self.provision_id!r} has retention_years="
                f"{self.retention_years} but retention.period is {got}; the scalar and "
                "the structured period must agree"
            )
        if not (self.retention_years_basis or "").strip():
            raise ValueError(
                f"ACEF-034: provision {self.provision_id!r} sets retention_years with an empty retention_years_basis"
            )
        if self.retention_years_basis != self.retention.basis:
            raise ValueError(
                f"ACEF-034: provision {self.provision_id!r} has retention_years_basis "
                "differing from retention.basis; two provenance strings that can "
                "drift are one too many"
            )
        return self


class Template(BaseModel):
    """A regulation mapping template.

    ``extra="allow"`` preserves template-LEVEL metadata blocks that are not
    modelled as explicit fields (e.g. the OECD ``oecd_framework`` block carrying
    ``mandatory_criteria_ordinals``). Keeping them on the loaded model makes
    :func:`acef.templates.registry.load_template` the single source of truth for
    those blocks, so validators read them via the model instead of a divergent
    raw-file read. This does NOT affect the hash domain: template digests are
    computed from on-disk JSON bytes (see
    :func:`acef.templates.registry.compute_template_digest`), never from a
    Pydantic re-serialization, and the on-disk templates already contain these
    keys — so preserving them on load is byte-neutral.
    """

    model_config = ConfigDict(extra="allow")

    template_id: str
    template_name: str = ""
    version: str = "1.0.0"
    jurisdiction: str = ""
    source_legislation: str = ""
    instrument_type: str = ""  # law | standard | code_of_practice | guidance | parliamentary_report
    legal_force: str = ""  # binding | voluntary | advisory
    instrument_status: str = "final"  # final | draft
    default_effective_date: str | None = None
    superseded_by: str | None = None
    applicable_system_types: list[str] = Field(default_factory=list)
    provisions: list[Provision] = Field(default_factory=list)
    test_vectors: list[str] = Field(default_factory=list)
