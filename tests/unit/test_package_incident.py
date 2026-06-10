"""Unit tests for the F-M5-BUILDER incident DX helpers (VAL-DX-001/002/003).

These tests pin the SDK developer-experience surface RFC-0002 v1.1 adds to
:class:`acef.package.Package`:

- :func:`acef.package.mint_incident_id` — a ONE-CALL helper that returns a
  pattern-valid ``AIIC-{LABEL}-{year}-{suffix}`` id (``id_grade: self-asserted``,
  >=128-bit CSPRNG suffix) PLUS the DNS-01 / ``.well-known`` challenge token, and
  round-trips through the OPTIONAL online domain-control verifier (VAL-DX-002).
- :meth:`Package.report_incident` / :meth:`Package.incident_card` — fluent
  builders that auto-derive ``harm_core`` -> ``taxonomy_crosswalk``, compute the
  ACEF-SEV ``band()``, assemble ``card_source.eu_ai_act_facts`` and the Art.73
  ``regulatory_timeline`` shortest-clock entry, and apply the §5.11 publishability
  projection (VAL-DX-001 — the end-to-end signable-bundle proof lives in
  ``tests/integration/test_report_incident_e2e.py``).
- ACEF-08x fix-hint surfacing through :func:`acef.render.render_markdown`
  (VAL-DX-003).

Determinism: all id minting takes an explicit ``year`` / ``now`` (no wall-clock in
the hash domain); the only entropy is the CSPRNG suffix, which the tests assert on
by PATTERN, never by value.
"""

from __future__ import annotations

import re

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from acef.domain_control import (
    DomainControlVerdict,
    HttpResponse,
    assigner_to_registrable_domain,
    challenge_token_for,
    jwk_thumbprint,
    verify_domain_control,
)
from acef.errors import ValidationDiagnostic, incident_error_detail
from acef.models.assessment import AssessmentBundle
from acef.package import Package, mint_incident_id
from acef.redaction import RedactionPolicy
from acef.render import render_console, render_markdown
from acef.signing import _derive_jwk

# The full public_incident_id grammar (RFC §5.3): AIIC-{assigner}-{year}-{suffix},
# assigner 2-8 uppercase alphanumerics, year 4 digits, suffix >=26 Crockford-base32.
_PUBLIC_INCIDENT_ID_PATTERN = re.compile(r"^AIIC-[A-Z0-9]{2,8}-[0-9]{4}-[0-9A-HJKMNP-TV-Z]{26,}$")
_CROCKFORD_SUFFIX_PATTERN = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26,}$")


def _gen_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


# ---------------------------------------------------------------------------
# VAL-DX-002 — mint_incident_id one-call helper
# ---------------------------------------------------------------------------


class TestMintIncidentId:
    def test_one_call_returns_pattern_valid_id_and_token(self) -> None:
        key = _gen_key()
        minted = mint_incident_id("openai.com", key, year=2026)
        # ONE call returns an id + a challenge token + id_grade.
        assert _PUBLIC_INCIDENT_ID_PATTERN.match(minted.public_incident_id)
        assert minted.id_grade == "self-asserted"
        assert minted.challenge_token  # non-empty
        # The token binds the assigner LABEL to the key's RFC-7638 thumbprint.
        assert jwk_thumbprint(minted.jwk) in minted.challenge_token

    def test_suffix_is_at_least_128_bits_crockford(self) -> None:
        key = _gen_key()
        minted = mint_incident_id("openai.com", key, year=2026)
        suffix = minted.public_incident_id.rsplit("-", 1)[-1]
        # >=26 Crockford-base32 chars => >=130 bits of entropy (26 * log2(32)).
        assert len(suffix) >= 26
        assert _CROCKFORD_SUFFIX_PATTERN.match(suffix)

    def test_label_derived_from_registrable_domain_round_trips(self) -> None:
        key = _gen_key()
        minted = mint_incident_id("openai.com", key, year=2026)
        # AIIC-OPENAI-2026-... — the LABEL is the registrable domain's leftmost
        # label, uppercased, and round-trips through the default .com mapper.
        assert minted.assigner == "OPENAI"
        assert assigner_to_registrable_domain(minted.assigner) == "openai.com"

    def test_suffix_is_unpredictable_across_calls(self) -> None:
        key = _gen_key()
        a = mint_incident_id("openai.com", key, year=2026)
        b = mint_incident_id("openai.com", key, year=2026)
        # CSPRNG suffix: two mints differ (the only entropy in the id).
        assert a.public_incident_id != b.public_incident_id

    def test_subdomain_uses_registrable_label(self) -> None:
        key = _gen_key()
        # api.openai.com -> registrable domain openai.com -> LABEL OPENAI.
        minted = mint_incident_id("api.openai.com", key, year=2026)
        assert minted.assigner == "OPENAI"

    def test_label_too_long_raises_valueerror(self) -> None:
        key = _gen_key()
        # 'abcdefghi' (9 chars) cannot satisfy the [A-Z0-9]{2,8} assigner grammar.
        with pytest.raises(ValueError, match=r"assigner|label|2.?8|grammar"):
            mint_incident_id("abcdefghi.com", key, year=2026)

    def test_label_too_short_raises_valueerror(self) -> None:
        key = _gen_key()
        with pytest.raises(ValueError, match=r"assigner|label|2.?8|grammar"):
            mint_incident_id("a.com", key, year=2026)

    def test_empty_domain_raises_valueerror(self) -> None:
        key = _gen_key()
        with pytest.raises(ValueError):
            mint_incident_id("", key, year=2026)

    def test_minted_id_round_trips_through_verifier_to_verified(self) -> None:
        """The minted id + derived JWK + a stub resolver returning the minted token
        -> verify_domain_control returns VERIFIED. Proves the mint helper and the
        OPTIONAL online verifier agree on the challenge binding (VAL-DX-002)."""
        key = _gen_key()
        minted = mint_incident_id("openai.com", key, year=2026)

        def dns_resolver(name: str) -> list[str]:
            # The registrant publishes the EXACT token the mint helper handed back.
            return [minted.challenge_token]

        def no_http(url: str) -> HttpResponse:
            return HttpResponse(status=404, content_type="", body="")

        result = verify_domain_control(
            minted.public_incident_id,
            minted.jwk,
            dns_resolver=dns_resolver,
            http_fetcher=no_http,
        )
        assert result.verdict is DomainControlVerdict.VERIFIED
        assert result.diagnostic is None

    def test_minted_token_equals_challenge_token_for_helper(self) -> None:
        # The minted token is exactly challenge_token_for(LABEL, jwk) — no bespoke
        # derivation path; it reuses the domain_control primitive verbatim.
        key = _gen_key()
        minted = mint_incident_id("openai.com", key, year=2026)
        assert minted.challenge_token == challenge_token_for(minted.assigner, _derive_jwk(key))

    # roborev F2 — the .com-default LABEL derivation must REJECT domains that do
    # not round-trip under assigner_to_registrable_domain (<label>.com). Silently
    # taking labels[-2] misparses multi-label public suffixes (service.example.co.uk
    # -> CO -> co.com challenge), so those MUST raise rather than emit a wrong
    # challenge location. v1.1's default mapper has no PSL; pass a <label>.com domain.

    def test_subdomain_round_trips_to_label(self) -> None:
        # api.openai.com -> OPENAI -> openai.com round-trips, so it is accepted.
        key = _gen_key()
        minted = mint_incident_id("api.openai.com", key, year=2026)
        assert minted.assigner == "OPENAI"
        assert assigner_to_registrable_domain(minted.assigner) == "openai.com"

    def test_multi_label_public_suffix_raises_valueerror(self) -> None:
        # service.example.co.uk would misparse to assigner CO (co.com challenge) —
        # it does NOT round-trip under <label>.com, so it MUST raise.
        key = _gen_key()
        with pytest.raises(ValueError, match=r"round-?trip|\.com|custom mapping"):
            mint_incident_id("service.example.co.uk", key, year=2026)

    def test_non_com_etld_raises_valueerror(self) -> None:
        # example.ai derives EXAMPLE but maps to example.com (NOT example.ai), so it
        # does NOT round-trip under the default mapper and MUST raise.
        key = _gen_key()
        with pytest.raises(ValueError, match=r"round-?trip|\.com|custom mapping"):
            mint_incident_id("example.ai", key, year=2026)

    def test_two_label_etld_raises_valueerror(self) -> None:
        # example.co.uk -> EXAMPLE -> example.com (NOT example.co.uk) — no round-trip.
        key = _gen_key()
        with pytest.raises(ValueError, match=r"round-?trip|\.com|custom mapping"):
            mint_incident_id("example.co.uk", key, year=2026)


# ---------------------------------------------------------------------------
# VAL-DX-001 — fluent incident_card / report_incident builder shape
# ---------------------------------------------------------------------------

_HARM_CORE = {
    "realization": "harm_event",
    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
    "harm_class": "physical_health",
}


def _new_pkg() -> Package:
    # A RedactionPolicy is attached so report_incident's regulator-only record can
    # auto-populate the X1/X2 redaction envelope fields (ACEF-074) without the
    # caller wiring them by hand.
    return Package(
        producer={"name": "test", "version": "1.0"},
        redaction_policy=RedactionPolicy(version="1.0.0"),
    )


class TestIncidentCardBuilder:
    def test_incident_card_returns_envelope_with_incident_card_type(self) -> None:
        pkg = _new_pkg()
        key = _gen_key()
        minted = mint_incident_id("openai.com", key, year=2026)
        env = pkg.incident_card(
            public_incident_id=minted.public_incident_id,
            harm_core=dict(_HARM_CORE),
            severity_vector="ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": False,
            },
        )
        assert env.record_type == "incident_card"
        assert env.payload["public_incident_id"] == minted.public_incident_id
        assert env.payload["id_grade"] == "self-asserted"

    def test_incident_card_auto_derives_crosswalk_from_harm_core(self) -> None:
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id="AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
            harm_core=dict(_HARM_CORE),  # harm_class physical_health
            severity_vector="ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": False,
            },
        )
        crosswalk = env.payload["taxonomy_crosswalk"]
        # physical_health derives 3.49.a + nist categories.
        eu = crosswalk["eu_ai_act"]
        assert "3.49.a" in eu["serious_incident_triggers"]
        # The auto-derived nist member is consistent with the derivation row.
        nist_cats = crosswalk["nist_ai_600_1"]["categories"]
        assert "CBRN Information or Capabilities" in nist_cats

    def test_incident_card_computes_band_into_severity(self) -> None:
        pkg = _new_pkg()
        # HG:H + BR:P => critical band.
        env = pkg.incident_card(
            public_incident_id="AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
            harm_core=dict(_HARM_CORE),
            severity_vector="ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:P",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": False,
            },
        )
        assert env.payload["severity"] == "critical"

    def test_incident_card_assembles_art73_timeline_shortest_clock(self) -> None:
        pkg = _new_pkg()
        # death_involved=true => 10-day clock; awareness 2026-08-01 => deadline 08-11.
        env = pkg.incident_card(
            public_incident_id="AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
            harm_core=dict(_HARM_CORE),
            severity_vector="ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": True,
            },
        )
        timeline = env.payload["coordinated_disclosure"]["regulatory_timeline"]
        art73 = next(e for e in timeline if e["framework"] == "eu-ai-act-art73")
        assert art73["deadline"] == "2026-08-11T00:00:00Z"

    def test_incident_card_sets_core_version_1_1_0(self) -> None:
        pkg = _new_pkg()
        pkg.incident_card(
            public_incident_id="AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
            harm_core=dict(_HARM_CORE),
            severity_vector="ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": False,
            },
        )
        assert pkg.versioning.core_version == "1.1.0"


class TestReportIncidentBuilder:
    def test_report_incident_returns_incident_report_with_card_source(self) -> None:
        pkg = _new_pkg()
        env = pkg.report_incident(
            public_incident_id="AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="Confidential Art.73 serious-incident report.",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": True,
            },
        )
        assert env.record_type == "incident_report"
        card_source = env.payload["card_source"]
        assert card_source["public_incident_id"] == "AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS"
        assert card_source["id_grade"] == "self-asserted"
        assert card_source["id_state"] == "RESERVED"

    def test_report_incident_assembles_eu_ai_act_facts(self) -> None:
        pkg = _new_pkg()
        env = pkg.report_incident(
            public_incident_id="AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="x",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": True,
            },
        )
        facts = env.payload["card_source"]["eu_ai_act_facts"]
        assert facts["death_involved"] is True
        assert facts["serious_incident_triggers"] == ["3.49.a"]
        assert facts["edition"]  # an edition pin is filled in

    def test_report_incident_art73_deadline_is_shortest_clock(self) -> None:
        pkg = _new_pkg()
        # death + 3.49.b => 2-day clock (shortest applicable). awareness 08-01 => 08-03.
        env = pkg.report_incident(
            public_incident_id="AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
            harm_core={
                "realization": "harm_event",
                "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
                "harm_class": "critical_infrastructure",
            },
            incident_type="operational_failure",
            description="x",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a", "3.49.b"],
                "widespread": False,
                "death_involved": True,
            },
        )
        timeline = env.payload["card_source"]["coordinated_disclosure"]["regulatory_timeline"]
        art73 = next(e for e in timeline if e["framework"] == "eu-ai-act-art73")
        assert art73["deadline"] == "2026-08-03T00:00:00Z"

    def test_report_incident_declares_art73_profile(self) -> None:
        pkg = _new_pkg()
        pkg.report_incident(
            public_incident_id="AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="x",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": True,
            },
        )
        declared = [p.profile_id for p in pkg.profiles]
        assert "eu-ai-act-art73-2026" in declared


# ---------------------------------------------------------------------------
# VAL-DX-001 (roborev F1) — the Art.73 clock the builder WRITES must equal the
# clock the validator DERIVES from the same harm_core-derived crosswalk facts.
#
# The builder derives harm_core -> serious_incident_triggers (a
# critical_infrastructure card DERIVES "3.49.b" even when the caller omits it),
# and the validator reads those DERIVED triggers from card_source.eu_ai_act_facts
# (report) / taxonomy_crosswalk.eu_ai_act (card) when computing the shortest
# clock. So the deadline the builder writes MUST be computed from the SAME merged
# (derived ∪ supplied) fact block, or the validator fires ACEF-084. These tests
# assert the deadline alone; the end-to-end zero-ACEF-084 proof is in the
# integration suite.
# ---------------------------------------------------------------------------

_CRITICAL_INFRA_HARM_CORE = {
    "realization": "harm_event",
    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
    "harm_class": "critical_infrastructure",
}


class TestArt73DerivedTriggerClockConsistency:
    def test_report_incident_derives_3_49_b_for_2_day_clock_when_caller_omits_trigger(self) -> None:
        # critical_infrastructure DERIVES 3.49.b -> 2-day clock, even though the
        # caller supplies NO triggers. awareness 08-01 -> deadline 08-03.
        pkg = _new_pkg()
        env = pkg.report_incident(
            public_incident_id="AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
            harm_core=dict(_CRITICAL_INFRA_HARM_CORE),
            incident_type="operational_failure",
            description="x",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": [],  # OMITTED — must be derived
                "widespread": False,
                "death_involved": False,
            },
        )
        card_source = env.payload["card_source"]
        facts = card_source["eu_ai_act_facts"]
        # The derived trigger is merged into the persisted card_source facts...
        assert "3.49.b" in facts["serious_incident_triggers"]
        timeline = card_source["coordinated_disclosure"]["regulatory_timeline"]
        art73 = next(e for e in timeline if e["framework"] == "eu-ai-act-art73")
        # ...and the deadline reflects the 2-day clock derived from that trigger.
        assert art73["deadline"] == "2026-08-03T00:00:00Z"

    def test_incident_card_derives_3_49_b_for_2_day_clock_when_caller_omits_trigger(self) -> None:
        # Same on the public path: the crosswalk carries the derived 3.49.b and the
        # timeline deadline matches the 2-day clock the validator derives from it.
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id="AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
            harm_core=dict(_CRITICAL_INFRA_HARM_CORE),
            severity_vector="ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": [],  # OMITTED — must be derived
                "widespread": False,
                "death_involved": False,
            },
        )
        eu = env.payload["taxonomy_crosswalk"]["eu_ai_act"]
        assert "3.49.b" in eu["serious_incident_triggers"]
        timeline = env.payload["coordinated_disclosure"]["regulatory_timeline"]
        art73 = next(e for e in timeline if e["framework"] == "eu-ai-act-art73")
        assert art73["deadline"] == "2026-08-03T00:00:00Z"

    def test_report_incident_widespread_drives_2_day_clock(self) -> None:
        # widespread=True (no 3.49.b) -> 2-day clock. awareness 08-01 -> deadline 08-03.
        pkg = _new_pkg()
        env = pkg.report_incident(
            public_incident_id="AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
            harm_core=dict(_HARM_CORE),  # physical_health derives 3.49.a (15-day base)
            incident_type="operational_failure",
            description="x",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": [],
                "widespread": True,
                "death_involved": False,
            },
        )
        card_source = env.payload["card_source"]
        assert card_source["eu_ai_act_facts"]["widespread"] is True
        timeline = card_source["coordinated_disclosure"]["regulatory_timeline"]
        art73 = next(e for e in timeline if e["framework"] == "eu-ai-act-art73")
        assert art73["deadline"] == "2026-08-03T00:00:00Z"

    def test_incident_card_widespread_drives_2_day_clock(self) -> None:
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id="AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
            harm_core=dict(_HARM_CORE),
            severity_vector="ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": [],
                "widespread": True,
                "death_involved": False,
            },
        )
        eu = env.payload["taxonomy_crosswalk"]["eu_ai_act"]
        assert eu["widespread"] is True
        timeline = env.payload["coordinated_disclosure"]["regulatory_timeline"]
        art73 = next(e for e in timeline if e["framework"] == "eu-ai-act-art73")
        assert art73["deadline"] == "2026-08-03T00:00:00Z"


# ---------------------------------------------------------------------------
# VAL-DX-003 — ACEF-08x fix hints surfaced through SDK error rendering
# ---------------------------------------------------------------------------


def _assessment_with(codes: list[str]) -> AssessmentBundle:
    assessment = AssessmentBundle(evaluation_instant="2026-08-10T00:00:00Z")
    for code in codes:
        assessment.structural_errors.append(
            ValidationDiagnostic(code, f"{code} failed for record 'r1'.", path="/r1/x").to_dict()
        )
    return assessment


class TestIncidentFixHintRendering:
    def test_rendered_084_contains_fatal_clock_fix_hint(self) -> None:
        assessment = _assessment_with(["ACEF-084"])
        rendered = render_markdown(assessment)
        fix = incident_error_detail("ACEF-084")
        assert fix is not None
        # The fatal-clock fix hint text is present in the rendered report.
        assert fix.fix in rendered
        assert "shortest applicable clock" in rendered  # the §5.7 fix-hint phrasing

    def test_rendered_086_contains_publishability_fix_hint(self) -> None:
        assessment = _assessment_with(["ACEF-086"])
        rendered = render_markdown(assessment)
        fix = incident_error_detail("ACEF-086")
        assert fix is not None
        assert fix.fix in rendered

    def test_rendered_084_and_086_both_show_their_fix_hints(self) -> None:
        # A single rendered assessment carrying ACEF-084 AND one other 08x
        # (ACEF-086) shows BOTH fix hints (VAL-DX-003 acceptance).
        assessment = _assessment_with(["ACEF-084", "ACEF-086"])
        rendered = render_markdown(assessment)
        assert incident_error_detail("ACEF-084").fix in rendered  # type: ignore[union-attr]
        assert incident_error_detail("ACEF-086").fix in rendered  # type: ignore[union-attr]

    def test_rendered_08x_shows_cause_and_problem(self) -> None:
        # problem + cause + fix are all surfaced (the structured incident detail).
        assessment = _assessment_with(["ACEF-084"])
        rendered = render_markdown(assessment)
        detail = incident_error_detail("ACEF-084")
        assert detail is not None
        assert detail.cause in rendered
        assert "Fix:" in rendered or "fix" in rendered.lower()

    def test_markdown_084_renders_problem_cause_and_fix(self) -> None:
        # roborev F3: the structured PROBLEM text (not only cause/fix) is rendered.
        assessment = _assessment_with(["ACEF-084"])
        rendered = render_markdown(assessment)
        detail = incident_error_detail("ACEF-084")
        assert detail is not None
        assert detail.problem in rendered
        assert detail.cause in rendered
        assert detail.fix in rendered

    def test_markdown_086_renders_problem_cause_and_fix(self) -> None:
        assessment = _assessment_with(["ACEF-086"])
        rendered = render_markdown(assessment)
        detail = incident_error_detail("ACEF-086")
        assert detail is not None
        assert detail.problem in rendered
        assert detail.cause in rendered
        assert detail.fix in rendered

    def test_console_084_renders_problem_cause_and_fix(self) -> None:
        # roborev F3: the console renderer surfaces Problem + Cause + Fix, not Fix alone.
        assessment = _assessment_with(["ACEF-084"])
        rendered = render_console(assessment)
        detail = incident_error_detail("ACEF-084")
        assert detail is not None
        assert detail.problem in rendered
        assert detail.cause in rendered
        assert detail.fix in rendered

    def test_console_086_renders_problem_cause_and_fix(self) -> None:
        assessment = _assessment_with(["ACEF-086"])
        rendered = render_console(assessment)
        detail = incident_error_detail("ACEF-086")
        assert detail is not None
        assert detail.problem in rendered
        assert detail.cause in rendered
        assert detail.fix in rendered

    def test_non_incident_code_renders_without_fix_block(self) -> None:
        # A v0.4 code (no IncidentErrorDetail) renders normally with NO fix-hint
        # block (incident_error_detail returns None for it).
        assert incident_error_detail("ACEF-022") is None
        assessment = _assessment_with(["ACEF-022"])
        rendered = render_markdown(assessment)
        assert "ACEF-022" in rendered  # still rendered as a structural error
        # No incident fix-hint label is emitted for a non-incident code.
        assert "ACEF-022 fix:" not in rendered.lower()

    def test_console_render_surfaces_084_fix_hint(self) -> None:
        # The concise console renderer also surfaces the incident fix hint.
        assessment = _assessment_with(["ACEF-084"])
        rendered = render_console(assessment)
        fix = incident_error_detail("ACEF-084")
        assert fix is not None
        assert fix.fix in rendered
