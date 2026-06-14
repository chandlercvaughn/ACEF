"""Unit tests for the offline incident validation rules (F-M3-VALIDATOR-RULES).

These tests drive the new module :mod:`acef.validation.incident_rules` directly,
exercising each rule family in isolation against in-memory record dicts. The
engine-level version-gating (incident rules fire only on core_version 1.1.0) and
the on-disk integration path are covered in
``tests/integration/test_incident_validation_engine.py``.

Assertions fulfilled here:
- VAL-CLOCK-001 — Art.73 shortest-clock computation from eu_ai_act_facts /
  taxonomy_crosswalk.eu_ai_act, the ACEF-084 deadline-mismatch error, the
  existential dual-source rule, and the regulatory_timeline framework-match rule
  (the ART73-DELEGATED list).
- VAL-PUB-001 — the §5.11 publishability gate (declared_publication_basis,
  commitment linkage, publishability_map pointer resolution) raising ACEF-086.
- The remaining §7 offline rules: ACEF-081 (missing mandatory crosswalk member),
  ACEF-082 (unparseable severity_vector), ACEF-083 (offline id-trust, no
  attribution), ACEF-085 (crosswalk contradicts harm_core), ACEF-087 (near_miss
  INFO marker), ACEF-088 (severity != band()).

Determinism: every fixture is a static literal; no wall-clock / random values.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import jsonpointer
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from acef.integrity import canonicalize, sha256_hex
from acef.signing import create_detached_jws
from acef.validation import incident_rules as ir

# A 26-char Crockford-base32 suffix (>=128 bits, the pattern minimum).
_SUFFIX = "0123456789ABCDEFGHJKMNPQRS"
_VALID_ID = f"AIIC-OPENAI-2026-{_SUFFIX}"

_VALID_HARM_CORE: dict[str, Any] = {
    "realization": "harm_event",
    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
    "harm_class": "physical_health",
}


def _codes(diags: list[Any]) -> list[str]:
    return [d.code for d in diags]


def _sign_incident_record(rec: dict[str, Any], *, signed_fields: tuple[str, ...] = ("/payload",)) -> dict[str, Any]:
    """Attach a self-consistent record-envelope ``attestation`` block to ``rec``.

    Mirrors the §3.1 / §3.5 detached-JWS recipe (the same one
    ``_attestation_verifies`` checks): extract each ``signed_fields`` pointer from
    the record dict, RFC 8785-canonicalize the ``{pointer: value}`` subset, and
    detached-JWS-sign it with an ES256 key whose public JWK is embedded in the
    JWS header. The returned record verifies against its OWN embedded key — that
    is the §5.3(ii) attribution-free self-consistency the offline class checks.
    Returns a new dict (the caller's ``rec`` is not mutated).
    """
    rec = copy.deepcopy(rec)
    key = ec.generate_private_key(ec.SECP256R1())
    subset = {pointer: jsonpointer.resolve_pointer(rec, pointer) for pointer in signed_fields}
    rec["attestation"] = {
        "method": "jws",
        "signer": "provider",
        "signed_fields": list(signed_fields),
        "signature": create_detached_jws(canonicalize(subset), key, kid="card-key"),
    }
    return rec


# ---------------------------------------------------------------------------
# band() — §5.4 normative band table
# ---------------------------------------------------------------------------


class TestBand:
    def test_critical_hg_high_and_breadth_population(self) -> None:
        # HG:H AND BR:P -> critical (row 1).
        assert ir.band("ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:P") == "critical"

    def test_critical_hg_high_and_irreversible(self) -> None:
        # HG:H AND RV:I -> critical (row 1).
        assert ir.band("ACEF-SEV:1.0/HT:P/HG:H/RV:I/SC:U/BR:I") == "critical"

    def test_major_hg_high_only(self) -> None:
        # HG:H but BR not P and RV not I -> major (row 2).
        assert ir.band("ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I") == "major"

    def test_major_hg_low_and_population(self) -> None:
        # HG:L AND BR:P -> major (row 3).
        assert ir.band("ACEF-SEV:1.0/HT:P/HG:L/RV:A/SC:U/BR:P") == "major"

    def test_minor_hg_low_only(self) -> None:
        assert ir.band("ACEF-SEV:1.0/HT:P/HG:L/RV:A/SC:U/BR:I") == "minor"

    def test_informational_hg_negligible(self) -> None:
        assert ir.band("ACEF-SEV:1.0/HT:P/HG:N/RV:A/SC:U/BR:I") == "informational"

    def test_unparseable_returns_none(self) -> None:
        assert ir.band("not-a-vector") is None
        assert ir.band("ACEF-SEV:1.0/HT:P/RV:A/SC:U/BR:I") is None  # HG missing


# ---------------------------------------------------------------------------
# Art.73 clock — §5.7 shortest applicable clock
# ---------------------------------------------------------------------------


class TestArt73Clock:
    def test_death_involved_ten_days(self) -> None:
        facts = {"death_involved": True, "widespread": False, "serious_incident_triggers": ["3.49.a"]}
        assert ir.shortest_art73_clock_days(facts) == 10

    def test_critical_infra_two_days(self) -> None:
        facts = {"death_involved": False, "widespread": False, "serious_incident_triggers": ["3.49.b"]}
        assert ir.shortest_art73_clock_days(facts) == 2

    def test_widespread_two_days(self) -> None:
        facts = {"death_involved": False, "widespread": True, "serious_incident_triggers": ["3.49.c"]}
        assert ir.shortest_art73_clock_days(facts) == 2

    def test_general_fifteen_days(self) -> None:
        # Non-fatal 3.49.a serious-health-harm takes the general 15-day clock.
        facts = {"death_involved": False, "widespread": False, "serious_incident_triggers": ["3.49.a"]}
        assert ir.shortest_art73_clock_days(facts) == 15

    def test_compound_death_and_critical_infra_shortest_two(self) -> None:
        # death (10) + 3.49.b (2) -> shortest applicable is 2.
        facts = {"death_involved": True, "widespread": False, "serious_incident_triggers": ["3.49.a", "3.49.b"]}
        assert ir.shortest_art73_clock_days(facts) == 2


# ---------------------------------------------------------------------------
# ACEF-084 — deadline mismatch (source-backed: card_source.eu_ai_act_facts)
# ---------------------------------------------------------------------------


def _report_record(card_source: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": "rec-report-1",
        "record_type": "incident_report",
        "payload": {
            "incident_type": "malfunction",
            "severity": "major",
            "description": "x",
            "card_source": card_source,
        },
    }


def _good_card_source(
    *,
    triggers: list[str],
    widespread: bool,
    death: bool,
    deadline: str | None,
    awareness: str = "2026-08-10T00:00:00Z",
) -> dict[str, Any]:
    timeline: list[dict[str, Any]] = []
    if deadline is not None:
        timeline = [
            {
                "framework": "eu-ai-act-art73",
                "clock_model": "awareness_days",
                "awareness_date": awareness,
                "deadline": deadline,
            }
        ]
    return {
        "public_incident_id": _VALID_ID,
        "id_grade": "self-asserted",
        "id_state": "RESERVED",
        "harm_core": dict(_VALID_HARM_CORE),
        "publishability_map": {"/root_cause_analysis": "regulator-only"},
        "eu_ai_act_facts": {
            "edition": "reg-2024-1689",
            "serious_incident_triggers": triggers,
            "widespread": widespread,
            "death_involved": death,
        },
        "coordinated_disclosure": {"status": "coordinated", "regulatory_timeline": timeline},
    }


class TestACEF084:
    def test_death_correct_ten_day_deadline_passes(self) -> None:
        cs = _good_card_source(
            triggers=["3.49.a"],
            widespread=False,
            death=True,
            awareness="2026-08-01T00:00:00Z",
            deadline="2026-08-11T00:00:00Z",
        )
        diags = ir.check_art73_clock([_report_record(cs)], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" not in _codes(diags)

    def test_death_wrong_fifteen_day_deadline_raises_084(self) -> None:
        # death_involved -> 10 days required; a 15-day deadline is inconsistent.
        cs = _good_card_source(
            triggers=["3.49.a"],
            widespread=False,
            death=True,
            awareness="2026-08-01T00:00:00Z",
            deadline="2026-08-16T00:00:00Z",
        )
        diags = ir.check_art73_clock([_report_record(cs)], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" in _codes(diags)

    def test_compound_death_plus_critical_infra_two_day_deadline_passes(self) -> None:
        cs = _good_card_source(
            triggers=["3.49.a", "3.49.b"],
            widespread=False,
            death=True,
            awareness="2026-08-01T00:00:00Z",
            deadline="2026-08-03T00:00:00Z",
        )
        diags = ir.check_art73_clock([_report_record(cs)], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" not in _codes(diags)

    def test_clock_not_checked_when_profile_absent(self) -> None:
        cs = _good_card_source(
            triggers=["3.49.a"],
            widespread=False,
            death=True,
            awareness="2026-08-01T00:00:00Z",
            deadline="2026-08-16T00:00:00Z",
        )
        # No eu-ai-act-art73-2026 profile declared -> ACEF-084 not evaluated.
        diags = ir.check_art73_clock([_report_record(cs)], profiles=[])
        assert "ACEF-084" not in _codes(diags)

    # --- INCVAL-004: within-clock deadline relation (not exact-instant) ---

    def test_awareness_with_time_midnight_deadline_passes(self) -> None:
        # CONFORMANT: awareness carries a time-of-day (09:30Z) and the deadline is
        # the legally-natural midnight of day N (within the 10-day clock). Under
        # strict-instant equality this spuriously raised ACEF-084; under the
        # within-clock relation (awareness <= deadline <= awareness + N) it passes.
        cs = _good_card_source(
            triggers=["3.49.a"],
            widespread=False,
            death=True,  # 10-day clock
            awareness="2026-08-01T09:30:00Z",
            deadline="2026-08-11T00:00:00Z",  # midnight day 10 (before awareness+10d=09:30Z)
        )
        diags = ir.check_art73_clock([_report_record(cs)], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" not in _codes(diags)

    def test_timezone_offset_equivalent_instants_pass(self) -> None:
        # awareness as +02:00 offset and deadline as the equivalent Zulu instant
        # exactly N days later: the two parse to instants whose delta is exactly
        # the clock, so the deadline is within the clock -> no ACEF-084.
        cs = _good_card_source(
            triggers=["3.49.a"],
            widespread=False,
            death=True,  # 10-day clock
            awareness="2026-08-01T11:30:00+02:00",  # == 2026-08-01T09:30:00Z
            deadline="2026-08-11T09:30:00Z",  # exactly awareness + 10d
        )
        diags = ir.check_art73_clock([_report_record(cs)], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" not in _codes(diags)

    def test_earlier_than_clock_deadline_passes(self) -> None:
        # A deadline EARLIER than the ceiling (reported more promptly) is legally
        # consistent: the clock is a "not later than N days" ceiling, not a target.
        cs = _good_card_source(
            triggers=["3.49.a"],
            widespread=False,
            death=True,  # 10-day clock
            awareness="2026-08-01T00:00:00Z",
            deadline="2026-08-05T00:00:00Z",  # day 4, well within the 10-day ceiling
        )
        diags = ir.check_art73_clock([_report_record(cs)], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" not in _codes(diags)

    def test_genuinely_late_deadline_with_time_still_raises_084(self) -> None:
        # A deadline AFTER awareness + N (even by a representation-natural amount)
        # is genuinely too late and MUST still raise ACEF-084.
        cs = _good_card_source(
            triggers=["3.49.a"],
            widespread=False,
            death=True,  # 10-day clock
            awareness="2026-08-01T09:30:00Z",
            deadline="2026-08-12T00:00:00Z",  # day 11 midnight > awareness + 10d
        )
        diags = ir.check_art73_clock([_report_record(cs)], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" in _codes(diags)

    def test_deadline_before_awareness_raises_084(self) -> None:
        # A deadline BEFORE awareness is incoherent (a clock cannot expire before it
        # starts) -> ACEF-084.
        cs = _good_card_source(
            triggers=["3.49.a"],
            widespread=False,
            death=True,
            awareness="2026-08-10T00:00:00Z",
            deadline="2026-08-09T00:00:00Z",  # before awareness
        )
        diags = ir.check_art73_clock([_report_record(cs)], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" in _codes(diags)

    def test_public_card_clock_from_taxonomy_crosswalk(self) -> None:
        card = {
            "record_id": "rec-card-1",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
                "taxonomy_crosswalk": {
                    "eu_ai_act": {
                        "edition": "reg-2024-1689",
                        "serious_incident_triggers": ["3.49.b"],
                        "widespread": False,
                        "death_involved": False,
                    }
                },
                "coordinated_disclosure": {
                    "status": "coordinated",
                    "regulatory_timeline": [
                        {
                            "framework": "eu-ai-act-art73",
                            "clock_model": "awareness_days",
                            "awareness_date": "2026-08-01T00:00:00Z",
                            "deadline": "2026-08-16T00:00:00Z",  # wrong: 3.49.b -> 2 days
                        }
                    ],
                },
            },
        }
        diags = ir.check_art73_clock([card], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" in _codes(diags)

    def test_public_card_missing_widespread_death_facts_raises_084(self) -> None:
        # FINDING 1: a declared-Art.73 PUBLIC card with triggers + id but with NO
        # widespread / death_involved booleans is an INCOMPLETE Art.73 fact set.
        # The confidential card_source.eu_ai_act_facts schema REQUIRES both; the
        # public taxonomy_crosswalk.eu_ai_act path must not silently default them to
        # false and pass a wrong 15-day clock. It MUST raise ACEF-084 (missing facts),
        # not silently accept a 15-day deadline.
        card = {
            "record_id": "rec-card-incomplete",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
                "taxonomy_crosswalk": {
                    "eu_ai_act": {
                        "edition": "reg-2024-1689",
                        "serious_incident_triggers": ["3.49.a"],
                        # widespread / death_involved INTENTIONALLY ABSENT
                    }
                },
                "coordinated_disclosure": {
                    "status": "coordinated",
                    "regulatory_timeline": [
                        {
                            "framework": "eu-ai-act-art73",
                            "clock_model": "awareness_days",
                            "awareness_date": "2026-08-01T00:00:00Z",
                            # 15-day deadline would be ACCEPTED if both booleans
                            # silently defaulted to false — that is the bug.
                            "deadline": "2026-08-16T00:00:00Z",
                        }
                    ],
                },
            },
        }
        diags = ir.check_art73_clock([card], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" in _codes(diags)

    def test_public_card_incomplete_facts_message_sharpened(self) -> None:
        # INCVAL-005: a schema-valid public card (eu_ai_act requires only `edition`)
        # that omits the booleans is validator-rejected by design (no silent
        # default-to-false). The ACEF-084 message MUST sharpen the guidance: it
        # must name the three required public-Art.73 facts AND state explicitly
        # that the VALIDATOR enforces this even though the SCHEMA permits omission.
        card = {
            "record_id": "rec-card-incomplete",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
                "taxonomy_crosswalk": {
                    "eu_ai_act": {
                        "edition": "reg-2024-1689",
                        "serious_incident_triggers": ["3.49.a"],
                        # widespread / death_involved omitted (schema-valid: only
                        # `edition` is required on the public eu_ai_act member).
                    }
                },
                "coordinated_disclosure": {
                    "status": "coordinated",
                    "regulatory_timeline": [
                        {
                            "framework": "eu-ai-act-art73",
                            "clock_model": "awareness_days",
                            "awareness_date": "2026-08-01T00:00:00Z",
                            "deadline": "2026-08-16T00:00:00Z",
                        }
                    ],
                },
            },
        }
        diags = ir.check_art73_clock([card], profiles=["eu-ai-act-art73-2026"])
        d084 = next(d for d in diags if d.code == "ACEF-084")
        msg = d084.message
        # Names the three required public Art.73 facts.
        assert "serious_incident_triggers" in msg
        assert "widespread" in msg
        assert "death_involved" in msg
        # States the schema-permits-vs-validator-enforces tension explicitly.
        assert "schema" in msg.lower()
        assert "validator" in msg.lower() or "enforce" in msg.lower()

    def test_public_card_complete_facts_correct_clock_passes(self) -> None:
        # The same public card WITH both widespread + death_involved present and a
        # correct 15-day deadline (non-fatal 3.49.a, not widespread) passes.
        card = {
            "record_id": "rec-card-complete",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
                "taxonomy_crosswalk": {
                    "eu_ai_act": {
                        "edition": "reg-2024-1689",
                        "serious_incident_triggers": ["3.49.a"],
                        "widespread": False,
                        "death_involved": False,
                    }
                },
                "coordinated_disclosure": {
                    "status": "coordinated",
                    "regulatory_timeline": [
                        {
                            "framework": "eu-ai-act-art73",
                            "clock_model": "awareness_days",
                            "awareness_date": "2026-08-01T00:00:00Z",
                            "deadline": "2026-08-16T00:00:00Z",  # 15 days, correct
                        }
                    ],
                },
            },
        }
        diags = ir.check_art73_clock([card], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" not in _codes(diags)


# ---------------------------------------------------------------------------
# VAL-CLOCK-001 ART73-DELEGATED: existential dual-source + framework-match
# ---------------------------------------------------------------------------


class TestArt73DelegatedExistential:
    def test_no_evidence_art73_bundle_fails(self) -> None:
        # eu-ai-act-art73-2026 declared but NO record carries public_incident_id +
        # Art.3(49) trigger facts on either path -> existential failure (ACEF-084).
        empty_card = {
            "record_id": "rec-card-empty",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
        }
        diags = ir.check_art73_existential([empty_card], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" in _codes(diags)

    def test_public_card_incomplete_facts_does_not_satisfy_existential(self) -> None:
        # FINDING 1 (existential side): a public card with triggers + id but WITHOUT
        # widespread / death_involved is NOT a complete Art.73 fact carrier, so the
        # existential dual-source rule is NOT satisfied -> ACEF-084.
        card = {
            "record_id": "rec-card-incomplete",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
                "taxonomy_crosswalk": {
                    "eu_ai_act": {
                        "edition": "reg-2024-1689",
                        "serious_incident_triggers": ["3.49.a"],
                        # widespread / death_involved ABSENT
                    }
                },
                "coordinated_disclosure": {
                    "status": "coordinated",
                    "regulatory_timeline": [
                        {
                            "framework": "eu-ai-act-art73",
                            "clock_model": "awareness_days",
                            "awareness_date": "2026-08-01T00:00:00Z",
                            "deadline": "2026-08-16T00:00:00Z",
                        }
                    ],
                },
            },
        }
        diags = ir.check_art73_existential([card], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" in _codes(diags)

    def test_public_card_complete_facts_satisfies_existential(self) -> None:
        # The same public card WITH both booleans present is a complete fact carrier
        # and (with a framework-matched timeline entry) satisfies the existential rule.
        card = {
            "record_id": "rec-card-complete",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
                "taxonomy_crosswalk": {
                    "eu_ai_act": {
                        "edition": "reg-2024-1689",
                        "serious_incident_triggers": ["3.49.a"],
                        "widespread": False,
                        "death_involved": False,
                    }
                },
                "coordinated_disclosure": {
                    "status": "coordinated",
                    "regulatory_timeline": [
                        {
                            "framework": "eu-ai-act-art73",
                            "clock_model": "awareness_days",
                            "awareness_date": "2026-08-01T00:00:00Z",
                            "deadline": "2026-08-16T00:00:00Z",
                        }
                    ],
                },
            },
        }
        diags = ir.check_art73_existential([card], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" not in _codes(diags)

    def test_reserved_id_card_source_only_satisfied(self) -> None:
        # A reserved-id no-public-card report is satisfied by card_source alone.
        cs = _good_card_source(
            triggers=["3.49.a"],
            widespread=False,
            death=True,
            awareness="2026-08-01T00:00:00Z",
            deadline="2026-08-11T00:00:00Z",
        )
        diags = ir.check_art73_existential([_report_record(cs)], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" not in _codes(diags)

    def test_empty_regulatory_timeline_does_not_satisfy_framework_match(self) -> None:
        cs = _good_card_source(
            triggers=["3.49.a"],
            widespread=False,
            death=True,
            awareness="2026-08-01T00:00:00Z",
            deadline=None,
        )
        cs["coordinated_disclosure"] = {"status": "coordinated", "regulatory_timeline": []}
        diags = ir.check_art73_existential([_report_record(cs)], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" in _codes(diags)

    def test_non_eu_only_regulatory_timeline_fails_framework_match(self) -> None:
        cs = _good_card_source(
            triggers=["3.49.a"],
            widespread=False,
            death=True,
            awareness="2026-08-01T00:00:00Z",
            deadline=None,
        )
        cs["coordinated_disclosure"] = {
            "status": "coordinated",
            "regulatory_timeline": [
                {
                    "framework": "us-circia",
                    "clock_model": "awareness_days",
                    "awareness_date": "2026-08-01T00:00:00Z",
                    "deadline": "2026-08-31T00:00:00Z",
                }
            ],
        }
        diags = ir.check_art73_existential([_report_record(cs)], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" in _codes(diags)

    def test_existential_skipped_when_profile_absent(self) -> None:
        empty_card = {
            "record_id": "rec-card-empty",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
        }
        diags = ir.check_art73_existential([empty_card], profiles=[])
        assert "ACEF-084" not in _codes(diags)


# ---------------------------------------------------------------------------
# VAL-PUB-001 — §5.11 publishability gate (ACEF-086)
# ---------------------------------------------------------------------------


def _published_card(payload_extra: dict[str, Any]) -> dict[str, Any]:
    base: dict[str, Any] = {
        "public_incident_id": _VALID_ID,
        "id_grade": "self-asserted",
        "harm_core": dict(_VALID_HARM_CORE),
        "coordinated_disclosure": {"status": "public", "reporter_role": "internal"},
    }
    base.update(payload_extra)
    return {"record_id": "rec-card-pub", "record_type": "incident_card", "payload": base}


class TestACEF086PublishabilityGate:
    def test_special_category_without_basis_raises_086(self) -> None:
        # harm_distribution_basis is GDPR Art.9 special-category; publishing it
        # verbatim with NO declared_publication_basis -> ACEF-086.
        card = _published_card({"harm_distribution_basis": ["race", "sex"]})
        diags = ir.check_publishability([card], source_backed=False)
        assert "ACEF-086" in _codes(diags)
        assert "ACEF-022" not in _codes(diags)

    def test_special_category_with_full_basis_passes(self) -> None:
        card = _published_card(
            {
                "harm_distribution_basis": ["race"],
                "declared_publication_basis": {
                    "art6_basis": "legitimate_interests",
                    "art9_condition": "substantial_public_interest",
                },
            }
        )
        diags = ir.check_publishability([card], source_backed=False)
        assert "ACEF-086" not in _codes(diags)

    def test_basis_with_only_art6_insufficient_raises_086(self) -> None:
        card = _published_card(
            {
                "harm_distribution_basis": ["race"],
                "declared_publication_basis": {"art6_basis": "legitimate_interests"},
            }
        )
        diags = ir.check_publishability([card], source_backed=False)
        assert "ACEF-086" in _codes(diags)

    def test_anonymization_method_satisfies_basis(self) -> None:
        card = _published_card(
            {
                "harm_distribution_basis": ["race"],
                "declared_publication_basis": {"anonymization_method": "k-anonymity k=5"},
            }
        )
        diags = ir.check_publishability([card], source_backed=False)
        assert "ACEF-086" not in _codes(diags)

    def test_unlinked_commitment_raises_086(self) -> None:
        # A *_commitment key whose disposition is NOT hash-committed in the source
        # publishability_map is an orphan -> ACEF-086 (source-backed only).
        report = _report_record(
            {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "id_state": "PUBLISHED",
                "harm_core": dict(_VALID_HARM_CORE),
                "publishability_map": {"/root_cause_analysis": "regulator-only"},
                "eu_ai_act_facts": {
                    "edition": "reg-2024-1689",
                    "serious_incident_triggers": ["3.49.a"],
                    "widespread": False,
                    "death_involved": False,
                },
            }
        )
        card = _published_card({"description_commitment": "sha256:" + "0" * 64})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" in _codes(diags)

    def test_unresolvable_pointer_source_backed_raises_086(self) -> None:
        # A publishability_map pointer that does not resolve in the source
        # incident_report -> ACEF-086 (source-backed only).
        report = _report_record(
            {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "id_state": "PUBLISHED",
                "harm_core": dict(_VALID_HARM_CORE),
                "publishability_map": {"/nonexistent_field": "regulator-only"},
                "eu_ai_act_facts": {
                    "edition": "reg-2024-1689",
                    "serious_incident_triggers": ["3.49.a"],
                    "widespread": False,
                    "death_involved": False,
                },
            }
        )
        diags = ir.check_publishability([report], source_backed=True)
        assert "ACEF-086" in _codes(diags)

    def test_pointer_not_resolved_in_card_only_mode(self) -> None:
        # card-only mode does NOT resolve publishability_map pointers (§5.11).
        report = _report_record(
            {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "id_state": "PUBLISHED",
                "harm_core": dict(_VALID_HARM_CORE),
                "publishability_map": {"/nonexistent_field": "regulator-only"},
                "eu_ai_act_facts": {
                    "edition": "reg-2024-1689",
                    "serious_incident_triggers": ["3.49.a"],
                    "widespread": False,
                    "death_involved": False,
                },
            }
        )
        diags = ir.check_publishability([report], source_backed=False)
        assert "ACEF-086" not in _codes(diags)

    def test_linked_commitment_matching_preimage_passes(self) -> None:
        # A *_commitment linked to a hash-committed source field whose preimage
        # equals sha256(JCS(source_value)) -> no ACEF-086 (source-backed).
        from acef.integrity import canonicalize, sha256_hex

        source_value = "sensitive description text"
        good_commit = "sha256:" + sha256_hex(canonicalize(source_value))
        report = _report_record(
            {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "id_state": "PUBLISHED",
                "harm_core": dict(_VALID_HARM_CORE),
                "publishability_map": {"/description": "hash-committed"},
                "eu_ai_act_facts": {
                    "edition": "reg-2024-1689",
                    "serious_incident_triggers": ["3.49.a"],
                    "widespread": False,
                    "death_involved": False,
                },
            }
        )
        # _report_record puts the source value at payload.description.
        report["payload"]["description"] = source_value
        card = _published_card({"description_commitment": good_commit})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" not in _codes(diags)

    def test_linked_commitment_wrong_preimage_raises_086(self) -> None:
        report = _report_record(
            {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "id_state": "PUBLISHED",
                "harm_core": dict(_VALID_HARM_CORE),
                "publishability_map": {"/description": "hash-committed"},
                "eu_ai_act_facts": {
                    "edition": "reg-2024-1689",
                    "serious_incident_triggers": ["3.49.a"],
                    "widespread": False,
                    "death_involved": False,
                },
            }
        )
        report["payload"]["description"] = "sensitive description text"
        card = _published_card({"description_commitment": "sha256:" + "1" * 64})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" in _codes(diags)

    # --- INCVAL-003: source-backed disposition-honored check -------------

    def _report_with_severity_disposition(self, disposition: str) -> dict[str, Any]:
        """An incident_report whose publishability_map disposes /severity, paired
        to a public card by public_incident_id. severity is the ONE field shared
        between the report root and incident_card (the narrow exploit surface)."""
        report = _report_record(
            {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "id_state": "PUBLISHED",
                "harm_core": dict(_VALID_HARM_CORE),
                "severity": "major",
                "publishability_map": {"/severity": disposition},
                "eu_ai_act_facts": {
                    "edition": "reg-2024-1689",
                    "serious_incident_triggers": ["3.49.a"],
                    "widespread": False,
                    "death_involved": False,
                },
            }
        )
        return report

    def test_regulator_only_field_present_on_card_raises_086(self) -> None:
        # /severity disposed regulator-only in the source map but COPIED onto the
        # public card -> dishonored disposition -> ACEF-086 (source-backed).
        report = self._report_with_severity_disposition("regulator-only")
        card = _published_card({"severity": "major"})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" in _codes(diags)

    def test_omitted_field_present_on_card_raises_086(self) -> None:
        # /severity disposed omitted but present on the card -> dishonored -> ACEF-086.
        report = self._report_with_severity_disposition("omitted")
        card = _published_card({"severity": "major"})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" in _codes(diags)

    def test_regulator_only_field_absent_from_card_passes(self) -> None:
        # /severity disposed regulator-only AND absent from the public card ->
        # disposition honored -> no ACEF-086.
        report = self._report_with_severity_disposition("regulator-only")
        card = _published_card({})  # no severity projected
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" not in _codes(diags)

    def test_regulator_only_dishonored_not_flagged_in_card_only_mode(self) -> None:
        # The disposition-honored check is source-backed ONLY (§5.11 / §6). In
        # card-only mode it does NOT fire (no source to read the map from).
        card = _published_card({"severity": "major"})
        diags = ir.check_publishability([card], source_backed=False)
        assert "ACEF-086" not in _codes(diags)

    def _report_with_nested_pointer_disposition(self, *, root_key: str, leaf: str, disposition: str) -> dict[str, Any]:
        """An incident_report whose publishability_map disposes a NESTED pointer
        ``/<root_key>/<leaf>`` that DOES resolve in the source (the nested object is
        placed at the report payload ROOT, where pointer resolution runs). This
        isolates the disposition-honored check: the only ACEF-086 in play would be
        the leaf-name collapse — which the fix removes for nested pointers."""
        report = _report_record(
            {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "id_state": "PUBLISHED",
                "harm_core": dict(_VALID_HARM_CORE),
                "publishability_map": {f"/{root_key}/{leaf}": disposition},
                "eu_ai_act_facts": {
                    "edition": "reg-2024-1689",
                    "serious_incident_triggers": ["3.49.a"],
                    "widespread": False,
                    "death_involved": False,
                },
            }
        )
        # Place the nested object at the report payload ROOT so the JSON Pointer
        # /<root_key>/<leaf> resolves (pointer resolution runs against the payload).
        report["payload"][root_key] = {leaf: "internal-value"}
        return report

    def test_nested_source_pointer_does_not_false_positive_on_unrelated_card_root(self) -> None:
        # A NESTED source pointer /details/severity disposed regulator-only must
        # NOT be collapsed to leaf 'severity' and matched against an UNRELATED card
        # root 'severity'. Pre-fix this raised a spurious ACEF-086; post-fix it does
        # NOT, because /details/severity is not a single-segment root pointer and so
        # does not name a card-root field.
        report = self._report_with_nested_pointer_disposition(
            root_key="details", leaf="severity", disposition="regulator-only"
        )
        card = _published_card({"severity": "major"})  # unrelated card-root severity
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" not in _codes(diags), (
            "nested source pointer /details/severity must not false-positive ACEF-086 "
            "against an unrelated card-root 'severity' field"
        )

    def test_nested_source_pointer_omitted_does_not_false_positive(self) -> None:
        # Same lock for the 'omitted' disposition: a nested /details/severity entry
        # must not trip the leaf-name collapse against a card-root 'severity'.
        report = self._report_with_nested_pointer_disposition(
            root_key="details", leaf="severity", disposition="omitted"
        )
        card = _published_card({"severity": "major"})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" not in _codes(diags)

    def test_internal_nested_pointer_with_root_public_incident_id_no_086(self) -> None:
        # A nested /internal/public_incident_id disposed regulator-only must not be
        # collapsed to 'public_incident_id' and flagged against the card's own
        # (legitimately present) root public_incident_id.
        report = self._report_with_nested_pointer_disposition(
            root_key="internal", leaf="public_incident_id", disposition="regulator-only"
        )
        card = _published_card({})  # card has its own root public_incident_id (always)
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" not in _codes(diags)

    # --- INCVAL-003 over-correction repair: explicit /card_source/<field>
    #     -> incident_card-root projection map. The single-segment-root filter
    #     introduced in 42873f56 dropped the LEGITIMATE source-to-card projection
    #     pointers (/card_source/severity_vector etc.), a real ACEF-086
    #     false-NEGATIVE. The projection map restores them WITHOUT reintroducing
    #     the nested-pointer false-positive. ----------------------------------

    _SEV_VECTOR = "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I"

    def _report_with_card_source_disposition(
        self,
        *,
        pointer: str,
        disposition: str,
        cs_extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """An incident_report whose publishability_map disposes ``pointer`` (a
        ``/card_source/<field>`` projection input that DOES resolve in the source,
        because card_source carries the field). Isolates the disposition-honored
        check for the source-to-card projection map."""
        card_source: dict[str, Any] = {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "id_state": "PUBLISHED",
            "harm_core": dict(_VALID_HARM_CORE),
            "severity_vector": self._SEV_VECTOR,
            "coordinated_disclosure": {"status": "public", "reporter_role": "internal"},
            "publishability_map": {pointer: disposition},
            "eu_ai_act_facts": {
                "edition": "reg-2024-1689",
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": False,
            },
        }
        if cs_extra:
            card_source.update(cs_extra)
        return _report_record(card_source)

    def test_card_source_severity_vector_regulator_only_present_raises_086(self) -> None:
        # THE roborev RED: /card_source/severity_vector (a REAL projection pointer)
        # disposed regulator-only while severity_vector IS published on the card ->
        # ACEF-086. Pre-fix (42873f56) the single-segment filter SKIPS this 3-segment
        # pointer entirely -> false-NEGATIVE (no ACEF-086). The projection map fires it.
        report = self._report_with_card_source_disposition(
            pointer="/card_source/severity_vector", disposition="regulator-only"
        )
        card = _published_card({"severity_vector": self._SEV_VECTOR})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" in _codes(diags)

    def test_card_source_severity_vector_omitted_present_raises_086(self) -> None:
        report = self._report_with_card_source_disposition(
            pointer="/card_source/severity_vector", disposition="omitted"
        )
        card = _published_card({"severity_vector": self._SEV_VECTOR})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" in _codes(diags)

    def test_card_source_severity_vector_regulator_only_absent_passes(self) -> None:
        # Disposition HONORED: regulator-only and severity_vector NOT on the card.
        report = self._report_with_card_source_disposition(
            pointer="/card_source/severity_vector", disposition="regulator-only"
        )
        card = _published_card({})  # no severity_vector projected
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" not in _codes(diags)

    def test_card_source_coordinated_disclosure_regulator_only_present_raises_086(self) -> None:
        # /card_source/coordinated_disclosure -> card root coordinated_disclosure.
        report = self._report_with_card_source_disposition(
            pointer="/card_source/coordinated_disclosure", disposition="regulator-only"
        )
        # _published_card always carries coordinated_disclosure (public boundary) ->
        # disposing it regulator-only while it is published is DISHONORED.
        card = _published_card({})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" in _codes(diags)

    def test_card_source_harm_core_regulator_only_present_raises_086(self) -> None:
        # /card_source/harm_core -> card root harm_core (always present on the card).
        report = self._report_with_card_source_disposition(pointer="/card_source/harm_core", disposition="omitted")
        card = _published_card({})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" in _codes(diags)

    def test_card_source_public_incident_id_regulator_only_present_raises_086(self) -> None:
        # /card_source/public_incident_id -> card root public_incident_id (always present).
        report = self._report_with_card_source_disposition(
            pointer="/card_source/public_incident_id", disposition="regulator-only"
        )
        card = _published_card({})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" in _codes(diags)

    def test_card_source_id_grade_regulator_only_present_raises_086(self) -> None:
        # /card_source/id_grade -> card root id_grade (always present).
        report = self._report_with_card_source_disposition(
            pointer="/card_source/id_grade", disposition="regulator-only"
        )
        card = _published_card({})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" in _codes(diags)

    def test_card_source_non_projecting_field_disposition_no_086(self) -> None:
        # A card_source field WITHOUT a card-root counterpart (id_state) is NOT in
        # the projection map, so disposing it regulator-only is not a card-leak
        # check at all -> no ACEF-086 from the disposition-honored rule. (The card
        # carries no 'id_state' root field; id_state lives only on card_source.)
        report = self._report_with_card_source_disposition(
            pointer="/card_source/id_state", disposition="regulator-only"
        )
        card = _published_card({})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" not in _codes(diags)

    def test_root_severity_regulator_only_present_still_raises_086(self) -> None:
        # RETAIN INCVAL-003: the incident_report-ROOT /severity projection ->
        # card root severity. Disposed regulator-only + severity on card -> ACEF-086.
        report = self._report_with_severity_disposition("regulator-only")
        card = _published_card({"severity": "major"})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" in _codes(diags)

    def test_arbitrary_nested_card_source_pointer_no_086(self) -> None:
        # RETAIN the 42873f56 false-positive fix: a DEEPER nested pointer under
        # card_source (/card_source/coordinated_disclosure/foo) is NOT in the
        # projection map -> ignored, no ACEF-086, even with an unrelated card root.
        report = self._report_with_card_source_disposition(
            pointer="/card_source/coordinated_disclosure/foo",
            disposition="regulator-only",
            cs_extra={"coordinated_disclosure": {"status": "public", "foo": "internal"}},
        )
        card = _published_card({})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" not in _codes(diags), (
            "a deeper-nested /card_source/<field>/<sub> pointer is not a projection-map "
            "entry and must not false-positive ACEF-086"
        )

    def test_unrelated_root_pointer_details_severity_no_086(self) -> None:
        # RETAIN: an unrelated root-nested pointer /details/severity is not in the
        # projection map (its only single root segment is 'details', not a card-root
        # field) -> no ACEF-086 even with an unrelated card-root severity.
        report = self._report_with_nested_pointer_disposition(
            root_key="details", leaf="severity", disposition="regulator-only"
        )
        card = _published_card({"severity": "major"})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" not in _codes(diags)


# ---------------------------------------------------------------------------
# Structural-review P2 — the commitment-linkage canonicalize() of an
# attacker-controlled hash-committed source value MUST NOT crash offline
# validation. An out-of-domain source value (integer magnitude > 2^53, NaN,
# Infinity) is one that json.loads parses but rfc8785.dumps rejects; feeding it
# to canonicalize() raises rfc8785.CanonicalizationError. The fix wraps JUST the
# canonicalize(source_value) call and treats the fault as a commitment FAILURE
# (precise ACEF-086), NOT a crash — so a valid sha256(JCS(source_value))
# commitment cannot exist for it. The in-domain mismatch path is unchanged.
# ---------------------------------------------------------------------------


# An integer with |value| > 2^53 — json.loads parses it; rfc8785.dumps rejects it
# (IntegerDomainError). 2^53 == 9007199254740992; this is far above the boundary.
_OUT_OF_DOMAIN_BIG_INT = 123456789012345678901234567890


class TestACEF086CommitmentSourceOutOfDomain:
    def _source_backed_pair_with_committed_source(
        self, *, source_value: Any, commitment: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """A source-backed (report, card) pair where the report payload root
        carries ``foo`` = ``source_value`` (the hash-committed source field) and
        the public incident_card carries ``foo_commitment``. ``/foo`` is disposed
        ``hash-committed`` in the source publishability_map, so the linkage block
        computes ``sha256(JCS(source_value))`` over ``source_value`` at line 1583.
        The card is at the public boundary (coordinated_disclosure.status:public)
        with the matching public_incident_id."""
        report = _report_record(
            {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "id_state": "PUBLISHED",
                "harm_core": dict(_VALID_HARM_CORE),
                "publishability_map": {"/foo": "hash-committed"},
                "eu_ai_act_facts": {
                    "edition": "reg-2024-1689",
                    "serious_incident_triggers": ["3.49.a"],
                    "widespread": False,
                    "death_involved": False,
                },
            }
        )
        # The hash-committed source value lives at the report payload ROOT, where
        # the /foo pointer resolves (commitment linkage reads source_payload).
        report["payload"]["foo"] = source_value
        card = _published_card({"foo_commitment": commitment})
        return report, card

    def test_out_of_domain_source_value_emits_086_not_crash(self) -> None:
        # The committed source value at /foo is an integer with |value| > 2^53 —
        # OUTSIDE the RFC-8785 / I-JSON domain. Pre-fix: canonicalize(source_value)
        # raises rfc8785.CanonicalizationError, which propagates out of
        # check_publishability (the call at line 1583 is unguarded) and crashes
        # the rule run. Post-fix: a PRECISE, non-fatal ACEF-086 commitment-linkage
        # diagnostic for /foo is emitted and the call NEVER raises.
        report, card = self._source_backed_pair_with_committed_source(
            source_value=_OUT_OF_DOMAIN_BIG_INT,
            commitment="sha256:" + "0" * 64,
        )
        # MUST NOT raise.
        diags = ir.check_publishability([card, report], source_backed=True)
        codes = _codes(diags)
        assert "ACEF-086" in codes, (
            "an out-of-domain committed source value must yield a commitment-linkage "
            "ACEF-086 (a valid sha256(JCS(source)) cannot exist for it), not a crash"
        )
        # The diagnostic must localize the offending source pointer and explain the
        # out-of-domain cause precisely (so the producer can act on it).
        linkage = [d for d in diags if d.code == "ACEF-086" and "/foo" in d.message]
        assert linkage, "ACEF-086 must reference the out-of-domain source pointer /foo"
        assert any("RFC 8785" in d.message or "RFC-8785" in d.message or "I-JSON" in d.message for d in linkage), (
            "the diagnostic must explain the source value is outside the RFC-8785/I-JSON domain"
        )

    def test_in_domain_mismatch_still_emits_normal_086(self) -> None:
        # CONTROL: an IN-DOMAIN source value whose commitment is WRONG must still
        # take the EXISTING ACEF-086 mismatch path (unchanged by the guard — the
        # guard is scoped to JUST the canonicalize call).
        report, card = self._source_backed_pair_with_committed_source(
            source_value="an ordinary in-domain string",
            commitment="sha256:" + "1" * 64,  # deliberately wrong preimage
        )
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" in _codes(diags)

    def test_in_domain_correct_commitment_still_passes(self) -> None:
        # CONTROL: an IN-DOMAIN source value with the CORRECT preimage must still
        # pass (no ACEF-086) — the guard must not perturb the legitimate path.
        source_value = "an ordinary in-domain string"
        good_commit = "sha256:" + sha256_hex(canonicalize(source_value))
        report, card = self._source_backed_pair_with_committed_source(
            source_value=source_value,
            commitment=good_commit,
        )
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" not in _codes(diags)

    def test_out_of_domain_does_not_abort_downstream_rules_in_full_run(self) -> None:
        # report-all-errors MUST be preserved: an out-of-domain committed source
        # value flagged by check_publishability MUST NOT abort the LATER incident
        # rules in run_incident_rules. We arm a downstream rule (ACEF-087 near_miss
        # marker, which runs AFTER check_publishability) and assert BOTH the precise
        # ACEF-086 (for /foo) AND the downstream ACEF-087 are produced.
        report, card = self._source_backed_pair_with_committed_source(
            source_value=_OUT_OF_DOMAIN_BIG_INT,
            commitment="sha256:" + "0" * 64,
        )
        # Arm the downstream near-miss rule on the SAME source: realization is
        # near_miss in card_source.harm_core (the container check_near_miss_marker
        # inspects), so ACEF-087 fires ONLY if check_publishability did not abort.
        report["payload"]["card_source"]["harm_core"]["realization"] = "near_miss"
        diags = ir.run_incident_rules({}, [card, report])
        codes = _codes(diags)
        assert "ACEF-086" in codes, "precise commitment-linkage ACEF-086 must be emitted"
        assert "ACEF-087" in codes, (
            "the downstream near-miss rule (ACEF-087) MUST still run — the "
            "out-of-domain canonicalize() must not abort the remaining incident rules"
        )
        # And no generic FATAL ACEF-001 backstop must appear at the rule level.
        assert "ACEF-001" not in codes


# ---------------------------------------------------------------------------
# ACEF-081 — incident profile declared but crosswalk missing a mandatory member
# ---------------------------------------------------------------------------


def _bare_card_no_crosswalk_member() -> dict[str, Any]:
    return {
        "record_id": "rec-card-1",
        "record_type": "incident_card",
        "payload": {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
            "taxonomy_crosswalk": {"nist_ai_600_1": {"edition": "2024-07-final", "categories": []}},
        },
    }


class TestACEF081:
    def test_art73_profile_without_eu_ai_act_member_raises_081(self) -> None:
        diags = ir.check_crosswalk_mandatory_members(
            [_bare_card_no_crosswalk_member()], profiles=["eu-ai-act-art73-2026"]
        )
        assert "ACEF-081" in _codes(diags)

    def test_art73_profile_with_eu_ai_act_member_passes(self) -> None:
        card = {
            "record_id": "rec-card-1",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
                "taxonomy_crosswalk": {
                    "eu_ai_act": {"edition": "reg-2024-1689", "serious_incident_triggers": ["3.49.a"]}
                },
            },
        }
        diags = ir.check_crosswalk_mandatory_members([card], profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-081" not in _codes(diags)


class TestACEF081LegalForceAware:
    """Finding 1: the ACEF-081 missing-crosswalk-member check is legal_force-aware.

    A BINDING profile (eu-ai-act-art73-2026) keeps ACEF-081 at ERROR severity.
    A VOLUNTARY/advisory profile (oecd-ai-incidents-2025) must NOT emit a binding
    ACEF-081 error — the missing member surfaces as an ADVISORY (warning/info)
    diagnostic that does not block conformance, consistent with the template's
    legal_force=voluntary marking.
    """

    def test_binding_profile_missing_member_is_error_severity(self) -> None:
        diags = ir.check_crosswalk_mandatory_members(
            [_bare_card_no_crosswalk_member()], profiles=["eu-ai-act-art73-2026"]
        )
        d081 = [d for d in diags if d.code == "ACEF-081"]
        assert d081, "binding Art.73 profile must still raise ACEF-081 for a missing member"
        assert all(d.severity.value == "error" for d in d081), (
            "a BINDING profile's missing mandatory crosswalk member must remain ERROR severity"
        )

    def test_voluntary_oecd_profile_missing_member_is_advisory_not_binding(self) -> None:
        # OECD profile declared but the card has no taxonomy_crosswalk.oecd member.
        # The diagnostic MUST NOT be a binding ACEF-081 error; it surfaces advisory.
        diags = ir.check_crosswalk_mandatory_members(
            [_bare_card_no_crosswalk_member()], profiles=["oecd-ai-incidents-2025"]
        )
        # No binding (error-severity) ACEF-081 may be emitted for a voluntary profile.
        binding = [d for d in diags if d.code == "ACEF-081" and d.severity.value == "error"]
        assert not binding, (
            "a VOLUNTARY OECD profile produced a BINDING ACEF-081 error; voluntary "
            "missing-member must be advisory (warning/info), never error"
        )
        # An advisory diagnostic SHOULD still be surfaced (warning/info) so the gap
        # is visible without blocking conformance.
        advisory = [d for d in diags if d.severity.value in {"warning", "info"}]
        assert advisory, "the voluntary missing-member gap should surface an advisory diagnostic"

    def test_unknown_profile_defaults_to_strict_error(self) -> None:
        # An unknown profile (no template) must default to the strict ERROR
        # behavior — never silently downgrade to advisory.
        diags = ir.check_crosswalk_mandatory_members(
            [_bare_card_no_crosswalk_member()], profiles=["eu-ai-act-art73-2026"]
        )
        assert any(d.code == "ACEF-081" and d.severity.value == "error" for d in diags)


# ---------------------------------------------------------------------------
# OECD mandatory-core completeness — advisory (Finding 2)
# ---------------------------------------------------------------------------

# The 7 mandatory OECD ordinals (#1,2,3,4,7,10,11) — read from the template in
# the source under test; mirrored here for the assertions.
_OECD_MANDATORY = [1, 2, 3, 4, 7, 10, 11]
_OECD_PROFILE = "oecd-ai-incidents-2025"


def _oecd_crit_id(n: int) -> str:
    return f"oecd-crf-2025/{n}"


def _oecd_card(criteria_ordinals: list[int]) -> dict[str, Any]:
    return {
        "record_id": "rec-oecd-1",
        "record_type": "incident_card",
        "payload": {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
            "taxonomy_crosswalk": {
                "oecd": {
                    "edition": "oecd-crf-2025",
                    "criteria": [{"id": _oecd_crit_id(n), "value": f"v-{n}"} for n in criteria_ordinals],
                }
            },
        },
    }


class TestOECDMandatoryCoreCompleteness:
    """Finding 2: a REAL advisory OECD mandatory-core completeness check.

    When the OECD profile is declared and a taxonomy_crosswalk.oecd member is
    present, the validator scans criteria[].id (order-insensitive) for the 7
    mandatory OECD ordinals and emits an ADVISORY (warning/info) diagnostic
    listing any missing mandatory ids. It is NEVER a binding error.
    """

    def test_missing_mandatory_criteria_surfaces_advisory_listing_gaps(self) -> None:
        # Present: edition + only #1; missing #2,3,4,7,10,11.
        card = _oecd_card([1])
        diags = ir.check_oecd_mandatory_core_completeness([card], profiles=[_OECD_PROFILE])
        assert diags, "a card with an OECD member but missing mandatory criteria must surface a completeness advisory"
        # Advisory only — never error/fatal severity (voluntary profile).
        assert all(d.severity.value in {"warning", "info"} for d in diags), (
            "the OECD completeness diagnostic must be advisory (warning/info), never binding"
        )
        # The diagnostic enumerates each missing mandatory ordinal id (structured
        # details list is the precise surface; the message text mirrors it).
        listed_missing: set[str] = set()
        for d in diags:
            listed_missing.update(d.details.get("missing_mandatory_criteria", []))
        for n in (2, 3, 4, 7, 10, 11):
            assert _oecd_crit_id(n) in listed_missing, (
                f"missing mandatory {_oecd_crit_id(n)} not listed in the advisory"
            )
        # Present criterion #1 must NOT be reported as missing (exact-id, not a
        # substring of e.g. oecd-crf-2025/10).
        assert _oecd_crit_id(1) not in listed_missing, "present criterion #1 must NOT be listed as missing"

    def test_all_seven_mandatory_present_no_advisory(self) -> None:
        card = _oecd_card(_OECD_MANDATORY)
        diags = ir.check_oecd_mandatory_core_completeness([card], profiles=[_OECD_PROFILE])
        assert diags == [], "a card carrying all 7 mandatory OECD criteria must produce no completeness advisory"

    def test_no_oecd_member_no_completeness_advisory(self) -> None:
        # No oecd crosswalk member at all -> the completeness check is a no-op here
        # (the missing-member case is the legal_force-aware ACEF-081 advisory, not
        # this per-ordinal completeness scan).
        card = _bare_card_no_crosswalk_member()
        diags = ir.check_oecd_mandatory_core_completeness([card], profiles=[_OECD_PROFILE])
        assert diags == []

    def test_check_is_skipped_when_oecd_profile_not_declared(self) -> None:
        card = _oecd_card([1])  # missing mandatory criteria, but OECD not declared
        diags = ir.check_oecd_mandatory_core_completeness([card], profiles=["eu-ai-act-art73-2026"])
        assert diags == []

    def test_completeness_is_order_insensitive(self) -> None:
        # criteria[] supplied in a scrambled order -> still complete, no advisory.
        scrambled = list(reversed(_OECD_MANDATORY))
        card = _oecd_card(scrambled)
        diags = ir.check_oecd_mandatory_core_completeness([card], profiles=[_OECD_PROFILE])
        assert diags == []


# ---------------------------------------------------------------------------
# ACEF-082 — severity_vector unparseable against ACEF-SEV:1.0
# ---------------------------------------------------------------------------


class TestACEF082:
    def test_unparseable_vector_raises_082(self) -> None:
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {"severity_vector": "ACEF-SEV:1.0/HT:P/RV:A/SC:U/BR:I"},  # HG missing
        }
        diags = ir.check_severity_vector_parse([card])
        assert "ACEF-082" in _codes(diags)

    def test_valid_vector_passes(self) -> None:
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {"severity_vector": "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I"},
        }
        diags = ir.check_severity_vector_parse([card])
        assert "ACEF-082" not in _codes(diags)


# ---------------------------------------------------------------------------
# ACEF-083 — offline id-trust (NO attribution; forged card passes)
# ---------------------------------------------------------------------------


class TestACEF083Offline:
    def test_forged_assigner_self_consistent_passes_offline(self) -> None:
        # HONESTY DISCIPLINE: a forged AIIC-OPENAI-... card with a valid pattern
        # and no contradicting snapshot/JWS MUST pass the offline class.
        forged_id = f"AIIC-OPENAI-2026-{_SUFFIX}"
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": forged_id,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
        }
        diags = ir.check_public_incident_id_offline([card], manifest={})
        assert "ACEF-083" not in _codes(diags)

    def test_pattern_mismatch_raises_083(self) -> None:
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": "AIIC-OPENAI-2026-tooshort",
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
        }
        diags = ir.check_public_incident_id_offline([card], manifest={})
        codes = _codes(diags)
        assert "ACEF-083" in codes
        # The diagnostic is class-tagged offline-deterministic.
        d083 = next(d for d in diags if d.code == "ACEF-083")
        assert "offline-deterministic" in d083.message

    def test_assigner_absent_from_bundled_snapshot_raises_083(self) -> None:
        # When a snapshot IS bundled, local membership is checked.
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
        }
        manifest = {
            "namespaces": {
                "x-acef-incident": {"assigner_registry_snapshot": [{"assigner": "ANTHROPIC", "public_key": "k1"}]}
            }
        }
        diags = ir.check_public_incident_id_offline([card], manifest=manifest)
        assert "ACEF-083" in _codes(diags)

    def test_assigner_present_in_bundled_snapshot_passes(self) -> None:
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
        }
        manifest = {
            "namespaces": {
                "x-acef-incident": {"assigner_registry_snapshot": [{"assigner": "OPENAI", "public_key": "k1"}]}
            }
        }
        diags = ir.check_public_incident_id_offline([card], manifest=manifest)
        assert "ACEF-083" not in _codes(diags)

    def test_no_network_call_made(self, monkeypatch: Any) -> None:
        # Offline validation MUST perform no network access. Poison socket.
        import socket

        def _boom(*_a: Any, **_k: Any) -> None:
            raise AssertionError("offline validation must not open a socket")

        monkeypatch.setattr(socket.socket, "connect", _boom)
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
        }
        diags = ir.check_public_incident_id_offline([card], manifest={})
        assert "ACEF-083" not in _codes(diags)

    # --- §5.3(ii) JWS self-consistency (INCVAL-001) ------------------------

    def test_signed_card_matching_key_passes(self) -> None:
        # A card signed with a self-consistent detached JWS over /payload (key
        # embedded in the JWS header) verifies against its OWN key -> no ACEF-083.
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
        }
        signed = _sign_incident_record(card)
        diags = ir.check_public_incident_id_offline([signed], manifest={})
        assert "ACEF-083" not in _codes(diags)

    def test_signed_card_tampered_payload_raises_083(self) -> None:
        # Tamper the payload AFTER signing: the detached JWS no longer verifies
        # against its embedded key -> JWS self-inconsistency -> ACEF-083
        # (class:offline-deterministic).
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
        }
        signed = _sign_incident_record(card)
        signed["payload"]["harm_core"]["harm_class"] = "economic"  # tamper post-sign
        diags = ir.check_public_incident_id_offline([signed], manifest={})
        codes = _codes(diags)
        assert "ACEF-083" in codes
        d083 = next(d for d in diags if d.code == "ACEF-083")
        assert "offline-deterministic" in d083.message
        assert "JWS" in d083.message or "self-consisten" in d083.message.lower()

    def test_signed_card_wrong_key_raises_083(self) -> None:
        # Re-sign with a DIFFERENT key so the embedded JWK no longer matches the
        # signature material the original key produced. Achieved by swapping in a
        # JWS made over a DIFFERENT payload (the signature does not verify against
        # THIS card's /payload) -> ACEF-083.
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
        }
        # Sign a DIFFERENT card, then graft its attestation onto this card: the
        # grafted JWS verifies against its own embedded key but NOT over this
        # card's /payload (the signed bytes differ) -> self-inconsistent.
        other = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": {**_VALID_HARM_CORE, "harm_class": "economic"},
            },
        }
        signed_other = _sign_incident_record(other)
        card["attestation"] = signed_other["attestation"]
        diags = ir.check_public_incident_id_offline([card], manifest={})
        assert "ACEF-083" in _codes(diags)

    def test_forged_assigner_with_self_consistent_jws_still_passes(self) -> None:
        # HONESTY DISCIPLINE: a FORGED-assigner card (AIIC-OPENAI-...) that is
        # signed with a SELF-CONSISTENT JWS MUST still pass offline. The offline
        # class verifies self-consistency ONLY (attribution-free); it never proves
        # the signer controls openai.com. Only a self-INconsistent JWS raises.
        forged = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": f"AIIC-OPENAI-2026-{_SUFFIX}",
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
        }
        signed = _sign_incident_record(forged)
        diags = ir.check_public_incident_id_offline([signed], manifest={})
        assert "ACEF-083" not in _codes(diags)

    def test_unsigned_card_no_attestation_passes(self) -> None:
        # No attestation block -> the JWS sub-check is skipped entirely (the card
        # is unsigned); pattern still governs. An unsigned valid-pattern card
        # passes offline.
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
        }
        diags = ir.check_public_incident_id_offline([card], manifest={})
        assert "ACEF-083" not in _codes(diags)

    def test_signed_card_non_jws_method_skipped(self) -> None:
        # A non-jws attestation method does NOT trigger the JWS self-consistency
        # sub-check (v1 record attestation is jws-only; a non-jws method is not a
        # self-inconsistent JWS). No ACEF-083 from this branch.
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
            "attestation": {"method": "c2pa", "signer": "provider", "signature": "x"},
        }
        diags = ir.check_public_incident_id_offline([card], manifest={})
        assert "ACEF-083" not in _codes(diags)


# ---------------------------------------------------------------------------
# ACEF-085 — crosswalk member contradicts harm_core derivation
# ---------------------------------------------------------------------------


class TestACEF085:
    def test_contradicting_nist_member_raises_085(self) -> None:
        # harm_class physical_health derives nist categories {CBRN..., Dangerous...};
        # a member listing an unrelated NIST category contradicts the core.
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "harm_core": dict(_VALID_HARM_CORE),  # physical_health
                "taxonomy_crosswalk": {"nist_ai_600_1": {"edition": "2024-07-final", "categories": ["Data Privacy"]}},
            },
        }
        diags = ir.check_crosswalk_harm_core_consistency([card])
        assert "ACEF-085" in _codes(diags)

    def test_consistent_nist_member_passes(self) -> None:
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "harm_core": dict(_VALID_HARM_CORE),
                "taxonomy_crosswalk": {
                    "nist_ai_600_1": {
                        "edition": "2024-07-final",
                        "categories": ["CBRN Information or Capabilities"],
                    }
                },
            },
        }
        diags = ir.check_crosswalk_harm_core_consistency([card])
        assert "ACEF-085" not in _codes(diags)

    def test_eu_ai_act_trigger_contradicts_harm_class_raises_085(self) -> None:
        # harm_class physical_health keys to trigger 3.49.a; a member asserting
        # ONLY 3.49.d (property_or_environment) — and MISSING the derived 3.49.a —
        # contradicts the core.
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "harm_core": dict(_VALID_HARM_CORE),
                "taxonomy_crosswalk": {
                    "eu_ai_act": {"edition": "reg-2024-1689", "serious_incident_triggers": ["3.49.d"]}
                },
            },
        }
        diags = ir.check_crosswalk_harm_core_consistency([card])
        assert "ACEF-085" in _codes(diags)

    def test_compound_triggers_with_derived_present_passes(self) -> None:
        # A COMPOUND incident: harm_class physical_health derives 3.49.a; the array
        # carries 3.49.a (present) PLUS 3.49.b (critical_infrastructure, a different
        # keyed class). One incident may satisfy multiple Art.3(49) triggers
        # (RFC §5.5/§5.7) — the additional 3.49.b is NOT a contradiction. No ACEF-085.
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "harm_core": dict(_VALID_HARM_CORE),  # physical_health
                "taxonomy_crosswalk": {
                    "eu_ai_act": {
                        "edition": "reg-2024-1689",
                        "serious_incident_triggers": ["3.49.a", "3.49.b"],
                    }
                },
            },
        }
        diags = ir.check_crosswalk_harm_core_consistency([card])
        assert "ACEF-085" not in _codes(diags)

    def test_triggers_present_but_missing_derived_raises_085(self) -> None:
        # harm_class physical_health derives 3.49.a; an array with triggers but
        # WITHOUT 3.49.a (e.g. only 3.49.b/3.49.d) contradicts the derived core.
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "harm_core": dict(_VALID_HARM_CORE),  # physical_health -> 3.49.a
                "taxonomy_crosswalk": {
                    "eu_ai_act": {
                        "edition": "reg-2024-1689",
                        "serious_incident_triggers": ["3.49.b", "3.49.d"],
                    }
                },
            },
        }
        diags = ir.check_crosswalk_harm_core_consistency([card])
        assert "ACEF-085" in _codes(diags)


# ---------------------------------------------------------------------------
# ACEF-087 — near_miss INFO marker (never a failure)
# ---------------------------------------------------------------------------


class TestACEF087:
    def test_near_miss_emits_info_087(self) -> None:
        hc = dict(_VALID_HARM_CORE)
        hc["realization"] = "near_miss"
        card = {"record_id": "r", "record_type": "incident_card", "payload": {"harm_core": hc}}
        diags = ir.check_near_miss_marker([card])
        d = next((x for x in diags if x.code == "ACEF-087"), None)
        assert d is not None
        assert d.severity.value == "info"

    def test_harm_event_emits_no_087(self) -> None:
        card = {"record_id": "r", "record_type": "incident_card", "payload": {"harm_core": dict(_VALID_HARM_CORE)}}
        diags = ir.check_near_miss_marker([card])
        assert "ACEF-087" not in _codes(diags)


# ---------------------------------------------------------------------------
# ACEF-088 — severity disagrees with band(severity_vector)
# ---------------------------------------------------------------------------


class TestACEF088:
    def test_severity_disagrees_with_band_raises_088(self) -> None:
        # band(HG:H/BR:P) -> critical, but severity says minor.
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "severity": "minor",
                "severity_vector": "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:P",
            },
        }
        diags = ir.check_severity_band_consistency([card])
        assert "ACEF-088" in _codes(diags)

    def test_severity_agrees_with_band_passes(self) -> None:
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {
                "severity": "critical",
                "severity_vector": "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:P",
            },
        }
        diags = ir.check_severity_band_consistency([card])
        assert "ACEF-088" not in _codes(diags)

    def test_only_severity_present_no_088(self) -> None:
        card = {"record_id": "r", "record_type": "incident_card", "payload": {"severity": "minor"}}
        diags = ir.check_severity_band_consistency([card])
        assert "ACEF-088" not in _codes(diags)

    def test_only_vector_present_no_088(self) -> None:
        card = {
            "record_id": "r",
            "record_type": "incident_card",
            "payload": {"severity_vector": "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:P"},
        }
        diags = ir.check_severity_band_consistency([card])
        assert "ACEF-088" not in _codes(diags)

    def test_cross_container_root_severity_vs_card_source_vector_raises_088(self) -> None:
        # A source-backed incident_report carries the REQUIRED root payload.severity
        # while the severity_vector lives under payload.card_source. band() of the
        # card_source vector -> critical, but root severity says minor -> ACEF-088.
        report = {
            "record_id": "rec-report-1",
            "record_type": "incident_report",
            "payload": {
                "incident_type": "malfunction",
                "severity": "minor",
                "description": "x",
                "card_source": {
                    "public_incident_id": _VALID_ID,
                    "id_grade": "self-asserted",
                    "harm_core": dict(_VALID_HARM_CORE),
                    "severity_vector": "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:P",
                },
            },
        }
        diags = ir.check_severity_band_consistency([report])
        assert "ACEF-088" in _codes(diags)

    def test_cross_container_root_severity_matches_card_source_vector_passes(self) -> None:
        report = {
            "record_id": "rec-report-1",
            "record_type": "incident_report",
            "payload": {
                "incident_type": "malfunction",
                "severity": "critical",
                "description": "x",
                "card_source": {
                    "public_incident_id": _VALID_ID,
                    "id_grade": "self-asserted",
                    "harm_core": dict(_VALID_HARM_CORE),
                    "severity_vector": "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:P",
                },
            },
        }
        diags = ir.check_severity_band_consistency([report])
        assert "ACEF-088" not in _codes(diags)

    def test_root_vector_match_does_not_mask_card_source_mismatch_raises_088(self) -> None:
        # Source-backed incident_report: the REQUIRED root payload.severity is
        # "major" and a root payload.severity_vector ALSO projects to "major"
        # (BR:I/RV:A -> no escalation), so the root-vs-root comparison passes.
        # BUT payload.card_source.severity_vector escalates (BR:P -> critical) and
        # therefore DISAGREES with the governing root severity "major". The matching
        # root vector MUST NOT mask the card_source mismatch -> ACEF-088 still fires.
        report = {
            "record_id": "rec-report-1",
            "record_type": "incident_report",
            "payload": {
                "incident_type": "malfunction",
                "severity": "major",
                "severity_vector": "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",  # band -> major
                "description": "x",
                "card_source": {
                    "public_incident_id": _VALID_ID,
                    "id_grade": "self-asserted",
                    "harm_core": dict(_VALID_HARM_CORE),
                    # band -> critical (BR:P escalates), disagrees with root "major"
                    "severity_vector": "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:P",
                },
            },
        }
        diags = ir.check_severity_band_consistency([report])
        codes = _codes(diags)
        assert "ACEF-088" in codes
        # exactly one ACEF-088 for the single genuine (card_source) mismatch — the
        # passing root-vs-root comparison must not add a second.
        assert codes.count("ACEF-088") == 1

    def test_root_vector_and_card_source_vector_both_agree_no_088(self) -> None:
        # Positive control: root severity "major", root vector band -> major, and
        # card_source vector band -> major as well. No mismatch on any surface.
        report = {
            "record_id": "rec-report-1",
            "record_type": "incident_report",
            "payload": {
                "incident_type": "malfunction",
                "severity": "major",
                "severity_vector": "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",  # band -> major
                "description": "x",
                "card_source": {
                    "public_incident_id": _VALID_ID,
                    "id_grade": "self-asserted",
                    "harm_core": dict(_VALID_HARM_CORE),
                    "severity_vector": "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",  # band -> major
                },
            },
        }
        diags = ir.check_severity_band_consistency([report])
        assert "ACEF-088" not in _codes(diags)


# ---------------------------------------------------------------------------
# §5.5 incident_dedupe_key emit/omit confidentiality rule (ACEF-086).
#
# The subject-bearing incident_dedupe_key MUST be emitted ONLY on a
# PUBLISHED/public record; on ANY non-public record it MUST be OMITTED (three of
# four inputs are low-entropy/enumerable, so a published unsalted key would be
# offline-enumerable — §5.5, resolves Q20). A non-public record that EMITS
# incident_dedupe_key is a forged emit-on-non-public and FAILS validation. The
# keyed incident_dedupe_key_hmac variant is safe (pepper-keyed) and is NOT
# subject to the omit rule.
# ---------------------------------------------------------------------------

_GOOD_DEDUPE_KEY = "sha256:" + "a" * 64
_GOOD_DEDUPE_HMAC = "hmac-sha256:" + "b" * 64


def _dedupe_card(*, confidentiality: str, payload_extra: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "public_incident_id": _VALID_ID,
        "id_grade": "self-asserted",
        "harm_core": dict(_VALID_HARM_CORE),
    }
    payload.update(payload_extra)
    return {
        "record_id": "rec-dedupe-1",
        "record_type": "incident_card",
        "confidentiality": confidentiality,
        "payload": payload,
    }


class TestDedupeKeyConfidentiality:
    def test_public_card_with_dedupe_key_passes(self) -> None:
        card = _dedupe_card(
            confidentiality="public",
            payload_extra={"incident_dedupe_key": _GOOD_DEDUPE_KEY},
        )
        diags = ir.check_dedupe_key_confidentiality([card])
        assert "ACEF-086" not in _codes(diags)

    def test_non_public_card_emitting_dedupe_key_fails_086(self) -> None:
        # The forged emit-on-non-public: a regulator-only record MUST NOT carry the
        # subject-bearing key.
        card = _dedupe_card(
            confidentiality="regulator-only",
            payload_extra={"incident_dedupe_key": _GOOD_DEDUPE_KEY},
        )
        diags = ir.check_dedupe_key_confidentiality([card])
        assert "ACEF-086" in _codes(diags)
        # The reserved §5.11 publishability code is used — NOT ACEF-022.
        assert "ACEF-022" not in _codes(diags)
        d = next(d for d in diags if d.code == "ACEF-086")
        assert "incident_dedupe_key" in d.message

    def test_redacted_card_emitting_dedupe_key_fails_086(self) -> None:
        card = _dedupe_card(
            confidentiality="redacted",
            payload_extra={"incident_dedupe_key": _GOOD_DEDUPE_KEY},
        )
        assert "ACEF-086" in _codes(ir.check_dedupe_key_confidentiality([card]))

    def test_hash_committed_card_emitting_dedupe_key_fails_086(self) -> None:
        card = _dedupe_card(
            confidentiality="hash-committed",
            payload_extra={"incident_dedupe_key": _GOOD_DEDUPE_KEY},
        )
        assert "ACEF-086" in _codes(ir.check_dedupe_key_confidentiality([card]))

    def test_non_public_card_omitting_dedupe_key_passes(self) -> None:
        card = _dedupe_card(confidentiality="regulator-only", payload_extra={})
        assert "ACEF-086" not in _codes(ir.check_dedupe_key_confidentiality([card]))

    def test_non_public_card_with_only_hmac_variant_passes(self) -> None:
        # The keyed HMAC variant is safe (pepper-keyed) and is NOT subject to the
        # public-only omit rule — a non-public record MAY carry it.
        card = _dedupe_card(
            confidentiality="regulator-only",
            payload_extra={"incident_dedupe_key_hmac": _GOOD_DEDUPE_HMAC},
        )
        assert "ACEF-086" not in _codes(ir.check_dedupe_key_confidentiality([card]))

    def test_incident_report_non_public_emitting_key_fails_086(self) -> None:
        report = {
            "record_id": "rec-report-1",
            "record_type": "incident_report",
            "confidentiality": "regulator-only",
            "payload": {
                "incident_type": "malfunction",
                "severity": "major",
                "description": "x",
                "incident_dedupe_key": _GOOD_DEDUPE_KEY,
            },
        }
        assert "ACEF-086" in _codes(ir.check_dedupe_key_confidentiality([report]))

    def test_rule_is_wired_into_run_incident_rules(self) -> None:
        # End-to-end: the aggregate run_incident_rules surfaces the emit-on-non-public
        # failure (the rule is registered in the dispatch).
        card = _dedupe_card(
            confidentiality="regulator-only",
            payload_extra={"incident_dedupe_key": _GOOD_DEDUPE_KEY},
        )
        diags = ir.run_incident_rules({}, [card])
        assert "ACEF-086" in _codes(diags)


# ---------------------------------------------------------------------------
# Finding 3 — rule-level SHAPE validation of incident_dedupe_key /
# incident_dedupe_key_hmac on BOTH record types (incident_card + incident_report).
#
# The v1.1 incident_report schema has additionalProperties: true and does NOT
# define these two properties, so a MALFORMED dedupe value on a report payload is
# NOT caught at the schema phase. The validator rule mirrors the incident_card
# schema patterns (^sha256:[0-9a-f]{64}$ / ^hmac-sha256:[0-9a-f]{64}$) so a
# malformed value FAILS validation with ACEF-086 regardless of record type.
# ---------------------------------------------------------------------------

# Malformed values an attacker / buggy producer might emit.
_BAD_DEDUPE_KEY_UPPER = "sha256:" + "A" * 64  # uppercase hex — not [0-9a-f]
_BAD_DEDUPE_KEY_SHORT = "sha256:" + "a" * 63  # 63 hex chars
_BAD_DEDUPE_KEY_NOPREFIX = "a" * 64  # missing sha256: prefix
_BAD_DEDUPE_HMAC_WRONG = "sha256:" + "b" * 64  # hmac field with non-hmac prefix


class TestDedupeKeyShapeValidation:
    def test_public_card_malformed_dedupe_key_fails_086(self) -> None:
        card = _dedupe_card(confidentiality="public", payload_extra={"incident_dedupe_key": _BAD_DEDUPE_KEY_UPPER})
        diags = ir.check_dedupe_key_confidentiality([card])
        assert "ACEF-086" in _codes(diags)
        d = next(d for d in diags if d.code == "ACEF-086")
        assert "incident_dedupe_key" in d.message

    def test_public_card_short_dedupe_key_fails_086(self) -> None:
        card = _dedupe_card(confidentiality="public", payload_extra={"incident_dedupe_key": _BAD_DEDUPE_KEY_SHORT})
        assert "ACEF-086" in _codes(ir.check_dedupe_key_confidentiality([card]))

    def test_public_card_no_prefix_dedupe_key_fails_086(self) -> None:
        card = _dedupe_card(confidentiality="public", payload_extra={"incident_dedupe_key": _BAD_DEDUPE_KEY_NOPREFIX})
        assert "ACEF-086" in _codes(ir.check_dedupe_key_confidentiality([card]))

    def test_public_card_malformed_hmac_fails_086(self) -> None:
        card = _dedupe_card(
            confidentiality="public", payload_extra={"incident_dedupe_key_hmac": _BAD_DEDUPE_HMAC_WRONG}
        )
        diags = ir.check_dedupe_key_confidentiality([card])
        assert "ACEF-086" in _codes(diags)
        d = next(d for d in diags if d.code == "ACEF-086")
        assert "incident_dedupe_key_hmac" in d.message

    def test_well_formed_hmac_on_public_card_passes(self) -> None:
        card = _dedupe_card(confidentiality="public", payload_extra={"incident_dedupe_key_hmac": _GOOD_DEDUPE_HMAC})
        assert "ACEF-086" not in _codes(ir.check_dedupe_key_confidentiality([card]))

    def test_report_malformed_dedupe_key_fails_086(self) -> None:
        # The incident_report path: schema additionalProperties:true does NOT catch
        # a malformed dedupe key, so the rule MUST. (A well-formed key on a non-public
        # report ALSO fails on the confidentiality rule — here we use a public report
        # to isolate the SHAPE failure.)
        report = {
            "record_id": "rec-report-shape-1",
            "record_type": "incident_report",
            "confidentiality": "public",
            "payload": {
                "incident_type": "malfunction",
                "severity": "major",
                "description": "x",
                "incident_dedupe_key": _BAD_DEDUPE_KEY_SHORT,
            },
        }
        assert "ACEF-086" in _codes(ir.check_dedupe_key_confidentiality([report]))

    def test_report_malformed_hmac_fails_086(self) -> None:
        report = {
            "record_id": "rec-report-shape-2",
            "record_type": "incident_report",
            "confidentiality": "regulator-only",
            "payload": {
                "incident_type": "malfunction",
                "severity": "major",
                "description": "x",
                "incident_dedupe_key_hmac": _BAD_DEDUPE_HMAC_WRONG,
            },
        }
        assert "ACEF-086" in _codes(ir.check_dedupe_key_confidentiality([report]))

    def test_report_well_formed_hmac_on_non_public_passes(self) -> None:
        # A well-formed hmac on a non-public report is the report's dedupe path —
        # it is NOT subject to the confidentiality omit rule and its shape is valid.
        report = {
            "record_id": "rec-report-shape-3",
            "record_type": "incident_report",
            "confidentiality": "regulator-only",
            "payload": {
                "incident_type": "malfunction",
                "severity": "major",
                "description": "x",
                "incident_dedupe_key_hmac": _GOOD_DEDUPE_HMAC,
            },
        }
        assert "ACEF-086" not in _codes(ir.check_dedupe_key_confidentiality([report]))

    def test_non_string_dedupe_key_fails_086(self) -> None:
        card = _dedupe_card(confidentiality="public", payload_extra={"incident_dedupe_key": 12345})
        assert "ACEF-086" in _codes(ir.check_dedupe_key_confidentiality([card]))


# ---------------------------------------------------------------------------
# check_incident_edges — public_projection_of SEMANTIC validation (§5.8 / §5.1)
# ---------------------------------------------------------------------------

_EDGE_RPT = "urn:acef:rec:00000000-0000-0000-0000-0000000000d1"
_EDGE_CARD = "urn:acef:rec:00000000-0000-0000-0000-0000000000d2"
_EDGE_PID = f"AIIC-OPENAI-2026-{_SUFFIX}"
# A DISTINCT but individually pattern-valid Crockford suffix (excludes I/L/O/U).
_EDGE_PID_OTHER = "AIIC-OPENAI-2026-TVWXYZ9876543210ABCDEFGHJK"


def _edge_record(
    record_id: str,
    record_type: str,
    *,
    pid: str | None = None,
    pid_on_card_source: bool = False,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if pid is not None:
        if pid_on_card_source:
            payload["card_source"] = {"public_incident_id": pid}
        else:
            payload["public_incident_id"] = pid
    return {"record_id": record_id, "record_type": record_type, "payload": payload}


def _edge_manifest(
    *,
    relationship_type: str = "public_projection_of",
    source_ref: str = _EDGE_RPT,
    target_ref: str = _EDGE_CARD,
) -> dict[str, Any]:
    return {
        "entities": {
            "relationships": [
                {"source_ref": source_ref, "target_ref": target_ref, "relationship_type": relationship_type}
            ]
        }
    }


def _well_formed_projection_records() -> list[dict[str, Any]]:
    return [
        _edge_record(_EDGE_RPT, "incident_report", pid=_EDGE_PID, pid_on_card_source=True),
        _edge_record(_EDGE_CARD, "incident_card", pid=_EDGE_PID),
    ]


class TestCheckIncidentEdges:
    def test_correct_report_to_card_same_pid_passes(self) -> None:
        diags = ir.check_incident_edges(_edge_manifest(), _well_formed_projection_records())
        assert _codes(diags) == [], f"a correct report→card projection must pass, got {_codes(diags)}"

    def test_source_not_incident_report_fails_083(self) -> None:
        records = [
            _edge_record(_EDGE_RPT, "risk_register"),
            _edge_record(_EDGE_CARD, "incident_card", pid=_EDGE_PID),
        ]
        diags = ir.check_incident_edges(_edge_manifest(), records)
        assert "ACEF-083" in _codes(diags)
        assert "incident_report" in next(d for d in diags if d.code == "ACEF-083").message

    def test_target_not_incident_card_fails_083(self) -> None:
        records = [
            _edge_record(_EDGE_RPT, "incident_report", pid=_EDGE_PID, pid_on_card_source=True),
            _edge_record(_EDGE_CARD, "incident_report", pid=_EDGE_PID, pid_on_card_source=True),
        ]
        diags = ir.check_incident_edges(_edge_manifest(), records)
        assert "ACEF-083" in _codes(diags)
        assert "incident_card" in next(d for d in diags if d.code == "ACEF-083").message

    def test_mismatched_public_incident_id_fails_083(self) -> None:
        records = [
            _edge_record(_EDGE_RPT, "incident_report", pid=_EDGE_PID, pid_on_card_source=True),
            _edge_record(_EDGE_CARD, "incident_card", pid=_EDGE_PID_OTHER),
        ]
        diags = ir.check_incident_edges(_edge_manifest(), records)
        assert "ACEF-083" in _codes(diags)
        assert "public_incident_id" in next(d for d in diags if d.code == "ACEF-083").message

    def test_reversed_direction_card_to_report_fails_083(self) -> None:
        # The edge runs source=card → target=report: BOTH type checks fail.
        records = [
            _edge_record(_EDGE_RPT, "incident_card", pid=_EDGE_PID),
            _edge_record(_EDGE_CARD, "incident_report", pid=_EDGE_PID, pid_on_card_source=True),
        ]
        diags = ir.check_incident_edges(_edge_manifest(), records)
        assert "ACEF-083" in _codes(diags)

    def test_missing_pid_on_card_fails_083(self) -> None:
        records = [
            _edge_record(_EDGE_RPT, "incident_report", pid=_EDGE_PID, pid_on_card_source=True),
            _edge_record(_EDGE_CARD, "incident_card"),  # no public_incident_id
        ]
        diags = ir.check_incident_edges(_edge_manifest(), records)
        assert "ACEF-083" in _codes(diags)

    def test_dangling_endpoint_not_judged_here(self) -> None:
        # An endpoint that resolves to NO in-bundle record is the reference
        # checker's ACEF-020 concern, not this rule's — check_incident_edges is
        # silent so the dangling-ref is never double-reported.
        records = [_edge_record(_EDGE_RPT, "incident_report", pid=_EDGE_PID, pid_on_card_source=True)]
        diags = ir.check_incident_edges(_edge_manifest(), records)  # _EDGE_CARD absent
        assert _codes(diags) == [], "a dangling projection endpoint must be left to the reference checker"

    def test_other_incident_edges_not_over_constrained(self) -> None:
        # caused_by / harms / mitigated_by / transferable_to are general in-bundle
        # record-graph edges; §5.8 does not pin their endpoint types, so this rule
        # must NOT raise on them even with non-report/non-card endpoints.
        records = [
            _edge_record(_EDGE_RPT, "risk_register"),
            _edge_record(_EDGE_CARD, "dataset_card"),
        ]
        for edge in ("caused_by", "harms", "mitigated_by", "transferable_to"):
            diags = ir.check_incident_edges(_edge_manifest(relationship_type=edge), records)
            assert _codes(diags) == [], f"edge {edge!r} must not be semantically over-constrained, got {_codes(diags)}"

    def test_no_relationships_is_noop(self) -> None:
        assert ir.check_incident_edges({}, _well_formed_projection_records()) == []
        assert ir.check_incident_edges({"entities": {}}, _well_formed_projection_records()) == []

    def test_report_pid_only_on_root_does_not_resolve_083(self) -> None:
        # Finding 2 (roborev): the report's AUTHORITATIVE public_incident_id is its
        # card_source.public_incident_id (§5.7). A report carrying the id ONLY at the
        # payload root (no card_source id) does NOT supply the authoritative id, so
        # the projection's shared-id check sees a missing card_source id → ACEF-083.
        records = [
            _edge_record(_EDGE_RPT, "incident_report", pid=_EDGE_PID),  # root id only
            _edge_record(_EDGE_CARD, "incident_card", pid=_EDGE_PID),
        ]
        diags = ir.check_incident_edges(_edge_manifest(), records)
        assert "ACEF-083" in _codes(diags)
        assert "card_source.public_incident_id" in next(d for d in diags if d.code == "ACEF-083").message

    def test_report_root_id_does_not_mask_divergent_card_source_083(self) -> None:
        # Finding 2 (roborev): a root-level public_incident_id on the report that
        # MATCHES the card MUST NOT mask a DIVERGENT card_source.public_incident_id.
        # The by-record-type extraction reads the report id from card_source only.
        report = {
            "record_id": _EDGE_RPT,
            "record_type": "incident_report",
            "payload": {
                "public_incident_id": _EDGE_PID,  # root matches the card …
                "card_source": {"public_incident_id": _EDGE_PID_OTHER},  # … but card_source diverges
            },
        }
        records = [report, _edge_record(_EDGE_CARD, "incident_card", pid=_EDGE_PID)]
        diags = ir.check_incident_edges(_edge_manifest(), records)
        assert "ACEF-083" in _codes(diags)
        assert "card_source.public_incident_id" in next(d for d in diags if d.code == "ACEF-083").message

    def test_source_entity_urn_endpoint_fails_083(self) -> None:
        # Finding 1 (roborev): a public_projection_of source that is an ENTITY URN
        # (not urn:acef:rec:) is a malformed record↔entity projection → ACEF-083,
        # NOT silently skipped because the entity URN is absent from the record index.
        sub_urn = "urn:acef:sub:00000000-0000-0000-0000-0000000000e1"
        records = [_edge_record(_EDGE_CARD, "incident_card", pid=_EDGE_PID)]
        diags = ir.check_incident_edges(_edge_manifest(source_ref=sub_urn, target_ref=_EDGE_CARD), records)
        assert "ACEF-083" in _codes(diags)
        assert "not a record URN" in next(d for d in diags if d.code == "ACEF-083").message

    def test_target_entity_urn_endpoint_fails_083(self) -> None:
        # Finding 1 (roborev): an ENTITY URN target → ACEF-083.
        sub_urn = "urn:acef:sub:00000000-0000-0000-0000-0000000000e1"
        records = [_edge_record(_EDGE_RPT, "incident_report", pid=_EDGE_PID, pid_on_card_source=True)]
        diags = ir.check_incident_edges(_edge_manifest(source_ref=_EDGE_RPT, target_ref=sub_urn), records)
        assert "ACEF-083" in _codes(diags)
        assert "not a record URN" in next(d for d in diags if d.code == "ACEF-083").message

    def test_dangling_record_urn_endpoint_not_double_reported(self) -> None:
        # Finding 1 (roborev): a WELL-FORMED but dangling record URN endpoint is the
        # reference checker's ACEF-020 concern — this rule must NOT raise ACEF-083.
        dangling = "urn:acef:rec:00000000-0000-0000-0000-0000000000ff"
        records = [_edge_record(_EDGE_RPT, "incident_report", pid=_EDGE_PID, pid_on_card_source=True)]
        diags = ir.check_incident_edges(_edge_manifest(source_ref=_EDGE_RPT, target_ref=dangling), records)
        assert _codes(diags) == [], (
            "a dangling record URN endpoint must be left to the reference checker (ACEF-020), "
            f"not double-reported as ACEF-083, got {_codes(diags)}"
        )


# ---------------------------------------------------------------------------
# Install-safety: the §5.11 source-to-card projection map must be a FROZEN
# module constant (always packaged in src/acef), NOT a runtime read of
# acef-conventions/v1.1/ schema files (which are absent in a pip-installed
# wheel/sdist). roborev (codex xhigh) Medium on fe58b71f: a schema-derived
# runtime map FAILS OPEN in an installed deployment — every /card_source/*
# projection edge VANISHES and the disposition-honored ACEF-086 check silently
# disappears. The frozen constant is fail-CLOSED.
# ---------------------------------------------------------------------------


def _derive_projection_from_v1_1_schemas() -> dict[str, str] | None:
    """Derive the §5.11 projection set from the on-disk v1.1 schemas, the same
    read the pre-fix runtime did. Returns ``None`` when the schema dir is ABSENT
    (installed-only CI) so the drift-guard test can skip rather than fail."""
    here = Path(__file__).resolve()
    card_path: Path | None = None
    source_path: Path | None = None
    for ancestor in here.parents:
        c = ancestor / "acef-conventions" / "v1.1" / "incident_card.schema.json"
        s = ancestor / "acef-conventions" / "v1.1" / "incident_report.card_source.schema.json"
        if c.is_file() and s.is_file():
            card_path, source_path = c, s
            break
    if card_path is None or source_path is None:
        return None
    card_schema = json.loads(card_path.read_text(encoding="utf-8"))
    source_schema = json.loads(source_path.read_text(encoding="utf-8"))
    card_root_props = card_schema.get("properties", {})
    card_source_props = source_schema.get("properties", {})
    projection: dict[str, str] = {}
    for field in card_source_props:
        if isinstance(field, str) and field in card_root_props:
            projection[f"/card_source/{field}"] = field
    if "severity" in card_root_props:
        projection["/severity"] = "severity"
    return projection


class TestProjectionMapInstallSafety:
    """The frozen-constant projection map is install-safe and fail-closed."""

    def test_runtime_projection_source_is_frozen_constant_not_disk_read(self) -> None:
        # The runtime disposition-honored check MUST source its projection map from
        # the frozen module constant, never from a disk read. (If a schema-reading
        # function survives only as a checkout test helper, the runtime accessor must
        # equal the frozen constant.)
        assert isinstance(ir._SOURCE_TO_CARD_PROJECTION, dict)
        assert ir._SOURCE_TO_CARD_PROJECTION  # non-empty
        # The exact frozen set the constant must mirror (schema-derived in fe58b71f).
        assert ir._SOURCE_TO_CARD_PROJECTION == {
            "/card_source/severity_vector": "severity_vector",
            "/card_source/harm_core": "harm_core",
            "/card_source/coordinated_disclosure": "coordinated_disclosure",
            "/card_source/public_incident_id": "public_incident_id",
            "/card_source/id_grade": "id_grade",
            "/severity": "severity",
        }

    def test_installed_layout_absent_schemas_still_fires_086(self, monkeypatch: Any) -> None:
        # INSTALLED-LAYOUT SIMULATION. Force every ``acef-conventions/v1.1`` schema
        # file to report ABSENT (the wheel/sdist packages only src/acef), without
        # mutating any frozen file: patch ``Path.is_file`` so any path under
        # ``acef-conventions/v1.1`` is treated as missing. Pre-fix (schema-derived
        # runtime) the projection map COLLAPSED to {'/severity': 'severity'} — every
        # /card_source/* projection edge VANISHED and /card_source/severity_vector
        # disposed regulator-only + present-on-card NO LONGER fired ACEF-086
        # (fail-OPEN). Post-fix (frozen constant) the edge fires REGARDLESS of schema
        # presence because the runtime reads NO schema file at all.
        real_is_file = Path.is_file

        def _is_file_hiding_v1_1(self_path: Path) -> bool:
            if "acef-conventions/v1.1" in self_path.as_posix():
                return False
            return real_is_file(self_path)

        monkeypatch.setattr(Path, "is_file", _is_file_hiding_v1_1)
        # Clear any process-cached projection map if a schema-reading helper survives
        # (it must NOT be the runtime source post-fix; this is belt-and-suspenders).
        helper = getattr(ir, "_source_to_card_projection_map", None)
        if helper is not None and hasattr(helper, "cache_clear"):
            helper.cache_clear()
        loader = getattr(ir, "_load_v1_1_schema", None)
        if loader is not None and hasattr(loader, "cache_clear"):
            loader.cache_clear()

        report = TestACEF086PublishabilityGate._report_with_card_source_disposition(
            TestACEF086PublishabilityGate(),
            pointer="/card_source/severity_vector",
            disposition="regulator-only",
        )
        sev_vector = TestACEF086PublishabilityGate._SEV_VECTOR
        card = _published_card({"severity_vector": sev_vector})
        diags = ir.check_publishability([card, report], source_backed=True)
        assert "ACEF-086" in _codes(diags), (
            "with the v1.1 schema dir ABSENT (installed wheel), the disposition-honored "
            "check must STILL fire ACEF-086 for a /card_source/severity_vector edge — the "
            "projection map must be the frozen module constant, not a runtime schema read "
            "that collapses to {'/severity': 'severity'} off-checkout (fail-OPEN)"
        )

    def test_frozen_constant_matches_schema_derived_set_drift_guard(self) -> None:
        # SCHEMA-DRIFT GUARD (checkout-only). Derive the projection set from the v1.1
        # schemas on disk and assert it EQUALS the frozen constant — so any future
        # schema drift (a new public card_source field that overlaps an incident_card
        # root) is caught in CI. The constant is the runtime authority; this test only
        # guards it from going stale. If the schema dir is absent (installed-only CI),
        # SKIP — the constant remains authoritative and install-safe.
        derived = _derive_projection_from_v1_1_schemas()
        if derived is None:
            pytest.skip(
                "v1.1 schema dir absent (installed-only layout); the frozen "
                "_SOURCE_TO_CARD_PROJECTION constant is authoritative — the schema "
                "cross-check is a checkout-only drift guard"
            )
        assert derived == ir._SOURCE_TO_CARD_PROJECTION, (
            "v1.1 schemas drifted from the frozen _SOURCE_TO_CARD_PROJECTION constant; "
            "update the constant (and its citation comment) to mirror the new schema set"
        )
