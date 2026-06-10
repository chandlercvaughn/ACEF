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

from typing import Any

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
