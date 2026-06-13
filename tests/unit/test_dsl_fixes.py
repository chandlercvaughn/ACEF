"""RED-first tests for F-M5-DSL audit fixes.

Covers six audit findings:
  - validation-engine-dsl-3 (VAL-FIX-DSL-003): invalid JSON Pointer not detected
    when zero records match (empty-set short-circuit hides ACEF-043).
  - validation-engine-dsl-7 (VAL-FIX-DSL-007): _validate_pointer_syntax is dead
    code (wired live by DSL-3 fix).
  - validation-engine-dsl-4 (VAL-FIX-DSL-004): operator-raised ACEF-043/ACEF-045
    codes are stringified into free text and the machine-readable code is lost.
  - validation-engine-dsl-5 (VAL-FIX-DSL-005): regex operator runs on Python re
    where \\d/\\w match Unicode; ECMA-262 (no /u flag) is ASCII-only.
  - validation-engine-dsl-6 (VAL-FIX-DSL-006): bundle_signed required_alg accepts
    a bare string and degrades to substring matching (type confusion).
  - envelope-manifest-1 (VAL-FIX-ENVELOPE-001): ISO 8601 date/date-time formats
    are never enforced because the validator has no format_checker.
"""

from __future__ import annotations

import pytest

from acef.errors import ACEFEvaluationError
from acef.models.enums import RuleOutcome
from acef.models.records import EntityRefs, RecordEnvelope
from acef.schemas.registry import validate_against_schema
from acef.templates.models import EvaluationRule, Provision
from acef.validation.operators import (
    _compare,
    op_bundle_signed,
    op_exists_where,
    op_field_present,
    op_field_value,
)
from acef.validation.rule_engine import evaluate_rules_for_subject


def _record(record_type: str, payload: dict | None = None, *, record_id: str = "rec-1") -> RecordEnvelope:
    """Build a minimal valid RecordEnvelope for operator tests."""
    return RecordEnvelope(
        record_id=record_id,
        record_type=record_type,
        timestamp="2026-01-01T00:00:00Z",
        obligation_role="provider",
        entity_refs=EntityRefs(),
        payload=payload or {},
    )


# ---------------------------------------------------------------------------
# VAL-FIX-DSL-003 / VAL-FIX-DSL-007: invalid pointer detected on zero-match set
# ---------------------------------------------------------------------------


class TestPointerSyntaxOnEmptySet:
    def test_field_present_invalid_pointer_zero_match_raises_acef043(self) -> None:
        # Record set has ZERO records of the rule's record_type, so the
        # universal operator would short-circuit to vacuous PASS. The invalid
        # pointer (no leading slash) MUST still raise ACEF-043.
        params = {"record_type": "risk_register", "field": "no-leading-slash"}
        with pytest.raises(ACEFEvaluationError) as exc:
            op_field_present(params, [])
        assert exc.value.code == "ACEF-043"

    def test_field_value_invalid_pointer_zero_match_raises_acef043(self) -> None:
        params = {
            "record_type": "risk_register",
            "field": "bad~3escape",  # ~ not followed by 0 or 1 -> RFC 6901 invalid
            "op": "eq",
            "value": 1,
        }
        with pytest.raises(ACEFEvaluationError) as exc:
            op_field_value(params, [])
        assert exc.value.code == "ACEF-043"

    def test_exists_where_invalid_pointer_zero_match_raises_acef043(self) -> None:
        params = {
            "record_type": "risk_register",
            "field": "no-leading-slash",
            "op": "eq",
            "value": 1,
            "min_count": 1,
        }
        with pytest.raises(ACEFEvaluationError) as exc:
            op_exists_where(params, [])
        assert exc.value.code == "ACEF-043"

    def test_valid_pointer_empty_set_still_passes(self) -> None:
        # A WELL-FORMED pointer over a zero-match universal operator must
        # still return vacuous PASS (no false ACEF-043).
        params = {"record_type": "risk_register", "field": "/payload/level"}
        passed, refs = op_field_present(params, [])
        assert passed is True
        assert refs == []

    def test_field_present_invalid_pointer_with_records_still_raises(self) -> None:
        # The non-empty path must also raise (regression guard on the existing
        # per-record path; the new pre-check fires first).
        rec = _record("risk_register", {"level": "high"})
        params = {"record_type": "risk_register", "field": "no-leading-slash"}
        with pytest.raises(ACEFEvaluationError) as exc:
            op_field_present(params, [rec])
        assert exc.value.code == "ACEF-043"


# ---------------------------------------------------------------------------
# VAL-FIX-DSL-004: machine-readable error code survives to the RuleResult
# ---------------------------------------------------------------------------


class TestRuleResultErrorCode:
    def _provision_with_rule(self, rule: EvaluationRule) -> Provision:
        return Provision(
            provision_id="prov-1",
            evaluation=[rule],
        )

    def test_acef043_pointer_error_surfaces_machine_readable_code(self) -> None:
        rule = EvaluationRule(
            rule_id="r1",
            rule="field_present",
            params={"record_type": "risk_register", "field": "no-leading-slash"},
            severity="fail",
            message="needs field",
        )
        results = evaluate_rules_for_subject(
            [self._provision_with_rule(rule)],
            [],  # zero records -> the pre-check still fires ACEF-043
            profile_id="eu-ai-act",
        )
        assert len(results) == 1
        result = results[0]
        assert result.outcome == RuleOutcome.ERROR
        # Machine-readable code must survive — not buried in free text only.
        assert result.error_code == "ACEF-043"

    def test_acef045_regex_error_surfaces_machine_readable_code(self) -> None:
        rec = _record("risk_register", {"level": "high"})
        rec.entity_refs.subject_refs = []
        rule = EvaluationRule(
            rule_id="r2",
            rule="field_value",
            params={
                "record_type": "risk_register",
                "field": "/payload/level",
                "op": "regex",
                "value": "(?P<bad>x)",  # Python-only named group -> ACEF-045
            },
            severity="fail",
            message="regex",
        )
        results = evaluate_rules_for_subject(
            [self._provision_with_rule(rule)],
            [rec],
            profile_id="eu-ai-act",
        )
        assert len(results) == 1
        result = results[0]
        assert result.outcome == RuleOutcome.ERROR
        assert result.error_code == "ACEF-045"

    def test_unexpected_error_has_no_acef_code(self) -> None:
        # A genuinely unexpected (non-ACEFEvaluationError) failure must keep
        # error_code=None so consumers can distinguish a taxonomy code from an
        # internal crash. KeyError from a missing required param hits the
        # bare-except branch.
        rule = EvaluationRule(
            rule_id="r3",
            rule="field_present",
            params={"record_type": "risk_register"},  # missing 'field' -> KeyError
            severity="fail",
            message="m",
        )
        results = evaluate_rules_for_subject(
            [self._provision_with_rule(rule)],
            [],
            profile_id="eu-ai-act",
        )
        assert len(results) == 1
        result = results[0]
        assert result.outcome == RuleOutcome.ERROR
        assert result.error_code is None


# ---------------------------------------------------------------------------
# VAL-FIX-DSL-005: ASCII (ECMA-262 default) regex semantics
# ---------------------------------------------------------------------------


class TestRegexAsciiSemantics:
    def test_digit_class_does_not_match_arabic_indic_digit(self) -> None:
        # '٢' is Arabic-Indic '2'. Under Python Unicode \d it matches;
        # under ECMA-262 default (no /u) it must NOT.
        assert _compare("٢", "regex", r"^\d+$") is False

    def test_digit_class_matches_ascii_digit(self) -> None:
        assert _compare("2", "regex", r"^\d+$") is True

    def test_word_class_does_not_match_non_ascii_letter(self) -> None:
        # 'é' is a Unicode word char in Python but not ASCII \w.
        assert _compare("é", "regex", r"^\w+$") is False

    def test_word_class_matches_ascii_letter(self) -> None:
        assert _compare("a", "regex", r"^\w+$") is True


# ---------------------------------------------------------------------------
# VAL-FIX-DSL-006: bundle_signed required_alg string normalization
# ---------------------------------------------------------------------------


class TestBundleSignedRequiredAlg:
    def test_bare_string_required_alg_no_substring_false_match(self) -> None:
        # required_alg given as a bare string "ES256"; a (hypothetical) signed
        # alg "S256" is a SUBSTRING of "ES256" and is wrongly counted under the
        # old `a in required_alg` test. After the fix, membership is exact so
        # "S256" does NOT satisfy required_alg "ES256".
        params = {"min_signatures": 1, "required_alg": "ES256"}
        passed, _ = op_bundle_signed(
            params,
            [],
            signature_count=1,
            signature_algorithms=["S256"],
        )
        assert passed is False

    def test_bare_string_required_alg_exact_match_passes(self) -> None:
        params = {"min_signatures": 1, "required_alg": "ES256"}
        passed, _ = op_bundle_signed(
            params,
            [],
            signature_count=1,
            signature_algorithms=["ES256"],
        )
        assert passed is True

    def test_list_required_alg_still_works(self) -> None:
        params = {"min_signatures": 1, "required_alg": ["RS256", "ES256"]}
        passed, _ = op_bundle_signed(
            params,
            [],
            signature_count=2,
            signature_algorithms=["RS256", "ES256"],
        )
        assert passed is True

    def test_list_required_alg_excludes_substring_false_positive(self) -> None:
        # Regression: ["ES256"] must not match "S2" the way a string would.
        params = {"min_signatures": 1, "required_alg": ["ES256"]}
        passed, _ = op_bundle_signed(
            params,
            [],
            signature_count=1,
            signature_algorithms=["S2"],
        )
        assert passed is False


# ---------------------------------------------------------------------------
# VAL-FIX-ENVELOPE-001: ISO 8601 format enforcement via format_checker
# ---------------------------------------------------------------------------


class TestIso8601FormatEnforcement:
    """Fully schema-valid fixtures isolate the timestamp so the ONLY validation
    difference between the good and bad cases is the date-time FORMAT — this
    makes the test a true RED for the missing format_checker (envelope-manifest-1)
    rather than passing on unrelated structural errors.
    """

    def _valid_manifest(self, timestamp: str) -> dict:
        return {
            "metadata": {
                "package_id": "urn:acef:pkg:550e8400-e29b-41d4-a716-446655440000",
                "timestamp": timestamp,
                "producer": {"name": "acef", "version": "1.0.0"},
            },
            "versioning": {"core_version": "1.0.0", "profiles_version": "1.0.0"},
            "subjects": [
                {
                    "subject_id": "urn:acef:sub:550e8400-e29b-41d4-a716-446655440010",
                    "subject_type": "ai_system",
                    "name": "x",
                    "version": "1.0.0",
                    "provider": "acme",
                    "risk_classification": "high-risk",
                    "modalities": ["text"],
                    "lifecycle_phase": "deployment",
                }
            ],
            "entities": {"components": [], "datasets": [], "actors": [], "relationships": []},
            "profiles": [],
            "record_files": [],
            "audit_trail": [],
        }

    def _valid_record(self, timestamp: str) -> dict:
        return {
            "record_id": "urn:acef:rec:550e8400-e29b-41d4-a716-446655440001",
            "record_type": "risk_register",
            "provisions_addressed": [],
            "timestamp": timestamp,
            "lifecycle_phase": "deployment",
            "collector": {"name": "acef", "version": "1.0.0"},
            "obligation_role": "provider",
            "confidentiality": "public",
            "trust_level": "self-attested",
            "entity_refs": {
                "subject_refs": [],
                "component_refs": [],
                "dataset_refs": [],
                "actor_refs": [],
            },
            "payload": {},
        }

    def test_valid_manifest_baseline_is_clean(self) -> None:
        # Sanity: the fixture itself is fully schema-valid with a good timestamp.
        errors = validate_against_schema(self._valid_manifest("2026-01-01T00:00:00Z"), "manifest", "v1")
        assert errors == []

    def test_manifest_non_iso_timestamp_now_fails(self) -> None:
        errors = validate_against_schema(self._valid_manifest("THIS-IS-NOT-A-DATE"), "manifest", "v1")
        # The non-ISO date-time MUST now surface exactly one format error.
        messages = " ".join(str(e) for e in errors)
        assert errors, "expected a date-time format error for non-ISO timestamp"
        assert "date-time" in messages

    def test_manifest_valid_iso_timestamp_passes_format(self) -> None:
        errors = validate_against_schema(self._valid_manifest("2026-01-01T00:00:00Z"), "manifest", "v1")
        assert errors == []

    def test_valid_record_baseline_is_clean(self) -> None:
        errors = validate_against_schema(self._valid_record("2026-01-01T00:00:00Z"), "record-envelope", "v1")
        assert errors == []

    def test_record_envelope_non_iso_timestamp_now_fails(self) -> None:
        errors = validate_against_schema(self._valid_record("NOT-A-TIMESTAMP"), "record-envelope", "v1")
        messages = " ".join(str(e) for e in errors)
        assert errors, "expected a date-time format error for non-ISO record timestamp"
        assert "date-time" in messages

    def test_record_envelope_valid_iso_timestamp_passes_format(self) -> None:
        errors = validate_against_schema(self._valid_record("2026-01-01T00:00:00Z"), "record-envelope", "v1")
        assert errors == []
