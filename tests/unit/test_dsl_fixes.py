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


# ---------------------------------------------------------------------------
# roborev follow-up 1 (VAL-FIX-DSL-006): required_alg is validated WHENEVER
# present, independent of whether any signatures exist. A malformed
# required_alg must raise ACEF-045 even with min_signatures=0 / zero sigs,
# instead of being silently treated-as-absent by the old
# `if required_alg and signature_algorithms` guard.
# ---------------------------------------------------------------------------


class TestBundleSignedRequiredAlgAlwaysValidated:
    def test_non_string_required_alg_zero_sigs_min_zero_raises_acef045(self) -> None:
        # required_alg=123 (int) with NO signatures and min_signatures=0 was
        # previously skipped (guard required signature_algorithms truthy) and
        # the operator returned PASS. It MUST now raise ACEF-045.
        params = {"min_signatures": 0, "required_alg": 123}
        with pytest.raises(ACEFEvaluationError) as exc:
            op_bundle_signed(params, [], signature_count=0, signature_algorithms=[])
        assert exc.value.code == "ACEF-045"

    def test_list_with_non_string_member_zero_sigs_raises_acef045(self) -> None:
        # ["RS256", 5] has a non-string member; previously skipped on zero sigs.
        params = {"min_signatures": 0, "required_alg": ["RS256", 5]}
        with pytest.raises(ACEFEvaluationError) as exc:
            op_bundle_signed(params, [], signature_count=0, signature_algorithms=[])
        assert exc.value.code == "ACEF-045"

    def test_non_string_required_alg_with_sigs_present_still_raises(self) -> None:
        # Regression: the previously-validated path (sigs present) stays ACEF-045.
        params = {"min_signatures": 1, "required_alg": 123}
        with pytest.raises(ACEFEvaluationError) as exc:
            op_bundle_signed(params, [], signature_count=1, signature_algorithms=["RS256"])
        assert exc.value.code == "ACEF-045"

    def test_valid_required_alg_zero_sigs_min_zero_passes(self) -> None:
        # A well-formed required_alg with min_signatures=0 and zero sigs must
        # still PASS (validation of the param does not change the count result).
        params = {"min_signatures": 0, "required_alg": ["RS256"]}
        passed, _ = op_bundle_signed(params, [], signature_count=0, signature_algorithms=[])
        assert passed is True

    def test_valid_required_alg_applied_when_sigs_present(self) -> None:
        # Set normalization still applied to the membership test.
        params = {"min_signatures": 1, "required_alg": "ES256"}
        passed, _ = op_bundle_signed(params, [], signature_count=1, signature_algorithms=["ES256"])
        assert passed is True
        passed_wrong, _ = op_bundle_signed(params, [], signature_count=1, signature_algorithms=["RS256"])
        assert passed_wrong is False

    def test_absent_required_alg_no_validation(self) -> None:
        # required_alg absent -> no validation, count is used directly.
        params = {"min_signatures": 1}
        passed, _ = op_bundle_signed(params, [], signature_count=1, signature_algorithms=["RS256"])
        assert passed is True


# ---------------------------------------------------------------------------
# roborev follow-up 2 (VAL-FIX-DSL-005): blanket re.ASCII overcorrected \s.
# ECMA-262 \s matches several NON-ASCII whitespace chars; \d/\w/\b stay ASCII.
# ---------------------------------------------------------------------------


class TestRegexWhitespaceEcma262:
    def test_s_matches_non_breaking_space(self) -> None:
        # U+00A0 (NBSP) is in ECMA-262 \s but NOT in re.ASCII's \s. It MUST match.
        assert _compare(" ", "regex", r"^\s+$") is True

    @pytest.mark.parametrize(
        "codepoint",
        [
            0x00A0,  # NO-BREAK SPACE
            0x1680,  # OGHAM SPACE MARK
            0x2000,  # EN QUAD
            0x2001,  # EM QUAD
            0x2002,  # EN SPACE
            0x2003,  # EM SPACE
            0x2004,
            0x2005,
            0x2006,
            0x2007,
            0x2008,
            0x2009,
            0x200A,  # HAIR SPACE
            0x2028,  # LINE SEPARATOR
            0x2029,  # PARAGRAPH SEPARATOR
            0x202F,  # NARROW NO-BREAK SPACE
            0x205F,  # MEDIUM MATHEMATICAL SPACE
            0x3000,  # IDEOGRAPHIC SPACE
            0xFEFF,  # ZERO WIDTH NO-BREAK SPACE (BOM)
        ],
    )
    def test_s_matches_all_ecma262_non_ascii_whitespace(self, codepoint: int) -> None:
        assert _compare(chr(codepoint), "regex", r"^\s$") is True

    @pytest.mark.parametrize(
        "ascii_ws",
        ["\t", "\n", "\r", " ", "\x0b", "\x0c"],
    )
    def test_s_matches_ascii_whitespace(self, ascii_ws: str) -> None:
        assert _compare(ascii_ws, "regex", r"^\s$") is True

    @pytest.mark.parametrize(
        "non_ws_codepoint",
        [
            0x1C,  # FILE SEPARATOR — Python \s matches, ECMA-262 does NOT
            0x1D,
            0x1E,
            0x1F,
            0x85,  # NEL — Python \s matches, ECMA-262 does NOT
        ],
    )
    def test_s_does_not_match_non_ecma262_control_separators(self, non_ws_codepoint: int) -> None:
        # These are in Python's default \s but NOT in ECMA-262 \s. A faithful
        # translation must EXCLUDE them.
        assert _compare(chr(non_ws_codepoint), "regex", r"^\s$") is False

    def test_capital_s_does_not_match_ecma262_whitespace(self) -> None:
        # \S (negated) must NOT match an ECMA-262 whitespace char.
        assert _compare(" ", "regex", r"^\S$") is False

    def test_capital_s_matches_non_whitespace(self) -> None:
        assert _compare("a", "regex", r"^\S$") is True

    def test_digit_stays_ascii_only(self) -> None:
        # Regression: \d must STILL be ASCII-only (the DSL-5 invariant holds).
        assert _compare("٢", "regex", r"^\d+$") is False  # Arabic-Indic 2
        assert _compare("2", "regex", r"^\d+$") is True

    def test_word_stays_ascii_only(self) -> None:
        assert _compare("é", "regex", r"^\w+$") is False
        assert _compare("a", "regex", r"^\w+$") is True

    def test_word_boundary_stays_ascii(self) -> None:
        # \b depends on \w; with ASCII \w the boundary is ASCII. 'é word' has an
        # ASCII boundary before 'word'.
        assert _compare("é word", "regex", r"\bword\b") is True
        assert _compare("abword", "regex", r"\bword\b") is False

    def test_s_inside_character_class(self) -> None:
        # \s appearing INSIDE a [...] class must still carry ECMA-262 semantics.
        assert _compare(" ", "regex", r"^[\sx]$") is True
        assert _compare("x", "regex", r"^[\sx]$") is True

    def test_d_inside_character_class_stays_ascii(self) -> None:
        # \d inside a class stays ASCII; Arabic-Indic digit excluded, ASCII in.
        assert _compare("٢", "regex", r"^[\dz]$") is False
        assert _compare("5", "regex", r"^[\dz]$") is True
        assert _compare("z", "regex", r"^[\dz]$") is True

    def test_negated_class_with_s(self) -> None:
        # [^\s] must exclude an ECMA-262 whitespace char.
        assert _compare(" ", "regex", r"^[^\s]$") is False
        assert _compare("a", "regex", r"^[^\s]$") is True

    # -- roborev follow-up (Finding 2): negated shorthands INSIDE a class --
    # \S/\D/\W inside a [...] class were previously left at Python re.ASCII
    # semantics, diverging from ECMA-262. They must translate to their explicit
    # ECMA-262-correct complement bodies both outside AND inside a class.

    def test_capital_s_inside_class_excludes_ecma262_whitespace(self) -> None:
        # [\S] is "non-whitespace". U+00A0 IS ECMA-262 whitespace, so it must
        # NOT match. Previously [\S] left \S at re.ASCII (which DROPS U+00A0
        # from \s, so \S WRONGLY MATCHED U+00A0). The fix excludes U+00A0.
        assert _compare(" ", "regex", r"^[\S]$") is False
        assert _compare("a", "regex", r"^[\S]$") is True
        assert _compare(" ", "regex", r"^[\S]$") is False

    def test_negated_class_with_capital_s_matches_ecma262_whitespace(self) -> None:
        # [^\S] is the inverse of [\S]: it must MATCH ECMA-262 whitespace and
        # reject non-whitespace. Previously the residual re.ASCII \S made [^\S]
        # WRONGLY match U+00A0 (because ASCII \S includes it).
        assert _compare(" ", "regex", r"^[^\S]$") is True
        assert _compare(" ", "regex", r"^[^\S]$") is True
        assert _compare("a", "regex", r"^[^\S]$") is False

    def test_capital_d_inside_class_full_complement(self) -> None:
        # [\D] is "non-digit" — must match a non-ASCII char and a letter, and
        # reject an ASCII digit. Consistent with the OUTSIDE \D -> [^0-9].
        assert _compare("5", "regex", r"^[\D]$") is False
        assert _compare("a", "regex", r"^[\D]$") is True
        assert _compare(" ", "regex", r"^[\D]$") is True

    def test_negated_class_with_capital_d(self) -> None:
        # [^\D] is the inverse of non-digit = digit.
        assert _compare("5", "regex", r"^[^\D]$") is True
        assert _compare("a", "regex", r"^[^\D]$") is False

    def test_capital_w_inside_class_full_complement(self) -> None:
        # [\W] is "non-word" — must reject an ASCII word char and match a symbol
        # and a non-ASCII char. Consistent with OUTSIDE \W -> [^A-Za-z0-9_].
        assert _compare("a", "regex", r"^[\W]$") is False
        assert _compare("_", "regex", r"^[\W]$") is False
        assert _compare("!", "regex", r"^[\W]$") is True
        assert _compare(" ", "regex", r"^[\W]$") is True

    def test_negated_class_with_capital_w(self) -> None:
        # [^\W] is the inverse of non-word = word char.
        assert _compare("a", "regex", r"^[^\W]$") is True
        assert _compare("!", "regex", r"^[^\W]$") is False

    def test_positive_shorthands_inside_class_still_ascii(self) -> None:
        # The prior positive-class semantics are unchanged: \d/\w inside a class
        # stay ASCII-only; \s inside a class stays ECMA-262.
        assert _compare("٢", "regex", r"^[\d]$") is False  # Arabic-Indic 2
        assert _compare("5", "regex", r"^[\d]$") is True
        assert _compare("é", "regex", r"^[\w]$") is False
        assert _compare("a", "regex", r"^[\w]$") is True
        assert _compare(" ", "regex", r"^[\s]$") is True  # ECMA-262 ws

    def test_escaped_literal_inside_class_unaffected(self) -> None:
        # An escaped literal (\.) inside a class is a literal dot, not a
        # metacharacter; the shorthand translation must not disturb it.
        assert _compare(".", "regex", r"^[\.]$") is True
        assert _compare("x", "regex", r"^[\.]$") is False
        # A literal backslash escape inside a class (\\) is a literal backslash.
        assert _compare("\\", "regex", r"^[\\]$") is True

    def test_mixed_negated_and_literal_inside_class(self) -> None:
        # [\Sx] is "non-whitespace OR x" = non-whitespace (x already non-ws).
        # U+00A0 (ws) must NOT match; 'x' and 'a' must match.
        assert _compare(" ", "regex", r"^[\Sx]$") is False
        assert _compare("x", "regex", r"^[\Sx]$") is True
        assert _compare("a", "regex", r"^[\Sx]$") is True

    def test_escaped_literal_backslash_s_not_translated(self) -> None:
        # An escaped backslash followed by a literal 's' (\\s) is backslash+s,
        # NOT the whitespace class. It must match literal "\s" — not whitespace.
        assert _compare("\\s", "regex", r"^\\s$") is True
        assert _compare(" ", "regex", r"^\\s$") is False

    def test_unparseable_pattern_still_acef045(self) -> None:
        # A genuinely unparseable pattern keeps ACEF-045.
        with pytest.raises(ACEFEvaluationError) as exc:
            _compare("x", "regex", r"[")
        assert exc.value.code == "ACEF-045"


# ---------------------------------------------------------------------------
# roborev follow-up 3 (VAL-FIX-ENVELOPE-001): lifecycle start_date/end_date
# declare format:date but the schema descriptions say "date OR date-time".
# Global format assertion previously rejected a valid date-time. A custom
# `date` checker must accept date OR date-time while still rejecting bogus.
# ---------------------------------------------------------------------------


class TestDateOrDateTimeFormatAcceptance:
    def _manifest_with_lifecycle(self, start_date: str, end_date: str | None = None) -> dict:
        timeline_item: dict = {"phase": "deployment", "start_date": start_date}
        if end_date is not None:
            timeline_item["end_date"] = end_date
        return {
            "metadata": {
                "package_id": "urn:acef:pkg:550e8400-e29b-41d4-a716-446655440000",
                "timestamp": "2026-01-01T00:00:00Z",
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
                    "lifecycle_timeline": [timeline_item],
                }
            ],
            "entities": {"components": [], "datasets": [], "actors": [], "relationships": []},
            "profiles": [],
            "record_files": [],
            "audit_trail": [],
        }

    def test_lifecycle_start_date_as_plain_date_accepted(self) -> None:
        errors = validate_against_schema(self._manifest_with_lifecycle("2026-01-01"), "manifest", "v1")
        assert errors == []

    def test_lifecycle_start_date_as_date_time_accepted(self) -> None:
        # The schema description allows date OR date-time; a date-time value MUST
        # be accepted even though the field declares format:date.
        errors = validate_against_schema(self._manifest_with_lifecycle("2026-01-01T12:30:00Z"), "manifest", "v1")
        assert errors == []

    def test_lifecycle_end_date_as_date_time_accepted(self) -> None:
        errors = validate_against_schema(
            self._manifest_with_lifecycle("2026-01-01", "2026-06-01T00:00:00+02:00"),
            "manifest",
            "v1",
        )
        assert errors == []

    def test_lifecycle_start_date_bogus_value_rejected(self) -> None:
        # A non-ISO value must STILL be rejected (ENVELOPE-001 intent preserved).
        errors = validate_against_schema(self._manifest_with_lifecycle("not-a-date"), "manifest", "v1")
        messages = " ".join(str(e) for e in errors)
        assert errors, "expected a format error for a bogus lifecycle start_date"
        assert "date" in messages

    def test_lifecycle_end_date_bogus_value_rejected(self) -> None:
        errors = validate_against_schema(self._manifest_with_lifecycle("2026-01-01", "BOGUS-END"), "manifest", "v1")
        assert errors, "expected a format error for a bogus lifecycle end_date"

    def test_metadata_timestamp_date_time_only_still_strict(self) -> None:
        # A genuine date-time field (metadata.timestamp) must STILL reject a
        # bare date — the date-or-date-time leniency is scoped to `date` format,
        # not to `date-time` format.
        bad = self._manifest_with_lifecycle("2026-01-01")
        bad["metadata"]["timestamp"] = "not-a-timestamp"
        errors = validate_against_schema(bad, "manifest", "v1")
        messages = " ".join(str(e) for e in errors)
        assert errors, "expected a date-time format error for a bogus metadata.timestamp"
        assert "date-time" in messages

    def test_lifecycle_v1_1_start_date_as_date_time_accepted(self) -> None:
        # The v1.1 manifest schema documents the SAME date-or-date-time contract
        # for lifecycle_timeline.start_date/end_date; the in-memory patch must
        # apply there too.
        errors = validate_against_schema(self._manifest_with_lifecycle("2026-01-01T12:30:00Z"), "manifest", "v1.1")
        assert errors == []

    def test_lifecycle_v1_1_start_date_bogus_value_rejected(self) -> None:
        errors = validate_against_schema(self._manifest_with_lifecycle("not-a-date"), "manifest", "v1.1")
        assert errors, "expected a format error for a bogus v1.1 lifecycle start_date"


# ---------------------------------------------------------------------------
# roborev follow-up (Finding 1): the date-or-date-time leniency was applied
# GLOBALLY to every `format: date` field, WRONGLY weakening date-ONLY record
# fields (evaluation_date, approval_date, implementation_date, …) so they
# accepted a date-time. Only the lifecycle_timeline fields (whose schema
# DESCRIPTION documents "date or date-time") may accept a date-time; every
# other `format: date` field must REJECT a date-time but still accept a plain
# date and reject a bogus value.
# ---------------------------------------------------------------------------


class TestDateOnlyRecordFieldsRejectDateTime:
    def test_evaluation_date_plain_date_accepted(self) -> None:
        payload = {"methodology": "manual", "evaluation_date": "2026-01-01"}
        errors = validate_against_schema(payload, "evaluation_report", "v1")
        assert errors == []

    def test_evaluation_date_date_time_rejected(self) -> None:
        # evaluation_report.evaluation_date is documented "ISO 8601" (date only).
        # A date-time value MUST be rejected — it was wrongly accepted under the
        # over-broad global checker.
        payload = {"methodology": "manual", "evaluation_date": "2026-01-01T12:00:00Z"}
        errors = validate_against_schema(payload, "evaluation_report", "v1")
        messages = " ".join(str(e) for e in errors)
        assert errors, "expected a date format error for a date-time evaluation_date"
        assert "date" in messages

    def test_evaluation_date_bogus_rejected(self) -> None:
        payload = {"methodology": "manual", "evaluation_date": "not-a-date"}
        errors = validate_against_schema(payload, "evaluation_report", "v1")
        assert errors, "expected a format error for a bogus evaluation_date"

    def test_governance_approval_date_date_time_rejected(self) -> None:
        payload = {"policy_type": "ai_governance_policy", "approval_date": "2026-01-01T08:30:00Z"}
        errors = validate_against_schema(payload, "governance_policy", "v1")
        messages = " ".join(str(e) for e in errors)
        assert errors, "expected a date format error for a date-time approval_date"
        assert "date" in messages

    def test_governance_approval_date_plain_date_accepted(self) -> None:
        payload = {"policy_type": "ai_governance_policy", "approval_date": "2026-01-01"}
        errors = validate_against_schema(payload, "governance_policy", "v1")
        assert errors == []

    def test_risk_treatment_implementation_date_date_time_rejected(self) -> None:
        payload = {
            "risk_id": "R-1",
            "treatment_type": "mitigate",
            "control_description": "x",
            "implementation_status": "implemented",
            "implementation_date": "2026-01-01T00:00:00Z",
        }
        errors = validate_against_schema(payload, "risk_treatment", "v1")
        messages = " ".join(str(e) for e in errors)
        assert errors, "expected a date format error for a date-time implementation_date"
        assert "date" in messages

    def test_risk_treatment_implementation_date_plain_date_accepted(self) -> None:
        payload = {
            "risk_id": "R-1",
            "treatment_type": "mitigate",
            "control_description": "x",
            "implementation_status": "implemented",
            "implementation_date": "2026-01-01",
        }
        errors = validate_against_schema(payload, "risk_treatment", "v1")
        assert errors == []

    def test_risk_treatment_implementation_date_bogus_rejected(self) -> None:
        payload = {
            "risk_id": "R-1",
            "treatment_type": "mitigate",
            "control_description": "x",
            "implementation_status": "implemented",
            "implementation_date": "not-a-date",
        }
        errors = validate_against_schema(payload, "risk_treatment", "v1")
        assert errors, "expected a format error for a bogus implementation_date"
