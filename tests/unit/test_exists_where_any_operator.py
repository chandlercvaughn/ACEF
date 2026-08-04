"""exists_where_any — an existential rule over ALTERNATIVE field pointers.

roborev finding on 0753d47 (High): the Art. 19(1)/26(6) six-month floor must
pass for a record that states retention on EITHER surface and fail only when
neither is present. ACEF expresses record retention in two places — the envelope
pointer ``/retention/min_retention_days`` and the payload pointer
``/payload/retention_policy_summary/min_days`` — and the repository's own
canonical logging record (golden-bundles/eu-high-risk-core/records/
event_log.jsonl:2) carries envelope ``retention: null`` and states retention
ONLY in the payload.

Splitting the surfaces across a fail-severity envelope rule and a
warning-severity payload rule (as 0753d47 did) means that canonical record trips
the fail rule and rolls the provision up to ``not-satisfied``. That disjunction
is not expressible with the ten §3.5 built-ins: ``exists_where`` takes a single
JSON Pointer, and neither ``RuleScope`` nor ``RuleCondition`` offers a
field-based conditional.

``exists_where_any`` is the minimal addition: identical to ``exists_where``
except ``fields`` is a non-empty list and a record matches when ANY listed
pointer resolves and satisfies the comparison.
"""

from __future__ import annotations

import pytest

from acef.errors import ACEFEvaluationError
from acef.models.records import RecordEnvelope
from acef.validation.operators import OPERATOR_REGISTRY

ENVELOPE_PTR = "/retention/min_retention_days"
PAYLOAD_PTR = "/payload/retention_policy_summary/min_days"


def _event_log(
    record_id: str,
    *,
    envelope_days: int | None = None,
    payload_days: int | None = None,
) -> RecordEnvelope:
    payload: dict = {"event_type": "logging_spec"}
    if payload_days is not None:
        payload["retention_policy_summary"] = {
            "min_days": payload_days,
            "start_event": "record_creation",
            "legal_basis": "EU AI Act Art. 19(1)",
        }
    kwargs: dict = {}
    if envelope_days is not None:
        kwargs["retention"] = {"min_retention_days": envelope_days}
    return RecordEnvelope(
        record_id=record_id,
        record_type="event_log",
        timestamp="2027-11-01T00:00:00Z",
        payload=payload,
        **kwargs,
    )


def _params(**over: object) -> dict:
    base: dict = {
        "record_type": "event_log",
        "fields": [ENVELOPE_PTR, PAYLOAD_PTR],
        "op": "gte",
        "value": 180,
        "min_count": 1,
    }
    base.update(over)
    return base


@pytest.fixture
def op():
    assert "exists_where_any" in OPERATOR_REGISTRY, (
        "exists_where_any is not registered; the §3.5 operator set must carry it"
    )
    return OPERATOR_REGISTRY["exists_where_any"]


class TestDisjunction:
    def test_envelope_only_record_passes(self, op) -> None:
        ok, refs = op(_params(), [_event_log("r1", envelope_days=365)])
        assert ok
        assert refs == ["r1"]

    def test_payload_only_record_passes(self, op) -> None:
        """The repo's own canonical logging_spec shape. This is the whole point."""
        ok, refs = op(_params(), [_event_log("r1", payload_days=365)])
        assert ok, "a payload-only retention policy must satisfy the floor"
        assert refs == ["r1"]

    def test_both_surfaces_present_passes_once(self, op) -> None:
        """A record satisfying both pointers is still ONE matching record."""
        ok, refs = op(_params(), [_event_log("r1", envelope_days=365, payload_days=365)])
        assert ok
        assert refs == ["r1"], "a record must not be double-counted toward min_count"

    def test_neither_surface_fails(self, op) -> None:
        ok, refs = op(_params(), [_event_log("r1")])
        assert not ok
        assert refs == []

    def test_below_floor_on_both_surfaces_fails(self, op) -> None:
        ok, refs = op(_params(), [_event_log("r1", envelope_days=30, payload_days=30)])
        assert not ok, "30 days does not satisfy a 180-day floor on either surface"
        assert refs == []

    def test_one_surface_below_other_above_passes(self, op) -> None:
        """Disjunction: satisfying ANY listed pointer is enough."""
        ok, refs = op(_params(), [_event_log("r1", envelope_days=30, payload_days=365)])
        assert ok
        assert refs == ["r1"]

    def test_no_records_fails_existentially(self, op) -> None:
        """Existential, like exists_where: zero records is a fail, not vacuous truth."""
        ok, refs = op(_params(), [])
        assert not ok
        assert refs == []

    def test_min_count_is_honoured(self, op) -> None:
        records = [_event_log("r1", payload_days=365), _event_log("r2", envelope_days=365)]
        assert op(_params(min_count=2), records)[0]
        assert not op(_params(min_count=3), records)[0]

    def test_other_record_types_are_not_considered(self, op) -> None:
        rec = _event_log("r1", payload_days=365)
        rec.record_type = "risk_register"
        ok, _ = op(_params(), [rec])
        assert not ok


class TestMalformedRuleRaises:
    def test_unknown_comparison_op_raises(self, op) -> None:
        """Parity with exists_where: a typo'd op is a malformed rule (ACEF-046)."""
        with pytest.raises(ACEFEvaluationError):
            op(_params(op="approximately"), [_event_log("r1", payload_days=365)])

    def test_malformed_pointer_raises_even_with_no_records(self, op) -> None:
        """Validated up front, so a bad pointer cannot hide behind an empty set."""
        with pytest.raises(ACEFEvaluationError):
            op(_params(fields=["not-a-pointer"]), [])

    def test_malformed_pointer_in_any_position_raises(self, op) -> None:
        """EVERY listed pointer is validated, not just the first."""
        with pytest.raises(ACEFEvaluationError):
            op(_params(fields=[ENVELOPE_PTR, "also-not-a-pointer"]), [])

    def test_empty_fields_list_raises(self, op) -> None:
        """A disjunction over nothing is not a rule."""
        with pytest.raises(ACEFEvaluationError):
            op(_params(fields=[]), [_event_log("r1", payload_days=365)])


class TestUnresolvedPointersAreNotMatches:
    """roborev MEDIUM on 4e583bd: `ne` counted records where nothing resolved.

    `_resolve_pointer` returns None for a missing path, and
    `_compare(None, "ne", value)` is True — so a rule asserting "some record has
    a value other than X" was satisfied by records having no such field at all,
    contradicting the "resolves and satisfies" semantics. The same defect was
    PRE-EXISTING in `exists_where`.
    """

    def test_ne_does_not_count_a_record_with_no_resolving_pointer(self, op) -> None:
        ok, refs = op(_params(op="ne", value=999), [_event_log("r1")])
        assert not ok and refs == [], "a record where neither pointer resolves must not satisfy an existential rule"

    def test_ne_still_counts_a_genuinely_different_value(self, op) -> None:
        ok, refs = op(_params(op="ne", value=999), [_event_log("r1", payload_days=365)])
        assert ok and refs == ["r1"]

    def test_ne_does_not_count_an_equal_resolved_value(self, op) -> None:
        ok, _ = op(_params(op="ne", value=365), [_event_log("r1", payload_days=365)])
        assert not ok

    def test_one_missing_one_equal_does_not_match(self, op) -> None:
        """The missing pointer must not rescue a record the resolved one rejects."""
        ok, _ = op(_params(op="ne", value=365), [_event_log("r1", payload_days=365)])
        assert not ok

    def test_exists_where_has_the_same_semantics(self) -> None:
        """The sibling operator carried the identical pre-existing defect."""
        single = OPERATOR_REGISTRY["exists_where"]
        params = {
            "record_type": "event_log",
            "field": ENVELOPE_PTR,
            "op": "ne",
            "value": 999,
            "min_count": 1,
        }
        assert not single(params, [_event_log("r1")])[0]
        assert single(params, [_event_log("r1", envelope_days=365)])[0]


class TestRegexOperandValidatedUpFront:
    """roborev MEDIUM on 4e583bd: an invalid pattern never got compiled.

    With zero records — or with every pointer unresolved — the per-record match
    loop never runs, so `"("` produced an ordinary rule FAILURE instead of the
    ACEF-045 rule ERROR a malformed rule requires.
    """

    def test_malformed_regex_raises_with_zero_records(self, op) -> None:
        with pytest.raises(ACEFEvaluationError) as exc:
            op(_params(op="regex", value="("), [])
        assert exc.value.code == "ACEF-045"

    def test_malformed_regex_raises_when_no_pointer_resolves(self, op) -> None:
        with pytest.raises(ACEFEvaluationError) as exc:
            op(_params(op="regex", value="["), [_event_log("r1")])
        assert exc.value.code == "ACEF-045"

    def test_non_string_regex_operand_raises(self, op) -> None:
        with pytest.raises(ACEFEvaluationError) as exc:
            op(_params(op="regex", value=42), [_event_log("r1", payload_days=365)])
        assert exc.value.code == "ACEF-045"

    def test_valid_regex_still_matches(self, op) -> None:
        ok, refs = op(
            _params(
                fields=["/payload/retention_policy_summary/legal_basis"],
                op="regex",
                value=r"Art(icle)?\.?\s*19\b",
            ),
            [_event_log("r1", payload_days=365)],
        )
        assert ok and refs == ["r1"]
