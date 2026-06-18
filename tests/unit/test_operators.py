"""Tests for acef.validation.operators — all 10 DSL operators with pass/fail and empty-set."""

from __future__ import annotations

import jsonpointer
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from acef.errors import ACEFEvaluationError
from acef.integrity import canonicalize
from acef.models.enums import ObligationRole
from acef.models.records import AttachmentRef, Attestation, EntityRefs, RecordEnvelope
from acef.signing import create_detached_jws
from acef.validation.operators import (
    OPERATOR_REGISTRY,
    op_attachment_exists,
    op_attachment_kind_exists,
    op_bundle_signed,
    op_entity_linked,
    op_evidence_freshness,
    op_exists_where,
    op_field_present,
    op_field_value,
    op_has_record_type,
    op_record_attested,
)


def _make_record(
    record_type: str = "risk_register",
    payload: dict | None = None,
    subject_refs: list[str] | None = None,
    component_refs: list[str] | None = None,
    dataset_refs: list[str] | None = None,
    actor_refs: list[str] | None = None,
    attachments: list[AttachmentRef] | None = None,
    attestation: Attestation | None = None,
    obligation_role: ObligationRole | None = None,
    timestamp: str = "2025-06-01T00:00:00Z",
    record_id: str | None = None,
) -> RecordEnvelope:
    """Helper to create test records."""
    rec = RecordEnvelope(
        record_type=record_type,
        payload=payload or {},
        entity_refs=EntityRefs(
            subject_refs=subject_refs or [],
            component_refs=component_refs or [],
            dataset_refs=dataset_refs or [],
            actor_refs=actor_refs or [],
        ),
        attachments=attachments or [],
        attestation=attestation,
        obligation_role=obligation_role,
        timestamp=timestamp,
    )
    if record_id:
        rec.record_id = record_id
    return rec


class TestOperatorRegistry:
    """Verify all 10 operators registered."""

    def test_all_10_operators(self):
        expected = {
            "has_record_type",
            "field_present",
            "field_value",
            "evidence_freshness",
            "attachment_exists",
            "entity_linked",
            "exists_where",
            "attachment_kind_exists",
            "bundle_signed",
            "record_attested",
        }
        assert set(OPERATOR_REGISTRY.keys()) == expected


class TestHasRecordType:
    """has_record_type: Existential operator."""

    def test_pass_with_matching_records(self):
        records = [_make_record("risk_register")]
        passed, refs = op_has_record_type({"type": "risk_register"}, records)
        assert passed
        assert len(refs) == 1

    def test_fail_no_matching_records(self):
        records = [_make_record("dataset_card")]
        passed, refs = op_has_record_type({"type": "risk_register"}, records)
        assert not passed
        assert refs == []

    def test_fail_empty_records(self):
        passed, refs = op_has_record_type({"type": "risk_register", "min_count": 1}, [])
        assert not passed

    def test_min_count(self):
        records = [_make_record("risk_register")]
        passed, _ = op_has_record_type({"type": "risk_register", "min_count": 2}, records)
        assert not passed

    def test_min_count_satisfied(self):
        records = [_make_record("risk_register"), _make_record("risk_register")]
        passed, refs = op_has_record_type({"type": "risk_register", "min_count": 2}, records)
        assert passed
        assert len(refs) == 2


class TestFieldPresent:
    """field_present: Universal operator — vacuous truth on empty set."""

    def test_pass_field_exists(self):
        records = [_make_record("risk_register", payload={"description": "risk"})]
        passed, refs = op_field_present({"record_type": "risk_register", "field": "/payload/description"}, records)
        assert passed
        assert len(refs) == 1

    def test_fail_field_missing(self):
        records = [_make_record("risk_register", payload={})]
        passed, refs = op_field_present({"record_type": "risk_register", "field": "/payload/description"}, records)
        assert not passed

    def test_vacuous_truth_empty_set(self):
        passed, refs = op_field_present({"record_type": "risk_register", "field": "/payload/description"}, [])
        assert passed
        assert refs == []

    def test_vacuous_truth_no_matching_type(self):
        records = [_make_record("dataset_card")]
        passed, refs = op_field_present({"record_type": "risk_register", "field": "/payload/description"}, records)
        assert passed
        assert refs == []


class TestFieldValue:
    """field_value: Universal operator with comparison operations."""

    def test_eq_pass(self):
        records = [_make_record("risk_register", payload={"severity": "high"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/severity", "op": "eq", "value": "high"}, records
        )
        assert passed

    def test_eq_fail(self):
        records = [_make_record("risk_register", payload={"severity": "low"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/severity", "op": "eq", "value": "high"}, records
        )
        assert not passed

    def test_ne_pass(self):
        records = [_make_record("risk_register", payload={"severity": "low"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/severity", "op": "ne", "value": "high"}, records
        )
        assert passed

    def test_gt_pass(self):
        records = [_make_record("risk_register", payload={"score": 80})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/score", "op": "gt", "value": 70}, records
        )
        assert passed

    def test_gt_fail(self):
        records = [_make_record("risk_register", payload={"score": 50})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/score", "op": "gt", "value": 70}, records
        )
        assert not passed

    def test_gte_pass(self):
        records = [_make_record("risk_register", payload={"score": 70})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/score", "op": "gte", "value": 70}, records
        )
        assert passed

    def test_lt_pass(self):
        records = [_make_record("risk_register", payload={"score": 30})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/score", "op": "lt", "value": 50}, records
        )
        assert passed

    def test_lte_pass(self):
        records = [_make_record("risk_register", payload={"score": 50})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/score", "op": "lte", "value": 50}, records
        )
        assert passed

    def test_in_pass(self):
        records = [_make_record("risk_register", payload={"severity": "high"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/severity", "op": "in", "value": ["high", "critical"]},
            records,
        )
        assert passed

    def test_in_fail(self):
        records = [_make_record("risk_register", payload={"severity": "low"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/severity", "op": "in", "value": ["high", "critical"]},
            records,
        )
        assert not passed

    def test_regex_pass(self):
        records = [_make_record("risk_register", payload={"name": "Model-v2.3"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/name", "op": "regex", "value": r"Model-v\d+\.\d+"},
            records,
        )
        assert passed

    def test_regex_fail(self):
        records = [_make_record("risk_register", payload={"name": "Other"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/name", "op": "regex", "value": r"^Model-"}, records
        )
        assert not passed

    def test_invalid_regex_raises_acef_045(self):
        records = [_make_record("risk_register", payload={"name": "test"})]
        with pytest.raises(ACEFEvaluationError) as exc_info:
            op_field_value(
                {"record_type": "risk_register", "field": "/payload/name", "op": "regex", "value": "[invalid("}, records
            )
        assert exc_info.value.code == "ACEF-045"

    def test_catastrophic_backtracking_pattern_rejected_deterministically(self):
        """PhD-review finding 11: a catastrophic-backtracking pattern previously
        raised ACEF-045 ONLY on Unix-main-thread (SIGALRM) and hung/completed
        elsewhere — a platform-dependent provision verdict. A nested unbounded
        quantifier is now rejected by a DETERMINISTIC static check (ACEF-045) on
        every platform, FAST (no 5s wall-clock timeout)."""
        import time

        records = [_make_record("risk_register", payload={"name": "aaaaaaaaaaaaaaaaaaaaaaaa!"})]
        # Both ReDoS classes incl. WRAPPED alternation variants that evaded a
        # top-level-only check (roborev on 6147931/7cbc854).
        for pat in (
            r"(a+)+$",
            r"(a*)*$",
            r"(.*)+b",
            r"(\d+)+x",
            r"(a|aa)+$",
            r"(a|a)*$",
            r"((a|aa))+$",
            r"(?:(a(?:|a)))+$",
        ):
            t0 = time.monotonic()
            with pytest.raises(ACEFEvaluationError) as exc_info:
                op_field_value(
                    {"record_type": "risk_register", "field": "/payload/name", "op": "regex", "value": pat}, records
                )
            assert exc_info.value.code == "ACEF-045", f"{pat!r} must be ACEF-045"
            # Deterministic static rejection — NOT a 5s wall-clock timeout.
            assert time.monotonic() - t0 < 1.0, f"{pat!r} must be rejected statically/fast, not via a timeout"

    def test_safe_quantified_group_still_matches(self):
        """A non-nested quantified group (e.g. (ab)+) is SAFE and must still match —
        the static check rejects only NESTED unbounded quantifiers, not all groups."""
        records = [_make_record("risk_register", payload={"name": "abababab"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/name", "op": "regex", "value": r"^(ab)+$"}, records
        )
        assert passed

    def test_sequential_adjacent_quantifier_redos_rejected_deterministically(self):
        """PhD RE-review (CRYPTO-1 / standards-editor W1): the §3.5 'deterministic
        resource bound' MUST also covers the SEQUENTIAL / adjacent-quantifier ReDoS
        class — two or more unbounded quantifiers over overlapping atoms with no
        mandatory separator (``a*a*…c``, ``.*.*x``, ``[a-z]+[a-z]+$``). These have NO
        quantified group, so the group-anchored nested-quantifier check missed them
        and ``re.search`` then ran with NO time guard (a live DoS: minutes at
        field-realistic lengths). They MUST now be rejected statically as ACEF-045,
        FAST, on every platform.

        The match input is deliberately SHORT so this assertion proves the *static
        pre-match rejection mechanism* (the deterministic resource bound) and never
        depends on, or risks, the backtracking blow-up itself.
        """
        import time

        records = [_make_record("risk_register", payload={"name": "aaaa!"})]
        for pat in (
            r"a*a*a*a*a*a*a*a*a*a*c",  # ten adjacent unbounded `a*`
            r".*.*.*.*.*.*.*x",  # adjacent `.*` (overlap = everything)
            r"[a-z]+[a-z]+[a-z]+[a-z]+$",  # adjacent class quantifiers
            r"\d+\d+\d+x",  # adjacent shorthand-class quantifiers
            r"a+a+a+a+!",  # adjacent literal quantifiers
            r"(a*a*)b",  # adjacency WRAPPED inside a group
            r"\w*\w*z",  # \w overlaps itself
            r"a.*b.*c",  # quadratic: two `.*` over an overlapping separator
        ):
            t0 = time.monotonic()
            with pytest.raises(ACEFEvaluationError) as exc_info:
                op_field_value(
                    {"record_type": "risk_register", "field": "/payload/name", "op": "regex", "value": pat}, records
                )
            assert exc_info.value.code == "ACEF-045", f"{pat!r} must be ACEF-045"
            assert time.monotonic() - t0 < 1.0, f"{pat!r} must be rejected statically/fast, not via a timeout"

    def test_adjacent_quantifier_detector_unit(self):
        """Unit-level RED anchor for the new static detector: the adjacent /
        sequential ReDoS class is True; benign separated or single-quantifier
        patterns are False (so the check does not over-reject real matchers)."""
        from acef.validation.operators import _has_adjacent_unbounded_quantifiers as has_adjacent

        for bad in (r"a*a*c", r".*.*x", r"[a-z]+[a-z]+$", r"\d+\d+", r"(a*a*)b", r"a.*b.*c", r"\w+\w+"):
            assert has_adjacent(bad) is True, f"{bad!r} is adjacent-quantifier ReDoS and must be detected"
        for good in (
            r"Model-v\d+\.\d+",  # \d+ separated by mandatory \.
            r"\d+-\d+-\d+",  # separated by mandatory -
            r"[a-z]+@[a-z]+\.[a-z]+",  # separated by mandatory @ and \.
            r"^(ab)+$",  # single quantified group, body not adjacent
            r"abc.*def",  # only ONE unbounded quantifier
            r"^https?://[a-z]+",  # `s?` nullable then a single [a-z]+
        ):
            assert has_adjacent(good) is False, f"{good!r} is safe and must NOT be flagged as ReDoS"

    def test_safe_separated_quantifiers_still_match(self):
        """End-to-end guard: patterns where a MANDATORY separator disjoint from the
        surrounding quantified classes breaks the ambiguity, or that carry only a
        single unbounded quantifier, must still MATCH (not be rejected as ReDoS)."""
        cases = [
            (r"\d+-\d+-\d+", "2024-11-30"),
            (r"[a-z]+@[a-z]+\.[a-z]+", "user@example.com"),
            (r"^v\d+\.\d+\.\d+$", "v1.2.3"),
            (r"^https?://[a-z]+", "https://acef"),
            (r"abc.*def", "abcXYZdef"),
        ]
        for pat, text in cases:
            records = [_make_record("risk_register", payload={"name": text})]
            passed, _ = op_field_value(
                {"record_type": "risk_register", "field": "/payload/name", "op": "regex", "value": pat}, records
            )
            assert passed, f"{pat!r} should match {text!r} and must NOT be rejected as ReDoS"

    def test_unknown_op_raises_acef_046(self):
        """F13: a typo'd comparison operator must raise ACEF-046, not silently
        FALSE-FAIL the rule. Before the fix _compare's fallthrough returned False."""
        records = [_make_record("risk_register", payload={"severity": "high"})]
        with pytest.raises(ACEFEvaluationError) as exc_info:
            op_field_value(
                {"record_type": "risk_register", "field": "/payload/severity", "op": "equals", "value": "high"}, records
            )
        assert exc_info.value.code == "ACEF-046"
        # ACEF-046 resolves through EXTENDED_ERROR_DETAILS (kept OUT of the frozen
        # ERROR_REGISTRY) to error/evaluation, not the conservative error/schema
        # default that an unregistered code would get.
        from acef.errors import ErrorCategory, Severity

        assert exc_info.value.severity == Severity.ERROR
        assert exc_info.value.category == ErrorCategory.EVALUATION

    def test_non_string_op_raises_acef_046_not_typeerror(self):
        """roborev Medium on 9deeb28: a non-string op (list/dict from malformed
        JSON params) must raise ACEF-046, not a raw TypeError from set membership
        on an unhashable value."""
        records = [_make_record("risk_register", payload={"severity": "high"})]
        for bad_op in ([["eq"]], [{"op": "eq"}]):  # unhashable op values
            with pytest.raises(ACEFEvaluationError) as exc_info:
                op_field_value(
                    {"record_type": "risk_register", "field": "/payload/severity", "op": bad_op[0], "value": "high"},
                    records,
                )
            assert exc_info.value.code == "ACEF-046"

    def test_unknown_op_with_missing_path_raises_acef_046(self):
        """roborev Low on 9deeb28: _compare's missing-path branch (actual is None
        -> op == 'ne') must NOT silently swallow an unknown op. With the op
        absent from the record, the unknown op must still raise ACEF-046."""
        records = [_make_record("risk_register", payload={})]  # /payload/missing is None
        with pytest.raises(ACEFEvaluationError) as exc_info:
            op_field_value(
                {"record_type": "risk_register", "field": "/payload/missing", "op": "equals", "value": "x"}, records
            )
        assert exc_info.value.code == "ACEF-046"

    def test_unknown_op_raises_acef_046_even_on_empty_record_set(self):
        """The op is structurally invalid regardless of data presence — like the
        ACEF-043 pointer check, it must raise even when zero records match
        (otherwise a typo'd op on an absent record-type passes vacuously)."""
        with pytest.raises(ACEFEvaluationError) as exc_info:
            op_field_value({"record_type": "risk_register", "field": "/payload/x", "op": "gtr", "value": 1}, [])
        assert exc_info.value.code == "ACEF-046"

    def test_vacuous_truth_empty(self):
        passed, _ = op_field_value({"record_type": "risk_register", "field": "/payload/x", "op": "eq", "value": 1}, [])
        assert passed

    def test_missing_path_ne_true(self):
        records = [_make_record("risk_register", payload={})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/missing", "op": "ne", "value": "anything"}, records
        )
        assert passed

    def test_missing_path_eq_false(self):
        records = [_make_record("risk_register", payload={})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/missing", "op": "eq", "value": "anything"}, records
        )
        assert not passed


class TestEvidenceFreshness:
    """evidence_freshness: Universal operator."""

    def test_pass_within_window(self):
        records = [_make_record("risk_register", timestamp="2025-06-01T00:00:00Z")]
        passed, _ = op_evidence_freshness(
            {"max_days": 365},
            records,
            evaluation_instant="2025-06-15T00:00:00Z",
        )
        assert passed

    def test_fail_outside_window(self):
        records = [_make_record("risk_register", timestamp="2020-01-01T00:00:00Z")]
        passed, _ = op_evidence_freshness(
            {"max_days": 30},
            records,
            evaluation_instant="2025-06-01T00:00:00Z",
        )
        assert not passed

    def test_vacuous_truth_empty(self):
        passed, _ = op_evidence_freshness({"max_days": 30}, [], evaluation_instant="2025-01-01T00:00:00Z")
        assert passed


class TestAttachmentExists:
    """attachment_exists: Existential operator."""

    def test_pass_with_attachment(self):
        att = AttachmentRef(path="artifacts/report.pdf", media_type="application/pdf")
        records = [_make_record("evaluation_report", attachments=[att])]
        passed, refs = op_attachment_exists({"record_type": "evaluation_report"}, records)
        assert passed
        assert len(refs) == 1

    def test_fail_no_attachment(self):
        records = [_make_record("evaluation_report")]
        passed, refs = op_attachment_exists({"record_type": "evaluation_report"}, records)
        assert not passed

    def test_fail_empty_records(self):
        passed, _ = op_attachment_exists({"record_type": "evaluation_report"}, [])
        assert not passed

    def test_naive_obligation_reference_vs_aware_record_no_typeerror(self):
        # F12: reference_date=obligation_effective_date resolves to provision_effective_date.
        # A BARE-DATE effective date ("2026-08-02") parses NAIVE (tzinfo=None) while a
        # Z-suffixed record timestamp parses AWARE (tzinfo=UTC), so `rec_dt >= cutoff` raised
        # `TypeError: can't compare offset-naive and offset-aware datetimes`. Both must be
        # normalized to UTC so the spec-normative obligation_effective_date reference works.
        rec = _make_record(timestamp="2026-08-01T12:00:00Z")
        passed, refs = op_evidence_freshness(
            {"max_days": 180, "reference_date": "obligation_effective_date"},
            [rec],
            provision_effective_date="2026-08-02",
        )
        assert passed is True
        assert rec.record_id in refs

    def test_media_type_filter(self):
        att = AttachmentRef(path="artifacts/report.pdf", media_type="application/pdf")
        records = [_make_record("evaluation_report", attachments=[att])]
        passed, _ = op_attachment_exists({"record_type": "evaluation_report", "media_type": "image/png"}, records)
        assert not passed


class TestEntityLinked:
    """entity_linked: Universal operator — vacuous truth on empty set."""

    def test_pass_subject_linked(self):
        records = [_make_record("risk_register", subject_refs=["urn:acef:sub:00000000-0000-0000-0000-000000000001"])]
        passed, refs = op_entity_linked({"record_type": "risk_register", "entity_type": "subject"}, records)
        assert passed
        assert len(refs) == 1

    def test_fail_no_subject_linked(self):
        records = [_make_record("risk_register")]
        passed, _ = op_entity_linked({"record_type": "risk_register", "entity_type": "subject"}, records)
        assert not passed

    def test_vacuous_truth_empty(self):
        passed, _ = op_entity_linked({"record_type": "risk_register", "entity_type": "subject"}, [])
        assert passed

    def test_dataset_linked(self):
        records = [_make_record("data_provenance", dataset_refs=["urn:acef:dat:00000000-0000-0000-0000-000000000001"])]
        passed, _ = op_entity_linked({"record_type": "data_provenance", "entity_type": "dataset"}, records)
        assert passed


class TestExistsWhere:
    """exists_where: Existential operator."""

    def test_pass(self):
        records = [_make_record("risk_register", payload={"severity": "high"})]
        passed, refs = op_exists_where(
            {"record_type": "risk_register", "field": "/payload/severity", "op": "eq", "value": "high"}, records
        )
        assert passed
        assert len(refs) == 1

    def test_unknown_op_raises_acef_046(self):
        """F13: exists_where must also reject an unknown comparison operator with
        ACEF-046 (symmetric with field_value), upfront — even on zero records."""
        with pytest.raises(ACEFEvaluationError) as exc_info:
            op_exists_where(
                {"record_type": "risk_register", "field": "/payload/severity", "op": "contains", "value": "x"}, []
            )
        assert exc_info.value.code == "ACEF-046"

    def test_fail(self):
        records = [_make_record("risk_register", payload={"severity": "low"})]
        passed, _ = op_exists_where(
            {"record_type": "risk_register", "field": "/payload/severity", "op": "eq", "value": "high"}, records
        )
        assert not passed

    def test_fail_empty_records(self):
        passed, _ = op_exists_where(
            {"record_type": "risk_register", "field": "/payload/x", "op": "eq", "value": 1, "min_count": 1}, []
        )
        assert not passed

    def test_min_count(self):
        records = [_make_record("risk_register", payload={"severity": "high"})]
        passed, _ = op_exists_where(
            {"record_type": "risk_register", "field": "/payload/severity", "op": "eq", "value": "high", "min_count": 2},
            records,
        )
        assert not passed


class TestAttachmentKindExists:
    """attachment_kind_exists: Existential operator."""

    def test_pass(self):
        att = AttachmentRef(path="artifacts/report.pdf", attachment_type="evaluation_report")
        records = [_make_record("evaluation_report", attachments=[att])]
        passed, refs = op_attachment_kind_exists(
            {"record_type": "evaluation_report", "attachment_type": "evaluation_report"}, records
        )
        assert passed
        assert len(refs) == 1

    def test_fail_wrong_kind(self):
        att = AttachmentRef(path="artifacts/other.pdf", attachment_type="other")
        records = [_make_record("evaluation_report", attachments=[att])]
        passed, _ = op_attachment_kind_exists(
            {"record_type": "evaluation_report", "attachment_type": "evaluation_report"}, records
        )
        assert not passed

    def test_fail_empty(self):
        passed, _ = op_attachment_kind_exists(
            {"record_type": "evaluation_report", "attachment_type": "evaluation_report"}, []
        )
        assert not passed


class TestBundleSigned:
    """bundle_signed: Existential operator on signatures."""

    def test_pass(self):
        passed, _ = op_bundle_signed({"min_signatures": 1}, [], signature_count=1)
        assert passed

    def test_fail_no_signatures(self):
        passed, _ = op_bundle_signed({"min_signatures": 1}, [], signature_count=0)
        assert not passed

    def test_required_alg(self):
        passed, _ = op_bundle_signed(
            {"min_signatures": 1, "required_alg": ["RS256"]},
            [],
            signature_count=1,
            signature_algorithms=["ES256"],
        )
        assert not passed


class TestRecordAttested:
    """record_attested: Existential operator with REAL JWS verification (spec §3.5).

    Per spec §3.5 a record counts only when its attestation carries a valid
    detached JWS over the RFC 8785-canonicalized signed_fields extraction —
    a non-empty signature string is NOT sufficient (VAL-FIX-DSL-001/002).
    """

    @staticmethod
    def _attach_signed_attestation(record: RecordEnvelope) -> None:
        """Sign /payload per the normative recipe and attach the attestation."""
        key = ec.generate_private_key(ec.SECP256R1())
        record_dict = record.to_jsonl_dict()
        subset = {"/payload": jsonpointer.resolve_pointer(record_dict, "/payload")}
        record.attestation = Attestation(
            method="jws",
            signer="provider",
            signature=create_detached_jws(canonicalize(subset), key, kid="attestor-key"),
        )

    def test_pass_with_verified_attestation(self):
        rec = _make_record("risk_register", payload={"description": "Identified risk", "score": 42})
        self._attach_signed_attestation(rec)
        passed, refs = op_record_attested({"record_type": "risk_register"}, [rec])
        assert passed
        assert len(refs) == 1

    def test_fail_forged_signature(self):
        """The pre-fix enshrined vector: garbage signature MUST NOT count."""
        att = Attestation(method="jws", signer="provider", signature="abc")
        records = [_make_record("risk_register", attestation=att)]
        passed, _ = op_record_attested({"record_type": "risk_register"}, records)
        assert not passed

    def test_fail_tampered_payload_after_signing(self):
        rec = _make_record("risk_register", payload={"description": "Identified risk", "score": 42})
        self._attach_signed_attestation(rec)
        rec.payload["score"] = 99  # tamper AFTER signing
        passed, _ = op_record_attested({"record_type": "risk_register"}, [rec])
        assert not passed

    def test_fail_non_jws_method(self):
        """v1 restricts attestation to JWS — other methods do NOT count."""
        rec = _make_record("risk_register", payload={"description": "Identified risk", "score": 42})
        self._attach_signed_attestation(rec)
        assert rec.attestation is not None
        rec.attestation.method = "c2pa"  # cryptographically valid sig, wrong method
        passed, _ = op_record_attested({"record_type": "risk_register"}, [rec])
        assert not passed

    def test_fail_no_attestation(self):
        records = [_make_record("risk_register")]
        passed, _ = op_record_attested({"record_type": "risk_register"}, records)
        assert not passed

    def test_fail_empty_signature(self):
        att = Attestation(method="jws", signer="provider", signature="")
        records = [_make_record("risk_register", attestation=att)]
        passed, _ = op_record_attested({"record_type": "risk_register"}, records)
        assert not passed

    def test_fail_empty_records(self):
        passed, _ = op_record_attested({"record_type": "risk_register"}, [])
        assert not passed
