"""F-M8-ARRAYSORT — §5.10 exhaustive intra-payload array determinism.

RFC-0002 §5.10 (and Q26): RFC 8785 (JCS) canonicalizes object KEYS but does NOT
reorder array ELEMENTS, so **every order-insensitive array the incident profile
introduces** MUST be sorted ascending by the RFC-8785 canonical byte sequence of
its element before hashing and serialization — exactly mirroring ACEF's existing
record ordering. The governing (non-exhaustive) list is:

    taxonomy_crosswalk.oecd.criteria[]
    taxonomy_crosswalk.eu_ai_act.serious_incident_triggers[]
    taxonomy_crosswalk.nist_ai_600_1.categories[]
    taxonomy_crosswalk.aiid.report_ids[]            (NUMERIC ascending)
    taxonomy_crosswalk.stix.object_refs[]
    transferability.related_incident_ids[]
    harm_distribution_basis[]
    coordinated_disclosure.regulatory_timeline[]
    + every array inside a crosswalk subschema

The ONLY order-significant exception is ``notification_timeline[]``, which MUST be
left in caller order.

This is a property/fuzz suite: it builds the same logical incident_card /
incident_report from inputs whose order-insensitive arrays are SHUFFLED two
deterministic ways (reverse / rotate / index-keyed swap — ``random`` is banned in
the hash domain), serializes both via :func:`acef.integrity.canonicalize` (the
canonical hash-domain path), and asserts the two outputs are BYTE-IDENTICAL. It
also proves ``notification_timeline[]`` is NOT sorted (two cards built with
different notification orders emit DIFFERENT bytes).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from acef.integrity import canonicalize
from acef.package import Package
from acef.redaction import RedactionPolicy
from acef.schemas.registry import validate_record_payload

_HARM_CORE = {
    "realization": "harm_event",
    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
    "harm_class": "physical_health",
}

_SEVERITY_VECTOR = "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I"
_AWARENESS = "2026-08-01T00:00:00Z"
_PUBLIC_ID = "AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS"


def _new_pkg() -> Package:
    return Package(
        producer={"name": "test", "version": "1.0"},
        redaction_policy=RedactionPolicy(version="1.0.0"),
    )


# Two deterministic, seed-free permutations (no `random` in the hash domain). Each
# is a genuine reordering for any list of length >= 2, so the order-insensitive
# arrays reach the builder in two distinct orders.
def _identity(seq: Sequence[Any]) -> list[Any]:
    return list(seq)


def _reverse(seq: Sequence[Any]) -> list[Any]:
    return list(reversed(seq))


def _rotate(seq: Sequence[Any]) -> list[Any]:
    s = list(seq)
    if len(s) < 2:
        return s
    return s[1:] + s[:1]


# Order-insensitive sample values, chosen so the WRONG ordering diverges:
#  - related_incident_ids / criteria / triggers / categories: strings whose
#    code-point order != insertion order.
#  - report_ids: integers where lexicographic ("10" < "2") != numeric (2 < 10),
#    so a canonical-BYTE sort would mis-order them; the §5.10 numeric rule must win.
_RELATED_IDS = ["AIIC-ACME-2026-ZZ", "AIIC-ACME-2026-AA", "AIIC-ACME-2026-MM"]
_HARM_DIST = ["sex", "age", "race", "geography"]
_TRIGGERS = ["3.49.d", "3.49.a", "3.49.c"]
# Schema-VALID crosswalk values, transcribed from acef-conventions/v1.1/
# taxonomy_crosswalk.schema.json so the EMITTED record validates against the
# closed v1.1 schema (oecd.edition const "oecd-crf-2025"; oecd.criteria[*].id
# matches ^oecd-crf-2025/[0-9]+$; aiid.edition const "aiid"; nist edition const
# "2024-07-final"; nist categories from the closed enum). The chosen orderings
# diverge from the §5.10 canonical sort so the WRONG order is detectable.
_OECD_EDITION = "oecd-crf-2025"
_OECD_CRITERIA = [
    {"id": "oecd-crf-2025/19", "value": "v19"},
    {"id": "oecd-crf-2025/3", "value": "v3"},
    {"id": "oecd-crf-2025/11", "value": "v11"},
]
_AIID_EDITION = "aiid"
_AIID_REPORT_IDS = [100, 2, 10, 3, 1]
_NIST_EDITION = "2024-07-final"
# Closed NIST AI 600-1 final enum members (verified, §5.5); insertion order is
# NOT canonical-byte order, so an un-normalized emission path diverges.
_NIST_CATEGORIES = [
    "Harmful Bias or Homogenization",
    "CBRN Information or Capabilities",
    "Dangerous, Violent, or Hateful Content",
]


def _build_card(perm: Callable[[Sequence[Any]], list[Any]]) -> dict[str, Any]:
    """Emit an incident_card via the typed ``incident_card()`` builder, with the
    order-insensitive arrays it CAN drive permuted by ``perm``.

    Exercises the arrays the typed builder owns end to end: the derived
    eu_ai_act.serious_incident_triggers (fed permuted supplied triggers),
    harm_distribution_basis, and transferability.related_incident_ids (via
    extra_payload). Returns the EMITTED envelope payload, so normalization is
    proven by what the builder actually stored — never by a private sorter.

    The closed crosswalk sub-members the typed builder does NOT derive
    (oecd.criteria, aiid.report_ids, an overridden nist categories set) cannot
    flow through this builder: ``incident_card`` merges ``extra_payload`` via
    ``setdefault`` and ``taxonomy_crosswalk`` is already derived, so a supplied
    crosswalk is dropped. Those members are exercised through the generic
    ``record()`` emission path instead (see ``_emit_card_via_record``).
    """
    pkg = _new_pkg()
    env = pkg.incident_card(
        public_incident_id=_PUBLIC_ID,
        harm_core=dict(_HARM_CORE),
        severity_vector=_SEVERITY_VECTOR,
        awareness_date=_AWARENESS,
        eu_ai_act_facts={
            "serious_incident_triggers": perm(_TRIGGERS),
            "widespread": False,
            "death_involved": False,
        },
        harm_distribution_basis=perm(_HARM_DIST),
        declared_publication_basis={
            "art6_basis": "legitimate_interests",
            "art9_condition": "explicit_consent",
        },
        extra_payload={
            "transferability": {
                "affects_other_models": True,
                "related_incident_ids": perm(_RELATED_IDS),
            },
        },
    )
    return dict(env.payload)


def _card_payload_with_crosswalk(perm: Callable[[Sequence[Any]], list[Any]]) -> dict[str, Any]:
    """A fully-formed, SCHEMA-VALID ``incident_card`` payload whose closed crosswalk
    sub-members (oecd.criteria, aiid.report_ids, nist categories) and the
    order-insensitive root arrays are permuted by ``perm``.

    All editions/values are valid against acef-conventions/v1.1/
    taxonomy_crosswalk.schema.json, so the payload — and the record emitted from it
    — passes the closed v1.1 schema. This is the input to the generic
    ``Package.record("incident_card", payload=...)`` emission path, which must
    normalize every order-insensitive array (the Medium roborev fix).
    """
    return {
        "public_incident_id": _PUBLIC_ID,
        "id_grade": "self-asserted",
        "harm_core": dict(_HARM_CORE),
        "severity_vector": _SEVERITY_VECTOR,
        "severity": "major",
        "harm_distribution_basis": perm(_HARM_DIST),
        "declared_publication_basis": {
            "art6_basis": "legitimate_interests",
            "art9_condition": "explicit_consent",
        },
        "transferability": {
            "affects_other_models": True,
            "related_incident_ids": perm(_RELATED_IDS),
        },
        "taxonomy_crosswalk": {
            "eu_ai_act": {
                "edition": "reg-2024-1689",
                "serious_incident_triggers": perm(_TRIGGERS),
                "widespread": False,
                "death_involved": False,
            },
            "oecd": {"edition": _OECD_EDITION, "criteria": perm(_OECD_CRITERIA)},
            "aiid": {"edition": _AIID_EDITION, "incident_id": 42, "report_ids": perm(_AIID_REPORT_IDS)},
            "nist_ai_600_1": {"edition": _NIST_EDITION, "categories": perm(_NIST_CATEGORIES)},
        },
    }


def _emit_card_via_record(perm: Callable[[Sequence[Any]], list[Any]]) -> dict[str, Any]:
    """Emit a crosswalk-bearing incident_card through the GENERIC ``record()`` path.

    This is the path the Medium roborev finding flagged: a producer that calls the
    public ``Package.record("incident_card", payload=...)`` API directly (not a
    typed builder) must still get §5.10-normalized output, or two logically
    identical incident records hash to different bytes. Returns the EMITTED
    envelope payload.
    """
    pkg = _new_pkg()
    env = pkg.record("incident_card", payload=_card_payload_with_crosswalk(perm))
    return dict(env.payload)


def _build_report(perm: Callable[[Sequence[Any]], list[Any]]) -> dict[str, Any]:
    pkg = _new_pkg()
    env = pkg.report_incident(
        public_incident_id=_PUBLIC_ID,
        harm_core=dict(_HARM_CORE),
        incident_type="malfunction",
        description="d",
        awareness_date=_AWARENESS,
        eu_ai_act_facts={
            "serious_incident_triggers": perm(_TRIGGERS),
            "widespread": False,
            "death_involved": False,
        },
    )
    return dict(env.payload)


class TestOrderInsensitiveArraysAreDeterministic:
    """Two builders fed shuffled inputs emit byte-identical canonical output."""

    def test_card_byte_identical_under_reverse_and_rotate(self) -> None:
        a = canonicalize(_build_card(_identity))
        b = canonicalize(_build_card(_reverse))
        c = canonicalize(_build_card(_rotate))
        assert a == b == c

    def test_harm_distribution_basis_sorted_canonical(self) -> None:
        card = _build_card(_reverse)
        assert card["harm_distribution_basis"] == sorted(_HARM_DIST, key=canonicalize)

    def test_eu_ai_act_triggers_sorted_canonical(self) -> None:
        card = _build_card(_reverse)
        triggers = card["taxonomy_crosswalk"]["eu_ai_act"]["serious_incident_triggers"]
        assert triggers == sorted(set(_TRIGGERS), key=canonicalize)

    def test_transferability_related_incident_ids_sorted_canonical(self) -> None:
        card = _build_card(_reverse)
        related = card["transferability"]["related_incident_ids"]
        assert related == sorted(_RELATED_IDS, key=canonicalize)

    def test_report_byte_identical_under_shuffle(self) -> None:
        a = canonicalize(_build_report(_identity))
        b = canonicalize(_build_report(_reverse))
        c = canonicalize(_build_report(_rotate))
        assert a == b == c

    def test_report_card_source_triggers_sorted_canonical(self) -> None:
        report = _build_report(_reverse)
        triggers = report["card_source"]["eu_ai_act_facts"]["serious_incident_triggers"]
        assert triggers == sorted(set(_TRIGGERS), key=canonicalize)


class TestGenericRecordPathNormalizesIncidentArrays:
    """The Medium roborev finding: the PUBLIC ``Package.record()`` API must apply the
    §5.10 normalization to ``incident_card`` / ``incident_report`` payloads, exactly
    like the typed builders, so the two paths emit byte-IDENTICAL output.

    Before the fix, ``Package.record("incident_card", payload=...)`` stored the
    caller's array order verbatim, so two logically identical incident records
    hashed to different hash-domain bytes.
    """

    def test_record_card_byte_identical_across_shuffled_inputs(self) -> None:
        # RED before the fix: the generic path stores caller order, so the two
        # shuffles emit DIVERGENT canonical bytes (a == b == c is False).
        a = canonicalize(_emit_card_via_record(_identity))
        b = canonicalize(_emit_card_via_record(_reverse))
        c = canonicalize(_emit_card_via_record(_rotate))
        assert a == b == c

    def test_record_card_matches_typed_builder_bytes_for_shared_arrays(self) -> None:
        # The generic path and the typed builder agree on every shared array, so a
        # producer cannot fork the hash by choosing one API over the other.
        via_record = _emit_card_via_record(_reverse)
        via_builder = _build_card(_reverse)
        assert via_record["harm_distribution_basis"] == via_builder["harm_distribution_basis"]
        assert (
            via_record["taxonomy_crosswalk"]["eu_ai_act"]["serious_incident_triggers"]
            == via_builder["taxonomy_crosswalk"]["eu_ai_act"]["serious_incident_triggers"]
        )
        assert (
            via_record["transferability"]["related_incident_ids"]
            == via_builder["transferability"]["related_incident_ids"]
        )

    def test_record_emitted_card_validates_against_v1_1_schema(self) -> None:
        # The emitted record (schema-valid editions/values) passes the closed v1.1
        # incident_card schema, proving these are real emission-path bytes, not a
        # private-sorter artifact on a schema-invalid fixture.
        payload = _emit_card_via_record(_reverse)
        errors = validate_record_payload(payload, "incident_card", "v1.1")
        assert errors == [], f"emitted incident_card failed v1.1 schema validation: {errors}"

    def test_record_oecd_criteria_sorted_canonical(self) -> None:
        criteria = _emit_card_via_record(_reverse)["taxonomy_crosswalk"]["oecd"]["criteria"]
        # Whole-object canonical byte ordering (criteria entries are objects).
        assert criteria == sorted(_OECD_CRITERIA, key=canonicalize)

    def test_record_aiid_report_ids_sorted_numeric_not_lexicographic(self) -> None:
        report_ids = _emit_card_via_record(_reverse)["taxonomy_crosswalk"]["aiid"]["report_ids"]
        # NUMERIC ascending: 1,2,3,10,100 — NOT canonical-byte (which would give
        # 1,10,100,2,3 because "10" sorts before "2" lexicographically).
        assert report_ids == [1, 2, 3, 10, 100]
        assert report_ids != sorted(_AIID_REPORT_IDS, key=lambda x: canonicalize(x))

    def test_record_nist_categories_sorted_canonical(self) -> None:
        cats = _emit_card_via_record(_reverse)["taxonomy_crosswalk"]["nist_ai_600_1"]["categories"]
        assert cats == sorted(_NIST_CATEGORIES, key=canonicalize)

    def test_record_report_byte_identical_across_shuffled_inputs(self) -> None:
        # The incident_report type is normalized through the generic path too.
        def _emit_report(perm: Callable[[Sequence[Any]], list[Any]]) -> dict[str, Any]:
            pkg = _new_pkg()
            payload = {
                "public_incident_id": _PUBLIC_ID,
                "harm_core": dict(_HARM_CORE),
                "incident_type": "malfunction",
                "description": "d",
                "card_source": {
                    "eu_ai_act_facts": {
                        "serious_incident_triggers": perm(_TRIGGERS),
                        "widespread": False,
                        "death_involved": False,
                    },
                },
            }
            return dict(pkg.record("incident_report", payload=payload).payload)

        a = canonicalize(_emit_report(_identity))
        b = canonicalize(_emit_report(_reverse))
        assert a == b
        card_source = _emit_report(_reverse)["card_source"]
        triggers = card_source["eu_ai_act_facts"]["serious_incident_triggers"]
        assert triggers == sorted(set(_TRIGGERS), key=canonicalize)

    def test_record_notification_timeline_is_order_significant(self) -> None:
        # notification_timeline[] stays order-SIGNIFICANT even through the generic
        # path: two different orders emit DIFFERENT bytes (never sorted).
        def _emit(entries: list[dict[str, Any]]) -> dict[str, Any]:
            pkg = _new_pkg()
            payload = {
                "public_incident_id": _PUBLIC_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_HARM_CORE),
                "notification_timeline": entries,
            }
            return dict(pkg.record("incident_card", payload=payload).payload)

        entries = [
            {"audience": "regulator", "date": "2026-08-02"},
            {"audience": "public", "date": "2026-08-10"},
        ]
        forward = _emit(entries)
        backward = _emit(list(reversed(entries)))
        assert forward["notification_timeline"] == entries
        assert canonicalize(forward) != canonicalize(backward)

    def test_record_does_not_mutate_caller_payload(self) -> None:
        # The generic path must NOT destructively reorder the caller's input dict
        # (the typed builders operate on their own assembled payload). A caller
        # who reuses the payload after record() must see their original order.
        payload = _card_payload_with_crosswalk(_reverse)
        original_hdb = list(payload["harm_distribution_basis"])
        original_oecd = [dict(c) for c in payload["taxonomy_crosswalk"]["oecd"]["criteria"]]
        pkg = _new_pkg()
        pkg.record("incident_card", payload=payload)
        assert payload["harm_distribution_basis"] == original_hdb
        assert payload["taxonomy_crosswalk"]["oecd"]["criteria"] == original_oecd

    def test_record_non_incident_type_is_untouched(self) -> None:
        # A non-incident record_type with an order-insensitive-looking array is NOT
        # normalized — §5.10 applies only to incident_card / incident_report.
        pkg = _new_pkg()
        payload = {"harm_distribution_basis": ["sex", "age", "race"]}
        env = pkg.record("event_log", payload=payload, obligation_role="provider")
        assert env.payload["harm_distribution_basis"] == ["sex", "age", "race"]


class TestNotificationTimelineIsOrderSignificant:
    """notification_timeline[] is the §5.10 exception — caller order MUST survive."""

    def _card_with_notifications(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEVERITY_VECTOR,
            awareness_date=_AWARENESS,
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": False,
            },
            extra_payload={"notification_timeline": entries},
        )
        return Package._sort_incident_arrays(dict(env.payload))

    def test_notification_timeline_order_preserved(self) -> None:
        entries = [
            {"audience": "regulator", "date": "2026-08-02"},
            {"audience": "affected_users", "date": "2026-08-05"},
            {"audience": "public", "date": "2026-08-10"},
        ]
        card = self._card_with_notifications(entries)
        # Order is NOT sorted — it is the exact caller sequence.
        assert card["notification_timeline"] == entries

    def test_notification_timeline_two_orders_diverge(self) -> None:
        entries = [
            {"audience": "regulator", "date": "2026-08-02"},
            {"audience": "public", "date": "2026-08-10"},
        ]
        forward = self._card_with_notifications(entries)
        backward = self._card_with_notifications(list(reversed(entries)))
        # Because notification_timeline is order-SIGNIFICANT (not sorted), the two
        # different orderings produce DIFFERENT canonical bytes.
        assert canonicalize(forward) != canonicalize(backward)
