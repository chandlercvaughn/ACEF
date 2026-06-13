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
_OECD_CRITERIA = [
    {"id": "oecd-crf-2025/19", "value": "v19"},
    {"id": "oecd-crf-2025/3", "value": "v3"},
    {"id": "oecd-crf-2025/11", "value": "v11"},
]
_AIID_REPORT_IDS = [100, 2, 10, 3, 1]
_NIST_CATEGORIES = ["cbrn", "dangerous-content", "harmful-bias"]


def _build_card(perm: Callable[[Sequence[Any]], list[Any]]) -> dict[str, Any]:
    """Build an incident_card whose order-insensitive arrays are permuted by ``perm``.

    The built-in derived arrays (eu_ai_act.serious_incident_triggers,
    nist_ai_600_1.categories) are exercised by feeding permuted supplied triggers;
    the caller-supplied crosswalk sub-members (oecd.criteria, aiid.report_ids) and
    transferability.related_incident_ids flow through extra_payload, which the
    builder must normalize.
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
    payload = dict(env.payload)
    # Splice the caller-supplied closed crosswalk sub-members (oecd.criteria,
    # aiid.report_ids, nist categories) the same shuffled two ways, mirroring a
    # producer that populates these members directly. They must be normalized at
    # emission time, so we re-run the public normalization the builder applies.
    crosswalk = dict(payload["taxonomy_crosswalk"])
    crosswalk["oecd"] = {"edition": "2025", "criteria": perm(_OECD_CRITERIA)}
    crosswalk["aiid"] = {"edition": "2024-12", "incident_id": 42, "report_ids": perm(_AIID_REPORT_IDS)}
    nist = dict(crosswalk.get("nist_ai_600_1", {"edition": "1.0"}))
    nist["categories"] = perm(_NIST_CATEGORIES)
    crosswalk["nist_ai_600_1"] = nist
    payload["taxonomy_crosswalk"] = crosswalk
    return Package._sort_incident_arrays(payload)


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

    def test_nist_categories_sorted_canonical(self) -> None:
        card = _build_card(_reverse)
        cats = card["taxonomy_crosswalk"]["nist_ai_600_1"]["categories"]
        assert cats == sorted(_NIST_CATEGORIES, key=canonicalize)

    def test_oecd_criteria_sorted_canonical(self) -> None:
        card = _build_card(_reverse)
        criteria = card["taxonomy_crosswalk"]["oecd"]["criteria"]
        # Whole-object canonical byte ordering (objects, not scalars).
        assert criteria == sorted(_OECD_CRITERIA, key=canonicalize)

    def test_aiid_report_ids_sorted_numeric_not_lexicographic(self) -> None:
        card = _build_card(_reverse)
        report_ids = card["taxonomy_crosswalk"]["aiid"]["report_ids"]
        # NUMERIC ascending: 1,2,3,10,100 — NOT canonical-byte (which would give
        # 1,10,100,2,3 because "10" < "2" lexicographically).
        assert report_ids == [1, 2, 3, 10, 100]
        assert report_ids != sorted(_AIID_REPORT_IDS, key=lambda x: canonicalize(x))

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
