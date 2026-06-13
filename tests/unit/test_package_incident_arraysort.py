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
from acef.models.enums import Confidentiality
from acef.package import (
    Package,
    _v1_1_only_incident_report_fields,
    compute_incident_dedupe_key,
)
from acef.redaction import RedactionPolicy
from acef.schemas.registry import validate_record_payload
from acef.validation.incident_rules import check_dedupe_key_confidentiality

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
        incident_type="operational_failure",
        description="d",
        awareness_date=_AWARENESS,
        eu_ai_act_facts={
            "serious_incident_triggers": perm(_TRIGGERS),
            "widespread": False,
            "death_involved": False,
        },
    )
    return dict(env.payload)


def _valid_report_payload(perm: Callable[[Sequence[Any]], list[Any]]) -> dict[str, Any]:
    """A SCHEMA-VALID source-backed ``incident_report`` payload for the GENERIC
    ``Package.record('incident_report', payload=...)`` path, with its
    order-insensitive ``card_source.eu_ai_act_facts.serious_incident_triggers``
    permuted by ``perm``.

    Every field is valid against acef-conventions/v1.1/incident_report.schema.json
    + incident_report.card_source.schema.json (roborev Low on 103bd03b — the prior
    fixture was schema-INVALID: ``incident_type:'malfunction'`` is outside the v1.1
    enum, the root ``severity`` was missing, and ``card_source`` omitted its
    required ``id_grade``/``id_state``/``publishability_map`` and the
    ``eu_ai_act_facts.edition`` const). Because it carries ``card_source`` it is a
    v1.1-only payload — recording it MUST route the package to 1.1.0 so the v1.1
    schema set + incident rules actually run (the Medium fix). The chosen trigger
    order diverges from the §5.10 canonical sort so the WRONG order is detectable.
    """
    return {
        "incident_type": "operational_failure",
        "description": "d",
        "severity": "major",
        "card_source": {
            "public_incident_id": _PUBLIC_ID,
            "id_grade": "self-asserted",
            "id_state": "RESERVED",
            "harm_core": dict(_HARM_CORE),
            "publishability_map": {},
            "eu_ai_act_facts": {
                "edition": "reg-2024-1689",
                "serious_incident_triggers": perm(_TRIGGERS),
                "widespread": False,
                "death_involved": False,
            },
        },
    }


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
        # The incident_report type is normalized through the generic path too. The
        # fixture is SCHEMA-VALID (roborev Low): so this proves real emission-path
        # bytes on a card_source the v1.1 schema accepts, not a private-sorter
        # artifact on a schema-invalid payload.
        def _emit_report(perm: Callable[[Sequence[Any]], list[Any]]) -> dict[str, Any]:
            pkg = _new_pkg()
            return dict(pkg.record("incident_report", payload=_valid_report_payload(perm)).payload)

        a = canonicalize(_emit_report(_identity))
        b = canonicalize(_emit_report(_reverse))
        assert a == b
        card_source = _emit_report(_reverse)["card_source"]
        triggers = card_source["eu_ai_act_facts"]["serious_incident_triggers"]
        assert triggers == sorted(set(_TRIGGERS), key=canonicalize)

    def test_record_emitted_report_validates_against_v1_1_schema(self) -> None:
        # roborev Low: the emitted source-backed incident_report passes the v1.1
        # schema (card_source schema-checked, not swallowed as an unchecked
        # additionalProperty under a v1.0 manifest).
        pkg = _new_pkg()
        env = pkg.record("incident_report", payload=_valid_report_payload(_reverse))
        errors = validate_record_payload(dict(env.payload), "incident_report", "v1.1")
        assert errors == [], f"emitted incident_report failed v1.1 schema validation: {errors}"

    def test_record_source_backed_report_routes_to_v1_1(self) -> None:
        # roborev Medium: a default (v1.0) Package recording an incident_report
        # whose payload carries the v1.1-only card_source block MUST bump
        # core_version to 1.1.0 — exactly as the typed report_incident() builder
        # does via _ensure_v1_1(). RED before the fix: the generic record() path
        # left a default package at core_version 1.0.0, so the FROZEN v1.0 schema
        # (additionalProperties:true, no card_source property) swallowed card_source
        # as an UNCHECKED additionalProperty and v1.1 card_source validation +
        # incident rules were SILENTLY BYPASSED.
        pkg = _new_pkg()
        assert pkg._versioning.core_version == "1.0.0"
        pkg.record("incident_report", payload=_valid_report_payload(_identity))
        assert pkg._versioning.core_version == "1.1.0"

    def test_record_v1_0_only_report_stays_v1_0(self) -> None:
        # Backward-compat guard (do NOT over-gate): a plain v1.0 incident_report
        # WITHOUT any v1.1-only member (no card_source) keeps core_version 1.0.0.
        # Only a v1.1-content payload triggers the bump.
        pkg = Package(producer={"name": "test", "version": "1.0"})
        assert pkg._versioning.core_version == "1.0.0"
        env = pkg.record(
            "incident_report",
            payload={"incident_type": "operational_failure", "description": "d", "severity": "major"},
            obligation_role="provider",
        )
        assert pkg._versioning.core_version == "1.0.0"
        # The v1.0-only payload validates against the v1.0 incident_report schema.
        assert validate_record_payload(dict(env.payload), "incident_report", "v1") == []

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


class TestGenericSourceBackedReportConfidentiality:
    """roborev High (8826e7f7 / 6211995b): a generic ``Package.record('incident_report',
    {…card_source…})`` MUST NOT export the source-backed §5.7 regulator-filing record as
    PUBLIC. The typed ``report_incident()`` builder defaults source-backed reports to
    ``regulator-only`` (package.py: ``confidentiality: ... = Confidentiality.REGULATOR_ONLY``);
    the generic path must MIRROR that — a ``card_source``-bearing report arriving at PUBLIC is
    coerced to ``regulator-only`` so the confidential ``eu_ai_act_facts`` block is never
    exported public.

    RED before the fix: the generic path left confidentiality at the ``record()`` default
    ``Confidentiality.PUBLIC``, so a confidential source-backed ``card_source`` exported PUBLIC.
    """

    def _build_pkg(self) -> Package:
        return _new_pkg()

    def test_generic_source_backed_report_is_not_public(self) -> None:
        # RED pre-fix: env.confidentiality == Confidentiality.PUBLIC (value "public").
        pkg = self._build_pkg()
        env = pkg.record("incident_report", payload=_valid_report_payload(_identity))
        assert env.confidentiality != Confidentiality.PUBLIC
        assert env.confidentiality == Confidentiality.REGULATOR_ONLY

    def test_generic_source_backed_report_matches_typed_default(self) -> None:
        # Generic↔typed PARITY: both default a source-backed report to regulator-only.
        generic = self._build_pkg().record("incident_report", payload=_valid_report_payload(_identity))
        typed = self._build_pkg().report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="d",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": False,
            },
        )
        assert generic.confidentiality == typed.confidentiality == Confidentiality.REGULATOR_ONLY

    def test_generic_source_backed_report_exported_confidentiality_is_non_public(self) -> None:
        # BUNDLE-LEVEL coverage: the SERIALIZED envelope (the on-disk shape a validator /
        # exporter reads) carries a non-public confidentiality for a source-backed report —
        # the confidential card_source.eu_ai_act_facts is never persisted under a PUBLIC label.
        pkg = self._build_pkg()
        env = pkg.record("incident_report", payload=_valid_report_payload(_identity))
        wire = env.to_jsonl_dict()
        assert "card_source" in wire["payload"]
        assert wire["confidentiality"] != Confidentiality.PUBLIC.value
        assert wire["confidentiality"] == Confidentiality.REGULATOR_ONLY.value

    def test_generic_caller_may_choose_a_different_non_public_level(self) -> None:
        # An explicit non-public level the caller chose is HONORED (the coercion only
        # rescues the PUBLIC default; it never overrides a caller's deliberate non-public
        # choice). under-nda survives.
        pkg = self._build_pkg()
        env = pkg.record(
            "incident_report",
            payload=_valid_report_payload(_identity),
            confidentiality=Confidentiality.UNDER_NDA,
        )
        assert env.confidentiality == Confidentiality.UNDER_NDA

    def test_plain_v1_0_report_honors_caller_public(self) -> None:
        # Backward-compat: a plain v1.0 incident_report (NO card_source) honors the caller's
        # PUBLIC confidentiality unchanged — the coercion is scoped to source-backed reports.
        pkg = Package(producer={"name": "test", "version": "1.0"})
        env = pkg.record(
            "incident_report",
            payload={"incident_type": "operational_failure", "description": "d", "severity": "major"},
            obligation_role="provider",
        )
        assert env.confidentiality == Confidentiality.PUBLIC
        assert pkg._versioning.core_version == "1.0.0"


class TestGenericReportDedupeKeyTriggersV11Rules:
    """roborev Medium (8826e7f7 / 6211995b): the generic-report v1.1 trigger set was ONLY the
    schema property diff (``{card_source}``), so rule-owned v1.1 fields
    ``incident_dedupe_key`` / ``incident_dedupe_key_hmac`` did NOT bump a generic
    ``incident_report`` to v1.1 — the incident rules (incl. ACEF-086: non-public plaintext
    dedupe leak + malformed dedupe shape) run ONLY on v1.1, so they were SILENTLY skipped.

    The fix extends the trigger to the UNION of (schema property diff) ∪ (rule-owned v1.1
    fields ``incident_dedupe_key`` / ``incident_dedupe_key_hmac``).
    """

    def test_trigger_set_includes_rule_owned_dedupe_fields(self) -> None:
        triggers = _v1_1_only_incident_report_fields()
        assert "card_source" in triggers  # the schema-diff member is preserved
        assert "incident_dedupe_key" in triggers
        assert "incident_dedupe_key_hmac" in triggers

    def test_generic_report_with_dedupe_key_routes_to_v1_1(self) -> None:
        # RED pre-fix: a default (v1.0) Package recording an incident_report carrying a
        # rule-owned incident_dedupe_key (but NO card_source) stayed at core_version 1.0.0,
        # so run_incident_rules (gated on schema_version == "v1.1") NEVER ran → ACEF-086
        # bypassed. (A RedactionPolicy is attached so the now-v1.1 non-public record can
        # auto-populate X1/X2; the routing assertion is independent of it.)
        pkg = _new_pkg()
        assert pkg._versioning.core_version == "1.0.0"
        pkg.record(
            "incident_report",
            payload={
                "incident_type": "operational_failure",
                "description": "d",
                "severity": "major",
                "incident_dedupe_key": "sha256:" + "a" * 64,
            },
            obligation_role="provider",
            confidentiality=Confidentiality.REGULATOR_ONLY,
        )
        assert pkg._versioning.core_version == "1.1.0"

    def test_generic_report_with_dedupe_hmac_routes_to_v1_1(self) -> None:
        pkg = _new_pkg()
        pkg.record(
            "incident_report",
            payload={
                "incident_type": "operational_failure",
                "description": "d",
                "severity": "major",
                "incident_dedupe_key_hmac": "hmac-sha256:" + "b" * 64,
            },
            obligation_role="provider",
            confidentiality=Confidentiality.REGULATOR_ONLY,
        )
        assert pkg._versioning.core_version == "1.1.0"

    def test_generic_non_public_plaintext_dedupe_is_stripped_not_emitted(self) -> None:
        # The §5.5 confidentiality MUST is enforced at EMISSION (roborev High on 7aa6c09f):
        # a subject-bearing plaintext incident_dedupe_key handed to a NON-public record is an
        # offline-enumerable leak, so the SDK STRIPS it (it does not author the leaky shape).
        # The record still routes to v1.1 (the dedupe field is a v1.1 trigger), and the emitted
        # envelope is ACEF-086-CONFORMANT — the rule does not fire on the SDK's own output. (The
        # rule's positive case — firing on a hand-built leaky shape — is proven separately in
        # TestCoercionDoesNotLeavePlaintextDedupeOnNonPublic.test_acef_086_would_fire_on_the_pre_fix_shape.)
        pkg = _new_pkg()
        env = pkg.record(
            "incident_report",
            payload={
                "incident_type": "operational_failure",
                "description": "d",
                "severity": "major",
                "incident_dedupe_key": "sha256:" + "a" * 64,
            },
            obligation_role="provider",
            confidentiality=Confidentiality.REGULATOR_ONLY,
        )
        assert pkg._versioning.core_version == "1.1.0"  # v1.1 routing still happens
        wire = env.to_jsonl_dict()
        assert "incident_dedupe_key" not in wire["payload"]
        diags = check_dedupe_key_confidentiality([wire])
        assert not any(d.code == "ACEF-086" for d in diags), diags

    def test_acef_086_fires_on_generic_malformed_dedupe_shape(self) -> None:
        # The shape MUST: a malformed incident_dedupe_key value → ACEF-086. The generic path
        # routes the record to v1.1 so the shape rule (which the v1.1 incident_report schema
        # does NOT enforce — additionalProperties:true) actually runs.
        pkg = Package(producer={"name": "test", "version": "1.0"})
        env = pkg.record(
            "incident_report",
            payload={
                "incident_type": "operational_failure",
                "description": "d",
                "severity": "major",
                # Malformed: not the ^sha256:[0-9a-f]{64}$ shape. PUBLIC so the confidentiality
                # rule does not also fire — isolates the SHAPE check.
                "incident_dedupe_key": "not-a-valid-dedupe-key",
            },
            obligation_role="provider",
        )
        diags = check_dedupe_key_confidentiality([env.to_jsonl_dict()])
        assert any(d.code == "ACEF-086" for d in diags), diags

    def test_plain_v1_0_report_without_dedupe_stays_v1_0(self) -> None:
        # Backward-compat (no over-gating): a plain v1.0 incident_report with NO v1.1 member
        # (no card_source, no dedupe field) stays at core_version 1.0.0.
        pkg = Package(producer={"name": "test", "version": "1.0"})
        env = pkg.record(
            "incident_report",
            payload={"incident_type": "operational_failure", "description": "d", "severity": "major"},
            obligation_role="provider",
        )
        assert pkg._versioning.core_version == "1.0.0"
        assert validate_record_payload(dict(env.payload), "incident_report", "v1") == []


class TestCoercionDoesNotLeavePlaintextDedupeOnNonPublic:
    """roborev High (7aa6c09f): the PUBLIC→regulator-only source-backed coercion can leave an
    already-present PLAINTEXT ``incident_dedupe_key`` (subject-bearing) on a now-NON-public record.

    The §5.5 confidentiality MUST (ACEF-086, owned by F-M8-DEDUPE): the plaintext
    ``incident_dedupe_key`` is a PUBLIC-ONLY spine — on a non-public record it MUST be HMAC'd
    (``incident_dedupe_key_hmac``) or OMITTED, never present in plaintext. The fix resolves the
    EFFECTIVE confidentiality (after any coercion) BEFORE the dedupe-key form is decided, then
    applies the F-M8-DEDUPE rule uniformly: PUBLIC → plaintext stays; NON-public → plaintext is
    stripped (and, lacking a generic-caller pepper, OMITTED — fail-safe, never emit plaintext on
    non-public).
    """

    _PLAINTEXT_KEY = "sha256:" + "a" * 64

    def _generic_source_backed_with_plaintext_dedupe(self) -> dict[str, Any]:
        payload = _valid_report_payload(_identity)
        payload["incident_dedupe_key"] = self._PLAINTEXT_KEY
        return payload

    def test_generic_coercion_strips_plaintext_dedupe_on_non_public(self) -> None:
        # EXPLOIT PATH 1 (generic). A source-backed report arriving at PUBLIC carrying a plaintext
        # incident_dedupe_key is coerced to regulator-only (non-public) by record(). RED pre-fix:
        # the coercion ran AFTER the plaintext key was accepted, so the EXPORTED regulator-only
        # record still carried the plaintext incident_dedupe_key (subject-bearing leak on a
        # non-public record) — ACEF-086 violation. After the fix: the emitted record is non-public
        # AND carries NO plaintext incident_dedupe_key (omitted; no pepper to HMAC with).
        pkg = _new_pkg()
        env = pkg.record(
            "incident_report",
            payload=self._generic_source_backed_with_plaintext_dedupe(),
            confidentiality=Confidentiality.PUBLIC,
        )
        wire = env.to_jsonl_dict()
        assert wire["confidentiality"] != Confidentiality.PUBLIC.value
        assert wire["confidentiality"] == Confidentiality.REGULATOR_ONLY.value
        assert "incident_dedupe_key" not in wire["payload"]

    def test_generic_coercion_emitted_record_is_acef_086_conformant(self) -> None:
        # The corrected output is conformant: ACEF-086 does NOT fire on the emitted (stripped)
        # record. RED pre-fix: ACEF-086 fired (plaintext key surviving on a regulator-only record).
        pkg = _new_pkg()
        env = pkg.record(
            "incident_report",
            payload=self._generic_source_backed_with_plaintext_dedupe(),
            confidentiality=Confidentiality.PUBLIC,
        )
        diags = check_dedupe_key_confidentiality([env.to_jsonl_dict()])
        assert not any(d.code == "ACEF-086" for d in diags), diags

    def test_acef_086_would_fire_on_the_pre_fix_shape(self) -> None:
        # Witness the violation the fix prevents: the PRE-FIX illegal shape (a regulator-only
        # record that still carries the plaintext key) DOES trip ACEF-086. This anchors the RED
        # observation independently of the builder, proving the omit is what makes it conformant.
        pre_fix_wire = {
            "record_id": "urn:acef:record:test",
            "record_type": "incident_report",
            "confidentiality": Confidentiality.REGULATOR_ONLY.value,
            "payload": {
                "incident_type": "operational_failure",
                "description": "d",
                "severity": "major",
                "incident_dedupe_key": self._PLAINTEXT_KEY,
            },
        }
        diags = check_dedupe_key_confidentiality([pre_fix_wire])
        assert any(d.code == "ACEF-086" for d in diags), diags

    def test_typed_report_incident_public_strips_plaintext_after_effective_coercion(self) -> None:
        # EXPLOIT PATH 2 (typed). report_incident(confidentiality=PUBLIC, …dedupe inputs…) computes
        # the plaintext key because the CALLER-supplied confidentiality is PUBLIC — but record()
        # then coerces the source-backed report to regulator-only. RED pre-fix: the plaintext key
        # was computed against the caller's PUBLIC then coerced, leaving plaintext on a non-public
        # record. After the fix: report_incident resolves the EFFECTIVE confidentiality first, so a
        # source-backed report (always coerced non-public) never computes/emits the plaintext key.
        pkg = _new_pkg()
        env = pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="d",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": False,
            },
            value_chain_role="provider",
            subject_identity=("org", "openai", "gpt"),
            occurrence_date="2026-07-30T00:00:00Z",
            confidentiality=Confidentiality.PUBLIC,
        )
        wire = env.to_jsonl_dict()
        assert wire["confidentiality"] != Confidentiality.PUBLIC.value
        assert "incident_dedupe_key" not in wire["payload"]
        diags = check_dedupe_key_confidentiality([wire])
        assert not any(d.code == "ACEF-086" for d in diags), diags

    def test_legitimate_public_card_keeps_plaintext_spine(self) -> None:
        # Backward-compat / no over-strip: the LEGITIMATE public spine — a PUBLIC incident_card
        # with the plaintext incident_dedupe_key — is UNAFFECTED. The strip only applies when the
        # record resolves NON-public; a genuinely public card keeps its plaintext key.
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
            value_chain_role="provider",
            subject_identity=("org", "openai", "gpt"),
            occurrence_date="2026-07-30T00:00:00Z",
            confidentiality=Confidentiality.PUBLIC,
        )
        wire = env.to_jsonl_dict()
        assert wire["confidentiality"] == Confidentiality.PUBLIC.value
        assert wire["payload"]["incident_dedupe_key"] == compute_incident_dedupe_key(
            value_chain_role="provider",
            subject_identity=("org", "openai", "gpt"),
            harm_class=_HARM_CORE["harm_class"],
            occurrence_date="2026-07-30T00:00:00Z",
            detection_date=None,
        )
        diags = check_dedupe_key_confidentiality([wire])
        assert not any(d.code == "ACEF-086" for d in diags), diags

    def test_generic_non_public_with_plaintext_dedupe_no_card_source_is_stripped(self) -> None:
        # The strip is keyed on EFFECTIVE non-public confidentiality, not solely on card_source: a
        # caller who explicitly records a NON-public incident_report carrying a plaintext dedupe key
        # (no card_source, so no coercion) must also have it omitted — the public-only spine rule is
        # uniform. RED pre-fix: the plaintext key survived on the explicitly-non-public record.
        pkg = _new_pkg()
        env = pkg.record(
            "incident_report",
            payload={
                "incident_type": "operational_failure",
                "description": "d",
                "severity": "major",
                "incident_dedupe_key": self._PLAINTEXT_KEY,
            },
            obligation_role="provider",
            confidentiality=Confidentiality.UNDER_NDA,
        )
        wire = env.to_jsonl_dict()
        assert wire["confidentiality"] == Confidentiality.UNDER_NDA.value
        assert "incident_dedupe_key" not in wire["payload"]
        diags = check_dedupe_key_confidentiality([wire])
        assert not any(d.code == "ACEF-086" for d in diags), diags


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
