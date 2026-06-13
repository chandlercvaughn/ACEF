"""VAL-BUILD-STIX-001 — RFC-0002 §5.8 STIX emit-only crosswalk path.

These tests pin the §5.8 STIX integration that :meth:`acef.package.Package.incident_card`
(and :meth:`Package.report_incident`'s ``card_source``) emits:

- ``taxonomy_crosswalk.stix`` is emitted as ``{"edition": "2.1", "object_refs": [...]}``
  ONLY when the caller supplies STIX object refs; it is OMITTED entirely otherwise
  (the member is optional — RFC §5.8 / Appendix E Q27).
- Each supplied ``object_ref`` MUST match the STIX 2.1 id grammar ``<type>--<uuidv4>``
  (mirroring ``acef-conventions/v1.1/taxonomy_crosswalk.schema.json`` ``object_refs``
  ``items.pattern``). A non-conformant ref raises a clear ``ValueError`` so the
  builder never emits a non-conformant id (producer-asserted: the builder validates
  and sorts, it does NOT mint refs).
- ``object_refs[]`` is sorted ascending by the RFC-8785 canonical byte sequence of
  its elements (§5.10), reusing the F-M3 :func:`acef.integrity.utf16_collation_key`
  collation helper. Two builds from the same (unsorted, possibly duplicated) input
  produce a byte-identical sorted, de-duplicated array.
- Emit-only: there is NO ingest path and the builder never invents STIX Incident
  Core Extension FIELD names (those are [unverified] / v1.2). The ACEF→STIX
  drop-list (:func:`acef.package.acef_stix_droplist`) documents the emit-direction
  mapping of each documented ACEF incident class/field to its STIX SDO TYPE, with
  explicit ``None`` (DROPPED) entries for ACEF concepts that have no STIX home.

Determinism: every test supplies fixed inputs and asserts on PATTERN / exact bytes,
never on wall-clock or random values.
"""

from __future__ import annotations

import re
import uuid

import pytest

from acef.integrity import utf16_collation_key
from acef.package import Package, acef_stix_droplist
from acef.redaction import RedactionPolicy
from acef.schemas.registry import validate_record_payload

# The STIX 2.1 id grammar mirrored from
# acef-conventions/v1.1/taxonomy_crosswalk.schema.json (stix.object_refs items.pattern).
_STIX_ID_PATTERN = re.compile(
    r"^[a-z][a-z0-9-]{2,249}--[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

_HARM_CORE = {
    "realization": "harm_event",
    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
    "harm_class": "physical_health",
}

_EU_FACTS = {
    "serious_incident_triggers": ["3.49.a"],
    "widespread": False,
    "death_involved": False,
}

# Fixed, deterministic, pattern-valid STIX 2.1 ids (v4 UUIDs hard-coded so the
# tests are byte-stable; the builder validates + sorts, it never mints these).
_STIX_INCIDENT = "incident--7c8d2f10-0000-4000-8000-000000000001"
_STIX_IDENTITY = "identity--a1b2c3d4-0000-4000-9000-000000000002"
_STIX_RELATIONSHIP = "relationship--ffffffff-0000-4000-bbbb-000000000003"
_STIX_MARKING = "marking-definition--0badf00d-0000-4000-a000-000000000004"


def _new_pkg() -> Package:
    return Package(
        producer={"name": "test", "version": "1.0"},
        redaction_policy=RedactionPolicy(version="1.0.0"),
    )


def _card(pkg: Package, **kwargs: object) -> object:
    return pkg.incident_card(
        public_incident_id="AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS",
        harm_core=dict(_HARM_CORE),
        severity_vector="ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",
        awareness_date="2026-08-01T00:00:00Z",
        eu_ai_act_facts=dict(_EU_FACTS),
        **kwargs,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Emit / omit gate.
# ---------------------------------------------------------------------------


class TestStixEmitGate:
    def test_stix_member_omitted_when_no_refs_supplied(self) -> None:
        env = _card(_new_pkg())
        assert "stix" not in env.payload["taxonomy_crosswalk"], (
            "the optional stix crosswalk member MUST be omitted when no object_refs are supplied"
        )

    def test_stix_member_emitted_with_edition_and_refs_when_supplied(self) -> None:
        env = _card(_new_pkg(), stix_object_refs=[_STIX_INCIDENT, _STIX_IDENTITY])
        stix = env.payload["taxonomy_crosswalk"]["stix"]
        assert stix["edition"] == "2.1"
        assert set(stix["object_refs"]) == {_STIX_INCIDENT, _STIX_IDENTITY}

    def test_stix_member_omitted_for_empty_list(self) -> None:
        # An explicitly empty list carries no SDO refs -> no member emitted.
        env = _card(_new_pkg(), stix_object_refs=[])
        assert "stix" not in env.payload["taxonomy_crosswalk"]

    def test_stix_is_scoped_to_public_incident_card_only(self) -> None:
        # The §5.8 emit-only STIX cross-reference lives on the PUBLIC incident_card's
        # taxonomy_crosswalk (Appendix A `incident_card` field table). The CONFIDENTIAL
        # incident_report.card_source is a CLOSED schema (additionalProperties: false)
        # that has NO taxonomy_crosswalk member, so report_incident does NOT accept a
        # stix_object_refs param and never emits a STIX member into card_source.
        import inspect

        report_params = inspect.signature(Package.report_incident).parameters
        assert "stix_object_refs" not in report_params, (
            "report_incident must NOT accept stix_object_refs — card_source is a closed "
            "schema with no taxonomy_crosswalk member; STIX is incident_card-only (§5.8)"
        )


# ---------------------------------------------------------------------------
# §5.10 deterministic sort + de-dup.
# ---------------------------------------------------------------------------


class TestStixSortAndDedup:
    def test_object_refs_sorted_by_rfc8785_canonical_bytes(self) -> None:
        unsorted = [_STIX_RELATIONSHIP, _STIX_INCIDENT, _STIX_MARKING, _STIX_IDENTITY]
        env = _card(_new_pkg(), stix_object_refs=list(unsorted))
        emitted = env.payload["taxonomy_crosswalk"]["stix"]["object_refs"]
        expected = sorted(unsorted, key=utf16_collation_key)
        assert emitted == expected, "object_refs[] must be sorted by the RFC-8785 canonical byte sequence (§5.10)"

    def test_two_builds_same_input_byte_identical_sorted_output(self) -> None:
        unsorted = [_STIX_MARKING, _STIX_INCIDENT, _STIX_RELATIONSHIP, _STIX_IDENTITY]
        first = _card(_new_pkg(), stix_object_refs=list(unsorted))
        second = _card(_new_pkg(), stix_object_refs=list(reversed(unsorted)))
        assert (
            first.payload["taxonomy_crosswalk"]["stix"]["object_refs"]
            == second.payload["taxonomy_crosswalk"]["stix"]["object_refs"]
        ), "the same input ref set MUST sort to byte-identical output regardless of input order"

    def test_duplicate_refs_are_deduplicated(self) -> None:
        env = _card(
            _new_pkg(),
            stix_object_refs=[_STIX_INCIDENT, _STIX_INCIDENT, _STIX_IDENTITY],
        )
        emitted = env.payload["taxonomy_crosswalk"]["stix"]["object_refs"]
        assert emitted == sorted({_STIX_INCIDENT, _STIX_IDENTITY}, key=utf16_collation_key)


# ---------------------------------------------------------------------------
# object_ref pattern validation (producer-asserted: validate, don't mint).
# ---------------------------------------------------------------------------


class TestStixRefValidation:
    @pytest.mark.parametrize(
        "bad_ref",
        [
            "incident-7c8d2f10-0000-4000-8000-000000000001",  # single dash, not `--`
            "Incident--7c8d2f10-0000-4000-8000-000000000001",  # uppercase type
            "incident--7c8d2f10-0000-1000-8000-000000000001",  # not a v4 UUID (version nibble)
            "incident--7c8d2f10-0000-4000-7000-000000000001",  # variant nibble not 8-b
            "incident--not-a-uuid",  # not a uuid at all
            "x--7c8d2f10-0000-4000-8000-000000000001",  # type token too short (< 3 chars)
            "",  # empty
        ],
    )
    def test_non_conformant_ref_raises_valueerror(self, bad_ref: str) -> None:
        with pytest.raises(ValueError):
            _card(_new_pkg(), stix_object_refs=[_STIX_INCIDENT, bad_ref])

    def test_valid_refs_match_schema_pattern(self) -> None:
        for ref in (_STIX_INCIDENT, _STIX_IDENTITY, _STIX_RELATIONSHIP, _STIX_MARKING):
            assert _STIX_ID_PATTERN.match(ref), f"test fixture {ref!r} is not a valid STIX 2.1 id"

    def test_emitted_card_validates_against_v1_1_schema(self) -> None:
        env = _card(_new_pkg(), stix_object_refs=[_STIX_RELATIONSHIP, _STIX_INCIDENT])
        errors = validate_record_payload(env.payload, "incident_card", "v1.1")
        assert errors == [], f"emitted incident_card with stix member failed v1.1 schema validation: {errors}"

    def test_freshly_minted_uuid4_ref_is_accepted(self) -> None:
        # A real uuid4 (lowercase hex) behind a valid type token is accepted.
        ref = f"sighting--{uuid.uuid4()}"
        env = _card(_new_pkg(), stix_object_refs=[ref])
        assert env.payload["taxonomy_crosswalk"]["stix"]["object_refs"] == [ref]


# ---------------------------------------------------------------------------
# ACEF -> STIX drop-list (documented emit-direction mapping).
# ---------------------------------------------------------------------------


class TestStixDropList:
    def test_droplist_is_a_mapping_of_acef_class_to_stix_type_or_none(self) -> None:
        dl = acef_stix_droplist()
        assert isinstance(dl, dict) and dl, "drop-list must be a non-empty mapping"
        for key, value in dl.items():
            assert isinstance(key, str)
            assert value is None or isinstance(value, str), (
                f"drop-list entry {key!r} must map to a STIX SDO type str or None (DROPPED), got {value!r}"
            )

    def test_droplist_covers_documented_crosswalk_fields(self) -> None:
        dl = acef_stix_droplist()
        # The documented ACEF incident_card fields from the Appendix A crosswalk
        # table (STIX 2.1 column, RFC §5.8 :470-482).
        for field in (
            "public_incident_id",
            "harm_core.harm_class",
            "harm_core.realization",
            "harm_core.causality",
            "harm_core.tangibility",
            "severity_vector",
            "value_chain_role",
            "autonomy_level",
            "harm_distribution_basis",
            "coordinated_disclosure",
            "transferability",
        ):
            assert field in dl, f"drop-list missing documented crosswalk field {field!r}"

    def test_droplist_covers_all_harm_class_codes(self) -> None:
        from acef.validation.incident_rules import _derivation_rows_by_class

        dl = acef_stix_droplist()
        for harm_class in _derivation_rows_by_class():
            key = f"harm_class:{harm_class}"
            assert key in dl, f"drop-list missing harm_class code {harm_class!r}"
            # harm_class codes have no STIX SDO home (Appendix A: harm_core.harm_class -> n/a).
            assert dl[key] is None, f"harm_class {harm_class!r} must be DROPPED (None), got {dl[key]!r}"

    def test_droplist_maps_known_fields_to_verified_stix_sdo_types(self) -> None:
        dl = acef_stix_droplist()
        # The mapped (non-DROPPED) entries point at verified STIX 2.1 SDO/SRO types,
        # never invented Incident-Core-Extension field names.
        assert dl["value_chain_role"] == "identity"
        assert dl["coordinated_disclosure"] == "marking-definition"
        assert dl["harm_core.causality"] == "relationship"
        assert dl["transferability"] == "relationship"
        # n/a STIX-column fields are explicitly DROPPED.
        assert dl["severity_vector"] is None
        assert dl["autonomy_level"] is None
        assert dl["harm_core.tangibility"] is None

    def test_droplist_values_are_lowercase_stix_type_tokens(self) -> None:
        dl = acef_stix_droplist()
        for value in dl.values():
            if value is not None:
                assert re.match(r"^[a-z][a-z0-9-]{2,}$", value), (
                    f"STIX SDO type token {value!r} is not a lowercase STIX type token"
                )
