"""VAL-BUILD-EDGES-001 — RFC-0002 §5.8/§8 incident relationship edges.

The §8-mandated additive Core change for the incident graph (RFC-0002 §5.8,
§8 #4):

1.  The closed ``relationship_type`` enum in
    ``acef-conventions/v1.1/manifest.schema.json`` is extended with the FIVE
    in-bundle incident edges — ``public_projection_of`` (report→card),
    ``caused_by``, ``harms``, ``mitigated_by``, ``transferable_to`` — keeping
    the original seven (``wraps|calls|fine_tunes|deploys|trains_on|
    evaluates_with|oversees``).
2.  ``relationships[].source_ref`` AND ``relationships[].target_ref`` are
    broadened to ALSO accept a record URN ``urn:acef:rec:<uuid>`` (in addition
    to the entity URNs ``urn:acef:(sub|cmp|dat|act):<uuid>``), because incident
    edges connect records/incidents.
3.  The builders emit the typed ``public_projection_of`` relationship linking the
    private ``incident_report`` record URN (source) to the public
    ``incident_card`` record URN (target), per §5.1.
4.  The production validator (referential-integrity phase) accepts record-URN
    relationship endpoints — resolving them to records, not only to entities —
    so the new edges validate clean (no ACEF-020 dangling-ref false positive).

The id-lifecycle edges (``supersedes`` / ``merged_from`` / ``split_into``) are
registry-level v1.2 (§11) and are NOT added to the manifest enum.

This change is ADDITIVE: v1.0 / pre-amendment v1.1 bundles (the original seven
relationship_type values + entity-URN-only refs) stay valid (the
``backward-compat`` class below).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator

from acef.models.enums import RelationshipType
from acef.models.urns import URNType
from acef.package import Package, mint_incident_id
from acef.redaction import RedactionPolicy
from acef.validation.engine import validate_bundle
from acef.validation.reference_checker import check_references

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_V1_1_MANIFEST_SCHEMA = _REPO_ROOT / "acef-conventions" / "v1.1" / "manifest.schema.json"

# The five in-bundle incident edges added to the closed relationship_type enum.
_INCIDENT_EDGES = (
    "public_projection_of",
    "caused_by",
    "harms",
    "mitigated_by",
    "transferable_to",
)
# The seven original (pre-amendment) entity relationship types, which MUST be
# preserved unchanged (additive-only contract).
_ORIGINAL_EDGES = (
    "wraps",
    "calls",
    "fine_tunes",
    "deploys",
    "trains_on",
    "evaluates_with",
    "oversees",
)
# The id-lifecycle edges that MUST remain registry-level (NOT in the manifest enum).
_REGISTRY_ONLY_EDGES = ("supersedes", "merged_from", "split_into")

_HARM_CORE = {
    "realization": "harm_event",
    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
    "harm_class": "physical_health",
}

_REC = "urn:acef:rec:00000000-0000-0000-0000-0000000000aa"
_REC2 = "urn:acef:rec:00000000-0000-0000-0000-0000000000bb"
_SUB = "urn:acef:sub:00000000-0000-0000-0000-000000000001"


def _load_manifest_schema() -> dict[str, Any]:
    return json.loads(_V1_1_MANIFEST_SCHEMA.read_text(encoding="utf-8"))


def _relationship_item_schema(manifest_schema: dict[str, Any]) -> dict[str, Any]:
    """Extract the ``entities.relationships`` array-item subschema."""
    return manifest_schema["properties"]["entities"]["properties"]["relationships"]["items"]


def _rel_validator() -> Draft202012Validator:
    """A validator over the relationships[] item subschema, $ref-resolvable
    against the full manifest schema (so $defs/anchors, if any, resolve)."""
    return Draft202012Validator(_relationship_item_schema(_load_manifest_schema()))


# --------------------------------------------------------------------------- #
# Schema: enum + ref-pattern amendment                                         #
# --------------------------------------------------------------------------- #


class TestRelationshipTypeEnumAmendment:
    def test_schema_itself_is_valid(self) -> None:
        # The amended manifest schema MUST remain a valid Draft 2020-12 schema.
        Draft202012Validator.check_schema(_load_manifest_schema())

    def test_enum_contains_all_five_incident_edges(self) -> None:
        item = _relationship_item_schema(_load_manifest_schema())
        enum = item["properties"]["relationship_type"]["enum"]
        for edge in _INCIDENT_EDGES:
            assert edge in enum, f"incident edge {edge!r} missing from relationship_type enum"

    def test_enum_preserves_all_seven_original_edges(self) -> None:
        item = _relationship_item_schema(_load_manifest_schema())
        enum = item["properties"]["relationship_type"]["enum"]
        for edge in _ORIGINAL_EDGES:
            assert edge in enum, f"original edge {edge!r} dropped from relationship_type enum"

    def test_registry_only_lifecycle_edges_not_in_manifest_enum(self) -> None:
        item = _relationship_item_schema(_load_manifest_schema())
        enum = item["properties"]["relationship_type"]["enum"]
        for edge in _REGISTRY_ONLY_EDGES:
            assert edge not in enum, f"registry-level id-lifecycle edge {edge!r} must NOT be in manifest enum"

    def test_public_projection_of_edge_validates_with_record_urn_endpoints(self) -> None:
        rel = {
            "source_ref": _REC,
            "target_ref": _REC2,
            "relationship_type": "public_projection_of",
        }
        _rel_validator().validate(rel)  # raises on failure

    def test_caused_by_and_harms_edges_validate_with_record_urns(self) -> None:
        v = _rel_validator()
        v.validate({"source_ref": _REC, "target_ref": _REC2, "relationship_type": "caused_by"})
        v.validate({"source_ref": _REC, "target_ref": _SUB, "relationship_type": "harms"})

    def test_original_entity_edge_still_validates(self) -> None:
        # Additive: a pre-amendment entity edge (entity URNs + a v1.0 type) stays valid.
        rel = {
            "source_ref": _SUB,
            "target_ref": "urn:acef:cmp:00000000-0000-0000-0000-000000000002",
            "relationship_type": "wraps",
        }
        _rel_validator().validate(rel)

    def test_record_urn_source_ref_accepted_by_pattern(self) -> None:
        rel = {"source_ref": _REC, "target_ref": _SUB, "relationship_type": "harms"}
        _rel_validator().validate(rel)

    def test_record_urn_target_ref_accepted_by_pattern(self) -> None:
        rel = {"source_ref": _SUB, "target_ref": _REC, "relationship_type": "mitigated_by"}
        _rel_validator().validate(rel)

    def test_unknown_relationship_type_still_rejected(self) -> None:
        # The enum stays CLOSED — a bogus edge type is still rejected.
        v = _rel_validator()
        errors = list(v.iter_errors({"source_ref": _REC, "target_ref": _REC2, "relationship_type": "not_a_real_edge"}))
        assert errors, "closed relationship_type enum must reject an unknown edge"

    def test_non_acef_urn_ref_still_rejected(self) -> None:
        # The ref pattern stays CLOSED to the acef URN grammar — a non-acef URN
        # (or a record URN with a bad uuid) is still rejected.
        v = _rel_validator()
        bad = {
            "source_ref": "urn:acef:rec:not-a-uuid",
            "target_ref": _REC2,
            "relationship_type": "caused_by",
        }
        assert list(v.iter_errors(bad)), "malformed record URN must still be rejected by the ref pattern"


# --------------------------------------------------------------------------- #
# Enum (SDK) parity                                                            #
# --------------------------------------------------------------------------- #


class TestRelationshipTypeSdkEnum:
    def test_sdk_enum_has_incident_edges(self) -> None:
        values = {m.value for m in RelationshipType}
        for edge in _INCIDENT_EDGES:
            assert edge in values, f"SDK RelationshipType missing incident edge {edge!r}"

    def test_sdk_enum_preserves_original_edges(self) -> None:
        values = {m.value for m in RelationshipType}
        for edge in _ORIGINAL_EDGES:
            assert edge in values

    def test_sdk_enum_matches_schema_enum_exactly(self) -> None:
        item = _relationship_item_schema(_load_manifest_schema())
        schema_enum = set(item["properties"]["relationship_type"]["enum"])
        sdk_values = {m.value for m in RelationshipType}
        assert sdk_values == schema_enum, (
            "SDK RelationshipType and schema relationship_type enum MUST be in sync; "
            f"sdk-only={sdk_values - schema_enum}, schema-only={schema_enum - sdk_values}"
        )

    def test_public_projection_of_constructs_from_string(self) -> None:
        assert RelationshipType("public_projection_of") is RelationshipType.PUBLIC_PROJECTION_OF


# --------------------------------------------------------------------------- #
# Validator: record-URN relationship endpoints                                 #
# --------------------------------------------------------------------------- #


def _manifest_with_relationship(rel: dict[str, Any], subjects: list[dict] | None = None) -> dict[str, Any]:
    return {
        "metadata": {"package_id": "urn:acef:pkg:00000000-0000-0000-0000-000000000001"},
        "subjects": subjects or [],
        "entities": {
            "components": [],
            "datasets": [],
            "actors": [],
            "relationships": [rel],
        },
        "record_files": [],
    }


class TestReferenceCheckerRecordUrnEndpoints:
    def test_record_urn_relationship_endpoints_resolve_to_records(self) -> None:
        # A public_projection_of edge whose source/target are RECORD URNs of
        # records that exist in the bundle MUST NOT raise ACEF-020 dangling-ref.
        rel = {
            "source_ref": _REC,
            "target_ref": _REC2,
            "relationship_type": "public_projection_of",
        }
        records = [
            {"record_id": _REC, "record_type": "incident_report"},
            {"record_id": _REC2, "record_type": "incident_card"},
        ]
        diags = check_references(_manifest_with_relationship(rel), records)
        acef_020 = [d for d in diags if d.code == "ACEF-020"]
        assert acef_020 == [], f"record-URN relationship endpoints must resolve, got: {acef_020}"

    def test_dangling_record_urn_relationship_endpoint_still_flagged(self) -> None:
        # A record-URN endpoint that points at NO record in the bundle is still
        # a dangling ref — the broadening accepts the URN grammar, not non-existence.
        rel = {
            "source_ref": _REC,
            "target_ref": _REC2,
            "relationship_type": "public_projection_of",
        }
        records = [{"record_id": _REC, "record_type": "incident_report"}]  # _REC2 absent
        diags = check_references(_manifest_with_relationship(rel), records)
        acef_020 = [d for d in diags if d.code == "ACEF-020"]
        assert acef_020, "a record URN pointing at no in-bundle record must still raise ACEF-020"

    def test_entity_urn_relationship_endpoint_still_resolves(self) -> None:
        # Mixed endpoint: a record-URN source + an entity-URN target both resolve.
        rel = {"source_ref": _REC, "target_ref": _SUB, "relationship_type": "harms"}
        records = [{"record_id": _REC, "record_type": "incident_report"}]
        diags = check_references(
            _manifest_with_relationship(rel, subjects=[{"subject_id": _SUB}]),
            records,
        )
        acef_020 = [d for d in diags if d.code == "ACEF-020"]
        assert acef_020 == [], f"mixed record/entity relationship endpoints must resolve, got: {acef_020}"


# --------------------------------------------------------------------------- #
# Builder: public_projection_of emission (report → card)                       #
# --------------------------------------------------------------------------- #


def _deterministic_urn_generator() -> Any:
    counter = {"n": 0}

    def _gen(urn_type: URNType) -> str:
        counter["n"] += 1
        return f"urn:acef:{urn_type.value}:00000000-0000-0000-0000-{counter['n']:012x}"

    return _gen


def _fixed_clock() -> datetime:
    return datetime(2026, 8, 10, 0, 0, 0, tzinfo=UTC)


def _write_ec_key(tmp_path: Path) -> tuple[str, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "signing-key.pem"
    key_path.write_bytes(pem)
    return str(key_path), key


def _new_pkg() -> Package:
    return Package(
        producer={"name": "acef-incident-edges", "version": "1.1.0"},
        redaction_policy=RedactionPolicy(version="1.0.0"),
        clock=_fixed_clock,
        urn_generator=_deterministic_urn_generator(),
    )


class TestPublicProjectionOfEmission:
    def test_link_emits_public_projection_of_report_to_card(self) -> None:
        pkg = _new_pkg()
        report = pkg.report_incident(
            public_incident_id="AIIC-openai.com-2026-0123456789abcdefghijklmnop",
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="Confidential Art.73 report.",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": True,
            },
        )
        card = pkg.incident_card(
            public_incident_id="AIIC-openai.com-2026-0123456789abcdefghijklmnop",
            harm_core=dict(_HARM_CORE),
            severity_vector="ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": False,
            },
        )
        rel = pkg.link_incident_projection(report, card)

        # Direction is report → card (§5.1).
        assert rel.relationship_type is RelationshipType.PUBLIC_PROJECTION_OF
        assert rel.source_ref == report.record_id
        assert rel.target_ref == card.record_id
        assert rel.source_ref.startswith("urn:acef:rec:")
        assert rel.target_ref.startswith("urn:acef:rec:")

        # It landed in the package relationship graph exactly once.
        graph = pkg.build_manifest().entities.relationships
        proj = [r for r in graph if r.relationship_type is RelationshipType.PUBLIC_PROJECTION_OF]
        assert len(proj) == 1
        assert proj[0].source_ref == report.record_id
        assert proj[0].target_ref == card.record_id

    def test_link_accepts_record_urn_strings(self) -> None:
        # The link helper also accepts bare record-URN strings (not just envelopes).
        pkg = _new_pkg()
        rel = pkg.link_incident_projection(_REC, _REC2)
        assert rel.source_ref == _REC
        assert rel.target_ref == _REC2
        assert rel.relationship_type is RelationshipType.PUBLIC_PROJECTION_OF


# --------------------------------------------------------------------------- #
# End-to-end conformance: report + card bundle with a public_projection_of edge #
# --------------------------------------------------------------------------- #

# A PRE-EXISTING, feature-unrelated SDK quirk: Package.__init__ appends an
# "Initial package creation" audit_trail entry with an EMPTY actor_ref, which the
# manifest schema's actor_ref URN pattern rejects (ACEF-002 at
# /audit_trail/0/actor_ref). Every vanilla SDK-built bundle exhibits it; exclude
# this one known path from the zero-ERROR assertion (see test_report_incident_e2e).
_PRE_EXISTING_SDK_ERROR_PATHS: frozenset[str] = frozenset({"/audit_trail/0/actor_ref"})


def _error_diags(assessment: Any) -> list[dict[str, Any]]:
    return [
        e
        for e in assessment.structural_errors
        if e.get("severity") in {"error", "fatal"} and e.get("path") not in _PRE_EXISTING_SDK_ERROR_PATHS
    ]


def _codes(assessment: Any) -> list[str]:
    return [e.get("code") for e in assessment.structural_errors]


class TestReportAndCardBundleEdge:
    def test_report_plus_card_with_projection_edge_validates_clean(self, tmp_path: Path) -> None:
        key_path, key = _write_ec_key(tmp_path)
        pkg = _new_pkg()
        minted = mint_incident_id("openai.com", key, year=2026)

        pkg.add_subject("ai_system", name="Sys", risk_classification="high-risk", modalities=["text"])
        report = pkg.report_incident(
            public_incident_id=minted.public_incident_id,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="Confidential Art.73 serious-incident report.",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": True,
            },
        )
        card = pkg.incident_card(
            public_incident_id=minted.public_incident_id,
            harm_core=dict(_HARM_CORE),
            severity_vector="ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={
                "serious_incident_triggers": ["3.49.a"],
                "widespread": False,
                "death_involved": False,
            },
        )
        rel = pkg.link_incident_projection(report, card)
        assert rel.source_ref.startswith("urn:acef:rec:")

        pkg.sign(key_path)
        bundle_dir = tmp_path / "report-card.acef"
        pkg.export(str(bundle_dir))

        # The exported manifest carries the schema-valid edge with record URNs.
        manifest = json.loads((bundle_dir / "acef-manifest.json").read_text(encoding="utf-8"))
        rels = manifest["entities"]["relationships"]
        proj = [r for r in rels if r["relationship_type"] == "public_projection_of"]
        assert len(proj) == 1
        assert proj[0]["source_ref"] == report.record_id
        assert proj[0]["target_ref"] == card.record_id

        assessment = validate_bundle(bundle_dir, profiles=["eu-ai-act-art73-2026"])
        errors = _error_diags(assessment)
        assert errors == [], f"unexpected ERROR/FATAL diagnostics: {errors}"
        # No dangling-ref false positive on the record-URN relationship endpoints.
        assert "ACEF-020" not in _codes(assessment)
