"""Stability-shakedown: the generic ``Package.record("incident_card", ...)`` path
must de-duplicate ``taxonomy_crosswalk.stix.object_refs`` exactly like the typed
``incident_card()`` builder, so the two paths emit byte-identical output.

Found by the whole-codebase review: ``_sort_incident_scope`` SORTED but did not
DEDUPE ``stix.object_refs`` (``_sort_str_array(stix, "object_refs")`` without
``dedupe=True``), while the typed builder de-dupes via
``_normalize_stix_object_refs``. A duplicate object_ref supplied through
``record()`` therefore survived, breaking generic-vs-typed byte parity (and the
now-stricter v1.1 ``uniqueItems`` schema).
"""

from __future__ import annotations

from acef.package import Package, _normalize_stix_object_refs

_A = "incident--11111111-1111-4111-8111-111111111111"
_B = "indicator--22222222-2222-4222-8222-222222222222"
_C = "malware--33333333-3333-4333-8333-333333333333"


def _stix_refs(record: object) -> list[str] | None:
    payload = record.payload  # type: ignore[attr-defined]
    return payload.get("taxonomy_crosswalk", {}).get("stix", {}).get("object_refs")


def _record_incident_card(object_refs: list[str]):
    pkg = Package(producer={"name": "Acme", "version": "1.0.0"})
    pkg.add_subject("ai_system", "Sys")
    return pkg.record(
        "incident_card",
        payload={"taxonomy_crosswalk": {"stix": {"edition": "2.1", "object_refs": list(object_refs)}}},
    )


class TestGenericRecordStixDedupParity:
    def test_generic_record_dedupes_object_refs(self) -> None:
        rec = _record_incident_card([_A, _A, _B, _B, _C])
        refs = _stix_refs(rec)
        assert refs is not None
        # de-duplicated (no repeats) and sorted — matches the typed builder.
        assert len(refs) == len(set(refs)) == 3
        assert refs == sorted(refs)

    def test_generic_matches_typed_normalization_primitive(self) -> None:
        """The generic-path emission equals the typed builder's
        _normalize_stix_object_refs output for the same (shuffled, duplicated)
        input — i.e. the two paths are byte-identical."""
        raw = [_C, _A, _B, _A, _C]
        rec = _record_incident_card(raw)
        assert _stix_refs(rec) == _normalize_stix_object_refs(raw)

    def test_order_independent(self) -> None:
        r1 = _stix_refs(_record_incident_card([_A, _B, _C]))
        r2 = _stix_refs(_record_incident_card([_C, _B, _A]))
        assert r1 == r2


class TestStixObjectRefsSchemaUniqueItems:
    """roborev follow-up: the SDK dedupes stix.object_refs, but the v1.1 schema
    lacked uniqueItems, so a RAW (non-SDK) bundle with duplicate object_refs would
    still validate. The schema now enforces the set semantics (ACEF-004 on a
    duplicate), matching the sibling serious_incident_triggers/harm_distribution_basis
    set arrays."""

    def _object_refs_schema(self) -> dict:
        import json
        from pathlib import Path

        sch = json.loads(
            Path("acef-conventions/v1.1/taxonomy_crosswalk.schema.json").read_text(encoding="utf-8")
        )
        return sch["properties"]["stix"]["properties"]["object_refs"]

    def test_schema_itself_valid(self) -> None:
        import json
        from pathlib import Path

        from jsonschema import Draft202012Validator

        sch = json.loads(
            Path("acef-conventions/v1.1/taxonomy_crosswalk.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(sch)
        assert sch["properties"]["stix"]["properties"]["object_refs"]["uniqueItems"] is True

    def test_duplicate_object_refs_rejected(self) -> None:
        from jsonschema import Draft202012Validator

        v = Draft202012Validator(self._object_refs_schema())
        assert list(v.iter_errors([_A, _A]))  # duplicate -> error

    def test_unique_object_refs_accepted(self) -> None:
        from jsonschema import Draft202012Validator

        v = Draft202012Validator(self._object_refs_schema())
        assert not list(v.iter_errors([_A, _B, _C]))
