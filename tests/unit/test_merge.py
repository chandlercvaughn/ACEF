"""Tests for acef.merge — multi-source evidence merging with conflict detection."""

from __future__ import annotations

import pytest

from acef.errors import ACEFMergeError
from acef.merge import MergeResult, merge_packages
from acef.package import Package


def _make_package(
    name: str = "tool",
    version: str = "1.0",
    subject_name: str = "System A",
    subject_type: str = "ai_system",
    record_type: str = "risk_register",
    payload: dict | None = None,
) -> Package:
    """Helper to create a package for testing."""
    pkg = Package(producer={"name": name, "version": version})
    sub = pkg.add_subject(subject_type, name=subject_name)
    pkg.record(
        record_type,
        payload=payload or {"data": "value"},
        entity_refs={"subject_refs": [sub.id]},
    )
    return pkg


class TestKeepLatestSubjectIntegrity:
    """F8 (audit high): ``keep_latest`` subject conflict resolution.

    Two defects: (1) dropping a same-named subject left records that referenced the
    DROPPED subject_id dangling (no remap to the winner); (2) the equal-timestamp tie-break
    used ``>=`` which favors whichever package was processed LATER, making the kept subject
    input-order-dependent and contradicting the module's byte-identical-determinism claim.
    """

    def _pkg(self, subject_name: str, timestamp: str, payload: dict) -> tuple[Package, str]:
        pkg = Package(producer={"name": "tool", "version": "1.0"})
        sub = pkg.add_subject("ai_system", name=subject_name)
        pkg.record("risk_register", payload=payload, entity_refs={"subject_refs": [sub.id]})
        pkg.metadata.timestamp = timestamp
        return pkg, sub.id

    def test_keep_latest_remaps_dangling_subject_refs(self) -> None:
        # pkg_b is strictly NEWER -> its subject wins; pkg_a's subject is dropped. The
        # surviving record from pkg_a that referenced subject_a MUST be remapped to the
        # winner subject_b — never left dangling.
        pkg_a, id_a = self._pkg("Shared System", "2026-01-01T00:00:00Z", {"a": 1})
        pkg_b, id_b = self._pkg("Shared System", "2026-06-01T00:00:00Z", {"b": 2})
        assert id_a != id_b
        result = merge_packages([pkg_a, pkg_b], conflict_strategy="keep_latest")
        kept = {s.id for s in result.package.subjects}
        assert kept == {id_b}, kept
        all_refs = [ref for r in result.package.records for ref in r.entity_refs.subject_refs]
        assert id_a not in all_refs, f"record left a dangling ref to the dropped subject {id_a}: {all_refs}"
        assert all(ref in kept for ref in all_refs), f"every subject_ref must resolve to a kept subject: {all_refs}"

    def test_keep_latest_equal_timestamp_tiebreak_is_order_independent(self) -> None:
        ts = "2026-03-15T00:00:00Z"
        pkg_a, _id_a = self._pkg("Shared System", ts, {"a": 1})
        pkg_b, _id_b = self._pkg("Shared System", ts, {"b": 2})
        # merge_packages deep-copies inputs (does not mutate them), so the SAME pkg objects
        # can be merged in both orders — the only variable is input order.
        forward = {s.id for s in merge_packages([pkg_a, pkg_b], conflict_strategy="keep_latest").package.subjects}
        reverse = {s.id for s in merge_packages([pkg_b, pkg_a], conflict_strategy="keep_latest").package.subjects}
        assert forward == reverse, f"equal-timestamp tie-break is input-order-dependent: fwd={forward} rev={reverse}"

    def test_keep_latest_remaps_subject_refs_in_entities_and_relationships(self) -> None:
        # F8 follow-up (roborev on eafa3a2): the dropped->winner subject remap must also
        # cover NON-record subject references — components[].subject_refs,
        # datasets[].subject_refs, and relationship source_ref/target_ref (an endpoint may
        # be a subject URN) — or keep_latest still emits a dangling reference to the dropped
        # subject in the merged entity graph.
        pkg_a = Package(producer={"name": "tool", "version": "1.0"})
        sub_a = pkg_a.add_subject("ai_system", name="Shared System")
        comp = pkg_a.add_component("Comp", "model", subject_refs=[sub_a.id])
        pkg_a.add_dataset("DS", subject_refs=[sub_a.id])
        pkg_a.add_relationship(sub_a.id, comp.id, "deploys")
        pkg_a.metadata.timestamp = "2026-01-01T00:00:00Z"

        pkg_b = Package(producer={"name": "tool", "version": "1.0"})
        sub_b = pkg_b.add_subject("ai_system", name="Shared System")  # newer -> wins
        pkg_b.metadata.timestamp = "2026-06-01T00:00:00Z"

        result = merge_packages([pkg_a, pkg_b], conflict_strategy="keep_latest")
        kept = {s.id for s in result.package.subjects}
        assert kept == {sub_b.id}
        ents = result.package.entities
        for c in ents.components:
            assert sub_a.id not in c.subject_refs, f"dangling component subject_ref: {c.subject_refs}"
            assert all(ref in kept for ref in c.subject_refs)
        for d in ents.datasets:
            assert sub_a.id not in d.subject_refs, f"dangling dataset subject_ref: {d.subject_refs}"
        for rel in ents.relationships:
            assert rel.source_ref != sub_a.id and rel.target_ref != sub_a.id, (
                f"dangling relationship endpoint to dropped subject: {rel.source_ref} -> {rel.target_ref}"
            )
        # the subject endpoint (was sub_a) is repointed to the winner sub_b
        assert any(rel.source_ref == sub_b.id for rel in ents.relationships), [r.source_ref for r in ents.relationships]


class TestMergeBasic:
    """Test basic merge operations."""

    def test_merge_two_packages(self):
        pkg1 = _make_package(subject_name="System A", payload={"a": 1})
        pkg2 = _make_package(subject_name="System B", payload={"b": 2})

        result = merge_packages([pkg1, pkg2])

        assert isinstance(result, MergeResult)
        assert len(result.package.subjects) == 2
        assert len(result.package.records) == 2
        assert not result.has_conflicts

    def test_merge_empty_raises(self):
        with pytest.raises(ACEFMergeError, match="No packages"):
            merge_packages([])

    def test_merge_single_package(self):
        pkg = _make_package()
        result = merge_packages([pkg])
        assert len(result.package.subjects) == 1
        assert len(result.package.records) == 1

    def test_merge_creates_audit_trail(self):
        import re

        pkg1 = _make_package(subject_name="A")
        pkg2 = _make_package(subject_name="B")
        result = merge_packages([pkg1, pkg2])
        manifest = result.package.build_manifest()
        merge_events = [e for e in manifest.audit_trail if "Merged" in e.description]
        assert len(merge_events) >= 1
        # The merge audit entry MUST carry a schema-valid actor_ref (roborev on
        # 3753e54): an empty actor_ref FATAL-fails ACEF-002 on merged output.
        actor_urn = re.compile(r"^urn:acef:act:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        assert all(actor_urn.match(e.actor_ref) for e in manifest.audit_trail), (
            f"every merge audit entry needs a valid actor_ref; got {[e.actor_ref for e in manifest.audit_trail]!r}"
        )


class TestDuplicateSubjects:
    """Test detection of duplicate subjects."""

    def test_duplicate_subject_detected(self):
        pkg1 = _make_package(subject_name="Same System")
        pkg2 = _make_package(subject_name="Same System")

        result = merge_packages([pkg1, pkg2])

        assert result.has_conflicts
        conflict_messages = [c.message for c in result.conflicts]
        assert any("Duplicate subject" in m for m in conflict_messages)


class TestDuplicateRecordIDs:
    """Test detection of duplicate record IDs."""

    def test_duplicate_record_id_detected(self):
        pkg1 = _make_package(subject_name="A")
        pkg2 = _make_package(subject_name="B")

        # Force same record ID
        pkg2._records[0].record_id = pkg1._records[0].record_id

        result = merge_packages([pkg1, pkg2])

        assert result.has_conflicts
        conflict_messages = [c.message for c in result.conflicts]
        assert any("Duplicate record_id" in m for m in conflict_messages)


class TestKeepLatestStrategy:
    """Test keep_latest conflict resolution strategy."""

    def test_keeps_later_on_duplicate_record(self):
        pkg1 = _make_package(subject_name="A", payload={"version": "old"})
        pkg2 = _make_package(subject_name="B", payload={"version": "new"})

        # Force same record ID
        shared_id = pkg1._records[0].record_id
        pkg2._records[0].record_id = shared_id

        result = merge_packages([pkg1, pkg2], conflict_strategy="keep_latest")

        # Should replace with the later one
        matching = [r for r in result.package.records if r.record_id == shared_id]
        assert len(matching) == 1
        assert matching[0].payload == {"version": "new"}

    def test_skips_duplicate_subject(self):
        pkg1 = _make_package(subject_name="Same")
        pkg2 = _make_package(subject_name="Same")

        result = merge_packages([pkg1, pkg2], conflict_strategy="keep_latest")
        # Should only have one subject with that name
        assert len(result.package.subjects) == 1


class TestKeepAllStrategy:
    """Test keep_all conflict resolution strategy."""

    def test_keeps_both_duplicate_records(self):
        pkg1 = _make_package(subject_name="A", payload={"v": 1})
        pkg2 = _make_package(subject_name="B", payload={"v": 2})

        # Force same record ID
        shared_id = pkg1._records[0].record_id
        pkg2._records[0].record_id = shared_id

        result = merge_packages([pkg1, pkg2], conflict_strategy="keep_all")

        matching = [r for r in result.package.records if r.record_id == shared_id]
        assert len(matching) == 2


class TestFailStrategy:
    """Test fail conflict resolution strategy."""

    def test_raises_on_duplicate_subject(self):
        pkg1 = _make_package(subject_name="Same")
        pkg2 = _make_package(subject_name="Same")

        with pytest.raises(ACEFMergeError, match="Conflict"):
            merge_packages([pkg1, pkg2], conflict_strategy="fail")

    def test_raises_on_duplicate_record(self):
        pkg1 = _make_package(subject_name="A")
        pkg2 = _make_package(subject_name="B")
        pkg2._records[0].record_id = pkg1._records[0].record_id

        with pytest.raises(ACEFMergeError, match="Conflict"):
            merge_packages([pkg1, pkg2], conflict_strategy="fail")


class TestMergeEntities:
    """Test that entities are properly merged."""

    def test_components_merged(self):
        pkg1 = _make_package(subject_name="A")
        pkg1.add_component(name="Model", type="model")
        pkg2 = _make_package(subject_name="B")
        pkg2.add_component(name="Guard", type="guardrail")

        result = merge_packages([pkg1, pkg2])
        assert len(result.package.entities.components) == 2

    def test_profiles_deduplicated(self):
        pkg1 = _make_package(subject_name="A")
        pkg1.add_profile("eu-ai-act", provisions=["article-9"])
        pkg2 = _make_package(subject_name="B")
        pkg2.add_profile("eu-ai-act", provisions=["article-10"])

        result = merge_packages([pkg1, pkg2])
        profiles = result.package.profiles
        profile_ids = [p.profile_id for p in profiles]
        assert profile_ids.count("eu-ai-act") == 1


class TestMergeInvalidProducer:
    """The public ``merge_packages`` API must surface a structured ``ACEFMergeError``
    — never a raw ``pydantic.ValidationError`` / ``TypeError`` — when the optional
    ``producer`` argument is malformed (``ProducerInfo`` requires ``name`` + ``version``
    string fields)."""

    def test_missing_version_raises_structured(self):
        with pytest.raises(ACEFMergeError) as exc:
            merge_packages([_make_package(), _make_package()], producer={"name": "X"})
        assert exc.value.code == "ACEF-060"

    def test_empty_producer_raises_structured(self):
        with pytest.raises(ACEFMergeError) as exc:
            merge_packages([_make_package(), _make_package()], producer={})
        assert exc.value.code == "ACEF-060"

    def test_wrong_type_field_raises_structured(self):
        with pytest.raises(ACEFMergeError) as exc:
            merge_packages([_make_package(), _make_package()], producer={"name": 123, "version": "1.0"})
        assert exc.value.code == "ACEF-060"

    @pytest.mark.parametrize("bad", ["foo", 5, ["a"]])
    def test_non_mapping_producer_raises_structured(self, bad):
        with pytest.raises(ACEFMergeError) as exc:
            merge_packages([_make_package(), _make_package()], producer=bad)
        assert exc.value.code == "ACEF-060"

    def test_valid_producer_merges(self):
        result = merge_packages(
            [_make_package(), _make_package()],
            producer={"name": "merger-tool", "version": "2.0"},
        )
        assert result.package.metadata.producer.name == "merger-tool"
        assert result.package.metadata.producer.version == "2.0"
