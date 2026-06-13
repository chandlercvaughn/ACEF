"""VAL-COVERAGE-MERGE-001 — merge.py v1.1 incident awareness.

RFC-0002 §5.5 ``incident_dedupe_key`` is the LOCAL cross-database linkage spine:
"link on equality; NO authority resolves merge/split until v1.2". The id-lifecycle
edges ``supersedes`` / ``merged_from`` / ``split_into`` are v1.2 REGISTRY-level
edges (RFC-0002 §5.8, §11) — they are NOT v1.1 manifest relationships. So when
two merged bundles carry incident records sharing an equal ``incident_dedupe_key``,
the correct v1.1 behavior is:

  * PRESERVE both records (no loss, no collapse, confidentiality intact);
  * SURFACE the shared-key linkage deterministically so a consumer of the merged
    bundle knows records X and Y are the same logical incident;
  * assert NO authority — never collapse/dedup the two records into one, never
    emit a v1.2 lifecycle/merge edge to represent the link.

This module covers:

Part B (link-on-equality):
  * two public incident_cards sharing a dedupe key -> BOTH present + linked;
  * different dedupe keys -> NOT linked;
  * a non-incident merge -> no spurious linkage (behavior unchanged);
  * the link output is deterministic (sorted, reproducible across runs);
  * the link is NON-authority (no collapse; no v1.2 lifecycle edge in the
    merged manifest relationships).

Part A (incident-loss audit regression):
  * incident payload fields (card_source / confidentiality / dedupe_key) survive
    merge intact;
  * §5.8 incident relationship edges (public_projection_of …) survive merge;
  * two DIFFERENT incidents that happen to share a record_id across orgs -> an
    ACEF-060 conflict (keep_latest picks the newer), never silent loss.

RED-first: the linkage assertions reference ``MergeResult.incident_links`` and the
``IncidentLink`` shape, which do not exist before the fix — pre-fix this module
raises ``AttributeError`` / ``ImportError`` on the linkage path. The merge module
has ZERO dedupe awareness today (no ``incident_dedupe_key`` mention anywhere in
``src/acef/merge.py``).
"""

from __future__ import annotations

import re

import pytest

from acef.merge import MergeResult, merge_packages
from acef.models.enums import Confidentiality, RelationshipType
from acef.package import Package
from acef.redaction import RedactionPolicy

_DEDUPE_KEY_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

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
_SEV_VECTOR = "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I"
_PID_A = "AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS"
_PID_B = "AIIC-ACME-2026-ZYXWVUTSRQPNMKJHGFEDCBA9876"


def _incident_pkg(
    producer_name: str,
    *,
    public_incident_id: str,
    subject_identity: tuple[str, str, str],
    occurrence_date: str = "2026-07-15T09:30:00Z",
    value_chain_role: str = "foundation_model",
    timestamp: str | None = None,
    record_id: str | None = None,
) -> tuple[Package, str]:
    """Build a package with ONE PUBLIC incident_card carrying a dedupe key.

    Returns the package and the dedupe key the card emitted (so a test can assert
    two packages share — or differ on — the key without recomputing the recipe).

    ``record_id`` pins the card's record URN so a determinism test can isolate the
    LINKAGE's reproducibility from the per-instance ``uuid4`` record-id randomness
    that ``RecordEnvelope`` injects by default (otherwise two independent fixture
    builds would carry different — though equally valid — record ids).
    """
    pkg = Package(
        producer={"name": producer_name, "version": "1.0"},
        redaction_policy=RedactionPolicy(version="1.0.0"),
    )
    env = pkg.incident_card(
        public_incident_id=public_incident_id,
        harm_core=dict(_HARM_CORE),
        severity_vector=_SEV_VECTOR,
        awareness_date="2026-08-01T00:00:00Z",
        eu_ai_act_facts=dict(_EU_FACTS),
        value_chain_role=value_chain_role,
        subject_identity=subject_identity,
        occurrence_date=occurrence_date,
        confidentiality=Confidentiality.PUBLIC,
        record_id=record_id,
    )
    if timestamp is not None:
        pkg.metadata.timestamp = timestamp
    key = env.payload["incident_dedupe_key"]
    assert _DEDUPE_KEY_PATTERN.match(key), f"fixture card must emit a §5.5 key, got {key!r}"
    return pkg, key


# Pinned record URNs for determinism fixtures (isolate linkage reproducibility
# from the per-instance uuid4 record-id randomness).
_RID_A = "urn:acef:rec:00000000-0000-4000-8000-00000000000a"
_RID_B = "urn:acef:rec:00000000-0000-4000-8000-00000000000b"


def _plain_pkg(producer_name: str, *, subject_name: str, payload: dict | None = None) -> Package:
    pkg = Package(producer={"name": producer_name, "version": "1.0"})
    sub = pkg.add_subject("ai_system", name=subject_name)
    pkg.record(
        "risk_register",
        payload=payload or {"k": producer_name},
        entity_refs={"subject_refs": [sub.id]},
    )
    return pkg


# ---------------------------------------------------------------------------
# Part B — link-on-equality (the coverage MUST)
# ---------------------------------------------------------------------------


class TestSharedDedupeKeyLinksWithoutLoss:
    def test_two_cards_sharing_a_key_are_both_preserved_and_linked(self) -> None:
        """Same §5.5 key across two bundles -> BOTH records kept + the link surfaced.

        The two cards spell the SAME subject_identity / harm_class / value_chain_role
        / occurrence_date, so §5.5 derives an EQUAL incident_dedupe_key — but they are
        different bundles with different public_incident_id and different record_ids.
        After merge, both records MUST remain (no loss/collapse) and the MergeResult
        MUST surface the shared-key linkage.
        """
        pkg_a, key_a = _incident_pkg(
            "Org-A",
            public_incident_id=_PID_A,
            subject_identity=("OpenAI", "GPT-X", "4.0"),
        )
        pkg_b, key_b = _incident_pkg(
            "Org-B",
            public_incident_id=_PID_B,
            subject_identity=("OpenAI", "GPT-X", "4.0"),
        )
        assert key_a == key_b, "fixture precondition: identical §5.5 inputs -> equal key"

        result = merge_packages([pkg_a, pkg_b])

        # (a) NO LOSS / NO COLLAPSE: both incident records survive the merge.
        incident_records = [r for r in result.package.records if r.record_type == "incident_card"]
        assert len(incident_records) == 2, "both incident cards MUST be preserved (no authority collapse)"

        # (b) the linkage is SURFACED deterministically on the MergeResult.
        links = result.incident_links
        assert len(links) == 1, "one shared dedupe key -> one link"
        link = links[0]
        assert link.dedupe_key == key_a
        # the link names the linked record_ids (sorted), both still in the bundle.
        linked_ids = set(link.record_ids)
        present_ids = {r.record_id for r in incident_records}
        assert linked_ids == present_ids, "the link MUST name exactly the two preserved records"

    def test_different_keys_are_not_linked(self) -> None:
        """Different subject_identity -> different §5.5 keys -> NO link surfaced."""
        pkg_a, key_a = _incident_pkg(
            "Org-A",
            public_incident_id=_PID_A,
            subject_identity=("OpenAI", "GPT-X", "4.0"),
        )
        pkg_b, key_b = _incident_pkg(
            "Org-B",
            public_incident_id=_PID_B,
            subject_identity=("Acme AI", "Vision-Pro", "2.1.0"),
        )
        assert key_a != key_b, "fixture precondition: distinct subjects -> distinct keys"

        result = merge_packages([pkg_a, pkg_b])

        incident_records = [r for r in result.package.records if r.record_type == "incident_card"]
        assert len(incident_records) == 2
        assert result.incident_links == [], "distinct dedupe keys MUST NOT be linked"

    def test_non_incident_merge_has_no_linkage(self) -> None:
        """A merge of plain (non-incident) bundles surfaces no incident links."""
        pkg_a = _plain_pkg("Org-A", subject_name="Sys A")
        pkg_b = _plain_pkg("Org-B", subject_name="Sys B")

        result = merge_packages([pkg_a, pkg_b])

        assert isinstance(result, MergeResult)
        assert result.incident_links == [], "non-incident merge must produce no spurious linkage"
        # behavior unchanged: both plain records survive, no conflicts.
        assert len(result.package.records) == 2
        assert not result.has_conflicts


class TestLinkageDeterminism:
    def test_links_are_deterministic_across_runs(self) -> None:
        """Two merges of the same inputs produce byte-equal link representations.

        Record ids are pinned so the assertion isolates LINKAGE determinism from the
        per-instance uuid4 record-id randomness ``RecordEnvelope`` injects.
        """
        a1, _ = _incident_pkg(
            "Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"), record_id=_RID_A
        )
        b1, _ = _incident_pkg(
            "Org-B", public_incident_id=_PID_B, subject_identity=("OpenAI", "GPT-X", "4.0"), record_id=_RID_B
        )
        a2, _ = _incident_pkg(
            "Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"), record_id=_RID_A
        )
        b2, _ = _incident_pkg(
            "Org-B", public_incident_id=_PID_B, subject_identity=("OpenAI", "GPT-X", "4.0"), record_id=_RID_B
        )

        r1 = merge_packages([a1, b1])
        r2 = merge_packages([a2, b2])

        s1 = [(lk.dedupe_key, tuple(lk.record_ids)) for lk in r1.incident_links]
        s2 = [(lk.dedupe_key, tuple(lk.record_ids)) for lk in r2.incident_links]
        assert s1 == s2, "link representation must be reproducible across runs"
        # The pinned record_ids are the sorted (_RID_A < _RID_B) tuple.
        assert s1 == [(r1.incident_links[0].dedupe_key, (_RID_A, _RID_B))]

    def test_link_record_ids_and_links_are_sorted(self) -> None:
        """The link's record_ids and the link list itself are deterministically sorted.

        Input order MUST NOT change the surfaced linkage (no set-iteration leakage).
        """
        a, _ = _incident_pkg(
            "Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"), record_id=_RID_A
        )
        b, _ = _incident_pkg(
            "Org-B", public_incident_id=_PID_B, subject_identity=("OpenAI", "GPT-X", "4.0"), record_id=_RID_B
        )

        forward = merge_packages([a, b]).incident_links
        # Rebuild fresh packages for the reversed order (packages are consumed once).
        a2, _ = _incident_pkg(
            "Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"), record_id=_RID_A
        )
        b2, _ = _incident_pkg(
            "Org-B", public_incident_id=_PID_B, subject_identity=("OpenAI", "GPT-X", "4.0"), record_id=_RID_B
        )
        reverse = merge_packages([b2, a2]).incident_links

        assert len(forward) == 1 and len(reverse) == 1
        # record_ids sorted ascending within the link.
        assert list(forward[0].record_ids) == sorted(forward[0].record_ids)
        assert forward[0].record_ids == (_RID_A, _RID_B)
        # input order does not perturb the surfaced linkage.
        assert [lk.dedupe_key for lk in forward] == [lk.dedupe_key for lk in reverse]
        assert forward[0].record_ids == reverse[0].record_ids


class TestLinkIsNonAuthority:
    def test_link_does_not_emit_a_v1_2_lifecycle_edge(self) -> None:
        """The link MUST NOT be represented as a supersedes/merged_from/split_into edge.

        Those are v1.2 REGISTRY-level edges (RFC-0002 §5.8/§11), not v1.1 manifest
        relationships. The merged manifest's relationships[] must carry no such edge
        synthesized by the dedupe linkage.
        """
        a, _ = _incident_pkg("Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"))
        b, _ = _incident_pkg("Org-B", public_incident_id=_PID_B, subject_identity=("OpenAI", "GPT-X", "4.0"))

        result = merge_packages([a, b])
        assert len(result.incident_links) == 1, "precondition: the two cards are linked"

        rel_types = {
            (r.relationship_type.value if hasattr(r.relationship_type, "value") else str(r.relationship_type))
            for r in result.package.entities.relationships
        }
        # No v1.2 lifecycle/merge edge may exist (none of these are even valid v1.1
        # RelationshipType values; assert by string to be defensive).
        for forbidden in ("supersedes", "merged_from", "split_into"):
            assert forbidden not in rel_types, f"dedupe link must not synthesize a v1.2 {forbidden} edge"

    def test_link_does_not_collapse_records_even_with_keep_all(self) -> None:
        """Neither keep_latest nor keep_all may collapse two same-key incidents."""
        for strategy in ("keep_latest", "keep_all", "fail"):
            a, _ = _incident_pkg("Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"))
            b, _ = _incident_pkg("Org-B", public_incident_id=_PID_B, subject_identity=("OpenAI", "GPT-X", "4.0"))
            result = merge_packages([a, b], conflict_strategy=strategy)
            cards = [r for r in result.package.records if r.record_type == "incident_card"]
            assert len(cards) == 2, f"{strategy}: a shared dedupe key is NOT a conflict and must not collapse"
            # A shared dedupe key is informational linkage, NEVER an ACEF-060 conflict.
            assert not result.has_conflicts, f"{strategy}: shared dedupe key must not raise a merge conflict"


# ---------------------------------------------------------------------------
# Part A — incident-loss audit regression
# ---------------------------------------------------------------------------


class TestIncidentPayloadSurvivesMerge:
    def test_card_source_confidentiality_and_dedupe_key_survive(self) -> None:
        """Incident payload fields are not dropped/corrupted by the merge copy path."""
        pkg_a, key_a = _incident_pkg("Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"))
        pkg_b = _plain_pkg("Org-B", subject_name="Sys B")

        result = merge_packages([pkg_a, pkg_b])

        card = next(r for r in result.package.records if r.record_type == "incident_card")
        # confidentiality preserved.
        assert card.confidentiality == Confidentiality.PUBLIC
        # §5.5 dedupe key preserved verbatim.
        assert card.payload.get("incident_dedupe_key") == key_a
        # core incident fields preserved.
        assert card.payload.get("public_incident_id") == _PID_A
        assert card.payload.get("harm_core", {}).get("harm_class") == "physical_health"
        assert "taxonomy_crosswalk" in card.payload

    def test_incident_relationship_edge_survives_merge(self) -> None:
        """A §5.8 public_projection_of edge between records survives the merge."""
        pkg = Package(
            producer={"name": "Org-A", "version": "1.0"},
            redaction_policy=RedactionPolicy(version="1.0.0"),
        )
        report = pkg.report_incident(
            public_incident_id=_PID_A,
            incident_type="malfunction",
            description="confidential source report",
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            occurrence_date="2026-07-15T09:30:00Z",
        )
        card = pkg.incident_card(
            public_incident_id=_PID_A,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            occurrence_date="2026-07-15T09:30:00Z",
            confidentiality=Confidentiality.PUBLIC,
        )
        pkg.link_incident_projection(report, card)

        other = _plain_pkg("Org-B", subject_name="Sys B")
        result = merge_packages([pkg, other])

        edges = [
            r
            for r in result.package.entities.relationships
            if r.relationship_type == RelationshipType.PUBLIC_PROJECTION_OF
        ]
        assert len(edges) == 1, "the §5.8 public_projection_of edge must survive merge intact"
        assert edges[0].source_ref == report.record_id
        assert edges[0].target_ref == card.record_id


class TestCrossOrgRecordIdCollisionIsConflictNotLoss:
    def test_two_different_incidents_sharing_a_record_id_conflict(self) -> None:
        """Two DIFFERENT incident cards forced to share a record_id -> ACEF-060.

        keep_latest must pick the newer record by timestamp, never silently drop
        an incident — the §3.6 ACEF-060 conflict MUST be recorded.
        """
        pkg_a, _ = _incident_pkg(
            "Org-A",
            public_incident_id=_PID_A,
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            timestamp="2026-01-01T00:00:00Z",
        )
        pkg_b, _ = _incident_pkg(
            "Org-B",
            public_incident_id=_PID_B,
            subject_identity=("Acme AI", "Vision-Pro", "2.1.0"),
            timestamp="2026-02-01T00:00:00Z",
        )
        # Force a cross-org record_id collision on two genuinely different cards.
        shared_id = pkg_a.records[0].record_id
        pkg_b.records[0].record_id = shared_id
        # Pin per-record timestamps so keep_latest is well-defined.
        pkg_a.records[0].timestamp = "2026-01-01T00:00:00Z"
        pkg_b.records[0].timestamp = "2026-02-01T00:00:00Z"

        result = merge_packages([pkg_a, pkg_b], conflict_strategy="keep_latest")

        assert result.has_conflicts, "a record_id collision across orgs MUST raise ACEF-060"
        assert any(c.code == "ACEF-060" for c in result.conflicts)
        # keep_latest keeps exactly one (the newer) — that is conflict resolution,
        # not silent loss; the conflict is recorded above.
        cards = [r for r in result.package.records if r.record_type == "incident_card"]
        assert len(cards) == 1
        assert cards[0].payload["public_incident_id"] == _PID_B  # the 2026-02 (newer) card

    def test_record_id_collision_fails_closed_under_fail_strategy(self) -> None:
        """conflict_strategy='fail' raises on the collision rather than dropping."""
        from acef.errors import ACEFMergeError

        pkg_a, _ = _incident_pkg("Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"))
        pkg_b, _ = _incident_pkg(
            "Org-B", public_incident_id=_PID_B, subject_identity=("Acme AI", "Vision-Pro", "2.1.0")
        )
        pkg_b.records[0].record_id = pkg_a.records[0].record_id

        with pytest.raises(ACEFMergeError, match="ACEF-060|duplicate record"):
            merge_packages([pkg_a, pkg_b], conflict_strategy="fail")
