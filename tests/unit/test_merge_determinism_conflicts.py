"""Tests for merge_packages determinism + attachment/profile conflict detection.

Covers audit findings loader-roundtrip-6/7/9/10 (VAL-FIX-LOADER-006/007/009/010):

  006  merged package_id (random UUID) and timestamp (wall clock) are
       non-deterministic -> two merges of identical inputs differ byte-wise.
  007  same attachment path with DIFFERENT bytes wins first-come silently,
       with no ACEF-060 conflict recorded.
  009  duplicate profile_id discards the later package's applicable_provisions
       (no union) and silently drops a differing template_version.
  010  merge audit trail mislabels the merge as 'Initial package creation' and
       stamps both entries with a wall-clock timestamp.

These were written RED-first: each test reproduces the defect against the
pre-fix merge_packages and passes only after the deterministic-id / conflict
detection fix lands.
"""

from __future__ import annotations

import pytest

from acef.errors import ACEFMergeError
from acef.package import Package


def _make_package(
    name: str,
    *,
    subject_name: str | None = None,
    payload: dict | None = None,
    attachment: tuple[str, bytes] | None = None,
    timestamp: str | None = None,
    record_refs_attachment: bool = False,
) -> Package:
    """Build a package with one subject, one record, and optional attachment.

    When ``record_refs_attachment`` is True, the record carries an
    ``attachments[].path`` pointing at the added artifact so we can assert
    that a keep_all relocation rewrites the in-record reference.
    """
    pkg = Package(producer={"name": name, "version": "1.0"})
    sub = pkg.add_subject("ai_system", name=subject_name or f"Sys {name}")
    record_attachments = None
    if attachment is not None and record_refs_attachment:
        att_path = attachment[0]
        if not att_path.startswith("artifacts/"):
            att_path = f"artifacts/{att_path}"
        record_attachments = [{"path": att_path}]
    pkg.record(
        "risk_register",
        payload=payload or {"k": name},
        entity_refs={"subject_refs": [sub.id]},
        attachments=record_attachments,
    )
    if attachment is not None:
        pkg.add_attachment(attachment[0], attachment[1])
    if timestamp is not None:
        pkg.metadata.timestamp = timestamp
    return pkg


# ---------------------------------------------------------------------------
# VAL-FIX-LOADER-006 — deterministic package_id + timestamp
# ---------------------------------------------------------------------------


class TestDeterministicMergeIdentity:
    def test_merge_package_id_is_deterministic_across_runs(self) -> None:
        """Two merges of identical inputs must produce the same package_id."""
        from acef.merge import merge_packages

        ts = "2026-01-01T00:00:00Z"
        a1 = _make_package("A", timestamp=ts)
        b1 = _make_package("B", timestamp=ts)
        a2 = _make_package("A", timestamp=ts)
        b2 = _make_package("B", timestamp=ts)
        # Force identical input package_ids so the only variable is merge_packages.
        a2.metadata.package_id = a1.metadata.package_id
        b2.metadata.package_id = b1.metadata.package_id

        r1 = merge_packages([a1, b1])
        r2 = merge_packages([a2, b2])

        assert r1.package.metadata.package_id == r2.package.metadata.package_id

    def test_merge_package_id_is_a_valid_lowercase_urn(self) -> None:
        from acef.merge import merge_packages
        from acef.models.urns import validate_urn

        ts = "2026-01-01T00:00:00Z"
        result = merge_packages([_make_package("A", timestamp=ts), _make_package("B", timestamp=ts)])
        pkg_id = result.package.metadata.package_id
        assert validate_urn(pkg_id)
        assert pkg_id.startswith("urn:acef:pkg:")
        # Frozen schema pins lowercase hex; assert no uppercase leaked in.
        assert pkg_id == pkg_id.lower()

    def test_merge_package_id_independent_of_input_order(self) -> None:
        """package_id derives from the SORTED set of inputs, not their order."""
        from acef.merge import merge_packages

        ts = "2026-01-01T00:00:00Z"
        a = _make_package("A", subject_name="Alpha", timestamp=ts)
        b = _make_package("B", subject_name="Beta", timestamp=ts)
        a2 = _make_package("A", subject_name="Alpha", timestamp=ts)
        b2 = _make_package("B", subject_name="Beta", timestamp=ts)
        a2.metadata.package_id = a.metadata.package_id
        b2.metadata.package_id = b.metadata.package_id

        fwd = merge_packages([a, b])
        rev = merge_packages([b2, a2])
        assert fwd.package.metadata.package_id == rev.package.metadata.package_id

    def test_merge_timestamp_is_max_of_inputs(self) -> None:
        """Merged timestamp is the latest input timestamp, deterministically."""
        from acef.merge import merge_packages

        early = _make_package("A", timestamp="2025-03-01T10:00:00Z")
        late = _make_package("B", timestamp="2026-09-15T08:30:00Z")
        result = merge_packages([early, late])
        assert result.package.metadata.timestamp == "2026-09-15T08:30:00Z"

    def test_explicit_package_id_and_timestamp_override(self) -> None:
        from acef.merge import merge_packages

        result = merge_packages(
            [_make_package("A", timestamp="2026-01-01T00:00:00Z")],
            package_id="urn:acef:pkg:00000000-0000-4000-8000-000000000000",
            timestamp="2030-12-31T23:59:59Z",
        )
        assert result.package.metadata.package_id == "urn:acef:pkg:00000000-0000-4000-8000-000000000000"
        assert result.package.metadata.timestamp == "2030-12-31T23:59:59Z"

    def test_explicit_invalid_package_id_rejected(self) -> None:
        from acef.merge import merge_packages

        with pytest.raises(ACEFMergeError):
            merge_packages(
                [_make_package("A", timestamp="2026-01-01T00:00:00Z")],
                package_id="not-a-urn",
            )

    # roborev MEDIUM — explicit package_id must be a PACKAGE-typed URN and
    # produce a lowercase UUID so it satisfies the frozen manifest schema.
    def test_explicit_non_package_urn_rejected(self) -> None:
        """A valid ACEF URN of the WRONG type (rec) must be rejected: the
        manifest schema requires urn:acef:pkg:<uuid>."""
        from acef.merge import merge_packages

        with pytest.raises(ACEFMergeError):
            merge_packages(
                [_make_package("A", timestamp="2026-01-01T00:00:00Z")],
                package_id="urn:acef:rec:00000000-0000-4000-8000-000000000000",
            )

    def test_explicit_uppercase_uuid_package_id_canonicalized(self) -> None:
        """An uppercase-UUID pkg URN (RFC 4122 permits it) must be lowercased
        so the merged package_id satisfies the lowercase-hex schema pattern."""
        from acef.merge import merge_packages
        from acef.models.urns import validate_urn

        result = merge_packages(
            [_make_package("A", timestamp="2026-01-01T00:00:00Z")],
            package_id="urn:acef:pkg:00000000-0000-4000-8000-ABCDEF000000",
        )
        pkg_id = result.package.metadata.package_id
        assert pkg_id == "urn:acef:pkg:00000000-0000-4000-8000-abcdef000000"
        assert validate_urn(pkg_id)
        assert pkg_id == pkg_id.lower()

    def test_explicit_lowercase_package_urn_accepted(self) -> None:
        from acef.merge import merge_packages

        result = merge_packages(
            [_make_package("A", timestamp="2026-01-01T00:00:00Z")],
            package_id="urn:acef:pkg:11111111-2222-4333-8444-555555555555",
        )
        assert result.package.metadata.package_id == "urn:acef:pkg:11111111-2222-4333-8444-555555555555"

    # roborev LOW — explicit timestamp must be parsed + canonicalized to ...Z
    # (or rejected) like derived timestamps, not passed through verbatim.
    def test_explicit_noncanonical_timestamp_normalized(self) -> None:
        """A valid-but-non-canonical instant (offset form) is normalized to
        canonical UTC ...Z, matching the derived-timestamp parser."""
        from acef.merge import merge_packages

        result = merge_packages(
            [_make_package("A", timestamp="2026-01-01T00:00:00Z")],
            timestamp="2030-12-31T23:59:59+02:00",
        )
        # +02:00 instant normalizes to its UTC equivalent in canonical Z form.
        assert result.package.metadata.timestamp == "2030-12-31T21:59:59Z"

    def test_explicit_invalid_timestamp_rejected(self) -> None:
        from acef.merge import merge_packages

        with pytest.raises(ACEFMergeError):
            merge_packages(
                [_make_package("A", timestamp="2026-01-01T00:00:00Z")],
                timestamp="not-a-timestamp",
            )

    def test_explicit_canonical_timestamp_passthrough(self) -> None:
        from acef.merge import merge_packages

        result = merge_packages(
            [_make_package("A", timestamp="2026-01-01T00:00:00Z")],
            timestamp="2030-12-31T23:59:59Z",
        )
        assert result.package.metadata.timestamp == "2030-12-31T23:59:59Z"


# ---------------------------------------------------------------------------
# VAL-FIX-LOADER-007 — attachment conflict detection
# ---------------------------------------------------------------------------


class TestAttachmentConflicts:
    def test_same_path_different_bytes_emits_acef_060(self) -> None:
        """Same attachment path + different bytes must raise an ACEF-060 conflict."""
        from acef.merge import merge_packages

        pkg1 = _make_package("A", attachment=("eval.pdf", b"CONTENT-1"), timestamp="2026-01-01T00:00:00Z")
        pkg2 = _make_package("B", attachment=("eval.pdf", b"CONTENT-2"), timestamp="2026-01-02T00:00:00Z")

        result = merge_packages([pkg1, pkg2])
        codes = [c.code for c in result.conflicts]
        assert "ACEF-060" in codes
        assert any("eval.pdf" in c.message for c in result.conflicts if c.code == "ACEF-060")

    def test_same_path_same_bytes_is_idempotent_no_conflict(self) -> None:
        """Identical attachment bytes at the same path must not conflict."""
        from acef.merge import merge_packages

        pkg1 = _make_package("A", attachment=("eval.pdf", b"SAME"), timestamp="2026-01-01T00:00:00Z")
        pkg2 = _make_package("B", attachment=("eval.pdf", b"SAME"), timestamp="2026-01-02T00:00:00Z")

        result = merge_packages([pkg1, pkg2])
        att_codes = [c.code for c in result.conflicts if "eval.pdf" in c.message]
        assert att_codes == []
        assert result.package.attachments["artifacts/eval.pdf"] == b"SAME"

    def test_keep_latest_selects_by_owning_package_timestamp(self) -> None:
        from acef.merge import merge_packages

        older = _make_package("A", attachment=("eval.pdf", b"OLD"), timestamp="2026-01-01T00:00:00Z")
        newer = _make_package("B", attachment=("eval.pdf", b"NEW"), timestamp="2026-06-01T00:00:00Z")

        # Newer second
        r = merge_packages([older, newer], conflict_strategy="keep_latest")
        assert r.package.attachments["artifacts/eval.pdf"] == b"NEW"
        assert any(c.code == "ACEF-060" for c in r.conflicts)

        # Newer first — order must not change the winner
        older2 = _make_package("A", attachment=("eval.pdf", b"OLD"), timestamp="2026-01-01T00:00:00Z")
        newer2 = _make_package("B", attachment=("eval.pdf", b"NEW"), timestamp="2026-06-01T00:00:00Z")
        r2 = merge_packages([newer2, older2], conflict_strategy="keep_latest")
        assert r2.package.attachments["artifacts/eval.pdf"] == b"NEW"

    def test_fail_strategy_raises_on_attachment_conflict(self) -> None:
        from acef.merge import merge_packages

        pkg1 = _make_package("A", attachment=("eval.pdf", b"C1"), timestamp="2026-01-01T00:00:00Z")
        pkg2 = _make_package("B", attachment=("eval.pdf", b"C2"), timestamp="2026-01-02T00:00:00Z")
        with pytest.raises(ACEFMergeError, match="ACEF-060"):
            merge_packages([pkg1, pkg2], conflict_strategy="fail")

    def test_keep_all_relocates_both_attachments(self) -> None:
        from acef.merge import merge_packages

        pkg1 = _make_package("A", attachment=("eval.pdf", b"C1"), timestamp="2026-01-01T00:00:00Z")
        pkg2 = _make_package("B", attachment=("eval.pdf", b"C2"), timestamp="2026-01-02T00:00:00Z")
        result = merge_packages([pkg1, pkg2], conflict_strategy="keep_all")
        # Both byte streams survive somewhere in the merged attachments.
        values = set(result.package.attachments.values())
        assert b"C1" in values
        assert b"C2" in values
        assert any(c.code == "ACEF-060" for c in result.conflicts)


# ---------------------------------------------------------------------------
# VAL-FIX-LOADER (roborev HIGH) — keep_all must rewrite record→artifact refs
#
# keep_all relocates the SECOND package's conflicting artifact bytes to a new
# path, but the records copied from that package still carried their ORIGINAL
# attachments[].path. Pre-fix: the later record points at the FIRST package's
# artifact (wrong bytes) and the relocated bytes are an UNREFERENCED orphan.
# Post-fix: the later record's attachments[].path is rewritten to the relocated
# path; every record's attachment ref resolves and no relocated artifact is
# orphaned.
# ---------------------------------------------------------------------------


class TestKeepAllRewritesRecordRefs:
    @staticmethod
    def _record_att_paths(pkg) -> dict[str, list[str]]:
        """Map record payload-key -> its attachments[].path list."""
        out: dict[str, list[str]] = {}
        for rec in pkg.records:
            key = rec.payload.get("k", rec.record_id)
            out[key] = [att.path for att in rec.attachments]
        return out

    def test_pre_fix_later_record_points_at_first_artifact_orphan(self) -> None:
        """RED proof: without rewrite, the later record references the FIRST
        package's artifact path while the relocated bytes are unreferenced."""
        from acef.merge import merge_packages

        pkg1 = _make_package(
            "A", attachment=("eval.pdf", b"C1"), timestamp="2026-01-01T00:00:00Z", record_refs_attachment=True
        )
        pkg2 = _make_package(
            "B", attachment=("eval.pdf", b"C2"), timestamp="2026-01-02T00:00:00Z", record_refs_attachment=True
        )
        result = merge_packages([pkg1, pkg2], conflict_strategy="keep_all")

        att_keys = set(result.package.attachments.keys())
        record_refs = self._record_att_paths(result.package)

        # The relocated path holds the SECOND package's bytes.
        relocated_paths = att_keys - {"artifacts/eval.pdf"}
        assert relocated_paths, "keep_all must relocate the conflicting artifact"
        relocated = next(iter(relocated_paths))
        assert result.package.attachments[relocated] == b"C2"

        # Every record attachment ref must resolve to a real artifact key.
        all_refs = {p for paths in record_refs.values() for p in paths}
        for ref in all_refs:
            assert ref in att_keys, f"record ref {ref!r} does not resolve to a merged artifact"

        # The later (B) record must reference the RELOCATED path (its own bytes),
        # not the first package's artifacts/eval.pdf (which holds C1).
        assert record_refs["B"] == [relocated]
        assert record_refs["A"] == ["artifacts/eval.pdf"]

        # No relocated artifact is unreferenced (no orphan evidence).
        for key in att_keys:
            assert key in all_refs, f"relocated artifact {key!r} is unreferenced (orphan)"

    def test_keep_all_multiple_records_share_relocated_artifact(self) -> None:
        """Two records in the later package referencing the same conflicting
        artifact both get rewritten to the single relocated path."""
        from acef.merge import merge_packages

        pkg1 = _make_package(
            "A", attachment=("eval.pdf", b"C1"), timestamp="2026-01-01T00:00:00Z", record_refs_attachment=True
        )
        pkg2 = Package(producer={"name": "B", "version": "1.0"})
        sub = pkg2.add_subject("ai_system", name="Sys B")
        pkg2.record(
            "risk_register",
            payload={"k": "B1"},
            entity_refs={"subject_refs": [sub.id]},
            attachments=[{"path": "artifacts/eval.pdf"}],
        )
        pkg2.record(
            "risk_register",
            payload={"k": "B2"},
            entity_refs={"subject_refs": [sub.id]},
            attachments=[{"path": "artifacts/eval.pdf"}],
        )
        pkg2.add_attachment("eval.pdf", b"C2")
        pkg2.metadata.timestamp = "2026-01-02T00:00:00Z"

        result = merge_packages([pkg1, pkg2], conflict_strategy="keep_all")
        att_keys = set(result.package.attachments.keys())
        relocated = next(iter(att_keys - {"artifacts/eval.pdf"}))
        record_refs = self._record_att_paths(result.package)
        assert record_refs["B1"] == [relocated]
        assert record_refs["B2"] == [relocated]
        assert record_refs["A"] == ["artifacts/eval.pdf"]

    def test_keep_latest_record_refs_stay_correct(self) -> None:
        """keep_latest keeps the winner's bytes at the original path; the
        surviving record's ref must still point at that original path."""
        from acef.merge import merge_packages

        older = _make_package(
            "A", attachment=("eval.pdf", b"OLD"), timestamp="2026-01-01T00:00:00Z", record_refs_attachment=True
        )
        newer = _make_package(
            "B", attachment=("eval.pdf", b"NEW"), timestamp="2026-06-01T00:00:00Z", record_refs_attachment=True
        )
        result = merge_packages([older, newer], conflict_strategy="keep_latest")
        att_keys = set(result.package.attachments.keys())
        assert att_keys == {"artifacts/eval.pdf"}
        assert result.package.attachments["artifacts/eval.pdf"] == b"NEW"
        record_refs = self._record_att_paths(result.package)
        for paths in record_refs.values():
            for p in paths:
                assert p in att_keys

    def test_non_conflicting_attachment_refs_unchanged(self) -> None:
        """Distinct attachment paths (no conflict) keep their original refs."""
        from acef.merge import merge_packages

        pkg1 = _make_package(
            "A", attachment=("a.pdf", b"AAA"), timestamp="2026-01-01T00:00:00Z", record_refs_attachment=True
        )
        pkg2 = _make_package(
            "B", attachment=("b.pdf", b"BBB"), timestamp="2026-01-02T00:00:00Z", record_refs_attachment=True
        )
        result = merge_packages([pkg1, pkg2], conflict_strategy="keep_all")
        record_refs = self._record_att_paths(result.package)
        assert record_refs["A"] == ["artifacts/a.pdf"]
        assert record_refs["B"] == ["artifacts/b.pdf"]


# ---------------------------------------------------------------------------
# VAL-FIX-LOADER-009 — profile provisions union + template_version conflict
# ---------------------------------------------------------------------------


class TestProfileProvisionUnion:
    def test_duplicate_profile_unions_provisions_sorted(self) -> None:
        from acef.merge import merge_packages

        pkg1 = _make_package("A", subject_name="A", timestamp="2026-01-01T00:00:00Z")
        pkg1.add_profile("eu-ai-act", provisions=["article-10", "article-9"])
        pkg2 = _make_package("B", subject_name="B", timestamp="2026-01-02T00:00:00Z")
        pkg2.add_profile("eu-ai-act", provisions=["article-15", "article-9"])

        result = merge_packages([pkg1, pkg2])
        profiles = [p for p in result.package.profiles if p.profile_id == "eu-ai-act"]
        assert len(profiles) == 1
        assert profiles[0].applicable_provisions == ["article-10", "article-15", "article-9"]

    def test_union_is_deterministic_across_input_order(self) -> None:
        from acef.merge import merge_packages

        def build() -> tuple[Package, Package]:
            p1 = _make_package("A", subject_name="A", timestamp="2026-01-01T00:00:00Z")
            p1.add_profile("eu-ai-act", provisions=["article-10"])
            p2 = _make_package("B", subject_name="B", timestamp="2026-01-02T00:00:00Z")
            p2.add_profile("eu-ai-act", provisions=["article-9"])
            return p1, p2

        a, b = build()
        c, d = build()
        fwd = merge_packages([a, b])
        rev = merge_packages([d, c])
        fwd_prov = next(p for p in fwd.package.profiles if p.profile_id == "eu-ai-act").applicable_provisions
        rev_prov = next(p for p in rev.package.profiles if p.profile_id == "eu-ai-act").applicable_provisions
        assert fwd_prov == rev_prov == ["article-10", "article-9"]

    def test_differing_template_version_emits_acef_060(self) -> None:
        from acef.merge import merge_packages

        pkg1 = _make_package("A", subject_name="A", timestamp="2026-01-01T00:00:00Z")
        pkg1.add_profile("eu-ai-act", template_version="1.0.0", provisions=["article-9"])
        pkg2 = _make_package("B", subject_name="B", timestamp="2026-01-02T00:00:00Z")
        pkg2.add_profile("eu-ai-act", template_version="2.0.0", provisions=["article-9"])

        result = merge_packages([pkg1, pkg2])
        codes = [c.code for c in result.conflicts]
        assert "ACEF-060" in codes
        assert any("template_version" in c.message for c in result.conflicts)

    def test_first_seen_profile_vendor_extension_preserved(self) -> None:
        """Unioning provisions must not drop the first entry's vendor x-* fields."""
        from acef.merge import merge_packages
        from acef.models.manifest import ProfileEntry

        pkg1 = _make_package("A", subject_name="A", timestamp="2026-01-01T00:00:00Z")
        pkg1._profiles.append(
            ProfileEntry.model_validate(
                {
                    "profile_id": "eu-ai-act",
                    "template_version": "1.0.0",
                    "applicable_provisions": ["article-9"],
                    "x-vendor": {"note": "keep me"},
                }
            )
        )
        pkg2 = _make_package("B", subject_name="B", timestamp="2026-01-02T00:00:00Z")
        pkg2.add_profile("eu-ai-act", template_version="1.0.0", provisions=["article-10"])

        result = merge_packages([pkg1, pkg2])
        merged = next(p for p in result.package.profiles if p.profile_id == "eu-ai-act")
        assert merged.applicable_provisions == ["article-10", "article-9"]
        # Vendor extension from the first-seen entry survives the union.
        assert merged.model_dump().get("x-vendor") == {"note": "keep me"}

    def test_same_template_version_no_conflict(self) -> None:
        from acef.merge import merge_packages

        pkg1 = _make_package("A", subject_name="A", timestamp="2026-01-01T00:00:00Z")
        pkg1.add_profile("eu-ai-act", template_version="1.0.0", provisions=["article-9"])
        pkg2 = _make_package("B", subject_name="B", timestamp="2026-01-02T00:00:00Z")
        pkg2.add_profile("eu-ai-act", template_version="1.0.0", provisions=["article-10"])

        result = merge_packages([pkg1, pkg2])
        tv_conflicts = [c for c in result.conflicts if "template_version" in c.message]
        assert tv_conflicts == []


# ---------------------------------------------------------------------------
# VAL-FIX-LOADER-010 — merge-specific audit trail + deterministic timestamps
# ---------------------------------------------------------------------------


class TestMergeAuditTrail:
    def test_audit_trail_does_not_claim_initial_creation(self) -> None:
        from acef.merge import merge_packages

        result = merge_packages(
            [
                _make_package("A", timestamp="2026-01-01T00:00:00Z"),
                _make_package("B", timestamp="2026-01-02T00:00:00Z"),
            ]
        )
        manifest = result.package.build_manifest()
        descriptions = [e.description for e in manifest.audit_trail]
        assert all("Initial package creation" not in d for d in descriptions)
        assert any("Merged from 2 packages" in d for d in descriptions)

    def test_audit_trail_timestamp_is_deterministic(self) -> None:
        from acef.merge import merge_packages

        result = merge_packages(
            [
                _make_package("A", timestamp="2025-05-01T00:00:00Z"),
                _make_package("B", timestamp="2026-07-04T12:00:00Z"),
            ]
        )
        manifest = result.package.build_manifest()
        for entry in manifest.audit_trail:
            assert entry.timestamp == "2026-07-04T12:00:00Z"
