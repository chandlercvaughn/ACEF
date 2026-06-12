"""RED-first tests for F-M3-MERKLE-SORT (findings integrity-jcs-merkle-1/2/4/5).

These tests reproduce four integrity defects in :mod:`acef.integrity` /
:mod:`acef.records_util` and pin the post-fix behavior:

1. (HIGH) Merkle leaf order diverges from content-hashes.json on-disk key order
   for supplementary-plane (U+10000+) paths: the leaves are built with Python's
   default code-point ``sorted`` while ``rfc8785.dumps`` writes the keys in
   UTF-16 code-unit order. A second spec-conformant exporter deriving leaf order
   from the canonical content-hashes.json would compute a DIFFERENT Merkle root.
2. (low) ``records_util.sort_records`` uses code-point order on
   ``(timestamp, record_id)`` rather than the RFC 8785 UTF-16 collation used for
   every canonical-JSON key elsewhere.
3. (info) An empty hash domain is silently rooted at ``SHA-256("")`` — an
   implementation-defined, non-spec value. A valid bundle always contains
   ``acef-manifest.json``; the empty case MUST be rejected so the sentinel is
   never load-bearing for interop.
4. (low) An out-of-domain number (>2^53, NaN, Infinity) in hash-domain
   JSON/JSONL leaks a raw ``rfc8785.IntegerDomainError`` / ``FloatDomainError``
   and crashes the validator instead of surfacing a structured ACEF-051.

The UTF-16 collation reference order is taken from ``rfc8785.dumps`` itself (the
exact order the canonical content-hashes.json is written in), so the assertions
cannot drift from the canonicalizer.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import rfc8785

from acef.integrity import (
    ACEFCanonicalizationError,
    build_merkle_tree,
    canonicalize_json_str,
    sha256_file,
    utf16_collation_key,
)

# A BMP path and a supplementary-plane path whose code-point order and UTF-16
# code-unit order DISAGREE. ``ﬀ`` is U+FB00 (BMP); ``𐀀`` is U+10000
# (supplementary, encoded as the surrogate pair 0xD800 0xDC00). Under code-point
# order U+FB00 < U+10000, but under UTF-16 code-unit order the first unit 0xD800
# (for U+10000) sorts before 0xFB00, so ``𐀀`` comes FIRST. Both are valid
# UTF-8 NFC artifact filenames per spec §3.1.1.
_BMP_PATH = "artifacts/ﬀ.txt"  # ﬀ.txt
_SUPP_PATH = "artifacts/\U00010000.txt"  # 𐀀.txt


def _rfc8785_key_order(d: dict[str, str]) -> list[str]:
    """The exact key order ``rfc8785.dumps`` writes (UTF-16 code-unit order)."""
    return list(json.loads(rfc8785.dumps(d)).keys())


class TestUtf16CollationHelper:
    """The shared UTF-16 collation key must match rfc8785's object-key order."""

    def test_helper_matches_rfc8785_for_supplementary_plane(self) -> None:
        d = {_SUPP_PATH: "h0", _BMP_PATH: "h1"}
        canonical_order = _rfc8785_key_order(d)
        helper_order = sorted(d, key=utf16_collation_key)
        assert helper_order == canonical_order
        # Sanity: this is the case Python's default sort gets WRONG.
        assert sorted(d) != canonical_order

    def test_helper_is_identity_on_ascii(self) -> None:
        # For ASCII/BMP keys the helper must agree with code-point order so
        # existing (ASCII) bundles are byte-neutral.
        keys = ["acef-manifest.json", "artifacts/a.pdf", "records/z.jsonl"]
        assert sorted(keys, key=utf16_collation_key) == sorted(keys)


class TestMerkleLeafOrderMatchesContentHashes:
    """Finding integrity-jcs-merkle-1 (HIGH)."""

    def test_leaf_order_matches_rfc8785_key_order(self) -> None:
        # Supplementary-plane path present: leaves[] MUST be in the same order
        # as the canonical content-hashes.json keys (UTF-16), not code-point.
        content_hashes = {_BMP_PATH: "a" * 64, _SUPP_PATH: "b" * 64}
        canonical_order = _rfc8785_key_order(content_hashes)
        tree = build_merkle_tree(content_hashes)
        leaf_order = [leaf["path"] for leaf in tree["leaves"]]
        assert leaf_order == canonical_order

    def test_root_is_collation_stable_cross_producer(self) -> None:
        # Two producers feeding the SAME logical file set in DIFFERENT dict
        # insertion orders must compute the SAME root, and that root must be
        # the one derived from the canonical (UTF-16-sorted) key order.
        a = {_BMP_PATH: "a" * 64, _SUPP_PATH: "b" * 64}
        b = {_SUPP_PATH: "b" * 64, _BMP_PATH: "a" * 64}
        root_a = build_merkle_tree(a)["root"]
        root_b = build_merkle_tree(b)["root"]
        assert root_a == root_b

        # Independently derive the expected root from the UTF-16 leaf order.
        ordered = sorted(a.items(), key=lambda kv: utf16_collation_key(kv[0]))
        level = [hashlib.sha256(p.encode("utf-8") + b"\x00" + h.encode("utf-8")).digest() for p, h in ordered]
        while len(level) > 1:
            nxt: list[bytes] = []
            i = 0
            while i < len(level):
                if i + 1 < len(level):
                    nxt.append(hashlib.sha256(level[i] + level[i + 1]).digest())
                    i += 2
                else:
                    nxt.append(level[i])
                    i += 1
            level = nxt
        assert root_a == level[0].hex()


class TestRecordSortUtf16:
    """Finding integrity-jcs-merkle-2 (low)."""

    def test_sort_records_uses_utf16_collation(self) -> None:
        from acef.records_util import sort_records

        class _Rec:
            def __init__(self, timestamp: str, record_id: str) -> None:
                self.timestamp = timestamp
                self.record_id = record_id

        ts = "2026-01-01T00:00:00Z"
        # Same supplementary-vs-BMP divergence, but in record_id position.
        bmp = _Rec(ts, "urn:acef:rec:ﬀ")
        supp = _Rec(ts, "urn:acef:rec:\U00010000")
        # Feed in code-point order; UTF-16 order must REVERSE them.
        ordered = sort_records([bmp, supp])  # type: ignore[list-item]
        ids = [r.record_id for r in ordered]
        expected = sorted([bmp.record_id, supp.record_id], key=utf16_collation_key)
        assert ids == expected
        # Sanity: code-point order would differ.
        assert ids != sorted([bmp.record_id, supp.record_id])


class TestEmptyDomainRootRejected:
    """Finding integrity-jcs-merkle-4 (info): empty hash domain is invalid."""

    def test_empty_hash_domain_raises(self) -> None:
        with pytest.raises(ACEFCanonicalizationError, match="acef-manifest.json"):
            build_merkle_tree({})


class TestOutOfDomainNumberStructured:
    """Finding integrity-jcs-merkle-5 (low): >2^53 / NaN / Infinity -> ACEF-051."""

    def test_json_big_integer_raises_structured(self, tmp_path: Path) -> None:
        p = tmp_path / "artifacts" / "big.json"
        p.parent.mkdir(parents=True)
        # >2^53: outside the RFC 8785 / I-JSON safe integer domain.
        p.write_text('{"big":100000000000000000000}', encoding="utf-8")
        with pytest.raises(ACEFCanonicalizationError, match="RFC 8785"):
            sha256_file(p)

    def test_jsonl_infinity_raises_structured(self, tmp_path: Path) -> None:
        p = tmp_path / "records" / "bad.jsonl"
        p.parent.mkdir(parents=True)
        # json.loads accepts the non-standard ``Infinity`` literal; rfc8785
        # rejects it as a FloatDomainError. Must surface as ACEF-051, not crash.
        p.write_text('{"x":Infinity}\n', encoding="utf-8")
        with pytest.raises(ACEFCanonicalizationError, match="RFC 8785"):
            sha256_file(p)

    def test_canonicalize_json_str_big_integer_raises_structured(self) -> None:
        with pytest.raises(ACEFCanonicalizationError, match="RFC 8785"):
            canonicalize_json_str('{"big":100000000000000000000}')

    def test_check_integrity_emits_acef051_not_crash(self, tmp_path: Path) -> None:
        # End-to-end: an out-of-domain number in a hash-domain artifact must
        # surface as a structured ACEF-051 diagnostic from check_integrity,
        # NOT propagate a raw rfc8785.IntegerDomainError (DoS / "report ALL
        # errors" MUST, spec §3.1.3 #6f).
        from acef.integrity import compute_content_hashes
        from acef.validation.integrity_checker import check_integrity

        bundle = tmp_path / "bundle"
        (bundle / "artifacts").mkdir(parents=True)
        (bundle / "hashes").mkdir()
        (bundle / "acef-manifest.json").write_text("{}", encoding="utf-8")
        # A well-formed content-hashes.json for the manifest only; the offending
        # artifact is added AFTER so its (uncomputable) hash is what crashes the
        # recompute step rather than the listing check.
        manifest_hash = compute_content_hashes(bundle)["acef-manifest.json"]
        (bundle / "artifacts" / "evil.json").write_text('{"big":100000000000000000000}', encoding="utf-8")
        content_hashes = {
            "acef-manifest.json": manifest_hash,
            "artifacts/evil.json": "0" * 64,
        }
        (bundle / "hashes" / "content-hashes.json").write_bytes(rfc8785.dumps(content_hashes))

        diags = check_integrity(bundle)
        codes = [d.code for d in diags]
        assert "ACEF-051" in codes
        # And the validator did not crash — it returned a diagnostic list.
        assert all(isinstance(d.code, str) for d in diags)
