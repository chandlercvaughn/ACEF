"""Fresh systems committee (DUP-KEY-IJSON-DETERMINISM @905302e): duplicate JSON
object member names in hash-domain files were silently collapsed (last-wins), not
rejected — so ``{"a":1,"a":2}`` hashed identically to ``{"a":2}``, breaking the
cross-implementation determinism/integrity MUST. The spec adopts RFC 7493 but
omitted its §2.3 member-uniqueness clause; the hash-domain parse now rejects
duplicates as ACEF-051.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acef.integrity import ACEFCanonicalizationError, canonicalize_json_str, sha256_file


def test_canonicalize_json_str_rejects_duplicate_member() -> None:
    with pytest.raises(ACEFCanonicalizationError):
        canonicalize_json_str('{"a":1,"a":2}')


def test_canonicalize_json_str_rejects_nested_duplicate_member() -> None:
    with pytest.raises(ACEFCanonicalizationError):
        canonicalize_json_str('{"x":{"a":1,"a":2}}')


def test_canonicalize_json_str_rejects_duplicate_in_array_element() -> None:
    with pytest.raises(ACEFCanonicalizationError):
        canonicalize_json_str('{"items":[{"k":1,"k":2}]}')


def test_canonicalize_json_str_accepts_unique_members() -> None:
    # Distinct keys, including a repeated key name at DIFFERENT object levels.
    out = canonicalize_json_str('{"a":1,"b":{"a":2}}')
    assert json.loads(out) == {"a": 1, "b": {"a": 2}}


def test_sha256_file_rejects_duplicate_member_json(tmp_path: Path) -> None:
    p = tmp_path / "acef-manifest.json"
    # Raw bytes with a literal duplicate member (json.dumps cannot produce one).
    p.write_text(
        '{"metadata":{"timestamp":"1999-01-01T00:00:00Z","timestamp":"2026-01-01T00:00:00Z"}}', encoding="utf-8"
    )
    with pytest.raises(ACEFCanonicalizationError):
        sha256_file(p)


def test_sha256_jsonl_rejects_duplicate_member(tmp_path: Path) -> None:
    from acef.integrity import sha256_jsonl_file

    p = tmp_path / "records.jsonl"
    p.write_text('{"record_id":"a","record_id":"b"}\n', encoding="utf-8")
    with pytest.raises(ACEFCanonicalizationError):
        sha256_jsonl_file(p)


def test_dup_key_bundle_is_rejected_end_to_end(tmp_path: Path) -> None:
    """A bundle whose acef-manifest.json carries a duplicate member name is FATAL —
    the content-hash computation (hash domain) rejects it, closing the determinism
    hole where a permissive parser would hash it identically to the deduped form."""
    from acef.package import Package
    from acef.validation.engine import validate_bundle

    pkg = Package(producer={"name": "dupkey", "version": "1.0.0"})
    pkg.add_subject("ai_system", name="S", risk_classification="high-risk", modalities=["text"])
    bundle_dir = tmp_path / "b.acef"
    pkg.export(str(bundle_dir))

    mp = bundle_dir / "acef-manifest.json"
    raw = mp.read_text(encoding="utf-8")
    # Inject a literal duplicate "version" member into metadata (textually).
    manifest = json.loads(raw)
    assert "metadata" in manifest
    tampered = raw.replace('"metadata":{', '"metadata":{"package_id":"DUP","package_id":"DUP2",', 1)
    assert tampered != raw
    mp.write_text(tampered, encoding="utf-8")

    assessment = validate_bundle(bundle_dir)
    assert any(e.get("severity") == "fatal" for e in assessment.structural_errors), (
        "a duplicate manifest member name must produce a FATAL assessment"
    )
