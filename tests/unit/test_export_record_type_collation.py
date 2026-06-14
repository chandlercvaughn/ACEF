"""Record-type GROUPING order must use RFC 8785 UTF-16 collation, not code-point.

Structural-review P1 (follow-up): the tar MEMBER sort was already brought onto
``integrity.utf16_collation_key`` (see ``test_export_tar_member_collation.py``),
but the record-type GROUPING that determines

  * the manifest ``record_files`` list order
    (``Package.build_manifest`` -> ``src/acef/package.py``), and
  * the directory-export JSONL shard emission order
    (``export_directory`` -> ``src/acef/export.py``)

still iterated ``sorted(records_by_type.items())`` == Python CODE-POINT order.

``Package.record()`` accepts ``x-``-prefixed EXTENSION record types, so a
supplementary-plane (U+10000+) extension type name makes Python order the
``record_files`` entries (which live in the content-hash domain) and the emitted
shard filenames DIFFERENTLY from the TypeScript reference exporter's
``Array.prototype.sort()`` (UTF-16 code-unit order). That diverges BOTH the
canonical manifest bytes AND the archive bytes across the two reference
exporters — the same §3.1.3 byte-identical MUST violation, one layer up from the
member sort.

Concrete divergence used below (both are valid ``x-``-prefixed extension types):
  - ``x-ﬀ``   U+FB00  (BMP, LATIN SMALL LIGATURE FF)
  - ``x-𐀀``  U+10000 (supplementary, LINEAR B SYLLABLE B008 A)

Code-point sort -> [``x-ﬀ`` (FB00), ``x-𐀀`` (10000)].
UTF-16 sort     -> [``x-𐀀`` (begins with surrogate 0xD800 < 0xFB00), ``x-ﬀ``].
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from acef import export as export_module
from acef import integrity
from acef.package import Package

# Two valid ``x-``-prefixed extension record types whose code-point order and
# UTF-16 collation order DIVERGE. The supplementary char's first UTF-16 unit
# (0xD800) sorts before U+FB00 under UTF-16, but after it under code point.
_TYPE_BMP = "x-ﬀ"  # U+FB00
_TYPE_SUPPLEMENTARY = "x-\U00010000"  # U+10000


def _build_package_with_record_types(types: list[str]) -> Package:
    pkg = Package(producer={"name": "rt-collation-test", "version": "1.0.0"})
    pkg.add_subject(
        subject_type="ai_system",
        name="CollationSystem",
        version="1.0.0",
        provider="acme",
        risk_classification="high-risk",
    )
    pkg.add_profile(profile_id="eu-ai-act-v1", provisions=["article-9"])
    for i, record_type in enumerate(types):
        pkg.record(
            record_type=record_type,
            provisions=["article-9"],
            payload={"k": f"v{i}"},
            timestamp=f"2025-01-01T00:00:0{i + 1}Z",
            record_id=(f"urn:acef:rec:0000000{i + 1}-0000-0000-0000-00000000000{i + 1}"),
        )
    return pkg


def test_manifest_record_files_order_uses_utf16_collation() -> None:
    """Manifest ``record_files`` are ordered by UTF-16 collation of the record
    type (the TS exporter order), NOT Python code-point order.

    RED (pre-fix): ``build_manifest`` iterates ``sorted(records_by_type.items())``
    == code-point order, so ``record_files`` is
    ``['records/x-ﬀ.jsonl', 'records/x-𐀀.jsonl']`` which != the UTF-16 order
    ``['records/x-𐀀.jsonl', 'records/x-ﬀ.jsonl']`` -> this assertion FAILS
    (manifest bytes diverge from the TS exporter in the content-hash domain).
    GREEN (post-fix): both orders coincide.
    """
    pkg = _build_package_with_record_types([_TYPE_BMP, _TYPE_SUPPLEMENTARY])
    manifest = pkg.build_manifest()

    emitted_types = [rf.record_type for rf in manifest.record_files]
    emitted_paths = [rf.path for rf in manifest.record_files]

    expected_utf16 = sorted([_TYPE_BMP, _TYPE_SUPPLEMENTARY], key=integrity.utf16_collation_key)
    expected_codepoint = sorted([_TYPE_BMP, _TYPE_SUPPLEMENTARY])

    # Guard the premise: the two collations genuinely diverge for these types.
    assert expected_utf16 != expected_codepoint, (
        "premise broken: x-U+FB00 vs x-U+10000 must order differently under code-point vs UTF-16 collation"
    )

    assert emitted_types == expected_utf16, (
        "Manifest record_files must be ordered by UTF-16 collation of the "
        "record type to match the TS exporter and the rest of the hash domain.\n"
        f"  emitted:          {emitted_types!r}\n"
        f"  expected (utf16): {expected_utf16!r}\n"
        f"  code-point order: {expected_codepoint!r}"
    )
    assert emitted_paths == [f"records/{t}.jsonl" for t in expected_utf16]


def test_directory_export_shard_emission_order_uses_utf16_collation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Directory export EMITS the per-record-type JSONL shard files in UTF-16
    collation order of the record type (export.py's record-emission loop), so
    the single source of truth for record-type grouping order matches the TS
    exporter and the rest of the hash domain.

    The shard *write order* is the exact site the finding targets
    (``export.py``: ``for record_type, recs in sorted(records_by_type.items())``).
    We intercept ``_write_jsonl`` to capture the order the loop actually emits
    files in (the final archive bytes are downstream-resorted by the tar member
    sort and the content-hash collation, which would otherwise mask the write
    order — so we assert at the loop itself).

    RED (pre-fix): the loop iterates ``sorted(records_by_type.items())`` ==
    code-point order, so the captured emission order is
    ``['x-ﬀ.jsonl', 'x-𐀀.jsonl']`` which != the UTF-16 order
    ``['x-𐀀.jsonl', 'x-ﬀ.jsonl']`` -> this assertion FAILS.
    GREEN (post-fix): both orders coincide.
    """
    pkg = _build_package_with_record_types([_TYPE_BMP, _TYPE_SUPPLEMENTARY])

    written_order: list[str] = []
    original_write_jsonl = export_module._write_jsonl

    def _capturing_write_jsonl(records: list[Any], path: Path) -> None:
        written_order.append(Path(path).name)
        original_write_jsonl(records, path)

    monkeypatch.setattr(export_module, "_write_jsonl", _capturing_write_jsonl)

    bundle_dir = tmp_path / "rt-collation.acef"
    pkg.export(str(bundle_dir))

    expected_utf16 = [f"{t}.jsonl" for t in sorted([_TYPE_BMP, _TYPE_SUPPLEMENTARY], key=integrity.utf16_collation_key)]
    expected_codepoint = [f"{t}.jsonl" for t in sorted([_TYPE_BMP, _TYPE_SUPPLEMENTARY])]

    assert expected_utf16 != expected_codepoint, (
        "premise broken: record-type names must order differently under code-point vs UTF-16 collation"
    )
    assert written_order == expected_utf16, (
        "Directory-export must EMIT JSONL shard files in UTF-16 collation "
        "order of the record type (single source of truth with the manifest "
        "and the rest of the hash domain).\n"
        f"  written order:    {written_order!r}\n"
        f"  expected (utf16): {expected_utf16!r}\n"
        f"  code-point order: {expected_codepoint!r}"
    )


def test_ascii_record_type_order_unchanged_control() -> None:
    """ASCII control: code-point order == UTF-16 order, so record_files order is
    unchanged by the collation-key sort (no churn for the all-ASCII record-type
    corpus that covers every golden bundle and existing vector)."""
    pkg = _build_package_with_record_types(["x-alpha", "x-beta", "x-zulu", "x-mike"])
    manifest = pkg.build_manifest()
    emitted = [rf.record_type for rf in manifest.record_files]

    ascii_types = ["x-alpha", "x-beta", "x-zulu", "x-mike"]
    assert sorted(ascii_types) == sorted(ascii_types, key=integrity.utf16_collation_key)
    assert emitted == sorted(ascii_types, key=integrity.utf16_collation_key)
