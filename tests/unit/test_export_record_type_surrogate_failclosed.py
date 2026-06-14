"""Surrogate-bearing extension record types must FAIL CLOSED (ACEF-052).

Structural-review P1 (roborev follow-up): bringing the record-type GROUPING sort
onto ``integrity.utf16_collation_key`` (see
``test_export_record_type_collation.py``) introduced a regression — the collation
key is computed by ``str.encode("utf-16-be")``, which raises a RAW
``UnicodeEncodeError`` for a string holding a lone UTF-16 surrogate.

``Package.record()`` accepts ANY ``x-``-prefixed extension record type WITHOUT a
strict-UTF-8 / NFC text check (it only gates on the ``x-`` prefix), so a
surrogate-bearing extension type such as ``x-\\udce9`` is accepted into the
package and reaches the collation-key sort at:

  * ``export._record_shard_relpaths`` (preflight member enumeration),
  * ``export.export_directory`` (shard-emission loop),
  * ``Package.build_manifest`` (record_files ordering).

Pre-fix, each of these raises a bare
``UnicodeEncodeError('utf-16-be', 'x-\\udce9', 2, 3, 'surrogates not allowed')``
during export PREFLIGHT — bypassing the structured ``ACEFExportError(ACEF-052)``
/ NFC-path-rejection surface every other invalid path byte uses
(``_validate_ustar_member_name`` -> ``path_nfc_utf8_problem`` -> ACEF-052).

Post-fix, the record-type text is validated with the SAME strict-UTF-8 / NFC
path rule BEFORE the collation key is taken, so a surrogate-bearing type surfaces
as a structured ``ACEFExportError`` carrying ``ACEF-052`` — never a raw
``UnicodeEncodeError``. A valid supplementary-plane type (``x-𐀀``, no lone
surrogate) still sorts via UTF-16 collation, so the legitimate cross-exporter
determinism fix is preserved.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acef.errors import ACEFExportError
from acef.export import export_archive
from acef.package import Package

# A lone-surrogate-bearing extension record type. ``Package.record()`` accepts it
# (only the ``x-`` prefix is gated); ``str.encode("utf-16-be")`` cannot encode the
# lone surrogate 0xDCE9, so the collation-key sort raises raw UnicodeEncodeError
# pre-fix.
_SURROGATE_TYPE = "x-\udce9"
# A VALID supplementary-plane extension type (U+10000 -> surrogate PAIR, encodable):
# this is the legitimate cross-exporter-determinism case the prior commit fixed.
_SUPPLEMENTARY_TYPE = "x-\U00010000"


def _new_package() -> Package:
    pkg = Package(producer={"name": "surrogate-failclosed-test", "version": "1.0.0"})
    pkg.add_subject(
        subject_type="ai_system",
        name="SurrogateSystem",
        version="1.0.0",
        provider="acme",
        risk_classification="high-risk",
    )
    pkg.add_profile(profile_id="eu-ai-act-v1", provisions=["article-9"])
    return pkg


def _record_one(pkg: Package, record_type: str) -> None:
    pkg.record(
        record_type=record_type,
        provisions=["article-9"],
        payload={"k": "v"},
        timestamp="2025-01-01T00:00:01Z",
        record_id="urn:acef:rec:00000001-0000-0000-0000-000000000001",
    )


def test_record_accepts_surrogate_extension_type_premise() -> None:
    """Premise: ``Package.record()`` accepts the surrogate-bearing ``x-`` type.

    If this ever changes (record() gains a strict-UTF-8 gate), the export-path
    guard below becomes unreachable and this premise test documents why.
    """
    pkg = _new_package()
    _record_one(pkg, _SURROGATE_TYPE)
    assert any(rec.record_type == _SURROGATE_TYPE for rec in pkg.records)


def test_export_archive_surrogate_type_raises_acef052_not_unicodeerror(tmp_path: Path) -> None:
    """``export_archive`` on a surrogate-bearing record type raises the structured
    ``ACEFExportError(ACEF-052)`` — NOT a raw ``UnicodeEncodeError``.

    RED (pre-fix): the preflight collation sort
    ``sorted(..., key=lambda kv: utf16_collation_key(kv[0]))`` calls
    ``"x-\\udce9".encode("utf-16-be")`` and raises
    ``UnicodeEncodeError('utf-16-be', 'x-\\udce9', 2, 3, 'surrogates not allowed')``.
    """
    pkg = _new_package()
    _record_one(pkg, _SURROGATE_TYPE)

    out = tmp_path / "surrogate.acef.tar.gz"
    with pytest.raises(ACEFExportError) as exc_info:
        export_archive(pkg, str(out))

    assert exc_info.value.code == "ACEF-052", (
        f"surrogate record type must fail closed with ACEF-052, got {exc_info.value.code!r}"
    )
    # The offending record type must be named in the message for diagnosis.
    assert "x-" in str(exc_info.value)


def test_export_directory_surrogate_type_raises_acef052_not_unicodeerror(tmp_path: Path) -> None:
    """``export_directory`` (the directory-bundle surface) on a surrogate-bearing
    record type raises the structured ``ACEFExportError(ACEF-052)`` — NOT a raw
    ``UnicodeEncodeError`` — at the entry-point preflight, before any filesystem
    work."""
    pkg = _new_package()
    _record_one(pkg, _SURROGATE_TYPE)

    out = tmp_path / "surrogate.acef"
    with pytest.raises(ACEFExportError) as exc_info:
        pkg.export(str(out))

    assert exc_info.value.code == "ACEF-052"
    # Fail-closed before FS work: no directory bundle is left behind.
    assert not out.exists()


def test_build_manifest_surrogate_type_raises_acef052_not_unicodeerror() -> None:
    """``Package.build_manifest`` orders ``record_files`` by the record-type
    collation key; a surrogate-bearing type must surface as the structured
    ``ACEFExportError(ACEF-052)`` — NOT a raw ``UnicodeEncodeError``."""
    pkg = _new_package()
    _record_one(pkg, _SURROGATE_TYPE)

    with pytest.raises(ACEFExportError) as exc_info:
        pkg.build_manifest()

    assert exc_info.value.code == "ACEF-052"


def test_valid_supplementary_type_still_sorts_and_exports(tmp_path: Path) -> None:
    """Regression guard: a VALID supplementary-plane type (``x-𐀀``, U+10000, no
    lone surrogate) is NOT rejected and still sorts by UTF-16 collation — the
    legitimate cross-exporter-determinism case the prior commit fixed must keep
    working (the fail-closed guard must not over-reject encodable code points)."""
    # build_manifest must succeed (no false ACEF-052 on an encodable type).
    pkg = _new_package()
    _record_one(pkg, _SUPPLEMENTARY_TYPE)
    manifest = pkg.build_manifest()
    assert any(rf.record_type == _SUPPLEMENTARY_TYPE for rf in manifest.record_files)

    # Full export succeeds and emits the supplementary-type shard.
    pkg2 = _new_package()
    _record_one(pkg2, _SUPPLEMENTARY_TYPE)
    out = tmp_path / "supplementary.acef"
    pkg2.export(str(out))
    assert (out / "records" / f"{_SUPPLEMENTARY_TYPE}.jsonl").exists()
