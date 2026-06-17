"""Loader RECORD-read robustness (F9): a non-UTF-8 record file must surface as a
structured ``ACEFFormatError`` (ACEF-050), not a RAW ``UnicodeDecodeError`` traceback
leaking out of the public ``acef.load()`` deserialization API.

Finding (audit F9):

    ``_parse_jsonl`` opens the record file with ``open(path, encoding="utf-8")`` and
    iterates ``for line_num, line in enumerate(f, 1):`` OUTSIDE the inner try/except
    (which catches only ``json.JSONDecodeError``). Text-mode iteration decodes LAZILY, so
    non-UTF-8 bytes raise ``UnicodeDecodeError`` DURING the ``for`` iteration — before the
    try block is entered — and it leaks raw. This diverges from the manifest read
    (loader.py) and the validation engine, which both map non-UTF-8 -> ACEF-050.

The fix reads each line in BINARY and decodes it explicitly, mapping a decode failure to
the loader's existing ``ACEFFormatError(code="ACEF-050")`` malformed-record path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import acef
from acef.errors import ACEFFormatError
from acef.package import Package

# A UTF-16 BOM (0xff 0xfe) is NOT decodable as UTF-8 (0xff is an invalid start byte).
_NON_UTF8_RECORD = b'\xff\xfe{"record_type": "risk_register"}\n'


def _valid_bundle_with_record(bundle: Path) -> Path:
    pkg = Package(producer={"name": "acef-sdk", "version": "0.1.0"})
    pkg.add_subject("ai_system", name="S", risk_classification="high-risk", modalities=["text"])
    pkg.record(
        "risk_register",
        payload={
            "risk_id": "R1",
            "description": "x",
            "category": "safety",
            "likelihood": "possible",
            "severity": "major",
        },
        obligation_role="provider",
    )
    pkg.export(str(bundle))
    return bundle


def test_directory_non_utf8_record_raises_acef_050(tmp_path: Path) -> None:
    """``acef.load(<dir>)`` whose ``records/*.jsonl`` holds non-UTF-8 bytes must raise a
    structured ``ACEFFormatError`` (ACEF-050) — pre-fix this leaked a RAW
    ``UnicodeDecodeError`` out of the public ``acef.load()`` API during file iteration."""
    bundle = _valid_bundle_with_record(tmp_path / "bundle.acef")
    record_files = list((bundle / "records").glob("*.jsonl"))
    assert record_files, "fixture must export at least one record file"
    record_files[0].write_bytes(_NON_UTF8_RECORD)

    with pytest.raises(ACEFFormatError) as exc_info:
        acef.load(str(bundle))

    assert exc_info.value.code == "ACEF-050"
    assert not isinstance(exc_info.value, UnicodeDecodeError)


def test_valid_utf8_record_still_loads(tmp_path: Path) -> None:
    """A well-formed UTF-8 record bundle still loads cleanly — the binary-read fix must
    not over-reject valid bundles."""
    bundle = _valid_bundle_with_record(tmp_path / "ok.acef")
    pkg = acef.load(str(bundle))
    assert len(pkg.records) == 1
    assert pkg.records[0].record_type == "risk_register"


def test_malformed_utf8_json_record_still_raises_acef_050(tmp_path: Path) -> None:
    """A record line that is valid UTF-8 but malformed JSON still raises ACEF-050 via the
    existing ``json.JSONDecodeError`` arm — the fix only changes HOW bytes are read, not
    the malformed-JSON behavior."""
    bundle = _valid_bundle_with_record(tmp_path / "badjson.acef")
    record_files = list((bundle / "records").glob("*.jsonl"))
    record_files[0].write_text("{ not json\n", encoding="utf-8")

    with pytest.raises(ACEFFormatError) as exc_info:
        acef.load(str(bundle))

    assert exc_info.value.code == "ACEF-050"
