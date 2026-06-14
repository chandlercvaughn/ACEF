"""Per-record JSONL type-confusion robustness for ``acef.load()``.

Structural-review P2 (``loader.py:814``). The loader-robustness work hardened
every MANIFEST section against type-confusion (structured ACEF-002/ACEF-050
instead of a raw ``AttributeError`` / ``TypeError``) but MISSED the per-record
JSONL path. ``_parse_jsonl`` appends ``json.loads(line)`` for ANY well-formed
JSON value with no object check, and ``check_load_rejections`` only ``continue``s
past non-dict records. So a bundle whose manifest-listed ``records/*.jsonl`` file
contains a bare scalar / array / null line (``42``, ``"x"``, ``[1, 2]``,
``null``) reached ``dict_to_record_envelope(rec_data)``, whose body does
``data.get("entity_refs", {})`` with no ``isinstance`` guard — leaking a raw
``AttributeError: 'int' / 'list' / 'NoneType' / 'str' object has no attribute
'get'`` out of the PUBLIC ``acef.load()`` deserialization API on
attacker-controlled bytes.

The VALIDATION engine already handles this case at
``acef.validation.engine`` — a non-object JSONL line emits **ACEF-050**
(``"JSONL line at <file>:<line> is not a JSON object (got <type>)"``). Before
the fix ``load()`` and ``validate_bundle()`` DIVERGED on the identical malicious
input. These tests pin CONVERGENCE: ``load()`` must raise the SAME structured
ACEF-050 ``ACEFFormatError`` the validate path reports, for BOTH directory and
``.acef.tar.gz`` archive inputs, and ``validate_bundle`` must report ACEF-050 on
the same tampered bundle.
"""

from __future__ import annotations

import shutil
import tarfile
from pathlib import Path

import pytest

import acef
from acef.errors import ACEFError, ACEFFormatError
from acef.validation.engine import validate_bundle

_GOLDEN = Path(__file__).resolve().parents[1] / "conformance" / "golden-bundles" / "eu-high-risk-core"

# Well-formed JSON values that are NOT objects and therefore cannot be records.
_NON_OBJECT_LINES = [
    pytest.param("42", "int", id="bare-int"),
    pytest.param("[1, 2]", "list", id="json-array"),
    pytest.param("null", "NoneType", id="json-null"),
    pytest.param('"x"', "str", id="json-string"),
]


def _copy_golden(dest: Path) -> Path:
    """Copy the (frozen) golden bundle to ``dest`` so the original stays
    byte-unchanged; the copy is what we tamper."""
    shutil.copytree(_GOLDEN, dest)
    return dest


def _tamper_first_record_file(bundle: Path, appended_line: str) -> Path:
    """Append a raw non-object JSON line to the first ``records/*.jsonl`` file."""
    record_files = sorted((bundle / "records").glob("*.jsonl"))
    assert record_files, "golden bundle must ship at least one records/*.jsonl file"
    target = record_files[0]
    with target.open("a", encoding="utf-8") as fh:
        fh.write(appended_line + "\n")
    return target


def _make_archive(bundle_dir: Path, archive_path: Path) -> Path:
    """Pack ``bundle_dir`` into a ``.acef.tar.gz`` nested under a single root
    directory (the canonical archive layout the loader resolves)."""
    with tarfile.open(str(archive_path), "w:gz") as tar:
        tar.add(str(bundle_dir), arcname=bundle_dir.name)
    return archive_path


# ---------------------------------------------------------------------------
# RED: a non-object JSONL record line must surface structured ACEF-050,
# never a raw AttributeError — directory input.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("line", "type_name"), _NON_OBJECT_LINES)
def test_directory_nonobject_record_line_raises_acef_050(tmp_path: Path, line: str, type_name: str) -> None:
    bundle = _copy_golden(tmp_path / "bundle")
    target = _tamper_first_record_file(bundle, line)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFFormatError)
    assert exc.value.code == "ACEF-050"
    # The message must name the offending file and that it is not a JSON object.
    assert target.name in exc.value.message
    assert "not a JSON object" in exc.value.message
    assert type_name in exc.value.message


# ---------------------------------------------------------------------------
# RED: same guarantee for .acef.tar.gz archive input — both ingestion entry
# points (directory AND archive) converge through _load_directory.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("line", "type_name"), _NON_OBJECT_LINES)
def test_archive_nonobject_record_line_raises_acef_050(tmp_path: Path, line: str, type_name: str) -> None:
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper_first_record_file(bundle, line)
    archive = _make_archive(bundle, tmp_path / "tampered.acef.tar.gz")

    with pytest.raises(ACEFError) as exc:
        acef.load(str(archive))

    assert isinstance(exc.value, ACEFFormatError)
    assert exc.value.code == "ACEF-050"
    assert "not a JSON object" in exc.value.message
    assert type_name in exc.value.message


# ---------------------------------------------------------------------------
# Convergence: validate_bundle reports ACEF-050 on the SAME tampered bundle, so
# load() and validate() no longer diverge on the identical malicious input.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("line", "type_name"), _NON_OBJECT_LINES)
def test_validate_bundle_reports_acef_050_on_same_tampered_bundle(tmp_path: Path, line: str, type_name: str) -> None:
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper_first_record_file(bundle, line)

    assessment = validate_bundle(str(bundle))

    errors = assessment.structural_errors
    codes = {d["code"] for d in errors}
    assert "ACEF-050" in codes, f"expected ACEF-050 in validate structural_errors, got {sorted(codes)}"
    matching = [d for d in errors if d["code"] == "ACEF-050" and "not a JSON object" in d["message"]]
    assert matching, "validate must emit an ACEF-050 'not a JSON object' diagnostic for the bad line"


# ---------------------------------------------------------------------------
# GREEN guard: the untampered golden bundle still loads cleanly (no over-rejection).
# ---------------------------------------------------------------------------


def test_untampered_golden_bundle_still_loads(tmp_path: Path) -> None:
    bundle = _copy_golden(tmp_path / "bundle")
    pkg = acef.load(str(bundle))
    assert pkg.records, "untampered golden bundle must load with records"
