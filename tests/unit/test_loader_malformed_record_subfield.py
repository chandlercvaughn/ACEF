"""Per-record SUB-FIELD type-confusion robustness for ``acef.load()``.

Structural-review P2 (``src/acef/models/records.py`` ``dict_to_record_envelope``).
The sibling fix (``test_loader_nonobject_jsonl_record.py``) hardened the case
where a JSONL line is NOT a JSON object at all. This file pins the next layer:
a line that IS a valid JSON object but carries a WRONG-TYPED sub-field.

``dict_to_record_envelope`` previously used the sub-fields without guarding
their types:

* ``entity_refs_data = data.get("entity_refs", {}) or {}`` — the ``or {}`` only
  rescues FALSY values; a TRUTHY non-dict (``[1, 2]``, ``"x"``, ``5``) passes
  through, then ``entity_refs_data.get("subject_refs", [])`` raises a raw
  ``AttributeError: 'list' object has no attribute 'get'``.
* ``for att_data in data.get("attachments", [])`` — a non-list ``attachments``
  (``5``) raises ``TypeError: 'int' object is not iterable``; a list whose
  element is a non-dict (``[5]``) raises ``TypeError: ...AttachmentRef()
  argument after ** must be a mapping, not int``.
* ``if data.get("attestation"): Attestation(**data["attestation"])`` — a truthy
  non-dict ``attestation`` (``"x"``) raises ``TypeError: ...Attestation()
  argument after ** must be a mapping, not str``.

``acef.load()`` is a documented PUBLIC deserialization API consuming
attacker-controlled bytes, so each malformed sub-field MUST surface a structured
``ACEFFormatError`` (ACEF-050, the same code the loader and validation engine use
for malformed structure) naming the offending field + record — never a leaked raw
``AttributeError`` / ``TypeError``.

These tests pin that contract for BOTH directory and ``.acef.tar.gz`` archive
inputs, confirm CONVERGENCE with ``validate_bundle`` (which routes the same
malformed line through ``dict_to_record_envelope`` and now records a clean
ACEF-050-backed diagnostic instead of a raw-exception backstop), and keep a
well-formed control (including a vendor ``x-`` extension ref key inside
``entity_refs``) loading cleanly so the fix does not over-reject.
"""

from __future__ import annotations

import json
import shutil
import tarfile
from pathlib import Path
from typing import Any

import pytest

import acef
from acef.errors import ACEFError, ACEFFormatError
from acef.validation.engine import validate_bundle

_GOLDEN = Path(__file__).resolve().parents[1] / "conformance" / "golden-bundles" / "eu-high-risk-core"


# The four malformed-sub-field cases. ``field`` is the corrupted envelope
# sub-field; ``value`` is the wrong-typed value; ``needle`` is a substring the
# structured ACEF-050 message must contain so it names the offending field.
_MALFORMED_SUBFIELDS = [
    pytest.param("entity_refs", [1, 2], "entity_refs", id="entity_refs-list"),
    pytest.param("attachments", 5, "attachments", id="attachments-int"),
    pytest.param("attestation", "x", "attestation", id="attestation-str"),
    pytest.param("attachments", [5], "attachments", id="attachments-nondict-element"),
]


def _copy_golden(dest: Path) -> Path:
    """Copy the (frozen) golden bundle to ``dest`` so the original stays
    byte-unchanged; the copy is what we tamper."""
    shutil.copytree(_GOLDEN, dest)
    return dest


def _tamper_first_record_file(bundle: Path, field: str, value: Any) -> Path:
    """Append a VALID JSON object record whose ``field`` sub-field is wrong-typed.

    The injected record is a real ``data_provenance`` record (so it passes the
    top-level object check and the manifest record_type cross-check) with a
    single sub-field corrupted. It is appended to ``data_provenance.jsonl`` so
    the manifest's declared record_type still matches.
    """
    target = bundle / "records" / "data_provenance.jsonl"
    assert target.exists(), "golden bundle must ship records/data_provenance.jsonl"
    base = json.loads(target.read_text(encoding="utf-8").splitlines()[0])
    base[field] = value
    # Give the injected record a distinct id so it is unambiguously the bad line.
    base["record_id"] = "urn:acef:rec:00000000-0000-4000-8000-000000000001"
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(base) + "\n")
    return target


def _make_archive(bundle_dir: Path, archive_path: Path) -> Path:
    """Pack ``bundle_dir`` into a ``.acef.tar.gz`` nested under a single root
    directory (the canonical archive layout the loader resolves)."""
    with tarfile.open(str(archive_path), "w:gz") as tar:
        tar.add(str(bundle_dir), arcname=bundle_dir.name)
    return archive_path


# ---------------------------------------------------------------------------
# RED: a wrong-typed record sub-field must surface structured ACEF-050, never a
# raw AttributeError / TypeError — directory input.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("field", "value", "needle"), _MALFORMED_SUBFIELDS)
def test_directory_malformed_subfield_raises_acef_050(tmp_path: Path, field: str, value: Any, needle: str) -> None:
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper_first_record_file(bundle, field, value)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    # Must be the structured format error — NOT a raw AttributeError / TypeError.
    assert isinstance(exc.value, ACEFFormatError)
    assert exc.value.code == "ACEF-050"
    # The message names the offending field (and the record it came from).
    assert needle in exc.value.message
    assert "urn:acef:rec:00000000-0000-4000-8000-000000000001" in exc.value.message


# ---------------------------------------------------------------------------
# RED: same guarantee for .acef.tar.gz archive input — both ingestion entry
# points (directory AND archive) converge through _load_directory.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("field", "value", "needle"), _MALFORMED_SUBFIELDS)
def test_archive_malformed_subfield_raises_acef_050(tmp_path: Path, field: str, value: Any, needle: str) -> None:
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper_first_record_file(bundle, field, value)
    archive = _make_archive(bundle, tmp_path / "tampered.acef.tar.gz")

    with pytest.raises(ACEFError) as exc:
        acef.load(str(archive))

    assert isinstance(exc.value, ACEFFormatError)
    assert exc.value.code == "ACEF-050"
    assert needle in exc.value.message


# ---------------------------------------------------------------------------
# No raw exception type ever escapes load() for these inputs (defence in depth:
# AttributeError / TypeError are NOT subclasses of ACEFError).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("field", "value", "needle"), _MALFORMED_SUBFIELDS)
def test_load_does_not_leak_raw_attribute_or_type_error(tmp_path: Path, field: str, value: Any, needle: str) -> None:
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper_first_record_file(bundle, field, value)

    try:
        acef.load(str(bundle))
    except ACEFFormatError:
        pass  # the structured, expected outcome
    except (AttributeError, TypeError) as exc:  # pragma: no cover - regression guard
        pytest.fail(f"load() leaked a raw {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Convergence: validate_bundle records an ACEF-050-backed diagnostic on the SAME
# tampered bundle, so load() and validate() do not diverge on the identical
# malicious input. (The engine catches the ACEFFormatError raised by
# dict_to_record_envelope and emits an ACEF-004 diagnostic that quotes the
# underlying ACEF-050 message.)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("field", "value", "needle"), _MALFORMED_SUBFIELDS)
def test_validate_bundle_reports_diagnostic_on_same_tampered_bundle(
    tmp_path: Path, field: str, value: Any, needle: str
) -> None:
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper_first_record_file(bundle, field, value)

    assessment = validate_bundle(str(bundle))

    errors = assessment.structural_errors
    # The engine must surface a structured diagnostic (never crash) and the
    # diagnostic must quote the ACEF-050 message that named the offending field.
    matching = [d for d in errors if "ACEF-050" in d["message"] and needle in d["message"]]
    assert matching, (
        f"validate must emit a diagnostic quoting ACEF-050 for the malformed "
        f"{needle!r} sub-field; got {[d['code'] + ':' + d['message'] for d in errors]}"
    )


# ---------------------------------------------------------------------------
# GREEN guards: well-formed records still load cleanly (no over-rejection),
# including a vendor ``x-`` extension ref key inside entity_refs — the
# ``**`` passthrough must keep working for a well-formed dict.
# ---------------------------------------------------------------------------


def test_untampered_golden_bundle_still_loads(tmp_path: Path) -> None:
    bundle = _copy_golden(tmp_path / "bundle")
    pkg = acef.load(str(bundle))
    assert pkg.records, "untampered golden bundle must load with records"


def test_vendor_extension_entity_ref_key_still_passes_through() -> None:
    """A well-formed entity_refs dict carrying a vendor ``x-`` extension key
    must still construct and round-trip the extension ref losslessly."""
    from acef.models.records import dict_to_record_envelope

    data: dict[str, Any] = {
        "record_id": "urn:acef:rec:00000000-0000-4000-8000-000000000002",
        "record_type": "data_provenance",
        "timestamp": "2026-03-01T10:00:00Z",
        "payload": {},
        "entity_refs": {
            "subject_refs": ["urn:acef:sub:00000000-0000-4000-8000-000000000abc"],
            "x-vendor-custom-refs": ["urn:vendor:thing:1"],
        },
    }

    env = dict_to_record_envelope(data)

    # The known ref survived.
    assert env.entity_refs.subject_refs == ["urn:acef:sub:00000000-0000-4000-8000-000000000abc"]
    # The vendor extension key survived the ** passthrough.
    dumped = env.entity_refs.model_dump()
    assert dumped.get("x-vendor-custom-refs") == ["urn:vendor:thing:1"]


def test_absent_subfields_default_cleanly() -> None:
    """A record that simply OMITS entity_refs / attachments / attestation must
    still construct (absent != malformed)."""
    from acef.models.records import dict_to_record_envelope

    data: dict[str, Any] = {
        "record_id": "urn:acef:rec:00000000-0000-4000-8000-000000000003",
        "record_type": "data_provenance",
        "timestamp": "2026-03-01T10:00:00Z",
        "payload": {},
    }

    env = dict_to_record_envelope(data)

    assert env.entity_refs.subject_refs == []
    assert env.attachments == []
    assert env.attestation is None
