"""Second-layer ``dict_to_record_envelope`` hardening for ``acef.load()``.

Structural-review P2 follow-up. The sibling file
(``test_loader_malformed_record_subfield.py``, commit ``c881ad11``) pinned the
CONTAINER-type guards: a wrong-typed *container* sub-field (``entity_refs: [1, 2]``,
``attachments: 5``, ``attestation: "x"``) surfaces a structured ``ACEF-050`` instead
of a raw ``AttributeError`` / ``TypeError``. roborev (codex xhigh) on ``c881ad11``
found two MORE gaps that this file pins RED-first:

Medium 1 — falsy malformed attestation silently dropped
    ``dict_to_record_envelope`` guarded attestation with a TRUTHINESS check
    (``if data.get("attestation"): ...``). A PRESENT, non-null, FALSY value —
    ``attestation: []`` / ``false`` / ``0`` / ``""`` — is falsy, so it was treated
    as ABSENT and SILENTLY DROPPED: ``load()`` succeeded with ``attestation = None``,
    even though the record-envelope schema permits attestation as ONLY an object
    (``oneOf[object, null]``) or ``null``. That is both a data-loss / round-trip
    defect (the wire bytes carried a value that vanished) and a missed rejection.
    Pre-fix (empirically): ``acef.load()`` on a record with ``attestation: []``
    SUCCEEDED, attestation = None  (SILENTLY DROPPED) — same for ``false``/``0``/``""``.
    Fix: distinguish key-PRESENCE from ``None``. A present, non-None, non-dict
    attestation MUST raise ``ACEF-050``; only an ABSENT key or explicit ``null``
    yields ``attestation = None``.

Medium 2 — nested Pydantic ValidationError leaks from load()
    The nested model constructors (``EntityRefs(...)``, ``AttachmentRef(**att)``,
    ``Attestation(**att)``) ran OUTSIDE the function's structured-error wrapper
    (only the FINAL ``RecordEnvelope(**kwargs)`` was wrapped → ACEF-004). A
    DICT-SHAPED but schema-invalid sub-value leaked a raw
    ``pydantic_core._pydantic_core.ValidationError`` straight out of the PUBLIC
    ``acef.load()``:
      * ``attachments: [{}]``            -> ValidationError for AttachmentRef (missing 'path')
      * ``entity_refs: {"subject_refs": 5}`` -> ValidationError for EntityRefs (subject_refs not a list)
      * ``attestation: {"signed_fields": 5}``-> ValidationError for Attestation (signed_fields not a list)
    Fix: wrap the nested-model construction so ``pydantic.ValidationError`` (and
    ``TypeError``) re-raises as ``ACEFFormatError(code="ACEF-050", ...)`` naming the
    offending field + record_id. After this, ``acef.load()`` NEVER leaks a raw
    ``ValidationError`` / ``TypeError`` / ``AttributeError`` on a malformed record.

Validate-path no-regression
    ``engine.py`` routes the same malformed line through
    ``dict_to_record_envelope`` and already wraps the call in BOTH an
    ``except _ACEFFormatErr`` (→ ACEF-004 diagnostic) and an ``except Exception``
    (→ ACEF-004 diagnostic) backstop, so validate NEVER aborts on these inputs.
    Pre-fix the dict-shaped-invalid cases produced an ACEF-004 per-record diagnostic
    quoting the raw pydantic message; post-fix the SAME ACEF-004 diagnostic quotes
    the structured ACEF-050 message — same code, no precision loss, no abort. The
    falsy-attestation cases produced NO per-record diagnostic pre-fix (silently
    dropped); post-fix they gain a precise ACEF-004 (quoting ACEF-050) — a strict
    improvement, never a downgrade. These tests assert validate keeps reporting a
    useful per-record diagnostic and does not abort.
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
from acef.models.records import dict_to_record_envelope
from acef.validation.engine import validate_bundle

_GOLDEN = Path(__file__).resolve().parents[1] / "conformance" / "golden-bundles" / "eu-high-risk-core"

_INJECTED_ID = "urn:acef:rec:00000000-0000-4000-8000-000000000001"


def _copy_golden(dest: Path) -> Path:
    """Copy the (frozen) golden bundle to ``dest`` so the original stays
    byte-unchanged; the copy is what we tamper."""
    shutil.copytree(_GOLDEN, dest)
    return dest


def _tamper_first_record_file(bundle: Path, field: str, value: Any) -> Path:
    """Append a VALID JSON object record whose ``field`` sub-field is malformed.

    The injected record is a real ``data_provenance`` record (so it passes the
    top-level object check and the manifest record_type cross-check) with a
    single sub-field corrupted, appended to ``data_provenance.jsonl`` so the
    manifest's declared record_type still matches.
    """
    target = bundle / "records" / "data_provenance.jsonl"
    assert target.exists(), "golden bundle must ship records/data_provenance.jsonl"
    base = json.loads(target.read_text(encoding="utf-8").splitlines()[0])
    base[field] = value
    base["record_id"] = _INJECTED_ID
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(base) + "\n")
    return target


def _make_archive(bundle_dir: Path, archive_path: Path) -> Path:
    """Pack ``bundle_dir`` into a ``.acef.tar.gz`` nested under a single root
    directory (the canonical archive layout the loader resolves)."""
    with tarfile.open(str(archive_path), "w:gz") as tar:
        tar.add(str(bundle_dir), arcname=bundle_dir.name)
    return archive_path


# ===========================================================================
# Medium 1 — present, non-null, FALSY attestation must RAISE (not be dropped).
# ===========================================================================

# Each value is PRESENT (key in dict), non-null, and FALSY — pre-fix each was
# silently dropped because the guard was truthiness-based.
_FALSY_ATTESTATIONS = [
    pytest.param([], id="attestation-empty-list"),
    pytest.param(False, id="attestation-false"),
    pytest.param(0, id="attestation-zero"),
    pytest.param("", id="attestation-empty-str"),
]


@pytest.mark.parametrize("value", _FALSY_ATTESTATIONS)
def test_falsy_attestation_raises_acef_050_unit(value: Any) -> None:
    """A present, non-None, FALSY, non-dict attestation must raise ACEF-050
    rather than being silently coerced to ``None`` (pre-fix: dropped)."""
    data: dict[str, Any] = {
        "record_id": _INJECTED_ID,
        "record_type": "data_provenance",
        "timestamp": "2026-03-01T10:00:00Z",
        "payload": {},
        "attestation": value,
    }

    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(data)

    assert exc.value.code == "ACEF-050"
    assert "attestation" in exc.value.message
    assert _INJECTED_ID in exc.value.message


@pytest.mark.parametrize("value", _FALSY_ATTESTATIONS)
def test_directory_falsy_attestation_raises_acef_050(tmp_path: Path, value: Any) -> None:
    """End-to-end: ``acef.load()`` on a directory bundle whose record carries a
    falsy, non-null attestation must raise structured ACEF-050 — NOT load with
    attestation silently dropped to None."""
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper_first_record_file(bundle, "attestation", value)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFFormatError)
    assert exc.value.code == "ACEF-050"
    assert "attestation" in exc.value.message
    assert _INJECTED_ID in exc.value.message


@pytest.mark.parametrize("value", _FALSY_ATTESTATIONS)
def test_archive_falsy_attestation_raises_acef_050(tmp_path: Path, value: Any) -> None:
    """Same guarantee for ``.acef.tar.gz`` archive input."""
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper_first_record_file(bundle, "attestation", value)
    archive = _make_archive(bundle, tmp_path / "tampered.acef.tar.gz")

    with pytest.raises(ACEFError) as exc:
        acef.load(str(archive))

    assert isinstance(exc.value, ACEFFormatError)
    assert exc.value.code == "ACEF-050"
    assert "attestation" in exc.value.message


def test_absent_attestation_key_yields_none() -> None:
    """An ABSENT attestation key must still default to None (absent != malformed)."""
    data: dict[str, Any] = {
        "record_id": _INJECTED_ID,
        "record_type": "data_provenance",
        "timestamp": "2026-03-01T10:00:00Z",
        "payload": {},
    }
    env = dict_to_record_envelope(data)
    assert env.attestation is None


def test_explicit_null_attestation_yields_none() -> None:
    """An explicit ``attestation: null`` must yield None (schema permits null)."""
    data: dict[str, Any] = {
        "record_id": _INJECTED_ID,
        "record_type": "data_provenance",
        "timestamp": "2026-03-01T10:00:00Z",
        "payload": {},
        "attestation": None,
    }
    env = dict_to_record_envelope(data)
    assert env.attestation is None


def test_valid_attestation_dict_still_constructs() -> None:
    """A valid attestation object must still construct the Attestation model."""
    data: dict[str, Any] = {
        "record_id": _INJECTED_ID,
        "record_type": "data_provenance",
        "timestamp": "2026-03-01T10:00:00Z",
        "payload": {},
        "attestation": {
            "method": "jws",
            "signer": "urn:acef:actor:signer",
            "signed_fields": ["/payload"],
            "signature": "sig",
        },
    }
    env = dict_to_record_envelope(data)
    assert env.attestation is not None
    assert env.attestation.signer == "urn:acef:actor:signer"


# ===========================================================================
# Medium 2 — dict-shaped but schema-invalid nested values must surface ACEF-050,
# never leak a raw pydantic.ValidationError from the public load().
# ===========================================================================

# ``field`` is the corrupted envelope sub-field; ``value`` is a DICT-SHAPED but
# schema-invalid value; ``needle`` is a substring the structured ACEF-050 message
# must contain so it names the offending field.
_NESTED_INVALID = [
    pytest.param("attachments", [{}], "attachments", id="attachments-missing-path"),
    pytest.param("entity_refs", {"subject_refs": 5}, "entity_refs", id="entity_refs-subject_refs-not-list"),
    pytest.param(
        "attestation",
        {"method": "jws", "signer": "s", "signed_fields": 5, "signature": "x"},
        "attestation",
        id="attestation-signed_fields-not-list",
    ),
]


@pytest.mark.parametrize(("field", "value", "needle"), _NESTED_INVALID)
def test_nested_invalid_raises_acef_050_unit(field: str, value: Any, needle: str) -> None:
    """A dict-shaped but schema-invalid nested value must raise structured
    ACEF-050 from ``dict_to_record_envelope`` — NOT a raw pydantic.ValidationError."""
    data: dict[str, Any] = {
        "record_id": _INJECTED_ID,
        "record_type": "data_provenance",
        "timestamp": "2026-03-01T10:00:00Z",
        "payload": {},
        field: value,
    }

    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(data)

    assert exc.value.code == "ACEF-050"
    assert needle in exc.value.message
    assert _INJECTED_ID in exc.value.message


@pytest.mark.parametrize(("field", "value", "needle"), _NESTED_INVALID)
def test_directory_nested_invalid_raises_acef_050(tmp_path: Path, field: str, value: Any, needle: str) -> None:
    """``acef.load()`` on a directory bundle must surface ACEF-050 for a
    dict-shaped-invalid nested value, never a raw pydantic.ValidationError."""
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper_first_record_file(bundle, field, value)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFFormatError)
    assert exc.value.code == "ACEF-050"
    assert needle in exc.value.message
    assert _INJECTED_ID in exc.value.message


@pytest.mark.parametrize(("field", "value", "needle"), _NESTED_INVALID)
def test_archive_nested_invalid_raises_acef_050(tmp_path: Path, field: str, value: Any, needle: str) -> None:
    """Same guarantee for ``.acef.tar.gz`` archive input."""
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper_first_record_file(bundle, field, value)
    archive = _make_archive(bundle, tmp_path / "tampered.acef.tar.gz")

    with pytest.raises(ACEFError) as exc:
        acef.load(str(archive))

    assert isinstance(exc.value, ACEFFormatError)
    assert exc.value.code == "ACEF-050"
    assert needle in exc.value.message


@pytest.mark.parametrize(("field", "value", "needle"), _NESTED_INVALID)
def test_load_does_not_leak_raw_pydantic_validation_error(tmp_path: Path, field: str, value: Any, needle: str) -> None:
    """Defence in depth: no raw pydantic.ValidationError (nor AttributeError /
    TypeError — none are ACEFError subclasses) ever escapes load() for these
    inputs."""
    from pydantic import ValidationError

    bundle = _copy_golden(tmp_path / "bundle")
    _tamper_first_record_file(bundle, field, value)

    try:
        acef.load(str(bundle))
    except ACEFFormatError:
        pass  # the structured, expected outcome
    except (ValidationError, AttributeError, TypeError) as exc:  # pragma: no cover - regression guard
        pytest.fail(f"load() leaked a raw {type(exc).__name__}: {exc}")


# ===========================================================================
# Validate-path no-regression: validate_bundle must NOT abort on these malformed
# records and must keep producing a useful per-record diagnostic (ACEF-004
# quoting the ACEF-050 reason) of equal-or-better precision.
# ===========================================================================

_VALIDATE_CASES = [
    pytest.param("attachments", [{}], id="v-attachments-missing-path"),
    pytest.param("entity_refs", {"subject_refs": 5}, id="v-entity_refs-subject_refs-not-list"),
    pytest.param(
        "attestation",
        {"method": "jws", "signer": "s", "signed_fields": 5, "signature": "x"},
        id="v-attestation-signed_fields-not-list",
    ),
    pytest.param("attestation", [], id="v-attestation-empty-list"),
    pytest.param("attestation", False, id="v-attestation-false"),
    pytest.param("attestation", 0, id="v-attestation-zero"),
    pytest.param("attestation", "", id="v-attestation-empty-str"),
]


@pytest.mark.parametrize(("field", "value"), _VALIDATE_CASES)
def test_validate_bundle_does_not_abort_and_reports_diagnostic(tmp_path: Path, field: str, value: Any) -> None:
    """validate_bundle must (a) NOT raise/abort and (b) surface a per-record
    ACEF-004 diagnostic that quotes the ACEF-050 reason naming the offending
    field — equal-or-better precision vs pre-fix (dict-shaped cases already had
    ACEF-004 quoting a raw pydantic message; falsy-attestation cases had NO
    per-record diagnostic at all and now gain one)."""
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper_first_record_file(bundle, field, value)

    # Must not abort.
    assessment = validate_bundle(str(bundle))

    errors = assessment.structural_errors
    matching = [d for d in errors if d["code"] == "ACEF-004" and "ACEF-050" in d["message"] and field in d["message"]]
    assert matching, (
        f"validate must emit an ACEF-004 diagnostic quoting ACEF-050 for the "
        f"malformed {field!r} sub-field; got "
        f"{[d['code'] + ':' + d['message'][:80] for d in errors]}"
    )


def test_validate_bundle_untampered_golden_has_no_subfield_diagnostic(tmp_path: Path) -> None:
    """Control: the untampered golden bundle must NOT gain a spurious ACEF-050
    diagnostic (the guards do not over-reject well-formed records)."""
    bundle = _copy_golden(tmp_path / "bundle")
    assessment = validate_bundle(str(bundle))
    spurious = [d for d in assessment.structural_errors if "ACEF-050" in d["message"]]
    assert not spurious, f"untampered golden must not raise ACEF-050; got {spurious}"
