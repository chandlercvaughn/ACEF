"""Comprehensive ``dict_to_record_envelope`` hardening for ``acef.load()``.

Structural-review P2, round 3. The two prior files pinned the entity_refs /
attachments / attestation CONTAINER-type guards
(``test_loader_malformed_record_subfield.py``, commit ``c881ad11``) and the
falsy-attestation drop + nested-``ValidationError`` leak
(``test_loader_malformed_record_subfield_nested.py``, commit ``98536373``).
roborev (codex xhigh) on ``98536373`` found the SAME class of gap still open in
the two nested fields the prior rounds did NOT touch — ``retention`` and
``collector`` — plus the attestation REQUIRED-KEY fabrication. This file pins the
remaining surface RED-first so the next review round finds nothing.

The empirically-observed pre-fix defects (captured on commit ``98536373``):

GAP A — present attestation OBJECT missing schema-required keys is ACCEPTED and
        re-exported with FABRICATED signature material
    ``Attestation`` supplies defaults for every field
    (``signer=""``, ``signed_fields=["/payload"]``, ``signature=""``). A present
    ``attestation: {}`` or ``attestation: {"method": "jws"}`` LOADED and
    re-exported as::

        {'method': 'jws', 'signer': '', 'signed_fields': ['/payload'], 'signature': ''}

    i.e. ``acef.load()`` FABRICATED signer / signed_fields / signature material the
    wire bytes never carried. The record-envelope schema declares attestation
    ``required: [method, signer, signed_fields, signature]`` — a present
    attestation object MUST carry all four. Fabricating signature material on load
    is a correctness + round-trip defect. Fix: a present attestation DICT missing
    any required key raises ``ACEF-050`` (no fabrication).

GAP B — retention is NOT covered (raw leak + truthiness drop)
    ``retention`` used a truthiness guard (``if data.get("retention"):``) and an
    UNWRAPPED ``RecordRetention(**data["retention"])``:
      * ``retention: {"min_retention_days": -1}`` raised a raw
        ``pydantic_core._pydantic_core.ValidationError`` straight out of load().
      * ``retention: "bad"`` (truthy non-dict) raised a raw
        ``TypeError: ...RecordRetention() argument after ** must be a mapping, not str``.
      * ``retention: []`` (falsy non-dict) was SILENTLY DROPPED to ``None``.
      * ``retention: {}`` (falsy empty dict) was SILENTLY DROPPED to ``None``
        instead of raising (the model requires ``min_retention_days``).
    Fix: present + non-None retention MUST be a dict (else ACEF-050); construction
    is wrapped so a ValidationError/TypeError becomes ACEF-050; absent / null
    defaults to ``None``.

GAP C — collector wrong-type / falsy is silently dropped + raw leak
    ``collector`` accepted only ``dict`` (→ ``CollectorInfo``) or ``str`` and
    silently dropped everything else to ``None`` (``collector: []`` / ``5`` /
    ``false`` LOADED with collector = None). And ``collector: {}`` (missing the
    schema-required ``name``) raised a raw
    ``pydantic_core._pydantic_core.ValidationError``. The record-envelope schema
    declares collector ``oneOf [object, string]`` — the string form is legitimate
    and MUST round-trip verbatim, but a present, non-None, non-(dict|str) value is
    malformed. Fix: present + non-None collector MUST be a dict OR str (else
    ACEF-050); the dict branch is wrapped (CollectorInfo ValidationError →
    ACEF-050); the string branch (including ``""``) round-trips verbatim; absent /
    null defaults to ``None``.

After this round ``acef.load()`` NEVER, for ANY of the five nested fields
(entity_refs, attachments, attestation, retention, collector):
  * leaks a raw ``pydantic.ValidationError`` / ``TypeError`` / ``AttributeError``;
  * silently DROPS a present, non-null, malformed (incl. falsy) value;
  * FABRICATES a schema-required attestation field the wire never carried.

Validate-path no-regression
    ``engine.py`` routes the identical line through ``dict_to_record_envelope``
    inside an ``except ACEFFormatError`` / ``except Exception`` backstop, so
    validate NEVER aborts. These tests assert validate keeps emitting a useful
    per-record ACEF-004 diagnostic that quotes the ACEF-050 reason (equal-or-better
    precision: the silently-dropped cases gain a diagnostic; the raw-leak cases
    keep their ACEF-004 but now quote a structured ACEF-050 instead of a raw
    pydantic message).
"""

from __future__ import annotations

import json
import shutil
import tarfile
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import acef
from acef.errors import ACEFError, ACEFFormatError
from acef.models.records import dict_to_record_envelope
from acef.validation.engine import validate_bundle

_GOLDEN = Path(__file__).resolve().parents[1] / "conformance" / "golden-bundles" / "eu-high-risk-core"

_INJECTED_ID = "urn:acef:rec:00000000-0000-4000-8000-0000000000c3"


def _base(**extra: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "record_id": _INJECTED_ID,
        "record_type": "data_provenance",
        "timestamp": "2026-03-01T10:00:00Z",
        "payload": {},
    }
    data.update(extra)
    return data


def _copy_golden(dest: Path) -> Path:
    """Copy the (frozen) golden bundle so the original stays byte-unchanged."""
    shutil.copytree(_GOLDEN, dest)
    return dest


def _tamper(bundle: Path, field: str, value: Any) -> Path:
    """Append a valid ``data_provenance`` record with ``field`` corrupted."""
    target = bundle / "records" / "data_provenance.jsonl"
    assert target.exists(), "golden bundle must ship records/data_provenance.jsonl"
    base = json.loads(target.read_text(encoding="utf-8").splitlines()[0])
    base[field] = value
    base["record_id"] = _INJECTED_ID
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(base) + "\n")
    return target


def _make_archive(bundle_dir: Path, archive_path: Path) -> Path:
    with tarfile.open(str(archive_path), "w:gz") as tar:
        tar.add(str(bundle_dir), arcname=bundle_dir.name)
    return archive_path


# ===========================================================================
# The full matrix: (field, value, needle, id). Each row is a present, non-null
# value that pre-fix either leaked a raw exception, was silently dropped, or
# fabricated schema-required material — and that post-fix MUST raise ACEF-050.
# ===========================================================================

_MALFORMED = [
    # --- entity_refs (covered prior rounds; re-pinned for the uniform path) ---
    pytest.param("entity_refs", [1, 2], "entity_refs", id="entity_refs-wrong-container-list"),
    pytest.param("entity_refs", "x", "entity_refs", id="entity_refs-wrong-container-str"),
    pytest.param("entity_refs", {"subject_refs": 5}, "entity_refs", id="entity_refs-subject_refs-not-list"),
    # --- attachments (covered prior rounds; re-pinned) ---
    pytest.param("attachments", 5, "attachments", id="attachments-wrong-container-int"),
    pytest.param("attachments", {"path": "a"}, "attachments", id="attachments-wrong-container-dict"),
    pytest.param("attachments", [5], "attachments", id="attachments-element-not-dict"),
    pytest.param("attachments", [{}], "attachments", id="attachments-missing-path"),
    # --- attestation: required-key fabrication (GAP A) + falsy + dict-invalid ---
    pytest.param("attestation", {}, "attestation", id="attestation-empty-dict-fabrication"),
    pytest.param("attestation", {"method": "jws"}, "attestation", id="attestation-method-only-fabrication"),
    pytest.param(
        "attestation",
        {"method": "jws", "signer": "s", "signed_fields": ["/payload"]},
        "attestation",
        id="attestation-missing-signature",
    ),
    pytest.param(
        "attestation",
        {"signer": "s", "signed_fields": ["/payload"], "signature": "x"},
        "attestation",
        id="attestation-missing-method",
    ),
    pytest.param("attestation", [], "attestation", id="attestation-falsy-list"),
    pytest.param("attestation", False, "attestation", id="attestation-falsy-false"),
    pytest.param("attestation", 0, "attestation", id="attestation-falsy-zero"),
    pytest.param("attestation", "", "attestation", id="attestation-falsy-empty-str"),
    pytest.param("attestation", "x", "attestation", id="attestation-wrong-container-str"),
    pytest.param(
        "attestation",
        {"method": "jws", "signer": "s", "signed_fields": 5, "signature": "x"},
        "attestation",
        id="attestation-signed_fields-not-list",
    ),
    # --- retention (GAP B) ---
    pytest.param("retention", [], "retention", id="retention-falsy-list"),
    pytest.param("retention", False, "retention", id="retention-falsy-false"),
    pytest.param("retention", 0, "retention", id="retention-falsy-zero"),
    pytest.param("retention", "", "retention", id="retention-falsy-empty-str"),
    pytest.param("retention", "bad", "retention", id="retention-truthy-str"),
    pytest.param("retention", 5, "retention", id="retention-truthy-int"),
    pytest.param("retention", {}, "retention", id="retention-empty-dict-missing-required"),
    pytest.param("retention", {"min_retention_days": -1}, "retention", id="retention-negative-days"),
    pytest.param(
        "retention",
        {"min_retention_days": "lots"},
        "retention",
        id="retention-days-not-int",
    ),
    # --- collector (GAP C) ---
    pytest.param("collector", [], "collector", id="collector-falsy-list"),
    pytest.param("collector", False, "collector", id="collector-falsy-false"),
    pytest.param("collector", 0, "collector", id="collector-falsy-zero"),
    pytest.param("collector", 5, "collector", id="collector-truthy-int"),
    pytest.param("collector", {}, "collector", id="collector-empty-dict-missing-name"),
    pytest.param("collector", {"version": "1.0"}, "collector", id="collector-missing-name"),
]


@pytest.mark.parametrize(("field", "value", "needle"), _MALFORMED)
def test_malformed_subfield_raises_acef_050_unit(field: str, value: Any, needle: str) -> None:
    """Every present, non-null, malformed nested value raises structured
    ACEF-050 from ``dict_to_record_envelope`` — never a raw exception, never a
    silent drop, never fabricated material."""
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(_base(**{field: value}))

    assert exc.value.code == "ACEF-050"
    assert needle in exc.value.message
    assert _INJECTED_ID in exc.value.message


@pytest.mark.parametrize(("field", "value", "needle"), _MALFORMED)
def test_directory_malformed_subfield_raises_acef_050(tmp_path: Path, field: str, value: Any, needle: str) -> None:
    """End-to-end: ``acef.load()`` on a directory bundle surfaces ACEF-050."""
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper(bundle, field, value)

    with pytest.raises(ACEFError) as exc:
        acef.load(str(bundle))

    assert isinstance(exc.value, ACEFFormatError)
    assert exc.value.code == "ACEF-050"
    assert needle in exc.value.message
    assert _INJECTED_ID in exc.value.message


@pytest.mark.parametrize(("field", "value", "needle"), _MALFORMED)
def test_archive_malformed_subfield_raises_acef_050(tmp_path: Path, field: str, value: Any, needle: str) -> None:
    """Same guarantee for ``.acef.tar.gz`` archive input."""
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper(bundle, field, value)
    archive = _make_archive(bundle, tmp_path / "tampered.acef.tar.gz")

    with pytest.raises(ACEFError) as exc:
        acef.load(str(archive))

    assert isinstance(exc.value, ACEFFormatError)
    assert exc.value.code == "ACEF-050"
    assert needle in exc.value.message


@pytest.mark.parametrize(("field", "value", "needle"), _MALFORMED)
def test_load_never_leaks_raw_exception(tmp_path: Path, field: str, value: Any, needle: str) -> None:
    """Defence in depth: no raw ValidationError / TypeError / AttributeError ever
    escapes ``acef.load()`` for ANY of the five nested fields."""
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper(bundle, field, value)

    try:
        acef.load(str(bundle))
    except ACEFFormatError:
        pass  # the structured, expected outcome
    except (ValidationError, AttributeError, TypeError) as exc:  # pragma: no cover - regression guard
        pytest.fail(f"load() leaked a raw {type(exc).__name__} for field {field!r}: {exc}")
    else:  # pragma: no cover - regression guard
        pytest.fail(f"load() accepted a malformed {field!r} value {value!r} (silent drop / fabrication)")


# ===========================================================================
# Attestation no-fabrication: a present attestation that omits a required key
# must NOT round-trip with a fabricated value.
# ===========================================================================


@pytest.mark.parametrize(
    "attestation",
    [
        pytest.param({}, id="empty"),
        pytest.param({"method": "jws"}, id="method-only"),
        pytest.param({"signer": "s", "signed_fields": ["/payload"], "signature": "x"}, id="no-method"),
        pytest.param({"method": "jws", "signed_fields": ["/payload"], "signature": "x"}, id="no-signer"),
    ],
)
def test_incomplete_attestation_does_not_fabricate_and_reexport(attestation: dict[str, Any]) -> None:
    """A present attestation object missing a schema-required field must raise
    ACEF-050 rather than load + re-export FABRICATED signer/signed_fields/
    signature material (the GAP A defect)."""
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(_base(attestation=attestation))
    assert exc.value.code == "ACEF-050"
    assert "attestation" in exc.value.message


def test_complete_attestation_constructs() -> None:
    """A fully-specified attestation object still constructs the model."""
    env = dict_to_record_envelope(
        _base(
            attestation={
                "method": "jws",
                "signer": "urn:acef:actor:signer",
                "signed_fields": ["/payload"],
                "signature": "sig",
            }
        )
    )
    assert env.attestation is not None
    assert env.attestation.signer == "urn:acef:actor:signer"
    assert env.attestation.signature == "sig"


# ===========================================================================
# Valid / control cases — the uniform guard must NOT over-reject.
# ===========================================================================


def test_absent_nested_fields_default_cleanly() -> None:
    """Absent retention / collector / attestation default to None; absent
    entity_refs / attachments default to empty containers."""
    env = dict_to_record_envelope(_base())
    assert env.attestation is None
    assert env.retention is None
    assert env.collector is None
    assert env.entity_refs.subject_refs == []
    assert env.attachments == []


@pytest.mark.parametrize("field", ["attestation", "retention", "collector"])
def test_explicit_null_nested_field_yields_none(field: str) -> None:
    """An explicit ``null`` on a oneOf[..., null]-shaped field yields None."""
    env = dict_to_record_envelope(_base(**{field: None}))
    assert getattr(env, field) is None


def test_valid_retention_constructs() -> None:
    env = dict_to_record_envelope(
        _base(retention={"min_retention_days": 180, "retention_start_event": "record_creation"})
    )
    assert env.retention is not None
    assert env.retention.min_retention_days == 180


def test_valid_collector_object_constructs() -> None:
    env = dict_to_record_envelope(_base(collector={"name": "acef-cli", "version": "1.0"}))
    assert isinstance(env.collector, type(env.collector))
    assert env.collector is not None
    assert env.collector.name == "acef-cli"  # type: ignore[union-attr]


def test_collector_string_form_roundtrips_verbatim() -> None:
    """The oneOf string form (incl. empty string) MUST round-trip as a bare str,
    never reshaped into a CollectorInfo object (§6.4 lossless export)."""
    env = dict_to_record_envelope(_base(collector="alice@example.com"))
    assert env.collector == "alice@example.com"
    assert isinstance(env.collector, str)


def test_collector_empty_string_form_preserved() -> None:
    """``collector: ""`` is a valid no-minLength wire shape; preserve verbatim."""
    env = dict_to_record_envelope(_base(collector=""))
    assert env.collector == ""
    assert isinstance(env.collector, str)


def test_vendor_extension_keys_still_pass_through() -> None:
    """A well-formed record with vendor ``x-`` extension keys (top-level and
    inside entity_refs) still loads cleanly — the guard does not over-reject."""
    env = dict_to_record_envelope(
        _base(
            **{
                "x-vendor-flag": "yes",
                "entity_refs": {"subject_refs": [], "x-vendor-rel": ["a"]},
            }
        )
    )
    assert env.entity_refs.subject_refs == []
    dumped = env.model_dump(mode="json")
    assert dumped.get("x-vendor-flag") == "yes"


def test_untampered_golden_loads_clean(tmp_path: Path) -> None:
    """The untampered golden bundle still loads without a spurious ACEF-050."""
    bundle = _copy_golden(tmp_path / "bundle")
    pkg = acef.load(str(bundle))
    assert pkg is not None


# ===========================================================================
# Validate-path no-regression: validate_bundle must NOT abort and must keep
# emitting a useful per-record ACEF-004 diagnostic quoting the ACEF-050 reason.
# ===========================================================================

_VALIDATE_CASES = [
    pytest.param("attestation", {}, id="v-attestation-empty-fabrication"),
    pytest.param("attestation", {"method": "jws"}, id="v-attestation-method-only"),
    pytest.param("retention", {"min_retention_days": -1}, id="v-retention-negative"),
    pytest.param("retention", [], id="v-retention-falsy-list"),
    pytest.param("retention", "bad", id="v-retention-truthy-str"),
    pytest.param("collector", {}, id="v-collector-missing-name"),
    pytest.param("collector", 5, id="v-collector-truthy-int"),
    pytest.param("collector", [], id="v-collector-falsy-list"),
]


@pytest.mark.parametrize(("field", "value"), _VALIDATE_CASES)
def test_validate_bundle_does_not_abort_and_reports_diagnostic(tmp_path: Path, field: str, value: Any) -> None:
    """validate_bundle must (a) not abort and (b) surface a per-record ACEF-004
    diagnostic quoting the ACEF-050 reason naming the offending field — strict
    precision improvement for the silently-dropped cases."""
    bundle = _copy_golden(tmp_path / "bundle")
    _tamper(bundle, field, value)

    assessment = validate_bundle(str(bundle))

    errors = assessment.structural_errors
    matching = [d for d in errors if d["code"] == "ACEF-004" and "ACEF-050" in d["message"] and field in d["message"]]
    assert matching, (
        f"validate must emit an ACEF-004 diagnostic quoting ACEF-050 for the "
        f"malformed {field!r} sub-field; got "
        f"{[d['code'] + ':' + d['message'][:80] for d in errors]}"
    )


def test_validate_bundle_untampered_golden_has_no_subfield_diagnostic(tmp_path: Path) -> None:
    """Control: the untampered golden must NOT gain a spurious ACEF-050."""
    bundle = _copy_golden(tmp_path / "bundle")
    assessment = validate_bundle(str(bundle))
    spurious = [d for d in assessment.structural_errors if "ACEF-050" in d["message"]]
    assert not spurious, f"untampered golden must not raise ACEF-050; got {spurious}"
