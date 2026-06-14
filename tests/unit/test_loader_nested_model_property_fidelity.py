"""Nested load models are FAITHFUL TYPED MIRRORS of the frozen record-envelope
schema's per-PROPERTY shapes (types, enums, numeric bounds, nullability).

Structural-review P2, round 5. roborev (codex xhigh) on commit ``ab39abc7`` found
the ``RecordRetention`` model — and, by the same audit, the other nested load
models — still DIVERGED from the frozen
``acef-conventions/v1/record-envelope.schema.json`` (byte-identical to ``v1.1``
for these five fields) at the PROPERTY level, even though the round-4 fix aligned
the OUTER object shape (nullability + required-key set). Two property-level
divergence classes remained:

  1. SCHEMA ENUMS not mirrored as ``Literal``. The frozen schema constrains
     ``retention.retention_start_event`` to
     ``enum: ["first_use","first_deployment","record_creation","custom"]`` and
     ``attestation.method`` to ``const: "jws"``. The round-4 models typed these
     as bare ``str`` / defaulted ``str``, so a present ``retention_start_event:
     "bad"`` or ``attestation.method: "pgp"`` LOADED + round-tripped the invalid
     value verbatim — a structural divergence load() should reject (the offending
     value is not in the schema's permitted set for that property).

  2. PRESENT-NULL on a non-nullable PROPERTY accepted. The schema property TYPES
     are ``integer`` / ``string`` (NOT ``["integer","null"]`` / ``["string",
     "null"]``), so an explicit ``null`` VALUE on a present property is a type
     violation. Pydantic ``X | None = None`` (the round-4 typing used to permit
     ABSENCE) ALSO silently accepts a present explicit ``null``, collapsing the
     absent-vs-present-null distinction the loader already enforces for the
     nested OBJECTS themselves (collector/attestation). So
     ``retention: {"min_retention_days": null}`` / ``{"legal_basis": null}``,
     ``attachments: [{..., "hash": null}]`` LOADED — accepting a value the schema
     forbids for that property.

Authoritative per-PROPERTY contract, extracted directly from the FROZEN
``acef-conventions/v1/record-envelope.schema.json`` (``v1.1`` byte-identical for
these five fields — verified in-band by the maintainer):

  EntityRefs (object; required: [subject_refs])
    subject_refs    array<string>       (required)
    component_refs  array<string>       (optional)
    dataset_refs    array<string>       (optional)
    actor_refs      array<string>       (optional)

  AttachmentRef (array element; required: [path, media_type])
    path            string              (required)
    hash            string              (optional, NON-nullable)
    media_type      string              (required)
    attachment_type string              (optional, NON-nullable)
    description     string              (optional, NON-nullable)

  Attestation (object | null; object required: [method,signer,signed_fields,signature])
    method          const "jws"         (required)  <- enum-of-one
    signer          string              (required)
    signed_fields   array<string>       (required)
    signature       string              (required)

  RecordRetention (object | null; NO required keys)
    min_retention_days     integer, minimum 0   (optional, NON-nullable)
    retention_start_event  enum[first_use,first_deployment,record_creation,custom]
                                                 (optional, NON-nullable)
    legal_basis            string               (optional, NON-nullable)

  CollectorInfo (object | string; object required: [name])
    name            string              (required)
    version         string              (optional, NON-nullable)

LOAD-LENIENCY vs VALIDATE-ENFORCEMENT boundary (pinned by
``test_invalid_retention_object_surfaces_acef004_via_validate`` below): the LOAD
models reject STRUCTURAL/type/enum/required-key violations of the nested objects
(so ``load()`` never crashes, never fabricates, and round-trips faithfully);
FULL record-payload schema conformance is enforced separately by
``validate_bundle`` (ACEF-004). The loader is NOT expected to reimplement the
full validator — it rejects only what it dereferences/constructs.
"""

from __future__ import annotations

from typing import Any

import pytest

from acef.errors import ACEFFormatError
from acef.models.records import (
    AttachmentRef,
    Attestation,
    CollectorInfo,
    RecordRetention,
    dict_to_record_envelope,
)

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


# ===========================================================================
# RecordRetention.retention_start_event — schema ENUM, must be Literal.
#
# RED quote (pre-fix, commit ab39abc7):
#     retention={'retention_start_event': 'bad'}  -> LOADS, re-export
#         {'retention_start_event': 'bad'}        (invalid value preserved)
# ===========================================================================


def test_retention_start_event_bad_enum_rejected() -> None:
    """RED: ``retention_start_event`` is a schema ENUM
    (``[first_use, first_deployment, record_creation, custom]``). A value outside
    the set is a STRUCTURAL divergence and MUST raise ACEF-050.

    On ``ab39abc7`` this LOADED and re-exported ``{'retention_start_event':
    'bad'}`` verbatim because the model typed the field as a bare ``str``.
    """
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(_base(retention={"retention_start_event": "bad"}))
    assert exc.value.code == "ACEF-050"
    assert "retention" in exc.value.message
    assert _INJECTED_ID in exc.value.message


@pytest.mark.parametrize(
    "value",
    ["first_use", "first_deployment", "record_creation", "custom"],
)
def test_retention_start_event_each_enum_value_loads(value: str) -> None:
    """Every schema-permitted enum value LOADS and round-trips verbatim."""
    env = dict_to_record_envelope(_base(retention={"retention_start_event": value}))
    assert env.retention is not None
    assert env.retention.retention_start_event == value
    assert env.to_jsonl_dict()["retention"] == {"retention_start_event": value}


# ===========================================================================
# RecordRetention present-null on non-nullable properties -> ACEF-050.
#
# RED quote (pre-fix, commit ab39abc7):
#     retention={'min_retention_days': None}      -> LOADS (None), re-export {}
#     retention={'retention_start_event': None}   -> LOADS (None), re-export {}
#     retention={'legal_basis': None}             -> LOADS (None)
# (schema property types are integer / string — NOT nullable)
# ===========================================================================


@pytest.mark.parametrize(
    "field",
    ["min_retention_days", "retention_start_event", "legal_basis"],
)
def test_retention_present_null_property_rejected(field: str) -> None:
    """RED: the schema property TYPES are ``integer`` / ``string`` — NOT
    nullable. A PRESENT explicit ``null`` on a retention property is a type
    violation and MUST raise ACEF-050, distinct from ABSENCE (which defaults).

    On ``ab39abc7`` each of these LOADED to ``None`` (the ``X | None = None``
    typing silently accepted the present null), re-exporting ``{}`` and thereby
    treating an explicit-null wire value as if the key were absent — a structural
    divergence from the schema's non-nullable property type.
    """
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(_base(retention={field: None}))
    assert exc.value.code == "ACEF-050"
    assert "retention" in exc.value.message
    assert _INJECTED_ID in exc.value.message


def test_retention_empty_object_still_loads() -> None:
    """Control (round-4 behaviour preserved): an ABSENT key is fine. A wholly
    empty ``retention: {}`` (NO keys present) loads — the schema declares no
    required keys — and round-trips as ``{}``."""
    env = dict_to_record_envelope(_base(retention={}))
    assert env.retention is not None
    assert env.retention.min_retention_days is None
    assert env.retention.retention_start_event is None
    assert env.retention.legal_basis is None
    assert env.to_jsonl_dict()["retention"] == {}


def test_retention_negative_min_days_still_rejected() -> None:
    """Control: ``min_retention_days: -1`` violates the schema ``minimum: 0``
    (model ``ge=0``) -> ACEF-050."""
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(_base(retention={"min_retention_days": -1}))
    assert exc.value.code == "ACEF-050"
    assert "retention" in exc.value.message


def test_retention_valid_full_object_round_trips() -> None:
    """Control: a fully-valid retention object round-trips verbatim."""
    src = {
        "min_retention_days": 180,
        "retention_start_event": "first_use",
        "legal_basis": "eu-ai-act-2024:article-12",
    }
    env = dict_to_record_envelope(_base(retention=src))
    assert env.to_jsonl_dict()["retention"] == src


def test_record_retention_model_rejects_present_null_directly() -> None:
    """The MODEL itself (not just the loader path) rejects present-null on a
    non-nullable property — proof the fidelity lives in the model, available to
    every constructor."""
    with pytest.raises(Exception):  # pydantic ValidationError  # noqa: B017,PT011
        RecordRetention(min_retention_days=None)  # type: ignore[arg-type]
    with pytest.raises(Exception):  # noqa: B017,PT011
        RecordRetention(retention_start_event=None)  # type: ignore[arg-type]
    with pytest.raises(Exception):  # noqa: B017,PT011
        RecordRetention(legal_basis=None)  # type: ignore[arg-type]
    # Absent (no args) still constructs.
    assert RecordRetention().min_retention_days is None


def test_record_retention_model_rejects_bad_enum_directly() -> None:
    """The MODEL rejects a bad ``retention_start_event`` enum value."""
    with pytest.raises(Exception):  # pydantic ValidationError  # noqa: B017,PT011
        RecordRetention(retention_start_event="bad")  # type: ignore[arg-type]


# ===========================================================================
# RecordRetention.min_retention_days — schema ``integer`` ⇒ STRICT int.
#
# Structural-review P2, round 6. roborev (codex xhigh) on commit ``d846875c``
# found ``min_retention_days`` still used Pydantic's DEFAULT (LAX) int handling,
# so a schema-invalid numeric STRING ``"180"`` LOADED as integer ``180`` — even
# though the frozen schema types the property as a JSON ``integer`` — and the
# coerced value re-exported, MUTATING the invalid wire data. The fix is
# ``pydantic.StrictInt`` (``StrictInt | None``) so a present non-int value
# (string / float / bool) is a type violation rejected at load (ACEF-050 via the
# nested-construction wrap), while a real JSON integer (keeping ``ge=0``) and an
# absent / empty ``retention: {}`` still load cleanly.
#
# RED quote (pre-fix, commit d846875c):
#     retention={'min_retention_days': '180'}  -> LOADS as int 180,
#         env.retention.min_retention_days == 180  (string coerced to int),
#         re-export {'min_retention_days': 180}    (invalid wire value MUTATED)
#     retention={'min_retention_days': True}   -> LOADS as int 1  (bool coerced)
# (float 1.5 already RAISED on d846875c — int-from-non-int-float is rejected —
#  but is asserted here to lock the behaviour against any future config change.)
# ===========================================================================


@pytest.mark.parametrize(
    ("bad_value", "label"),
    [
        ("180", "numeric string"),
        (1.5, "float"),
        (True, "bool true"),
        (False, "bool false"),
    ],
)
def test_retention_min_days_non_integer_rejected(bad_value: Any, label: str) -> None:
    """RED: ``min_retention_days`` is a schema ``integer``. A present non-integer
    value — a numeric STRING ``"180"``, a ``float`` ``1.5``, or a ``bool`` — is a
    TYPE violation and MUST raise ACEF-050, NOT silently coerce-and-mutate.

    On ``d846875c`` the string ``"180"`` LOADED as int ``180`` (re-exporting the
    MUTATED value ``{'min_retention_days': 180}``) and ``True`` LOADED as int
    ``1`` because the field used Pydantic's default lax int handling.
    """
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(_base(retention={"min_retention_days": bad_value}))
    assert exc.value.code == "ACEF-050", label
    assert "retention" in exc.value.message
    assert _INJECTED_ID in exc.value.message


def test_retention_min_days_valid_integer_loads_unmutated() -> None:
    """Control: a real JSON ``integer`` loads and round-trips verbatim (no
    coercion artifact)."""
    env = dict_to_record_envelope(_base(retention={"min_retention_days": 180}))
    assert env.retention is not None
    assert env.retention.min_retention_days == 180
    assert isinstance(env.retention.min_retention_days, int)
    assert env.to_jsonl_dict()["retention"] == {"min_retention_days": 180}


def test_retention_min_days_zero_loads() -> None:
    """Control: ``0`` is a valid integer at the ``ge=0`` boundary and loads."""
    env = dict_to_record_envelope(_base(retention={"min_retention_days": 0}))
    assert env.retention is not None
    assert env.retention.min_retention_days == 0


def test_record_retention_model_rejects_non_integer_min_days_directly() -> None:
    """The MODEL itself (not just the loader path) rejects a non-integer
    ``min_retention_days`` — proof the strict typing lives in the model, available
    to every constructor. ``ge=0`` and absent-defaulting are preserved."""
    for bad in ("180", 1.5, True, False):
        with pytest.raises(Exception):  # pydantic ValidationError  # noqa: B017,PT011
            RecordRetention(min_retention_days=bad)  # type: ignore[arg-type]
    # A real integer still constructs; absent still defaults to None.
    assert RecordRetention(min_retention_days=180).min_retention_days == 180
    assert RecordRetention().min_retention_days is None
    # ge=0 still enforced.
    with pytest.raises(Exception):  # noqa: B017,PT011
        RecordRetention(min_retention_days=-1)


# ===========================================================================
# Bounded scalar-coercion audit (round 6): ``min_retention_days`` is the ONLY
# non-string scalar across the five nested record-envelope models. The remaining
# scalar properties are all ``str`` (or ``Literal`` / ``list[str]``). Pydantic's
# default ``str`` typing already REJECTS a non-string input (it does NOT coerce
# an ``int`` to its decimal string), so no ``Strict*`` typing is needed on those
# fields. These tests PIN that audit conclusion: a non-string on a ``str``
# property must raise (never silently become ``"123"``).
# ===========================================================================


@pytest.mark.parametrize(
    "builder",
    [
        lambda: AttachmentRef(path=123),  # type: ignore[arg-type]
        lambda: AttachmentRef(path="p", media_type=123),  # type: ignore[arg-type]
        lambda: AttachmentRef(path="p", hash=123),  # type: ignore[arg-type]
        lambda: AttachmentRef(path="p", attachment_type=123),  # type: ignore[arg-type]
        lambda: CollectorInfo(name=123),  # type: ignore[arg-type]
        lambda: CollectorInfo(name="x", version=123),  # type: ignore[arg-type]
        lambda: Attestation(signer=123),  # type: ignore[arg-type]
        lambda: Attestation(signature=123),  # type: ignore[arg-type]
        lambda: RecordRetention(legal_basis=123),  # type: ignore[arg-type]
    ],
)
def test_nested_str_properties_reject_non_string_no_coercion(builder: Any) -> None:
    """Audit pin: every ``str`` property on the nested models REJECTS a non-string
    input rather than coercing it (e.g. ``123`` must NOT become ``"123"``).
    Confirms ``min_retention_days`` is the sole field that needed ``StrictInt``."""
    with pytest.raises(Exception):  # pydantic ValidationError  # noqa: B017,PT011
        builder()


# ===========================================================================
# Attestation.method — schema const "jws", must be Literal["jws"].
#
# RED quote (pre-fix, commit ab39abc7):
#     attestation={'method':'pgp', 'signer':'x',
#                  'signed_fields':['/payload'], 'signature':'sig'}
#         -> LOADS, env.attestation.method == 'pgp'   (invalid value preserved)
# ===========================================================================


def test_attestation_method_non_jws_rejected() -> None:
    """RED: the schema constrains ``attestation.method`` to ``const: "jws"``. A
    present complete attestation whose ``method`` is anything else is a
    STRUCTURAL divergence and MUST raise ACEF-050.

    On ``ab39abc7`` ``method: "pgp"`` LOADED and ``env.attestation.method ==
    'pgp'`` because the model typed it as a bare defaulted ``str``.
    """
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(
            _base(
                attestation={
                    "method": "pgp",
                    "signer": "urn:acef:actor:signer",
                    "signed_fields": ["/payload"],
                    "signature": "sig",
                }
            )
        )
    assert exc.value.code == "ACEF-050"
    assert "attestation" in exc.value.message


def test_attestation_method_jws_loads() -> None:
    """Control: the only schema-permitted ``method`` value loads + round-trips."""
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
    assert env.attestation.method == "jws"


def test_attestation_model_rejects_non_jws_method_directly() -> None:
    """The MODEL rejects a non-``jws`` method (Literal const)."""
    with pytest.raises(Exception):  # pydantic ValidationError  # noqa: B017,PT011
        Attestation(
            method="pgp",  # type: ignore[arg-type]
            signer="x",
            signed_fields=["/payload"],
            signature="sig",
        )


# ===========================================================================
# AttachmentRef present-null on non-nullable properties -> ACEF-050.
#
# RED quote (pre-fix, commit ab39abc7):
#     attachments=[{'path':'artifacts/x.pdf','media_type':'application/pdf',
#                   'hash': None}]
#         -> LOADS, env.attachments[0].hash is None   (present-null accepted)
# (schema hash/attachment_type/description property types are string — NOT null)
# ===========================================================================


@pytest.mark.parametrize("field", ["hash", "attachment_type", "description"])
def test_attachment_present_null_optional_property_rejected(field: str) -> None:
    """RED: the optional ``AttachmentRef`` string properties
    (hash/attachment_type/description) have schema type ``string`` — NOT
    nullable. A PRESENT explicit ``null`` is a type violation -> ACEF-050.

    On ``ab39abc7`` ``hash: null`` LOADED to ``None`` (the ``X | None = None``
    typing silently accepted it)."""
    att: dict[str, Any] = {
        "path": "artifacts/x.pdf",
        "media_type": "application/pdf",
        field: None,
    }
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(_base(attachments=[att]))
    assert exc.value.code == "ACEF-050"
    assert "attachments" in exc.value.message


def test_attachment_absent_optional_property_loads() -> None:
    """Control: ABSENT optional properties default cleanly and re-export only
    the present keys (no fabricated hash/attachment_type)."""
    env = dict_to_record_envelope(_base(attachments=[{"path": "artifacts/x.pdf", "media_type": "application/pdf"}]))
    assert len(env.attachments) == 1
    assert env.attachments[0].path == "artifacts/x.pdf"
    out = env.to_jsonl_dict()["attachments"][0]
    assert "hash" not in out
    assert "attachment_type" not in out


def test_attachment_full_object_round_trips() -> None:
    """Control: a fully-specified attachment round-trips its present keys."""
    att = {
        "path": "artifacts/report.pdf",
        "media_type": "application/pdf",
        "hash": "deadbeef",
        "attachment_type": "management_review",
        "description": "Q1 review",
    }
    env = dict_to_record_envelope(_base(attachments=[att]))
    out = env.to_jsonl_dict()["attachments"][0]
    for k, v in att.items():
        assert out[k] == v


# ===========================================================================
# CollectorInfo present-null on non-nullable ``version`` -> ACEF-050.
# ===========================================================================


def test_collector_present_null_version_rejected() -> None:
    """RED: ``CollectorInfo.version`` has schema type ``string`` — NOT nullable.
    A present ``version: null`` on the object form is a type violation ->
    ACEF-050."""
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(_base(collector={"name": "scanner", "version": None}))
    assert exc.value.code == "ACEF-050"
    assert "collector" in exc.value.message


def test_collector_object_without_version_loads() -> None:
    """Control: ABSENT ``version`` defaults cleanly (object form with name
    only)."""
    env = dict_to_record_envelope(_base(collector={"name": "scanner"}))
    assert env.collector is not None
    assert isinstance(env.collector, CollectorInfo)
    assert env.collector.name == "scanner"


def test_collector_model_rejects_present_null_version_directly() -> None:
    """The MODEL rejects a present-null ``version``."""
    with pytest.raises(Exception):  # pydantic ValidationError  # noqa: B017,PT011
        CollectorInfo(name="x", version=None)  # type: ignore[arg-type]
    # Absent version still constructs (default "").
    assert CollectorInfo(name="x").version == ""


# ===========================================================================
# LOAD-LENIENCY vs VALIDATE-ENFORCEMENT boundary — the ACEF-004 backstop.
#
# Pins the documented boundary: load() rejects structural/type/enum violations
# of the nested objects it dereferences; the FULL record-payload schema
# conformance is enforced by validate_bundle (ACEF-004). A record carrying an
# invalid retention object surfaces ACEF-004 at /records/<i>/retention through
# the schema validator (empirically confirmed) — the loader is NOT the only line
# of defence, and is NOT expected to reimplement the validator.
# ===========================================================================


def test_invalid_retention_object_surfaces_acef004_via_validate(tmp_path: Any) -> None:
    """A bundle whose record carries
    ``retention: {"min_retention_days": null, "retention_start_event": "bad"}``
    surfaces ACEF-004 at ``/records/0/retention`` from ``validate_bundle``'s
    record-envelope schema phase — the schema BACKSTOP behind the loader.

    This pins the load-leniency vs validate-enforcement boundary: the loader
    rejects the same record at load-time (ACEF-050, exercised above), while the
    validator independently catches it via the frozen envelope schema (ACEF-004).
    Neither is expected to reimplement the other.
    """
    import json

    from acef.validation.engine import validate_bundle

    bundle_dir = tmp_path / "ret.acef"
    (bundle_dir / "records").mkdir(parents=True)
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": [{"path": "records/r.jsonl", "record_type": "risk_register", "count": 1}],
    }
    (bundle_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    rec = {
        "record_id": _INJECTED_ID,
        "record_type": "risk_register",
        "provisions_addressed": [],
        "timestamp": "2026-03-01T10:00:00Z",
        "lifecycle_phase": "development",
        "collector": {"name": "x"},
        "obligation_role": "provider",
        "confidentiality": "public",
        "trust_level": "self-attested",
        "entity_refs": {"subject_refs": []},
        "payload": {},
        "retention": {"min_retention_days": None, "retention_start_event": "bad"},
    }
    (bundle_dir / "records" / "r.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")

    assessment = validate_bundle(str(bundle_dir))
    retention_errs = [
        e
        for e in assessment.structural_errors
        if e.get("code") == "ACEF-004" and e.get("path") == "/records/0/retention"
    ]
    assert retention_errs, (
        "validate_bundle must surface ACEF-004 at /records/0/retention for the "
        f"invalid retention object; codes={sorted({e.get('code') for e in assessment.structural_errors})}"
    )


def test_string_min_retention_days_surfaces_acef004_via_validate(tmp_path: Any) -> None:
    """Backstop for the StrictInt fix: a record carrying
    ``retention: {"min_retention_days": "180"}`` (a numeric STRING, schema-invalid
    against the ``integer`` property type) surfaces ACEF-004 at
    ``/records/0/retention`` from ``validate_bundle``'s record-envelope schema
    phase — DEEP scalar-type coercion is the validator's job, EMPIRICALLY
    confirmed here. The loader independently rejects the same record at load-time
    (ACEF-050, exercised above); neither reimplements the other.
    """
    import json

    from acef.validation.engine import validate_bundle

    bundle_dir = tmp_path / "strret.acef"
    (bundle_dir / "records").mkdir(parents=True)
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": [{"path": "records/r.jsonl", "record_type": "risk_register", "count": 1}],
    }
    (bundle_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    rec = {
        "record_id": _INJECTED_ID,
        "record_type": "risk_register",
        "provisions_addressed": [],
        "timestamp": "2026-03-01T10:00:00Z",
        "lifecycle_phase": "development",
        "collector": {"name": "x"},
        "obligation_role": "provider",
        "confidentiality": "public",
        "trust_level": "self-attested",
        "entity_refs": {"subject_refs": []},
        "payload": {},
        "retention": {"min_retention_days": "180"},
    }
    (bundle_dir / "records" / "r.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")

    assessment = validate_bundle(str(bundle_dir))
    retention_errs = [
        e
        for e in assessment.structural_errors
        if e.get("code") == "ACEF-004" and e.get("path") == "/records/0/retention"
    ]
    assert retention_errs, (
        "validate_bundle must surface ACEF-004 at /records/0/retention for the "
        "string min_retention_days; "
        f"codes={sorted({e.get('code') for e in assessment.structural_errors})}"
    )


def test_valid_min_retention_days_validates_clean_no_retention_error(tmp_path: Any) -> None:
    """Validate-path non-regression: a valid integer ``min_retention_days``
    produces NO retention schema error from ``validate_bundle`` (proving the
    StrictInt load-side change did not regress the validate path for valid data).
    """
    import json

    from acef.validation.engine import validate_bundle

    bundle_dir = tmp_path / "okint.acef"
    (bundle_dir / "records").mkdir(parents=True)
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": [{"path": "records/r.jsonl", "record_type": "risk_register", "count": 1}],
    }
    (bundle_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    rec = {
        "record_id": _INJECTED_ID,
        "record_type": "risk_register",
        "provisions_addressed": [],
        "timestamp": "2026-03-01T10:00:00Z",
        "lifecycle_phase": "development",
        "collector": {"name": "x"},
        "obligation_role": "provider",
        "confidentiality": "public",
        "trust_level": "self-attested",
        "entity_refs": {"subject_refs": []},
        "payload": {
            "risk_id": "r-1",
            "description": "d",
            "category": "safety",
        },
        "retention": {"min_retention_days": 180, "retention_start_event": "first_use"},
    }
    (bundle_dir / "records" / "r.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")

    assessment = validate_bundle(str(bundle_dir))
    retention_errs = [e for e in assessment.structural_errors if e.get("path") == "/records/0/retention"]
    assert not retention_errs, (
        f"valid integer min_retention_days must not produce a /records/0/retention diagnostic: {retention_errs!r}"
    )


def test_valid_empty_retention_validates_clean_no_retention_error(tmp_path: Any) -> None:
    """Validate-path non-regression: a now-valid ``retention: {}`` produces NO
    retention schema error from ``validate_bundle`` (the only ACEF-004s, if any,
    come from the unrelated payload, never ``/records/0/retention``)."""
    import json

    from acef.validation.engine import validate_bundle

    bundle_dir = tmp_path / "okret.acef"
    (bundle_dir / "records").mkdir(parents=True)
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": [{"path": "records/r.jsonl", "record_type": "risk_register", "count": 1}],
    }
    (bundle_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    rec = {
        "record_id": _INJECTED_ID,
        "record_type": "risk_register",
        "provisions_addressed": [],
        "timestamp": "2026-03-01T10:00:00Z",
        "lifecycle_phase": "development",
        "collector": {"name": "x"},
        "obligation_role": "provider",
        "confidentiality": "public",
        "trust_level": "self-attested",
        "entity_refs": {"subject_refs": []},
        "payload": {
            "risk_id": "r-1",
            "description": "d",
            "category": "safety",
        },
        "retention": {},
    }
    (bundle_dir / "records" / "r.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")

    assessment = validate_bundle(str(bundle_dir))
    retention_errs = [e for e in assessment.structural_errors if e.get("path") == "/records/0/retention"]
    assert not retention_errs, (
        f"valid empty retention must not produce a /records/0/retention diagnostic: {retention_errs!r}"
    )
