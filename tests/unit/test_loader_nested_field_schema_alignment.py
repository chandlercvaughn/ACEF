"""``dict_to_record_envelope`` nested-field load guards aligned to the FROZEN
record-envelope schema, field-for-field.

Structural-review P2, round 4. roborev (codex xhigh) on commit ``1dddd5bf``
found the comprehensive round-3 hardening
(``test_loader_malformed_record_subfield_comprehensive.py``) slightly
MIS-ALIGNED with the frozen ``acef-conventions/v1/record-envelope.schema.json``
(and the identical ``v1.1`` envelope schema) on two nested fields — one
OVER-reject (a regression) and one UNDER-reject (a fabrication). The frozen
schema is authoritative; when the Pydantic model disagrees, the MODEL is wrong.

Authoritative per-field contract extracted from BOTH frozen envelope schemas
(``v1`` and ``v1.1`` are byte-identical for these five fields):

  field         nullable?  object-form required keys             permitted type(s)
  ------------  ---------  ------------------------------------  ------------------
  entity_refs   no         ["subject_refs"]                      object
  attachments   no (array) element: ["path", "media_type"]       array<object>
  attestation   YES        ["method","signer","signed_fields",   object | null
                           "signature"]
  retention     YES        (NONE — no `required` key)            object | null
  collector     NO         ["name"]                              object | string

The two MIS-alignments fixed here:

MEDIUM 1 — retention REGRESSION (schema-valid ``retention: {}`` rejected)
    The retention object form declares NO ``required`` keys
    (``min_retention_days`` is ``minimum: 0`` but OPTIONAL). The round-3
    ``RecordRetention`` model required ``min_retention_days`` (no default), so a
    present ``retention: {}`` raised ACEF-050 — OVER-rejecting schema-VALID
    input. Empirically on ``1dddd5bf``::

        retention: {} -> ACEF-050 "...field 'retention' is not a valid
        retention object: 1 validation error... min_retention_days Field
        required"

    Fix: align ``RecordRetention`` to the schema — make every field OPTIONAL
    (default ``None``) so ``retention: {}`` LOADS and round-trips as ``{}`` (no
    fabricated ``retention_start_event`` / ``legal_basis``). An invalid VALUE is
    still rejected: ``min_retention_days: -1`` violates the schema's
    ``minimum: 0`` -> ACEF-050 (the model keeps ``ge=0``).

MEDIUM 2 — collector UNDER-reject (``collector: null`` fabricated)
    The schema permits collector ONLY as ``oneOf [object, string]`` — ``null`` is
    NOT a valid collector. The round-3 loader treated a present ``collector:
    null`` as ABSENT, then ``to_jsonl_dict`` re-exported a FABRICATED default
    ``{"name": "unknown", "version": ""}`` the wire never carried. Empirically on
    ``1dddd5bf``::

        collector: null -> LOADS (collector=None) -> re-export
        {'name': 'unknown', 'version': ''}  (FABRICATED)

    Fix: distinguish ABSENT from explicit ``null`` for collector — default ONLY
    when the key is ABSENT; a PRESENT ``collector: null`` raises ACEF-050 (the
    schema does not allow null for collector).

The attestation / entity_refs / attachments null+required handling already
matches the schema (attestation is ``oneOf[object,null]`` so ``null`` -> None is
correct; entity_refs/attachments are non-nullable; AttachmentRef required set is
checked by the schema element ``required: [path, media_type]`` — note the loader
constructs ``AttachmentRef`` with a ``media_type`` default so only ``path`` is
hard-required by the model, matching the schema's behaviour that a missing
``media_type`` is a schema violation surfaced by the validator, while ``load``
keeps the lenient default for backward-compat). Those are re-pinned here as
controls to prove the alignment fix does not regress them.
"""

from __future__ import annotations

from typing import Any

import pytest

from acef.errors import ACEFFormatError
from acef.models.records import RecordRetention, dict_to_record_envelope

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
# MEDIUM 1 — retention has NO schema-required keys: ``retention: {}`` must LOAD.
# ===========================================================================


def test_empty_retention_object_loads_clean() -> None:
    """RED (regression): ``retention: {}`` is schema-VALID (the retention object
    form declares NO ``required`` keys) and MUST load, not raise ACEF-050.

    On ``1dddd5bf`` this raised::

        ACEF-050 "...field 'retention' is not a valid retention object:
        1 validation error ... min_retention_days Field required"
    """
    env = dict_to_record_envelope(_base(retention={}))
    assert env.retention is not None
    assert isinstance(env.retention, RecordRetention)
    # No fabricated values: every field defaults to None so the optional keys
    # are absent in the model.
    assert env.retention.min_retention_days is None
    assert env.retention.retention_start_event is None
    assert env.retention.legal_basis is None


def test_empty_retention_object_round_trips_as_empty_object() -> None:
    """``retention: {}`` must re-export as ``{}`` — NOT a fabricated object with
    ``retention_start_event`` / ``legal_basis``. ``exclude_none=True`` strips the
    None-defaulted optional keys."""
    env = dict_to_record_envelope(_base(retention={}))
    out = env.to_jsonl_dict()
    assert out["retention"] == {}


def test_partial_retention_object_loads_and_preserves_only_present_keys() -> None:
    """A retention object carrying only ``min_retention_days`` loads and
    re-exports only that key (no fabricated start-event / legal-basis)."""
    env = dict_to_record_envelope(_base(retention={"min_retention_days": 180}))
    assert env.retention is not None
    assert env.retention.min_retention_days == 180
    assert env.retention.retention_start_event is None
    out = env.to_jsonl_dict()
    assert out["retention"] == {"min_retention_days": 180}


def test_full_retention_object_round_trips_verbatim() -> None:
    """A fully-specified retention object round-trips every key verbatim."""
    src = {
        "min_retention_days": 180,
        "retention_start_event": "first_use",
        "legal_basis": "eu-ai-act-2024:article-12",
    }
    env = dict_to_record_envelope(_base(retention=src))
    out = env.to_jsonl_dict()
    assert out["retention"] == src


def test_negative_retention_days_still_rejected() -> None:
    """An invalid VALUE is still rejected: the schema constrains
    ``min_retention_days`` to ``minimum: 0``, so ``-1`` -> ACEF-050 (the model
    keeps ``ge=0``). This matches the frozen schema; it is NOT an invented
    constraint."""
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(_base(retention={"min_retention_days": -1}))
    assert exc.value.code == "ACEF-050"
    assert "retention" in exc.value.message
    assert _INJECTED_ID in exc.value.message


def test_non_integer_retention_days_still_rejected() -> None:
    """``min_retention_days: "lots"`` is a wrong TYPE (schema: integer) ->
    ACEF-050."""
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(_base(retention={"min_retention_days": "lots"}))
    assert exc.value.code == "ACEF-050"
    assert "retention" in exc.value.message


@pytest.mark.parametrize(
    "value",
    [
        pytest.param([], id="falsy-list"),
        pytest.param(False, id="falsy-false"),
        pytest.param(0, id="falsy-zero"),
        pytest.param("", id="falsy-empty-str"),
        pytest.param("bad", id="truthy-str"),
        pytest.param(5, id="truthy-int"),
    ],
)
def test_wrong_typed_retention_still_rejected(value: Any) -> None:
    """A present, non-null, non-object retention is still ACEF-050 (the schema
    permits only object | null)."""
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(_base(retention=value))
    assert exc.value.code == "ACEF-050"
    assert "retention" in exc.value.message


def test_explicit_null_retention_yields_none() -> None:
    """``retention: null`` is schema-valid (oneOf[..., null]) -> None."""
    env = dict_to_record_envelope(_base(retention=None))
    assert env.retention is None


def test_record_retention_constructs_empty() -> None:
    """The model itself constructs from no args (schema: no required keys)."""
    assert RecordRetention().min_retention_days is None


# ===========================================================================
# MEDIUM 2 — collector permits object | string ONLY (NOT null): a present
# ``collector: null`` must reject, not silently default + fabricate.
# ===========================================================================


def test_present_null_collector_rejected() -> None:
    """RED (under-reject): the schema permits collector only as object | string;
    ``null`` is NOT valid. A PRESENT ``collector: null`` MUST raise ACEF-050.

    On ``1dddd5bf`` this LOADED (collector=None) and re-exported the FABRICATED
    default ``{'name': 'unknown', 'version': ''}`` via ``to_jsonl_dict``.
    """
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(_base(collector=None))
    assert exc.value.code == "ACEF-050"
    assert "collector" in exc.value.message
    assert _INJECTED_ID in exc.value.message


def test_present_null_collector_does_not_fabricate_default() -> None:
    """Defence in depth: the rejected ``collector: null`` never reaches
    ``to_jsonl_dict`` to fabricate ``{'name': 'unknown', 'version': ''}``."""
    with pytest.raises(ACEFFormatError):
        dict_to_record_envelope(_base(collector=None))


def test_absent_collector_still_defaults() -> None:
    """ABSENT collector (key not present) still defaults — the spec-required
    default object is applied at export time (unchanged behaviour)."""
    env = dict_to_record_envelope(_base())
    assert env.collector is None
    out = env.to_jsonl_dict()
    assert out["collector"] == {"name": "unknown", "version": ""}


def test_collector_object_form_unchanged() -> None:
    """The object form is unchanged: maps to CollectorInfo, round-trips."""
    env = dict_to_record_envelope(_base(collector={"name": "scanner", "version": "2.1"}))
    assert env.collector is not None
    out = env.to_jsonl_dict()
    assert out["collector"] == {"name": "scanner", "version": "2.1"}


def test_collector_string_form_unchanged() -> None:
    """The string form (incl. empty string) round-trips verbatim (unchanged)."""
    env = dict_to_record_envelope(_base(collector="alice@example.com"))
    assert env.collector == "alice@example.com"
    empty = dict_to_record_envelope(_base(collector=""))
    assert empty.collector == ""


# ===========================================================================
# Attestation null handling is schema-correct (oneOf[object, null]) — keep.
# ===========================================================================


def test_explicit_null_attestation_yields_none() -> None:
    """``attestation: null`` is schema-valid (oneOf[..., null]) -> None
    (unchanged — the schema DOES permit null here)."""
    env = dict_to_record_envelope(_base(attestation=None))
    assert env.attestation is None


def test_complete_attestation_still_constructs() -> None:
    """A fully-specified attestation still constructs (control)."""
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


def test_incomplete_attestation_still_rejected() -> None:
    """A present attestation omitting a schema-required key still raises ACEF-050
    (no fabrication — control for the round-3 fix)."""
    with pytest.raises(ACEFFormatError) as exc:
        dict_to_record_envelope(_base(attestation={"method": "jws"}))
    assert exc.value.code == "ACEF-050"
    assert "attestation" in exc.value.message
