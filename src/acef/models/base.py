"""Shared base for ACEF Pydantic models.

All ACEF models inherit from :class:`ACEFBaseModel` so that vendor extension
fields survive round-trip. Spec §3.7 "Extension semantics" and §6.4 "Open
boundary enforcement" require that ``x-vendor/*`` fields be preserved by
conformant tooling; without ``extra='allow'`` Pydantic v2 silently drops
them on parse, breaking byte-identical re-export.

The JSON Schemas under ``acef-conventions/v1/`` set
``additionalProperties: true`` throughout — the model layer must match.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class ACEFBaseModel(BaseModel):
    """Base class for every ACEF Pydantic model.

    Configures Pydantic to *allow* (preserve) unknown fields so that vendor
    extensions, future ACEF Profiles minors, and any other spec-permitted
    extra keys survive a load→export round-trip byte-identically.
    """

    model_config = ConfigDict(extra="allow")


def _reject_present_null(values: Any, fields: tuple[str, ...]) -> Any:
    """Reject a PRESENT explicit ``null`` on a NON-nullable schema property.

    Shared by the record-envelope models (``records.py``) and the package-metadata
    models (``metadata.py``): both must faithfully mirror frozen JSON Schemas whose
    listed properties are typed ``integer`` / ``string`` (NOT ``["integer","null"]``
    / ``["string","null"]``) with NO ``required`` array. That combination is
    OPTIONAL-but-NON-nullable: an ABSENT key defaults cleanly, but a PRESENT
    explicit ``null`` VALUE is a type violation.

    Pydantic's ``X | None = None`` typing (needed to express OPTIONAL / absent)
    ALSO silently accepts a present explicit ``null``, collapsing that distinction;
    this ``mode="before"`` helper restores it by raising ``ValueError`` (which
    Pydantic wraps as ``ValidationError`` — re-raised by the loader's model-build
    wrapper as a structured ``ACEFError``) when a listed key is present in the RAW
    input with a ``None`` value. A missing key is untouched, so absent → default is
    preserved.

    Only operates on a raw ``dict`` input (the wire shape); non-dict inputs are
    passed through unchanged for Pydantic's normal handling.
    """
    if isinstance(values, dict):
        present_null = [f for f in fields if f in values and values[f] is None]
        if present_null:
            raise ValueError(
                f"property {present_null!r} is present but null; the frozen schema "
                f"types these properties as non-nullable (integer/string), so an "
                f"explicit null is a type violation (omit the key instead)"
            )
    return values
