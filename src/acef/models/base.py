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

from pydantic import BaseModel, ConfigDict


class ACEFBaseModel(BaseModel):
    """Base class for every ACEF Pydantic model.

    Configures Pydantic to *allow* (preserve) unknown fields so that vendor
    extensions, future ACEF Profiles minors, and any other spec-permitted
    extra keys survive a load→export round-trip byte-identically.
    """

    model_config = ConfigDict(extra="allow")
