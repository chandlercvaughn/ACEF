"""ACEF metadata models — ProducerInfo, RetentionPolicy, PackageMetadata."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import Field, StrictInt, model_validator

from acef.models.base import ACEFBaseModel, _reject_present_null
from acef.models.urns import URNType, generate_urn


class ProducerInfo(ACEFBaseModel):
    """Organization/tool that created this package."""

    name: str
    version: str


class RetentionPolicy(ACEFBaseModel):
    """Package-level retention requirements.

    A FAITHFUL TYPED MIRROR of the FROZEN v1 manifest schema's ``retention_policy``
    object (``acef-conventions/v1`` and ``v1.1`` are byte-identical here), matched
    PROPERTY-by-PROPERTY. The object declares NO ``required`` array, so BOTH
    properties are OPTIONAL (default ``None``) — a required model field made
    ``load()`` over-reject a schema-valid manifest carrying ``retention_policy``
    without ``min_retention_days``, a load/validate divergence. But OPTIONAL is NOT
    NULLABLE:

    - ``min_retention_days``: schema ``integer, minimum: 0`` → ``StrictInt | None``
      with ``ge=0``. ``StrictInt`` (NOT Pydantic's LAX ``int``) so a present numeric
      STRING (``"180"``), ``float`` (``1.5``), or ``bool`` (``True``/``False``,
      which lax int coerces to ``1``/``0``) is a TYPE violation rejected at load
      (ACEF-002 via the loader's model-build wrap) rather than silently
      coerced-and-mutated on re-export. A real JSON ``integer`` still loads, ``ge=0``
      still rejects an out-of-range VALUE (``-1``), and an ABSENT key defaults to
      ``None``.
    - ``personal_data_interplay``: schema ``string`` → ``str``.

    PRESENT-NULL on these NON-nullable properties is rejected (the schema types them
    ``integer`` / ``string``, NOT ``[..., "null"]``): an explicit
    ``{"min_retention_days": null}`` / ``{"personal_data_interplay": null}`` is a
    type violation distinct from ABSENCE. The ``mode="before"`` validator raises
    (→ ACEF-002 via the loader wrap) while leaving an ABSENT key to default to
    ``None``. The whole-object ``retention_policy: null`` form ("no policy", schema
    ``["object","null"]``) is handled by the loader BEFORE model construction and is
    unaffected. Mirrors the record-level ``RecordRetention`` model.
    """

    min_retention_days: StrictInt | None = Field(default=None, ge=0)
    personal_data_interplay: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _no_present_null(cls, values: Any) -> Any:
        return _reject_present_null(values, ("min_retention_days", "personal_data_interplay"))


class Versioning(ACEFBaseModel):
    """Module version declarations."""

    core_version: str = "1.0.0"
    profiles_version: str = "1.0.0"


class PackageMetadata(ACEFBaseModel):
    """Package-level metadata for an ACEF Evidence Bundle."""

    package_id: str = Field(default_factory=lambda: generate_urn(URNType.PACKAGE))
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
    producer: ProducerInfo
    prior_package_ref: str | None = None
    retention_policy: RetentionPolicy | None = None
