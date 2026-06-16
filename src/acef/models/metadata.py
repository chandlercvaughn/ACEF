"""ACEF metadata models — ProducerInfo, RetentionPolicy, PackageMetadata."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import Field

from acef.models.base import ACEFBaseModel
from acef.models.urns import URNType, generate_urn


class ProducerInfo(ACEFBaseModel):
    """Organization/tool that created this package."""

    name: str
    version: str


class RetentionPolicy(ACEFBaseModel):
    """Package-level retention requirements."""

    # OPTIONAL to match the FROZEN v1 manifest schema, whose retention_policy
    # object declares NO `required` array (min_retention_days is a schema-optional
    # property). A required model field made load() over-reject a schema-valid
    # manifest carrying retention_policy without min_retention_days — a
    # load/validate divergence. Mirrors the record-level RecordRetention model.
    min_retention_days: int | None = Field(default=None, ge=0)
    personal_data_interplay: str | None = None


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
