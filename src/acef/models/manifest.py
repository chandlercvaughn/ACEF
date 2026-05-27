"""ACEF manifest models — the acef-manifest.json structure."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from acef.models.base import ACEFBaseModel
from acef.models.entities import EntitiesBlock
from acef.models.enums import AuditEventType
from acef.models.metadata import PackageMetadata, Versioning
from acef.models.subjects import Subject


class RecordFileEntry(ACEFBaseModel):
    """A reference to a record file in records/."""

    path: str
    record_type: str
    count: int = 0


class ProfileEntry(ACEFBaseModel):
    """A regulation profile declaration."""

    profile_id: str
    template_version: str = "1.0.0"
    applicable_provisions: list[str] = Field(default_factory=list)


class AuditTrailEntry(ACEFBaseModel):
    """A package-level audit trail event."""

    event_type: AuditEventType
    timestamp: str
    actor_ref: str = ""
    description: str = ""


class Manifest(ACEFBaseModel):
    """The complete acef-manifest.json structure."""

    metadata: PackageMetadata
    versioning: Versioning = Field(default_factory=Versioning)
    subjects: list[Subject] = Field(default_factory=list)
    entities: EntitiesBlock = Field(default_factory=EntitiesBlock)
    profiles: list[ProfileEntry] = Field(default_factory=list)
    record_files: list[RecordFileEntry] = Field(default_factory=list)
    audit_trail: list[AuditTrailEntry] = Field(default_factory=list)

    # v1.1 manifest extensions (X5, X6) — both OPTIONAL at the model/schema
    # level; conditional-required semantics (mode-gated required/forbidden
    # record types; tenant uniformity) are enforced at the validator level
    # so v1.0 bundles continue to validate clean (spec §8.1).
    analysis_mode: Literal["subscriber", "public_artifact", "canary", "unattributed_artifact"] | None = Field(
        default=None,
        description=(
            "X5: gates which v1.1 conditional-required envelope fields and "
            "mode-gated record-type rules apply. Violations emit ACEF-080."
        ),
    )
    namespaces: dict[str, dict[str, Any]] | None = Field(
        default=None,
        description=(
            "X6: vendor-extension namespaces; top-level keys MUST be "
            "x-vendor-prefixed (pattern '^x-[a-z0-9-]+/?$'). Registered "
            "namespaces may receive validator lint hooks via "
            "namespace_lints.py registry; unregistered namespaces validate "
            "without lint coverage (graceful degradation)."
        ),
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON output."""
        return self.model_dump(mode="json", exclude_none=True)
