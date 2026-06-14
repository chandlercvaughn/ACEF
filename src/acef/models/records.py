"""ACEF record models — RecordEnvelope and supporting types."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import Field, ValidationError

from acef.models.base import ACEFBaseModel
from acef.models.enums import Confidentiality, LifecyclePhase, ObligationRole, TrustLevel
from acef.models.urns import URNType, generate_urn


class EntityRefs(ACEFBaseModel):
    """Links to entities this record concerns."""

    subject_refs: list[str] = Field(default_factory=list)
    component_refs: list[str] = Field(default_factory=list)
    dataset_refs: list[str] = Field(default_factory=list)
    actor_refs: list[str] = Field(default_factory=list)


class AttachmentRef(ACEFBaseModel):
    """Reference to a file in the artifacts/ directory."""

    path: str
    hash: str | None = None
    media_type: str = "application/octet-stream"
    attachment_type: str | None = None
    description: str = ""


class Attestation(ACEFBaseModel):
    """Cryptographic attestation of evidence authenticity."""

    method: str = "jws"
    signer: str = ""
    signed_fields: list[str] = Field(default_factory=lambda: ["/payload"])
    signature: str = ""


class RecordRetention(ACEFBaseModel):
    """Per-record retention requirements."""

    min_retention_days: int = Field(ge=0)
    retention_start_event: str = "record_creation"
    legal_basis: str = ""


class CollectorInfo(ACEFBaseModel):
    """Tool/person that collected this evidence."""

    name: str
    version: str = ""


class RecordEnvelope(ACEFBaseModel):
    """The common record envelope — identical structure for all record types.

    Contains all envelope fields plus the type-specific payload.
    """

    record_id: str = Field(default_factory=lambda: generate_urn(URNType.RECORD))
    record_type: str
    provisions_addressed: list[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
    lifecycle_phase: LifecyclePhase | None = None
    # record-envelope.schema.json declares collector as oneOf [object, string].
    # The string form (e.g. "alice@example.com") is stored verbatim as a bare
    # ``str`` so it re-exports unchanged; wrapping it in CollectorInfo would
    # reshape the wire bytes (name/version object) and break the §6.4
    # lossless-export MUST (records-payloads-1).
    collector: CollectorInfo | str | dict[str, str] | None = None
    obligation_role: ObligationRole | None = None
    confidentiality: Confidentiality = Confidentiality.PUBLIC
    redaction_method: str | None = None
    access_policy: dict[str, Any] | None = None
    trust_level: TrustLevel = TrustLevel.SELF_ATTESTED
    entity_refs: EntityRefs = Field(default_factory=EntityRefs)
    payload: dict[str, Any] = Field(default_factory=dict)
    attachments: list[AttachmentRef] = Field(default_factory=list)
    attestation: Attestation | None = None
    retention: RecordRetention | None = None

    # v1.1 envelope extensions (X1-X4) — all OPTIONAL at the model/schema
    # level; conditional-required semantics keyed on confidentiality /
    # record_type / manifest.analysis_mode are enforced at the validator
    # level so v1.0 bundles continue to validate clean (spec §8.1).
    redaction_policy_version: str | None = Field(
        default=None,
        description=(
            "X1: redaction policy semver; required at validation time when "
            "confidentiality != public. Missing on a non-public record emits "
            "ACEF-074."
        ),
    )
    redaction_attestation_ref: str | None = Field(
        default=None,
        description=(
            "X2: URN of the attestation record proving the redaction policy "
            "executed against source content. Required at validation time when "
            "confidentiality != public. Unresolvable URN emits ACEF-078."
        ),
    )
    tenant_label: str | None = Field(
        default=None,
        description=(
            "X3: stable tenant identifier (urn:acef:tenant:<slug>). "
            "Bundle-wide uniformity enforced at validator level when "
            "manifest.analysis_mode is set; emits ACEF-075 on divergence."
        ),
    )
    causation_chain: list[str] | None = Field(
        default=None,
        description=(
            "X4: ordered upstream-record URNs (most-recent-first) that caused "
            "this record. Required on harness_attestation with at least one "
            "element; unresolvable URN emits ACEF-073."
        ),
    )

    @property
    def id(self) -> str:
        return self.record_id

    def to_jsonl_dict(self) -> dict[str, Any]:
        """Convert to a dict suitable for JSONL serialization.

        Excludes None values from optional fields. Fills sensible defaults
        for fields the JSON Schema marks as required so emitted records
        satisfy record-envelope.schema.json even when the in-memory
        model has them as ``None``. The fields the Pydantic model types
        as ``Optional`` for backward-compat but the schema requires:

        - ``lifecycle_phase``  → defaults to ``"development"``
        - ``obligation_role``  → defaults to ``"provider"``
        - ``collector``        → defaults to ``{"name": "unknown", "version": ""}``
          ONLY when absent (``None``); a present collector — including the
          empty string ``""``, a valid no-``minLength`` wire shape — is
          emitted verbatim so the round-trip stays lossless (§6.4).

        Callers that want explicit values should pass them through the
        Package builder API, which has its own (typically richer)
        defaulting logic in :meth:`acef.package.Package.record`.
        """
        data = self.model_dump(mode="json", exclude_none=True)
        # Ensure entity_refs always present even if empty
        if "entity_refs" not in data:
            data["entity_refs"] = {
                "subject_refs": [],
                "component_refs": [],
                "dataset_refs": [],
                "actor_refs": [],
            }
        # Spec-required envelope fields: fill sensible defaults if absent so
        # the JSONL output validates against record-envelope.schema.json.
        if "lifecycle_phase" not in data:
            data["lifecycle_phase"] = LifecyclePhase.DEVELOPMENT.value
        if "obligation_role" not in data:
            data["obligation_role"] = ObligationRole.PROVIDER.value
        if "collector" not in data:
            data["collector"] = {"name": "unknown", "version": ""}
        return data


def dict_to_record_envelope(data: dict[str, Any]) -> RecordEnvelope:
    """Convert a dict from JSONL deserialization to a RecordEnvelope.

    Handles nested structure conversion (entity_refs, attachments,
    attestation, retention, collector) and delegates final validation
    to Pydantic. Missing required fields will raise ACEFFormatError
    rather than silently fabricating blank defaults.

    Args:
        data: Parsed JSON dict from a JSONL record line.

    Returns:
        A validated RecordEnvelope.

    Raises:
        ACEFFormatError: If the data is missing required fields or fails
            Pydantic validation.
    """
    # Import here to avoid circular import (errors.py -> models -> errors)
    from acef.errors import ACEFFormatError

    # ``acef.load()`` is a PUBLIC deserialization API consuming
    # attacker-controlled bytes. A record line may be a well-formed JSON object
    # yet carry a WRONG-TYPED sub-field (e.g. ``entity_refs: [1, 2]``,
    # ``attachments: 5``, ``attestation: "x"``). Guard the TYPES of the three
    # sub-fields that this function dereferences before use, raising the same
    # structured ``ACEFFormatError(code="ACEF-050")`` the loader (loader.py) and
    # validation engine (engine.py, via ``isinstance`` -> ACEF-050 for manifest
    # sub-fields) use for malformed structure — so a malformed sub-field
    # surfaces a structured diagnostic naming the offending field + record,
    # never a leaked raw ``AttributeError`` / ``TypeError``. ``validate_bundle``
    # routes the identical line through this function, so load() and validate()
    # converge on the same verdict. This is deserialization hardening only — it
    # does NOT add schema-validation logic (the validator's job); absent
    # sub-fields default cleanly, and a well-formed dict still passes its
    # vendor ``x-*`` extension keys through the ``**`` splat unchanged.
    _record_id = data.get("record_id", "<unknown>")

    # Handle entity_refs. Pass through any unknown nested keys so
    # vendor-prefixed extension refs (e.g., a custom relationship type)
    # round-trip losslessly. A PRESENT non-dict must RAISE (the historical
    # ``or {}`` only rescued FALSY values, letting a truthy non-dict — list,
    # str, number — fall through to ``.get`` and raise a raw AttributeError);
    # an ABSENT entity_refs defaults to ``{}``.
    entity_refs_data = data.get("entity_refs", {})
    if not isinstance(entity_refs_data, dict):
        raise ACEFFormatError(
            f"Record {_record_id!r} field 'entity_refs' must be a JSON object, got {type(entity_refs_data).__name__}",
            code="ACEF-050",
        )
    _entity_refs_known = {"subject_refs", "component_refs", "dataset_refs", "actor_refs"}
    entity_refs = EntityRefs(
        subject_refs=entity_refs_data.get("subject_refs", []),
        component_refs=entity_refs_data.get("component_refs", []),
        dataset_refs=entity_refs_data.get("dataset_refs", []),
        actor_refs=entity_refs_data.get("actor_refs", []),
        **{k: v for k, v in entity_refs_data.items() if k not in _entity_refs_known},
    )

    # Handle attachments. A PRESENT non-list must RAISE (a bare scalar is not
    # iterable; a dict would iterate its keys into ``AttachmentRef(**str)``);
    # an ABSENT attachments defaults to ``[]``. Each list element must itself be
    # a dict before the ``**`` splat, else a non-dict element (``[5]``) raises a
    # raw ``TypeError: argument after ** must be a mapping``.
    attachments_data = data.get("attachments", [])
    if not isinstance(attachments_data, list):
        raise ACEFFormatError(
            f"Record {_record_id!r} field 'attachments' must be a JSON array, got {type(attachments_data).__name__}",
            code="ACEF-050",
        )
    attachments = []
    for att_index, att_data in enumerate(attachments_data):
        if not isinstance(att_data, dict):
            raise ACEFFormatError(
                f"Record {_record_id!r} field 'attachments[{att_index}]' must be a "
                f"JSON object, got {type(att_data).__name__}",
                code="ACEF-050",
            )
        attachments.append(AttachmentRef(**att_data))

    # Handle attestation. A PRESENT (truthy) non-dict must RAISE before the
    # ``**`` splat (``Attestation(**"x")`` raises a raw TypeError). A falsy /
    # absent attestation stays ``None``.
    attestation = None
    attestation_data = data.get("attestation")
    if attestation_data:
        if not isinstance(attestation_data, dict):
            raise ACEFFormatError(
                f"Record {_record_id!r} field 'attestation' must be a JSON object, "
                f"got {type(attestation_data).__name__}",
                code="ACEF-050",
            )
        attestation = Attestation(**attestation_data)

    # Handle retention
    retention = None
    if data.get("retention"):
        retention = RecordRetention(**data["retention"])

    # Handle collector. record-envelope.schema.json:47-69 declares the
    # collector as oneOf [object, string]. The object form maps to
    # CollectorInfo; the string form (e.g. "alice@example.com") is stored
    # verbatim as a bare ``str`` so re-export emits the original wire shape.
    # Wrapping a string into CollectorInfo(name=..., version="") would
    # reshape the bytes (object instead of string) and break the §6.4
    # lossless-export MUST (records-payloads-1).
    #
    # Use a key-PRESENCE check, not truthiness: the string branch carries no
    # ``minLength``, so the EMPTY string "" is a valid wire shape that MUST
    # round-trip verbatim. A truthiness check (``data.get("collector")``)
    # drops "" (falsy), which then re-exports as the default collector OBJECT
    # via ``to_jsonl_dict`` — a reshaped wire form that breaks lossless
    # round-trip and Python/TS parity. The default is applied ONLY when the
    # key is ABSENT (in ``to_jsonl_dict``).
    collector: CollectorInfo | str | None = None
    if "collector" in data:
        collector_data = data["collector"]
        if isinstance(collector_data, dict):
            collector = CollectorInfo(**collector_data)
        elif isinstance(collector_data, str):
            collector = collector_data

    # Build kwargs from the data dict, letting Pydantic validate
    # required fields rather than using empty-string defaults
    kwargs: dict[str, Any] = {
        "entity_refs": entity_refs,
        "attachments": attachments,
        "payload": data.get("payload", {}),
    }

    # Required fields — pass through from data without defaults
    for field_name in ("record_id", "record_type", "timestamp"):
        if field_name in data:
            kwargs[field_name] = data[field_name]

    # Optional fields with non-None data
    for field_name in (
        "provisions_addressed",
        "lifecycle_phase",
        "obligation_role",
        "confidentiality",
        "redaction_method",
        "access_policy",
        "trust_level",
        # v1.1 envelope extensions (X1-X4). Passed through explicitly so
        # Pydantic validates the declared types instead of landing them as
        # untyped extras.
        "redaction_policy_version",
        "redaction_attestation_ref",
        "tenant_label",
        "causation_chain",
    ):
        if field_name in data:
            kwargs[field_name] = data[field_name]

    if collector is not None:
        kwargs["collector"] = collector
    if attestation is not None:
        kwargs["attestation"] = attestation
    if retention is not None:
        kwargs["retention"] = retention

    # Pass through any unknown top-level keys (vendor extensions, future
    # spec fields) as extras so they survive load→export round-trip.
    # Spec §6.4 rule 5: "ACEF Evidence Bundle export MUST be lossless to
    # the open core". record-envelope.schema.json sets
    # additionalProperties: true at 7 locations, so unknown fields are
    # spec-permitted.
    _envelope_known = {
        "record_id",
        "record_type",
        "provisions_addressed",
        "timestamp",
        "lifecycle_phase",
        "collector",
        "obligation_role",
        "confidentiality",
        "redaction_method",
        "access_policy",
        "trust_level",
        "entity_refs",
        "payload",
        "attachments",
        "attestation",
        "retention",
        # v1.1 envelope extensions (X1-X4) — declared on RecordEnvelope.
        "redaction_policy_version",
        "redaction_attestation_ref",
        "tenant_label",
        "causation_chain",
    }
    for k, v in data.items():
        if k not in _envelope_known:
            kwargs[k] = v

    try:
        return RecordEnvelope(**kwargs)
    except ValidationError as e:
        raise ACEFFormatError(
            f"Invalid record data: {e}",
            code="ACEF-004",
        ) from e
