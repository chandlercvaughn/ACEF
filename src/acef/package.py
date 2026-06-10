"""ACEF Package — core evidence package builder.

The primary API for creating ACEF Evidence Bundles.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from acef.errors import ACEFError, ACEFSchemaError
from acef.integrity import canonicalize
from acef.models.agent_reliability import (
    AuthorizedTestScopePayload,
    DeliveryVerdictPayload,
    FindingRecordPayload,
    HarnessAttestationPayload,
    ScopeBoundaryEventPayload,
)
from acef.models.entities import Actor, Component, Dataset, EntitiesBlock, Relationship
from acef.models.enums import (
    RECORD_TYPES,
    ActorRole,
    AuditEventType,
    ComponentType,
    Confidentiality,
    DatasetModality,
    DatasetSourceType,
    LifecyclePhase,
    ObligationRole,
    RelationshipType,
    RiskClassification,
    SubjectType,
    TrustLevel,
)
from acef.models.manifest import AuditTrailEntry, Manifest, ProfileEntry, RecordFileEntry
from acef.models.metadata import PackageMetadata, ProducerInfo, RetentionPolicy, Versioning
from acef.models.records import (
    AttachmentRef,
    Attestation,
    CollectorInfo,
    EntityRefs,
    RecordEnvelope,
    RecordRetention,
)
from acef.models.subjects import LifecycleEntry, Subject
from acef.models.urns import URNType, generate_urn

# Spec §3.1 timestamp format — ISO 8601 with explicit ``Z`` suffix and no
# sub-second precision. Both the model default factories and the injected-
# clock path MUST format identically so v0.3 behavior is preserved.
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _default_clock() -> datetime:
    """Wall-clock default; replaced by the injected ``clock`` callable."""
    return datetime.now(UTC)


def _format_timestamp(dt: datetime) -> str:
    """Format a datetime per spec §3.1 — ISO 8601 with ``Z`` suffix.

    Naive datetimes are treated as UTC. Sub-second precision is dropped.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    return dt.strftime(_TIMESTAMP_FORMAT)


# Brief §3.6 / VAL-LOAD-001/002 — persona and LLM verifiers lack the
# determinism required to attest state transitions; they are rejected at
# SDK build time AND at load time AND mirrored by validate_bundle.
_BANNED_VERIFIER_CLASSES: frozenset[str] = frozenset({"persona", "llm"})

# Brief Q3 / VAL-SCHEMA-009 — the seven hard-coded state classes.
_STATE_CLASS_TAXONOMY: frozenset[str] = frozenset(
    {
        "step",
        "finding",
        "coverage_cell",
        "regression",
        "delivery",
        "badge",
        "attestation",
    }
)

# Brief §3.1 — ownership proof methods that prove genuine *ownership* of
# the underlying system (as opposed to mere *control of an account*).
# Production-capable authorization requires one of these methods.
_OWNERSHIP_PROVING_METHODS: frozenset[str] = frozenset({"dns_txt", "well_known_file", "sso_assertion"})


class Package:
    """ACEF Evidence Package builder.

    Usage:
        pkg = Package(producer={"name": "my-tool", "version": "1.0"})
        system = pkg.add_subject(subject_type="ai_system", name="My System")
        pkg.record("risk_register", provisions=["article-9"], payload={...})
        pkg.export("output.acef/")
    """

    def __init__(
        self,
        producer: dict[str, str] | ProducerInfo | None = None,
        *,
        retention_policy: dict[str, Any] | RetentionPolicy | None = None,
        prior_package_ref: str | None = None,
        clock: Callable[[], datetime] | None = None,
        urn_generator: Callable[[URNType], str] | None = None,
        redaction_policy: Any = None,
    ) -> None:
        """Build an empty Package.

        Args:
            producer: Tool/organization metadata.
            retention_policy: Package-level retention requirements.
            prior_package_ref: URN of a prior version of this package.
            clock: Optional callable returning the current
                :class:`datetime` (timezone-aware). When provided, replaces
                the default ``datetime.now(timezone.utc)`` for all
                timestamps minted by this builder (record envelopes,
                audit-trail entries, package metadata). Enables byte-
                deterministic export per VAL-SDK-007.
            urn_generator: Optional callable taking a
                :class:`acef.models.urns.URNType` and returning a URN
                string. When provided, replaces the default
                :func:`acef.models.urns.generate_urn` for all URN minting
                by this builder (``package_id``, ``record_id``, and the
                payload identifiers minted by the v1.1 typed builders).
                Enables byte-deterministic export per VAL-SDK-007.
            redaction_policy: Optional
                :class:`acef.redaction.RedactionPolicy` attached to this
                package. When attached, :meth:`record` auto-populates the
                X1 envelope field (``redaction_policy_version``) and the
                X2 field (``redaction_attestation_ref``) for any record
                whose ``confidentiality`` is not ``public``, also
                appending a Core ``event_log`` attestation record (per
                VAL-REDACTION-003 / 004 — no vendor namespace introduced).
                Typed as ``Any`` here to avoid an import cycle with
                ``acef.redaction``; the runtime check at use-time
                enforces the actual class.
        """
        # Stash injection callables BEFORE building metadata so the
        # metadata's timestamp / package_id come from the injected
        # implementations rather than the model's default factories.
        self._clock: Callable[[], datetime] = clock or _default_clock
        self._urn_generator: Callable[[URNType], str] = urn_generator or generate_urn

        if producer is None:
            producer = ProducerInfo(name="acef-sdk", version="0.1.0")
        elif isinstance(producer, dict):
            producer = ProducerInfo(**producer)

        retention = None
        if retention_policy is not None:
            if isinstance(retention_policy, dict):
                retention = RetentionPolicy(**retention_policy)
            else:
                retention = retention_policy

        self._metadata = PackageMetadata(
            package_id=self._urn_generator(URNType.PACKAGE),
            timestamp=_format_timestamp(self._clock()),
            producer=producer,
            prior_package_ref=prior_package_ref,
            retention_policy=retention,
        )
        self._versioning = Versioning()
        self._subjects: list[Subject] = []
        self._entities = EntitiesBlock()
        self._profiles: list[ProfileEntry] = []
        self._records: list[RecordEnvelope] = []
        self._audit_trail: list[AuditTrailEntry] = []
        self._attachments: dict[str, bytes] = {}  # path -> content
        self._signed = False
        self._signature_key: str | None = None
        self._signature_method: str | None = None
        # Stash any attached RedactionPolicy so Package.record() can
        # auto-populate the X1/X2 envelope fields (VAL-REDACTION-003).
        # Typed as ``Any`` to avoid an import cycle with acef.redaction.
        self._redaction_policy: Any = redaction_policy

        # Add creation audit entry
        self._audit_trail.append(
            AuditTrailEntry(
                event_type=AuditEventType.CREATED,
                timestamp=self._metadata.timestamp,
                description="Initial package creation",
            )
        )

    # ------------------------------------------------------------------
    # Injection helpers (private)
    # ------------------------------------------------------------------

    def _now_iso(self) -> str:
        """Return ``self._clock()`` formatted per spec §3.1."""
        return _format_timestamp(self._clock())

    def _mint_record_urn(self) -> str:
        """Mint a record URN via the injected URN generator."""
        return self._urn_generator(URNType.RECORD)

    @property
    def metadata(self) -> PackageMetadata:
        return self._metadata

    @property
    def versioning(self) -> Versioning:
        """Public read-only access to versioning info."""
        return self._versioning

    @property
    def subjects(self) -> list[Subject]:
        return list(self._subjects)

    @property
    def entities(self) -> EntitiesBlock:
        return self._entities

    @property
    def records(self) -> list[RecordEnvelope]:
        return list(self._records)

    @property
    def profiles(self) -> list[ProfileEntry]:
        return list(self._profiles)

    @property
    def audit_trail(self) -> list[AuditTrailEntry]:
        """Public read-only access to audit trail entries."""
        return list(self._audit_trail)

    @property
    def attachments(self) -> dict[str, bytes]:
        """Public read-only access to attachment content."""
        return dict(self._attachments)

    @property
    def is_signed(self) -> bool:
        """Whether this package is marked for signing during export."""
        return self._signed

    @property
    def signing_key(self) -> str | None:
        """Path to the signing key, if signing is enabled."""
        return self._signature_key

    def add_subject(
        self,
        subject_type: str | SubjectType,
        name: str,
        *,
        version: str = "1.0.0",
        provider: str = "",
        risk_classification: str | RiskClassification = RiskClassification.MINIMAL_RISK,
        modalities: list[str] | None = None,
        lifecycle_phase: str | LifecyclePhase = LifecyclePhase.DEVELOPMENT,
        lifecycle_timeline: list[dict[str, str]] | None = None,
    ) -> Subject:
        """Add a subject (AI system or model) to the package.

        Returns:
            The created Subject with generated URN.
        """
        if isinstance(subject_type, str):
            subject_type = SubjectType(subject_type)
        if isinstance(risk_classification, str):
            risk_classification = RiskClassification(risk_classification)
        if isinstance(lifecycle_phase, str):
            lifecycle_phase = LifecyclePhase(lifecycle_phase)

        timeline = []
        if lifecycle_timeline:
            timeline = [LifecycleEntry.model_validate(entry) for entry in lifecycle_timeline]

        subject = Subject(
            subject_id=self._urn_generator(URNType.SUBJECT),
            subject_type=subject_type,
            name=name,
            version=version,
            provider=provider,
            risk_classification=risk_classification,
            modalities=modalities or [],
            lifecycle_phase=lifecycle_phase,
            lifecycle_timeline=timeline,
        )
        self._subjects.append(subject)
        return subject

    def add_component(
        self,
        name: str,
        type: str | ComponentType,
        *,
        version: str = "1.0.0",
        subject_refs: list[str] | None = None,
        provider: str = "",
    ) -> Component:
        """Add a component entity to the package.

        Returns:
            The created Component with generated URN.
        """
        if isinstance(type, str):
            type = ComponentType(type)

        component = Component(
            component_id=self._urn_generator(URNType.COMPONENT),
            name=name,
            type=type,
            version=version,
            subject_refs=subject_refs or [],
            provider=provider,
        )
        self._entities.components.append(component)
        return component

    def add_dataset(
        self,
        name: str,
        *,
        version: str = "1.0.0",
        source_type: str | DatasetSourceType = DatasetSourceType.LICENSED,
        modality: str | DatasetModality = DatasetModality.TEXT,
        size: dict[str, Any] | None = None,
        subject_refs: list[str] | None = None,
    ) -> Dataset:
        """Add a dataset entity to the package.

        Returns:
            The created Dataset with generated URN.
        """
        if isinstance(source_type, str):
            source_type = DatasetSourceType(source_type)
        if isinstance(modality, str):
            modality = DatasetModality(modality)

        dataset = Dataset(
            dataset_id=self._urn_generator(URNType.DATASET),
            name=name,
            version=version,
            source_type=source_type,
            modality=modality,
            size=size or {"records": 0, "size_gb": 0.0},
            subject_refs=subject_refs or [],
        )
        self._entities.datasets.append(dataset)
        return dataset

    def add_actor(
        self,
        name: str = "",
        *,
        role: str | ActorRole = ActorRole.PROVIDER,
        organization: str = "",
    ) -> Actor:
        """Add an actor entity to the package.

        Returns:
            The created Actor with generated URN.
        """
        if isinstance(role, str):
            role = ActorRole(role)

        actor = Actor(
            actor_id=self._urn_generator(URNType.ACTOR),
            name=name,
            role=role,
            organization=organization,
        )
        self._entities.actors.append(actor)
        return actor

    def add_relationship(
        self,
        source_ref: str,
        target_ref: str,
        relationship_type: str | RelationshipType,
        *,
        description: str = "",
    ) -> Relationship:
        """Add a relationship between entities.

        Returns:
            The created Relationship.
        """
        if isinstance(relationship_type, str):
            relationship_type = RelationshipType(relationship_type)

        rel = Relationship(
            source_ref=source_ref,
            target_ref=target_ref,
            relationship_type=relationship_type,
            description=description,
        )
        self._entities.relationships.append(rel)
        return rel

    def add_profile(
        self,
        profile_id: str,
        *,
        provisions: list[str] | None = None,
        template_version: str = "1.0.0",
    ) -> ProfileEntry:
        """Declare a regulation profile for this package.

        Returns:
            The created ProfileEntry.
        """
        entry = ProfileEntry(
            profile_id=profile_id,
            template_version=template_version,
            applicable_provisions=provisions or [],
        )
        self._profiles.append(entry)
        return entry

    def record(
        self,
        record_type: str,
        *,
        provisions: list[str] | None = None,
        payload: dict[str, Any] | None = None,
        obligation_role: str | ObligationRole | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        redaction_method: str | None = None,
        access_policy: dict[str, Any] | None = None,
        trust_level: str | TrustLevel = TrustLevel.SELF_ATTESTED,
        lifecycle_phase: str | LifecyclePhase | None = None,
        collector: dict[str, str] | CollectorInfo | None = None,
        attachments: list[dict[str, Any] | AttachmentRef] | None = None,
        attestation: dict[str, Any] | Attestation | None = None,
        retention: dict[str, Any] | RecordRetention | None = None,
        timestamp: str | None = None,
        record_id: str | None = None,
        redaction_policy_version: str | None = None,
        redaction_attestation_ref: str | None = None,
    ) -> RecordEnvelope:
        """Record an evidence record.

        Args:
            record_type: One of the 16 ACEF v1 record types.
            provisions: Regulatory provisions this evidence supports.
            payload: The type-specific evidence payload.
            obligation_role: Who produced this evidence.
            entity_refs: Links to subjects, components, datasets, actors.
            confidentiality: Evidence confidentiality level.
            trust_level: Evidence trust provenance.
            lifecycle_phase: Which lifecycle phase this relates to.
            collector: Tool/person that collected this evidence.
            attachments: File references in artifacts/.
            attestation: Cryptographic attestation.
            retention: Per-record retention requirements.
            timestamp: Override timestamp (ISO 8601). When ``None``, the
                envelope timestamp is minted by the package's injected
                ``clock`` (or the default wall clock if no injection).
            record_id: Override record_id URN. When ``None``, the
                envelope record_id is minted by the package's injected
                ``urn_generator`` (or the default ``generate_urn`` if no
                injection). Caller-supplied IDs win.

        Returns:
            The created RecordEnvelope.

        Raises:
            ACEFSchemaError: If record_type is not recognized.
            ACEFError: If timestamp is not valid ISO 8601.
        """
        # Validate record type - allow extension types with x- prefix
        if record_type not in RECORD_TYPES and not record_type.startswith("x-"):
            raise ACEFSchemaError(
                f"Unknown record_type: {record_type!r}",
                code="ACEF-003",
            )

        # Resolve the schema-required envelope fields when callers omit
        # them, so SDK-produced records carry concrete values rather than
        # relying on to_jsonl_dict's emit-time defaults (which exist as a
        # safety net for direct RecordEnvelope construction).
        if obligation_role is None:
            obligation_role = ObligationRole.PROVIDER
        elif isinstance(obligation_role, str):
            obligation_role = ObligationRole(obligation_role)
        if isinstance(confidentiality, str):
            confidentiality = Confidentiality(confidentiality)
        if isinstance(trust_level, str):
            trust_level = TrustLevel(trust_level)
        if lifecycle_phase is None:
            lifecycle_phase = LifecyclePhase.DEVELOPMENT
        elif isinstance(lifecycle_phase, str):
            lifecycle_phase = LifecyclePhase(lifecycle_phase)

        if isinstance(entity_refs, dict):
            entity_refs = EntityRefs(**entity_refs)
        elif entity_refs is None:
            entity_refs = EntityRefs()

        if collector is None:
            # Default collector to the package's producer info if available.
            producer_name = self.metadata.producer.name if self.metadata and self.metadata.producer else "unknown"
            producer_version = self.metadata.producer.version if self.metadata and self.metadata.producer else ""
            collector = CollectorInfo(name=producer_name, version=producer_version)
        elif isinstance(collector, dict):
            collector = CollectorInfo(**collector)

        parsed_attachments: list[AttachmentRef] = []
        if attachments:
            for att in attachments:
                if isinstance(att, dict):
                    parsed_attachments.append(AttachmentRef(**att))
                else:
                    parsed_attachments.append(att)

        if isinstance(attestation, dict):
            attestation = Attestation(**attestation)
        if isinstance(retention, dict):
            retention = RecordRetention(**retention)

        # Resolve record_id + timestamp BEFORE RecordEnvelope construction
        # so the injected clock/URN generator are honored instead of the
        # model's default factories (which would otherwise mint random
        # uuid4-based URNs + wall-clock timestamps).
        if timestamp is not None:
            try:
                datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except (ValueError, AttributeError) as e:
                raise ACEFError(
                    f"Invalid ISO 8601 timestamp: {timestamp!r}",
                    code="ACEF-050",
                ) from e
            resolved_timestamp = timestamp
        else:
            resolved_timestamp = self._now_iso()

        resolved_record_id = record_id if record_id is not None else self._mint_record_urn()

        # ------------------------------------------------------------------
        # VAL-REDACTION-003 — auto-populate X1/X2 on non-public records.
        #
        # When the caller flags this record as non-public (anything other
        # than Confidentiality.PUBLIC), the v1.1 validator's
        # cross_record.enforce_redaction_policy_version /
        # enforce_redaction_attestation_ref will demand the X1
        # (redaction_policy_version) and X2 (redaction_attestation_ref)
        # envelope fields. We auto-populate them here so SDK callers do
        # not have to remember the wiring:
        #
        #   1. X1 resolves from an explicit kwarg OR the package's
        #      attached RedactionPolicy.version. If neither is available
        #      we raise ValueError immediately — the SDK refuses to mint
        #      a record the validator will then reject.
        #
        #   2. X2 resolves from an explicit kwarg OR from a freshly-
        #      generated event_log attestation record (via
        #      acef.redaction.apply_redaction). The attestation record
        #      reuses the Core event_log record_type — no vendor
        #      namespace is introduced (VAL-REDACTION-004).
        # ------------------------------------------------------------------
        resolved_policy_version: str | None = redaction_policy_version
        resolved_attestation_ref: str | None = redaction_attestation_ref

        is_non_public = confidentiality != Confidentiality.PUBLIC

        # Version-gating: X1/X2 are v1.1 additions (spec §8.1
        # conditional-required keyed on manifest.versioning.core_version).
        # v1.0 bundles have no schema for these fields and the v1.1
        # cross-record validator does not run against them — auto-
        # populating would emit fields v1.0 readers must ignore. Skip the
        # entire block unless the package declares v1.1+. Caller-supplied
        # X1/X2 kwargs still flow through to RecordEnvelope below; the
        # gate only suppresses *auto*-population.
        try:
            core_v = self._versioning.core_version
            v1_1_or_later = isinstance(core_v, str) and core_v >= "1.1"
        except AttributeError:
            v1_1_or_later = False

        if is_non_public and v1_1_or_later:
            policy = self._redaction_policy
            # ---- X1: redaction_policy_version ----
            if resolved_policy_version is None:
                if policy is None:
                    raise ValueError(
                        "Package.record(confidentiality="
                        f"{confidentiality.value!r}) requires "
                        "redaction_policy_version. Either pass it "
                        "explicitly as a kwarg, or attach a "
                        "RedactionPolicy to the Package via "
                        "Package(redaction_policy=...) — non-public "
                        "records without X1 fail validator ACEF-074."
                    )
                policy_version_attr = getattr(policy, "version", None)
                if not isinstance(policy_version_attr, str) or not policy_version_attr:
                    raise ValueError(
                        "Package.record: attached redaction_policy does "
                        "not expose a non-empty .version string; cannot "
                        "auto-populate redaction_policy_version."
                    )
                resolved_policy_version = policy_version_attr

            # ---- X2: redaction_attestation_ref ----
            if resolved_attestation_ref is None:
                if policy is None:
                    # We already raised above when policy is None and
                    # resolved_policy_version was None. But if the caller
                    # supplied X1 explicitly we still need a way to
                    # produce X2 — without a policy we cannot mint the
                    # event_log attestation. Caller must supply X2 too.
                    raise ValueError(
                        "Package.record(confidentiality="
                        f"{confidentiality.value!r}) requires "
                        "redaction_attestation_ref. Either pass it "
                        "explicitly as a kwarg, or attach a "
                        "RedactionPolicy to the Package via "
                        "Package(redaction_policy=...) so the SDK can "
                        "mint a Core event_log attestation record."
                    )
                # Lazy import — acef.redaction imports Package, so we
                # must not import at module load time.
                from acef.redaction import apply_redaction

                _redacted_payload, attestation_record = apply_redaction(
                    payload or {},
                    policy,
                    clock=self._clock,
                    urn_generator=self._urn_generator,
                )
                self._records.append(attestation_record)
                resolved_attestation_ref = attestation_record.record_id

        envelope = RecordEnvelope(
            record_id=resolved_record_id,
            record_type=record_type,
            provisions_addressed=provisions or [],
            payload=payload or {},
            obligation_role=obligation_role,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            redaction_method=redaction_method,
            access_policy=access_policy,
            trust_level=trust_level,
            lifecycle_phase=lifecycle_phase,
            collector=collector,
            attachments=parsed_attachments,
            attestation=attestation,
            retention=retention,
            timestamp=resolved_timestamp,
            redaction_policy_version=resolved_policy_version,
            redaction_attestation_ref=resolved_attestation_ref,
        )

        self._records.append(envelope)
        return envelope

    # ------------------------------------------------------------------
    # v1.1 typed builders (F-M1-SDK-BUILDERS)
    #
    # These five methods wrap :meth:`record` with Pydantic-validated
    # payloads and SDK-side pre-flight checks for the brief §3 cross-
    # field rules. Each method:
    #   1. Runs the brief-specified cross-field rule check (which Pydantic
    #      cannot express) — raises ValueError BEFORE any state mutation.
    #   2. Runs the relevant Pydantic payload model — raises ValueError
    #      (via :class:`pydantic.ValidationError`, which subclasses
    #      :class:`ValueError`) for shape/enum violations.
    #   3. Delegates to :meth:`record` with ``record_type`` set, the
    #      validated payload, and any envelope-level kwargs forwarded.
    # ------------------------------------------------------------------

    def authorize_test_scope(
        self,
        *,
        scope_id: str,
        scope_version: str,
        subject_ref: str,
        authorized_surfaces: list[dict[str, Any]],
        authorized_identities: list[dict[str, Any]],
        side_effect_policy: dict[str, Any],
        sandbox_boundary: dict[str, Any],
        ownership_proof: dict[str, Any],
        effective_from: str,
        authorizing_actor_ref: str,
        effective_until: str | None = None,
        kill_switch_ref: str | None = None,
        provisions: list[str] | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        obligation_role: str | ObligationRole | None = None,
        timestamp: str | None = None,
    ) -> RecordEnvelope:
        """Add an ``authorized_test_scope`` record (brief §3.1).

        Enforces the brief §3.1 cross-field rules BEFORE the record is
        appended to the bundle:

        - If any ``authorized_surfaces[*].authorization_level`` is
          ``production_capable_owner_authorized``, then
          ``ownership_proof.proof_method`` MUST be one of
          ``dns_txt``, ``well_known_file``, or ``sso_assertion`` (the
          three methods that prove genuine ownership; ``github_oauth``
          and ``http_header`` prove account control but not system
          ownership) — TC-FRD-001-N1.
        - If any surface is production-capable, ``kill_switch_ref``
          MUST be a non-empty string — TC-FRD-001-N2.

        Raises:
            ValueError: If either cross-field rule fails, or if the
                payload fails Pydantic validation. The record is NOT
                appended to ``self._records`` in either case.
        """
        # ---- Cross-field rules (brief §3.1) — run BEFORE Pydantic ----
        has_production_capable = any(
            isinstance(s, dict) and s.get("authorization_level") == "production_capable_owner_authorized"
            for s in authorized_surfaces
        )
        if has_production_capable:
            method = ownership_proof.get("proof_method") if isinstance(ownership_proof, dict) else None
            if method not in _OWNERSHIP_PROVING_METHODS:
                raise ValueError(
                    "authorized_test_scope rejected: "
                    "authorization_level='production_capable_owner_authorized' "
                    f"requires ownership_proof.proof_method in {sorted(_OWNERSHIP_PROVING_METHODS)!r}; "
                    f"got {method!r} (brief §3.1 TC-FRD-001-N1)."
                )
            if not (isinstance(kill_switch_ref, str) and kill_switch_ref):
                raise ValueError(
                    "authorized_test_scope rejected: "
                    "authorization_level='production_capable_owner_authorized' "
                    "requires kill_switch_ref (non-empty URN) "
                    "(brief §3.1 TC-FRD-001-N2)."
                )

        # ---- Pydantic validation ----
        payload_dict: dict[str, Any] = {
            "scope_id": scope_id,
            "scope_version": scope_version,
            "subject_ref": subject_ref,
            "authorized_surfaces": authorized_surfaces,
            "authorized_identities": authorized_identities,
            "side_effect_policy": side_effect_policy,
            "sandbox_boundary": sandbox_boundary,
            "ownership_proof": ownership_proof,
            "effective_from": effective_from,
            "authorizing_actor_ref": authorizing_actor_ref,
        }
        if effective_until is not None:
            payload_dict["effective_until"] = effective_until
        if kill_switch_ref is not None:
            payload_dict["kill_switch_ref"] = kill_switch_ref

        try:
            validated = AuthorizedTestScopePayload.model_validate(payload_dict)
        except ValidationError as e:
            raise ValueError(f"authorized_test_scope payload failed validation: {e}") from e

        return self.record(
            record_type="authorized_test_scope",
            payload=validated.model_dump(mode="json", exclude_none=True),
            provisions=provisions,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            obligation_role=obligation_role,
            timestamp=timestamp,
        )

    def record_scope_boundary_event(
        self,
        *,
        scope_ref: str,
        attempted_action: dict[str, Any],
        authorized_scope_snapshot: dict[str, Any],
        classification: str,
        hard_stop_triggered: bool,
        detected_at: str,
        detector: dict[str, Any],
        event_id: str | None = None,
        hard_stop_attestation_ref: str | None = None,
        provisions: list[str] | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        obligation_role: str | ObligationRole | None = None,
        timestamp: str | None = None,
    ) -> RecordEnvelope:
        """Add a ``scope_boundary_event`` record (brief §3.2).

        Enforces the brief §3.2 conditional rule BEFORE the record is
        appended: when ``hard_stop_triggered=True``,
        ``hard_stop_attestation_ref`` MUST be a non-empty URN.

        Raises:
            ValueError: If the conditional rule fails, or if the payload
                fails Pydantic validation. The record is NOT appended.
        """
        # ---- Cross-field rule (brief §3.2) ----
        if hard_stop_triggered and not (isinstance(hard_stop_attestation_ref, str) and hard_stop_attestation_ref):
            raise ValueError(
                "scope_boundary_event rejected: hard_stop_triggered=True "
                "requires a non-empty hard_stop_attestation_ref URN "
                "(brief §3.2)."
            )

        if event_id is None:
            event_id = self._mint_record_urn()

        payload_dict: dict[str, Any] = {
            "event_id": event_id,
            "scope_ref": scope_ref,
            "attempted_action": attempted_action,
            "authorized_scope_snapshot": authorized_scope_snapshot,
            "classification": classification,
            "hard_stop_triggered": hard_stop_triggered,
            "detected_at": detected_at,
            "detector": detector,
        }
        if hard_stop_attestation_ref is not None:
            payload_dict["hard_stop_attestation_ref"] = hard_stop_attestation_ref

        try:
            validated = ScopeBoundaryEventPayload.model_validate(payload_dict)
        except ValidationError as e:
            raise ValueError(f"scope_boundary_event payload failed validation: {e}") from e

        return self.record(
            record_type="scope_boundary_event",
            payload=validated.model_dump(mode="json", exclude_none=True),
            provisions=provisions,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            obligation_role=obligation_role,
            timestamp=timestamp,
        )

    def record_finding(
        self,
        *,
        class_: str,
        subject_ref: str,
        expected_behavior: str,
        reproduction_steps_ref_content_hash: str,
        severity: dict[str, Any],
        reproduction: dict[str, Any],
        attribution: dict[str, Any],
        discovered_at: str,
        discovered_in_run_ref: str,
        finding_id: str | None = None,
        variant_group_id: str | None = None,
        regulation_impact: list[str] | None = None,
        disposition_history: list[str] | None = None,
        accepted_risk_ref: str | None = None,
        regression_ref: str | None = None,
        provisions: list[str] | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        obligation_role: str | ObligationRole | None = None,
        timestamp: str | None = None,
    ) -> RecordEnvelope:
        """Add a ``finding_record`` (brief §3.3) with auto-computed
        ``dedupe_key``.

        The dedupe_key recipe is normative per brief Q5 / design
        decision D5::

            dedupe_key = "sha256:" + hex(SHA-256(JCS-canonicalize({
                "class": class_,
                "subject_ref": subject_ref,
                "expected_behavior": expected_behavior,
                "reproduction_steps_ref_content_hash":
                    reproduction_steps_ref_content_hash,
            })))

        The computation uses :func:`acef.integrity.canonicalize` (RFC
        8785 JCS) and has no entropy source — two identical-input calls
        produce byte-equal ``dedupe_key``.

        Note: ``class_`` is the Python parameter name (``class`` is
        reserved). The Pydantic model field is ``finding_class``; the
        dedupe_key recipe per brief uses the JSON key ``class``.
        """
        # Compute dedupe_key BEFORE Pydantic validation — the payload
        # model requires the field to be present and matching the
        # ^sha256:[0-9a-f]{64}$ pattern.
        recipe = {
            "class": class_,
            "subject_ref": subject_ref,
            "expected_behavior": expected_behavior,
            "reproduction_steps_ref_content_hash": reproduction_steps_ref_content_hash,
        }
        canonical = canonicalize(recipe)
        dedupe_key = "sha256:" + hashlib.sha256(canonical).hexdigest()

        if finding_id is None:
            finding_id = self._mint_record_urn()

        payload_dict: dict[str, Any] = {
            "finding_id": finding_id,
            "finding_class": class_,
            "subject_ref": subject_ref,
            "severity": severity,
            "dedupe_key": dedupe_key,
            "reproduction": reproduction,
            "attribution": attribution,
            "discovered_at": discovered_at,
            "discovered_in_run_ref": discovered_in_run_ref,
        }
        if variant_group_id is not None:
            payload_dict["variant_group_id"] = variant_group_id
        if regulation_impact is not None:
            payload_dict["regulation_impact"] = regulation_impact
        if disposition_history is not None:
            payload_dict["disposition_history"] = disposition_history
        if accepted_risk_ref is not None:
            payload_dict["accepted_risk_ref"] = accepted_risk_ref
        if regression_ref is not None:
            payload_dict["regression_ref"] = regression_ref

        try:
            validated = FindingRecordPayload.model_validate(payload_dict)
        except ValidationError as e:
            raise ValueError(f"finding_record payload failed validation: {e}") from e

        return self.record(
            record_type="finding_record",
            payload=validated.model_dump(mode="json", exclude_none=True),
            provisions=provisions,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            obligation_role=obligation_role,
            timestamp=timestamp,
        )

    def record_delivery_verdict(
        self,
        *,
        finding_ref: str,
        destination: dict[str, Any],
        write_attempt: dict[str, Any],
        delivery_state: str,
        verdict_id: str | None = None,
        read_back: dict[str, Any] | None = None,
        harness_attestation_ref: str | None = None,
        drift_classification: str | None = None,
        retry_history: list[dict[str, Any]] | None = None,
        provisions: list[str] | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        obligation_role: str | ObligationRole | None = None,
        timestamp: str | None = None,
    ) -> RecordEnvelope:
        """Add a ``delivery_verdict`` record (brief §3.4).

        Enforces two cross-field rules BEFORE the record is appended:

        1. If ``read_back`` is provided, ``read_back.read_back_digest``
           MUST equal ``write_attempt.request_digest``. A mismatch
           raises immediately so the bundle never contains a
           self-inconsistent verdict.
        2. If ``delivery_state == "verified_delivered"``, ALL of the
           following MUST hold per brief §3.4:
           - ``read_back`` is provided (not None)
           - ``read_back.digest_match`` is exactly True
           - ``harness_attestation_ref`` is a non-empty URN

        Raises:
            ValueError: For either rule above, or for Pydantic shape
                violations. The record is NOT appended in any failure
                case.
        """
        # Rule 1: read-back digest equality — applies whenever a
        # read_back block is present, regardless of delivery_state.
        if isinstance(read_back, dict):
            req_digest = write_attempt.get("request_digest") if isinstance(write_attempt, dict) else None
            rb_digest = read_back.get("read_back_digest")
            if req_digest is not None and rb_digest is not None and req_digest != rb_digest:
                raise ValueError(
                    "delivery_verdict rejected: read-back digest mismatch — "
                    f"write_attempt.request_digest={req_digest!r} but "
                    f"read_back.read_back_digest={rb_digest!r}. A delivery "
                    "verdict with self-inconsistent digests MUST NOT enter "
                    "the bundle (brief §3.4)."
                )

        # Rule 2: verified_delivered triple-requirement (brief §3.4).
        if delivery_state == "verified_delivered":
            problems: list[str] = []
            if not isinstance(read_back, dict):
                problems.append("read_back is missing")
            elif read_back.get("digest_match") is not True:
                problems.append(f"read_back.digest_match must be exactly True (got {read_back.get('digest_match')!r})")
            if not (isinstance(harness_attestation_ref, str) and harness_attestation_ref):
                problems.append("harness_attestation_ref is missing or empty")
            if problems:
                raise ValueError(
                    "delivery_verdict rejected: delivery_state='verified_delivered' "
                    "requires read_back + read_back.digest_match=True + "
                    f"harness_attestation_ref; problems: {problems!r} "
                    "(brief §3.4)."
                )

        if verdict_id is None:
            verdict_id = self._mint_record_urn()

        payload_dict: dict[str, Any] = {
            "verdict_id": verdict_id,
            "finding_ref": finding_ref,
            "destination": destination,
            "write_attempt": write_attempt,
            "delivery_state": delivery_state,
        }
        if read_back is not None:
            payload_dict["read_back"] = read_back
        if drift_classification is not None:
            payload_dict["drift_classification"] = drift_classification
        if retry_history is not None:
            payload_dict["retry_history"] = retry_history
        if harness_attestation_ref is not None:
            payload_dict["harness_attestation_ref"] = harness_attestation_ref

        try:
            validated = DeliveryVerdictPayload.model_validate(payload_dict)
        except ValidationError as e:
            raise ValueError(f"delivery_verdict payload failed validation: {e}") from e

        return self.record(
            record_type="delivery_verdict",
            payload=validated.model_dump(mode="json", exclude_none=True),
            provisions=provisions,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            obligation_role=obligation_role,
            timestamp=timestamp,
        )

    def attest(
        self,
        *,
        state_class: str,
        state_transition: dict[str, Any],
        bound_evidence_refs: list[str],
        verifier: dict[str, Any],
        claim: str,
        fake_green_test_ref: str | None,
        attestation_signature: dict[str, Any],
        signed_at: str,
        signer_kid: str,
        attestation_id: str | None = None,
        provisions: list[str] | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        obligation_role: str | ObligationRole | None = None,
        timestamp: str | None = None,
    ) -> RecordEnvelope:
        """Add a ``harness_attestation`` record (brief §3.6).

        Enforces the following SDK-side pre-flight checks BEFORE the
        record is appended:

        - ``state_class`` MUST be one of the seven values in the brief
          Q3 taxonomy (VAL-SCHEMA-009). Mirrors validator ACEF-076.
        - ``verifier.verifier_class`` MUST NOT be ``persona`` or ``llm``
          (brief §3.6, VAL-LOAD-001/002). Mirrors loader's ACEF-070
          LoadRejection at SDK build time.
        - ``bound_evidence_refs`` MUST be a non-empty list (VAL-SDK-005,
          brief TC8 — state-class records require >=1 binding).
        - ``fake_green_test_ref`` MUST be a non-empty string for any
          state_class (VAL-SDK-006).

        Raises:
            ValueError: For any of the above, or for Pydantic shape
                violations. The record is NOT appended.
        """
        # Pre-flight checks ordered so the most informative error
        # surfaces first.
        if state_class not in _STATE_CLASS_TAXONOMY:
            raise ValueError(
                f"harness_attestation rejected: state_class={state_class!r} "
                f"is not in the brief Q3 taxonomy {sorted(_STATE_CLASS_TAXONOMY)!r} "
                "(VAL-SCHEMA-009)."
            )

        verifier_class = verifier.get("verifier_class") if isinstance(verifier, dict) else None
        if verifier_class in _BANNED_VERIFIER_CLASSES:
            raise ValueError(
                f"harness_attestation rejected: verifier_class={verifier_class!r} "
                "is banned — persona and LLM verifiers lack the determinism "
                "required to attest state transitions (brief §3.6, "
                "VAL-LOAD-001/002)."
            )

        # VAL-SDK-005 — state-class records require >=1 ref.
        if not bound_evidence_refs:
            raise ValueError(
                f"harness_attestation rejected: state_class={state_class!r} "
                "record requires bound_evidence_refs with at least one entry "
                "(VAL-SDK-005, brief TC8)."
            )

        # VAL-SDK-006 — fake_green_test_ref required for any state_class.
        if not (isinstance(fake_green_test_ref, str) and fake_green_test_ref):
            raise ValueError(
                f"harness_attestation rejected: state_class={state_class!r} "
                "record requires a non-empty fake_green_test_ref "
                "(VAL-SDK-006)."
            )

        if attestation_id is None:
            attestation_id = self._mint_record_urn()

        payload_dict: dict[str, Any] = {
            "attestation_id": attestation_id,
            "state_class": state_class,
            "state_transition": state_transition,
            "bound_evidence_refs": bound_evidence_refs,
            "verifier": verifier,
            "claim": claim,
            "fake_green_test_ref": fake_green_test_ref,
            "attestation_signature": attestation_signature,
            "signed_at": signed_at,
            "signer_kid": signer_kid,
        }

        try:
            validated = HarnessAttestationPayload.model_validate(payload_dict)
        except ValidationError as e:
            raise ValueError(f"harness_attestation payload failed validation: {e}") from e

        return self.record(
            record_type="harness_attestation",
            payload=validated.model_dump(mode="json", exclude_none=True),
            provisions=provisions,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            obligation_role=obligation_role,
            timestamp=timestamp,
        )

    def add_attachment(self, path: str, content: bytes) -> None:
        """Add an attachment file to be included in artifacts/.

        Args:
            path: Relative path within artifacts/ (e.g., 'eval-report-v3.pdf').
            content: Raw file content.

        Raises:
            ACEFError: If the path contains traversal sequences, backslashes, or is absolute.
        """
        # Validate raw input path BEFORE prefix — catch absolute paths and traversal
        # on the raw caller-supplied value
        _validate_raw_attachment_path(path)

        if not path.startswith("artifacts/"):
            path = f"artifacts/{path}"

        # Validate final path — defense in depth
        _validate_attachment_path(path)

        self._attachments[path] = content

    def sign(self, key: str, *, method: str = "jws") -> None:
        """Mark this package for signing during export.

        The actual signing happens during export() when the content hashes
        are computed.

        Args:
            key: Path to the private key file (PEM format).
            method: Signing method ('jws' only for v1).
        """
        self._signed = True
        self._signature_key = key
        self._signature_method = method

    def build_manifest(self) -> Manifest:
        """Build the Manifest object from current package state.

        Uses the same deterministic sharding algorithm as the export module
        to ensure manifest record_files paths match actual file layout.

        Returns:
            A Manifest ready for serialization.
        """
        from acef.records_util import compute_shard_boundaries, sort_records

        # Build record_files index by grouping records by type
        records_by_type: dict[str, list[RecordEnvelope]] = {}
        for rec in self._records:
            records_by_type.setdefault(rec.record_type, []).append(rec)

        record_files: list[RecordFileEntry] = []
        for record_type, recs in sorted(records_by_type.items()):
            sorted_recs = sort_records(recs)
            shards = compute_shard_boundaries(sorted_recs)

            if len(shards) == 1:
                path = f"records/{record_type}.jsonl"
                record_files.append(RecordFileEntry(path=path, record_type=record_type, count=len(shards[0])))
            else:
                for i, shard in enumerate(shards):
                    shard_num = str(i + 1).zfill(4)
                    path = f"records/{record_type}/{record_type}.{shard_num}.jsonl"
                    record_files.append(RecordFileEntry(path=path, record_type=record_type, count=len(shard)))

        return Manifest(
            metadata=self._metadata,
            versioning=self._versioning,
            subjects=self._subjects,
            entities=self._entities,
            profiles=self._profiles,
            record_files=record_files,
            audit_trail=self._audit_trail,
        )

    def export(self, path: str) -> None:
        """Export the package to a directory or archive.

        If path ends with .tar.gz, exports as an archive.
        Otherwise, exports as a directory bundle.

        Args:
            path: Output path (directory or .acef.tar.gz).
        """
        from acef.export import export_archive, export_directory

        if path.endswith(".tar.gz"):
            export_archive(self, path)
        else:
            export_directory(self, path)

    @classmethod
    def _init_from_parts(
        cls,
        *,
        metadata: PackageMetadata,
        versioning: Versioning,
        subjects: list[Subject],
        entities: EntitiesBlock,
        profiles: list[ProfileEntry],
        records: list[RecordEnvelope],
        audit_trail: list[AuditTrailEntry],
        attachments: dict[str, bytes] | None = None,
    ) -> Package:
        """Create a Package from pre-parsed parts (deserialization path).

        This is the approved way for loader.py, merge.py, and redaction.py
        to construct Package instances without reaching into private attributes.

        Args:
            metadata: Fully constructed PackageMetadata.
            versioning: Versioning info.
            subjects: List of Subject instances.
            entities: EntitiesBlock with all entity types.
            profiles: List of ProfileEntry instances.
            records: List of RecordEnvelope instances.
            audit_trail: List of AuditTrailEntry instances.
            attachments: Dict mapping artifact paths to bytes content.

        Returns:
            A fully constructed Package.
        """
        pkg = cls.__new__(cls)
        # Seed injection callables with their defaults so post-load
        # callers can still invoke record() / typed builders without
        # AttributeError. Loaded packages are not expected to be
        # extended in deterministic-output workflows; callers wanting
        # deterministic post-load edits should construct a fresh
        # Package(clock=, urn_generator=) and re-add records.
        pkg._clock = _default_clock
        pkg._urn_generator = generate_urn
        pkg._metadata = metadata
        pkg._versioning = versioning
        pkg._subjects = list(subjects)
        pkg._entities = entities
        pkg._profiles = list(profiles)
        pkg._records = list(records)
        pkg._audit_trail = list(audit_trail)
        pkg._attachments = dict(attachments) if attachments else {}
        pkg._signed = False
        pkg._signature_key = None
        pkg._signature_method = None
        # _init_from_parts is the deserialization path — loaded packages
        # do not carry the source-side RedactionPolicy. Seed to None so
        # Package.record() can read the attribute without AttributeError.
        pkg._redaction_policy = None
        return pkg


def _validate_raw_attachment_path(path: str) -> None:
    """Validate raw caller-supplied attachment path before prefix is applied.

    Rejects:
    - Absolute paths (starting with '/')
    - Path traversal sequences ('..' segments)
    - Current-directory segments ('.' segments)
    - Backslash separators (spec 3.1.1: forward slashes only)

    Args:
        path: The raw caller-supplied path.

    Raises:
        ACEFError: If the path is unsafe.
    """
    # M4 (Implementer R2): Reject backslash separators per spec 3.1.1
    if "\\" in path:
        raise ACEFError(
            f"Backslash separators not allowed in attachment path (use forward slashes): {path!r}",
            code="ACEF-052",
        )

    if path.startswith("/"):
        raise ACEFError(
            f"Absolute attachment path not allowed: {path!r}",
            code="ACEF-052",
        )

    segments = path.split("/")
    for segment in segments:
        if segment == "..":
            raise ACEFError(
                f"Path traversal detected in attachment path: {path!r}",
                code="ACEF-052",
            )
        if segment == ".":
            raise ACEFError(
                f"Current-directory segment (.) not allowed in attachment path: {path!r}",
                code="ACEF-052",
            )


def _validate_attachment_path(path: str) -> None:
    """Validate a final attachment path for safety.

    Rejects:
    - Absolute paths (starting with '/')
    - Path traversal sequences ('..' segments)
    - Current-directory segments ('.' segments)
    - Paths not under artifacts/
    - Backslash separators (spec 3.1.1: forward slashes only)

    Args:
        path: The attachment path to validate (with artifacts/ prefix).

    Raises:
        ACEFError: If the path is unsafe.
    """
    # M4 (Implementer R2): Reject backslash separators per spec 3.1.1
    if "\\" in path:
        raise ACEFError(
            f"Backslash separators not allowed in attachment path (use forward slashes): {path!r}",
            code="ACEF-052",
        )

    if path.startswith("/"):
        raise ACEFError(
            f"Absolute attachment path not allowed: {path!r}",
            code="ACEF-052",
        )

    segments = path.split("/")
    for segment in segments:
        if segment == "..":
            raise ACEFError(
                f"Path traversal detected in attachment path: {path!r}",
                code="ACEF-052",
            )
        if segment == ".":
            raise ACEFError(
                f"Current-directory segment (.) not allowed in attachment path: {path!r}",
                code="ACEF-052",
            )

    if not path.startswith("artifacts/"):
        raise ACEFError(
            f"Attachment path must be under artifacts/: {path!r}",
            code="ACEF-052",
        )
