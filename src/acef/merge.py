"""ACEF merge module — multi-source evidence merging with conflict detection.

Merges evidence from multiple ACEF packages into a single package.
Detects and reports conflicts per ACEF-060.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from acef.errors import ACEFMergeError, ValidationDiagnostic
from acef.integrity import sha256_hex
from acef.models.entities import EntitiesBlock
from acef.models.enums import AuditEventType
from acef.models.manifest import AuditTrailEntry, ProfileEntry
from acef.models.metadata import PackageMetadata, ProducerInfo, Versioning
from acef.models.records import RecordEnvelope
from acef.models.subjects import Subject
from acef.models.urns import URNType, parse_urn, validate_urn
from acef.package import Package

# RFC 4122 §4.3 name-based (v5) namespace for ACEF merge package identifiers.
# Stable, project-scoped namespace so a deterministic merge package_id derives
# purely from the sorted input package_ids — never from uuid4()/wall clock.
_MERGE_PACKAGE_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "urn:acef:merge")


class MergeResult:
    """Result of a package merge operation."""

    def __init__(self, package: Package, conflicts: list[ValidationDiagnostic]) -> None:
        self.package = package
        self.conflicts = conflicts

    @property
    def has_conflicts(self) -> bool:
        return len(self.conflicts) > 0


def _timestamp_is_newer_or_equal(new_ts: str, old_ts: str) -> bool:
    """Compare two ISO 8601 timestamps, returning True if new >= old.

    Uses proper datetime parsing. Raises ACEFMergeError if either timestamp
    fails to parse, rather than falling back to lexicographic comparison
    which would produce nonsense results for malformed timestamps.

    Args:
        new_ts: The candidate newer timestamp.
        old_ts: The candidate older timestamp.

    Returns:
        True if new_ts is newer than or equal to old_ts.

    Raises:
        ACEFMergeError: If either timestamp cannot be parsed as ISO 8601.
    """
    try:
        new_dt = datetime.fromisoformat(new_ts.replace("Z", "+00:00"))
        old_dt = datetime.fromisoformat(old_ts.replace("Z", "+00:00"))
        return new_dt >= old_dt
    except (ValueError, AttributeError):
        raise ACEFMergeError(
            f"Cannot compare timestamps for keep_latest: {new_ts!r} vs {old_ts!r}",
            code="ACEF-060",
        )


def _normalize_explicit_package_id(package_id: str) -> str:
    """Validate + canonicalize a caller-supplied merged ``package_id``.

    The frozen manifest schema requires a lowercase ``urn:acef:pkg:<uuid>``.
    ``validate_urn`` alone is too permissive on two axes:

    1. It accepts ANY ACEF URN type (e.g. ``urn:acef:rec:...``) — a record URN
       would fail manifest schema validation. We REQUIRE ``URNType.PACKAGE``.
    2. RFC 4122 textual form permits uppercase hex, so ``validate_urn`` accepts
       an uppercase UUID — but the schema pattern pins lowercase hex. We
       canonicalize the UUID segment to lowercase so the merged package_id
       always satisfies the schema.

    Returns the canonical ``urn:acef:pkg:<lowercase-uuid>``.

    Raises:
        ACEFMergeError: If ``package_id`` is not a syntactically valid ACEF URN
            or is not a PACKAGE-typed URN.
    """
    if not validate_urn(package_id):
        raise ACEFMergeError(
            f"Invalid merged package_id URN: {package_id!r}",
            code="ACEF-060",
        )
    parsed = parse_urn(package_id)
    if parsed.urn_type is not URNType.PACKAGE:
        raise ACEFMergeError(
            f"Merged package_id must be a package URN (urn:acef:{URNType.PACKAGE.value}:<uuid>), got {package_id!r}",
            code="ACEF-060",
        )
    # Canonicalize the UUID segment to lowercase so the result matches the
    # frozen manifest schema's lowercase-hex pattern even if the caller passed
    # an (RFC-4122-legal) uppercase UUID.
    return f"urn:acef:{URNType.PACKAGE.value}:{parsed.uuid_str.lower()}"


def _normalize_explicit_timestamp(timestamp: str) -> str:
    """Validate + canonicalize a caller-supplied merged ``timestamp``.

    Applies the SAME ISO-8601 parse the derived-timestamp path uses
    (``_derive_merged_timestamp``) and renders the canonical UTC
    ``%Y-%m-%dT%H:%M:%SZ`` form, so an explicit override cannot bypass the
    parsing/canonicalization and inject an invalid or non-canonical instant
    into the merged metadata + audit entries.

    Raises:
        ACEFMergeError: If ``timestamp`` cannot be parsed as ISO 8601.
    """
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise ACEFMergeError(
            f"Invalid explicit merged timestamp (not ISO 8601): {timestamp!r}",
            code="ACEF-060",
        )
    # A naive instant (no offset) is treated as UTC, matching the derived path.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _derive_merged_package_id(packages: list[Package]) -> str:
    """Mint a deterministic merge package_id from the input package_ids.

    The id is a name-based (RFC 4122 v5) UUID over the SORTED, newline-joined
    input package_ids under a fixed ACEF-merge namespace, rendered as
    ``urn:acef:pkg:<uuid5>``. Two merges of the same logical inputs therefore
    produce a byte-identical package_id regardless of input order, and the
    output is lowercase-hex so it satisfies the frozen manifest URN pattern.
    No uuid4()/wall clock is used on this byte-stable path.
    """
    sorted_ids = sorted(pkg.metadata.package_id for pkg in packages)
    seed = "\n".join(sorted_ids)
    derived = uuid.uuid5(_MERGE_PACKAGE_NAMESPACE, seed)
    return f"urn:acef:{URNType.PACKAGE.value}:{derived}"


def _derive_merged_timestamp(packages: list[Package]) -> str:
    """Return the latest (max) input timestamp, deterministically.

    Parses each input timestamp as ISO 8601 and returns the canonical
    ``%Y-%m-%dT%H:%M:%SZ`` rendering of the maximum, so the merged timestamp
    is reproducible across runs (no wall clock). Raises ACEFMergeError if any
    input timestamp cannot be parsed, rather than falling back to a nonsense
    lexicographic max.
    """
    latest_dt: datetime | None = None
    for pkg in packages:
        ts = pkg.metadata.timestamp
        try:
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            raise ACEFMergeError(
                f"Cannot derive merged timestamp from unparseable input timestamp: {ts!r}",
                code="ACEF-060",
            )
        if latest_dt is None or parsed > latest_dt:
            latest_dt = parsed
    # latest_dt is non-None: merge_packages rejects an empty package list first.
    assert latest_dt is not None
    # Normalize to UTC so the canonical 'Z' rendering is correct even if an
    # input carried a non-UTC offset (e.g. '+02:00').
    return latest_dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def merge_packages(
    packages: list[Package],
    *,
    producer: dict[str, str] | None = None,
    conflict_strategy: str = "keep_latest",
    package_id: str | None = None,
    timestamp: str | None = None,
) -> MergeResult:
    """Merge multiple ACEF packages into one.

    Accumulates all data in local collections, then constructs the merged
    package via Package._init_from_parts() to avoid reaching into private
    attributes (M-R2-2).

    The merged package identity is byte-stable: when ``package_id`` /
    ``timestamp`` are not supplied, ``package_id`` is derived deterministically
    from the SORTED input package_ids (a name-based UUIDv5 URN) and
    ``timestamp`` is the maximum input timestamp. Two merges of the same logical
    inputs therefore produce a byte-identical merged bundle (no uuid4()/wall
    clock), satisfying the determinism requirement (loader-roundtrip-6).

    Args:
        packages: List of packages to merge.
        producer: Producer info for the merged package.
        conflict_strategy: How to handle conflicts:
            - 'keep_latest': Keep the record with the latest timestamp
            - 'keep_all': Keep all records (may have duplicates)
            - 'fail': Raise on any conflict
        package_id: Explicit merged package_id URN. Defaults to a deterministic
            URN derived from the input package_ids.
        timestamp: Explicit merged timestamp (ISO 8601). Defaults to the latest
            input timestamp.

    Returns:
        A MergeResult with the merged package and any conflicts.

    Raises:
        ACEFMergeError: If no packages are provided, if conflict_strategy
            is 'fail' and a conflict is detected, if an unknown strategy is
            used, or if an explicit ``package_id`` is not a valid ACEF URN.
    """
    if not packages:
        raise ACEFMergeError("No packages to merge", code="ACEF-060")

    # Validate conflict strategy
    valid_strategies = {"keep_latest", "keep_all", "fail"}
    if conflict_strategy not in valid_strategies:
        raise ACEFMergeError(
            f"Unknown conflict_strategy: {conflict_strategy!r}. Must be one of: {', '.join(sorted(valid_strategies))}",
            code="ACEF-060",
        )

    if producer is None:
        producer = {"name": "acef-merger", "version": "0.1.0"}

    # Deterministic merged identity (loader-roundtrip-6): derive from inputs
    # unless the caller supplied explicit values. An explicit package_id is
    # validated as a PACKAGE-typed URN and lowercased; an explicit timestamp is
    # parsed + canonicalized to UTC ...Z — so neither override can slip an
    # identity past the frozen manifest schema (roborev MEDIUM/LOW).
    merged_package_id = (
        _normalize_explicit_package_id(package_id) if package_id is not None else _derive_merged_package_id(packages)
    )
    merged_timestamp = (
        _normalize_explicit_timestamp(timestamp) if timestamp is not None else _derive_merged_timestamp(packages)
    )

    conflicts: list[ValidationDiagnostic] = []

    # Pre-build a lookup for package timestamps (N-R2-3: avoid O(n) scan per duplicate)
    pkg_timestamps: dict[str, str] = {pkg.metadata.package_id: pkg.metadata.timestamp for pkg in packages}

    # Accumulate all data in local collections
    merged_subjects: list[Subject] = []
    merged_entities = EntitiesBlock()
    # Profiles keyed by profile_id so duplicate declarations union their
    # applicable_provisions rather than first-wins (loader-roundtrip-9). The
    # accumulator stores (first-seen ProfileEntry, provisions-set, owning_pkg_id).
    # The first-seen entry is retained verbatim (deep copy) so vendor x-*
    # extensions survive; only applicable_provisions is recomputed at the end.
    merged_profiles: dict[str, tuple[ProfileEntry, set[str], str]] = {}
    # Records carry their owning package INDEX (not package_id) so that, after
    # keep_all relocates a conflicting artifact, we rewrite ONLY that owner's
    # record→artifact refs to the relocated path (roborev HIGH). The index is the
    # input-package position — unique per input INSTANCE even when two inputs
    # share a package_id, so a duplicate-id input cannot collapse two packages'
    # relocation maps into one (roborev MEDIUM). The element is
    # (owning_pkg_index, RecordEnvelope copy).
    merged_records: list[tuple[int, RecordEnvelope]] = []
    # Attachments keyed by path -> (content, owning_pkg_id) so we can compare
    # bytes and resolve same-path/different-bytes conflicts (loader-roundtrip-7).
    merged_attachments: dict[str, tuple[bytes, str]] = {}
    # Per-package keep_all relocations: owning_pkg_INDEX -> {original_path ->
    # relocated_path}. Keyed by input index (not package_id) so two inputs that
    # share a package_id keep SEPARATE relocation maps and each package's records
    # rewrite to their OWN relocated bytes (roborev MEDIUM). Populated in the
    # attachment-merge loop and applied to the owner's record attachment refs
    # AFTER the main loop, so a record copied before its artifact was relocated
    # still ends up pointing at the relocated bytes (roborev HIGH).
    relocations: dict[int, dict[str, str]] = {}

    # Track what we've seen for conflict detection
    seen_subjects: dict[str, tuple[str, Any]] = {}  # name+type -> (pkg_id, subject)
    seen_entities: dict[str, str] = {}  # entity_id -> pkg_id
    # For records: track record_id -> (pkg_id, record) so we can compare timestamps
    seen_records: dict[str, tuple[str, RecordEnvelope]] = {}
    # Dedup relationships by (source_ref, target_ref, type) — see below.
    seen_relationships: set[tuple[str, str, str]] = set()

    for pkg_index, pkg in enumerate(packages):
        pkg_id = pkg.metadata.package_id

        # Merge subjects (using public .subjects property)
        for subject in pkg.subjects:
            key = f"{subject.name}:{subject.subject_type.value}"
            if key in seen_subjects:
                conflicts.append(
                    ValidationDiagnostic(
                        "ACEF-060",
                        f"Duplicate subject {key!r} from packages {seen_subjects[key][0]} and {pkg_id}",
                    )
                )
                if conflict_strategy == "fail":
                    raise ACEFMergeError(f"Conflict: duplicate subject {key!r}", code="ACEF-060")
                elif conflict_strategy == "keep_latest":
                    old_pkg_id = seen_subjects[key][0]
                    old_pkg_ts = pkg_timestamps.get(old_pkg_id, "")
                    new_pkg_ts = pkg.metadata.timestamp
                    if _timestamp_is_newer_or_equal(new_pkg_ts, old_pkg_ts):
                        # New package is same age or newer — replace
                        merged_subjects = [
                            s
                            for s in merged_subjects
                            if not (s.name == subject.name and s.subject_type == subject.subject_type)
                        ]
                        seen_subjects[key] = (pkg_id, subject)
                        merged_subjects.append(subject.model_copy(deep=True))
                    # else: old is newer, keep it (already in merged_subjects)
                elif conflict_strategy == "keep_all":
                    merged_subjects.append(subject.model_copy(deep=True))
            else:
                seen_subjects[key] = (pkg_id, subject)
                merged_subjects.append(subject.model_copy(deep=True))

        # Merge entities (using public .entities property)
        for comp in pkg.entities.components:
            if comp.component_id not in seen_entities:
                seen_entities[comp.component_id] = pkg_id
                merged_entities.components.append(comp.model_copy(deep=True))

        for ds in pkg.entities.datasets:
            if ds.dataset_id not in seen_entities:
                seen_entities[ds.dataset_id] = pkg_id
                merged_entities.datasets.append(ds.model_copy(deep=True))

        for actor in pkg.entities.actors:
            if actor.actor_id not in seen_entities:
                seen_entities[actor.actor_id] = pkg_id
                merged_entities.actors.append(actor.model_copy(deep=True))

        for rel in pkg.entities.relationships:
            # Dedup by (source_ref, target_ref, relationship_type). Multiple
            # source packages declaring the same edge collapse to a single
            # entry in the merged graph (P2 from structural review).
            rel_type = (
                rel.relationship_type.value if hasattr(rel.relationship_type, "value") else str(rel.relationship_type)
            )
            rel_key = (rel.source_ref, rel.target_ref, rel_type)
            if rel_key not in seen_relationships:
                seen_relationships.add(rel_key)
                merged_entities.relationships.append(rel.model_copy(deep=True))

        # Merge profiles (using public .profiles property). Duplicate profile_id
        # declarations UNION their applicable_provisions instead of first-wins,
        # and a differing template_version raises ACEF-060 so the divergence is
        # visible rather than silently dropped (loader-roundtrip-9).
        for profile in pkg.profiles:
            if profile.profile_id in merged_profiles:
                first_entry, existing_provisions, first_pkg_id = merged_profiles[profile.profile_id]
                if profile.template_version != first_entry.template_version:
                    conflicts.append(
                        ValidationDiagnostic(
                            "ACEF-060",
                            f"Conflicting template_version for profile {profile.profile_id!r}: "
                            f"{first_entry.template_version!r} (from {first_pkg_id}) vs "
                            f"{profile.template_version!r} (from {pkg_id})",
                        )
                    )
                    if conflict_strategy == "fail":
                        raise ACEFMergeError(
                            f"Conflict: profile {profile.profile_id!r} template_version "
                            f"{first_entry.template_version!r} vs {profile.template_version!r}",
                            code="ACEF-060",
                        )
                existing_provisions.update(profile.applicable_provisions)
            else:
                merged_profiles[profile.profile_id] = (
                    profile.model_copy(deep=True),
                    set(profile.applicable_provisions),
                    pkg_id,
                )

        # Merge records (using public .records property)
        for record in pkg.records:
            if record.record_id in seen_records:
                conflicts.append(
                    ValidationDiagnostic(
                        "ACEF-060",
                        f"Duplicate record_id: {record.record_id!r}",
                    )
                )
                if conflict_strategy == "fail":
                    raise ACEFMergeError(
                        f"Conflict: duplicate record {record.record_id!r}",
                        code="ACEF-060",
                    )
                elif conflict_strategy == "keep_latest":
                    old_pkg_id, old_record = seen_records[record.record_id]
                    if _timestamp_is_newer_or_equal(record.timestamp, old_record.timestamp):
                        # New record is same age or newer — replace
                        merged_records = [r for r in merged_records if r[1].record_id != record.record_id]
                        seen_records[record.record_id] = (pkg_id, record)
                        merged_records.append((pkg_index, record.model_copy(deep=True)))
                    # else: old record is newer, keep it
                elif conflict_strategy == "keep_all":
                    merged_records.append((pkg_index, record.model_copy(deep=True)))
            else:
                seen_records[record.record_id] = (pkg_id, record)
                merged_records.append((pkg_index, record.model_copy(deep=True)))

        # Merge attachments (using public .attachments property). Same path +
        # IDENTICAL bytes is idempotent (no conflict). Same path + DIFFERENT
        # bytes is an ACEF-060 conflict resolved per conflict_strategy instead
        # of silent first-wins data loss (loader-roundtrip-7).
        for att_path, content in pkg.attachments.items():
            if att_path not in merged_attachments:
                merged_attachments[att_path] = (content, pkg_id)
                continue
            existing_content, first_pkg_id = merged_attachments[att_path]
            if existing_content == content:
                # Identical bytes — idempotent, nothing to resolve.
                continue
            conflicts.append(
                ValidationDiagnostic(
                    "ACEF-060",
                    f"Conflicting attachment at {att_path!r}: different bytes from "
                    f"packages {first_pkg_id} and {pkg_id}",
                )
            )
            if conflict_strategy == "fail":
                raise ACEFMergeError(
                    f"Conflict: attachment {att_path!r} has different bytes in {first_pkg_id} and {pkg_id}",
                    code="ACEF-060",
                )
            elif conflict_strategy == "keep_latest":
                first_ts = pkg_timestamps.get(first_pkg_id, "")
                if _timestamp_is_newer_or_equal(pkg.metadata.timestamp, first_ts):
                    # Incoming package is same age or newer — replace.
                    merged_attachments[att_path] = (content, pkg_id)
                # else: keep the existing (newer) attachment.
            elif conflict_strategy == "keep_all":
                # Relocate the incoming attachment under a deterministic,
                # package-scoped subpath so both byte streams survive. The
                # owning package's UUID keeps the relocated path schema-valid
                # (forward slashes, relative, NFC, no '..').
                base_target = _relocate_attachment_path(att_path, pkg_id)
                # The base target is NOT guaranteed unique: an input package may
                # already hold a real artifact there (e.g. a re-merge of a prior
                # merged bundle), OR two inputs sharing a package_id derive the
                # SAME target. Resolve a collision-free, content-hash-derived
                # final path so a different-bytes collision never overwrites the
                # pre-existing/colliding artifact, while identical bytes stay
                # idempotent (same path) (roborev MEDIUM).
                relocated = _resolve_collision_free_target(base_target, content, merged_attachments)
                merged_attachments[relocated] = (content, pkg_id)
                # Record the relocation so this package's records that referenced
                # the ORIGINAL path get rewritten to the FINAL relocated path
                # below; otherwise they would point at the FIRST package's
                # (different) bytes and the relocated bytes would be orphaned
                # (roborev HIGH). Keyed by pkg_index so a duplicate package_id
                # does not merge two inputs' relocation maps (roborev MEDIUM).
                relocations.setdefault(pkg_index, {})[att_path] = relocated

    # Deterministic merged metadata (loader-roundtrip-6).
    merged_metadata = PackageMetadata(
        package_id=merged_package_id,
        timestamp=merged_timestamp,
        producer=ProducerInfo(**producer),
    )

    # Merge-specific audit trail with a deterministic timestamp — do NOT label a
    # merge as 'Initial package creation' (loader-roundtrip-10).
    merge_audit_trail = [
        AuditTrailEntry(
            event_type=AuditEventType.UPDATED,
            timestamp=merged_timestamp,
            description=f"Merged from {len(packages)} packages",
        ),
    ]

    # Resolve accumulators back into the shapes _init_from_parts expects.
    # Rebuild each profile from its first-seen entry (preserving vendor x-*
    # extensions) with the deterministically-sorted union of provisions.
    resolved_profiles = [
        first_entry.model_copy(update={"applicable_provisions": sorted(provisions)})
        for _profile_id, (first_entry, provisions, _owner) in sorted(merged_profiles.items())
    ]
    resolved_attachments = {path: content for path, (content, _owner) in merged_attachments.items()}

    # Apply keep_all relocations to each owning package's record→artifact refs
    # so every record's attachments[].path resolves to its OWN (relocated) bytes
    # and no relocated artifact is left unreferenced (roborev HIGH). Keyed by the
    # owning package INDEX so duplicate package_ids never cross-rewrite one
    # package's records to another package's relocated bytes (roborev MEDIUM).
    # Records from packages with no relocations pass through unchanged.
    resolved_records = [
        _rewrite_record_attachment_refs(record, relocations.get(owner_pkg_index, {}))
        for owner_pkg_index, record in merged_records
    ]

    # Construct merged package via _init_from_parts (M-R2-2)
    merged = Package._init_from_parts(
        metadata=merged_metadata,
        versioning=Versioning(),
        subjects=merged_subjects,
        entities=merged_entities,
        profiles=resolved_profiles,
        records=resolved_records,
        audit_trail=merge_audit_trail,
        attachments=resolved_attachments,
    )

    return MergeResult(merged, conflicts)


def _rewrite_record_attachment_refs(record: RecordEnvelope, path_map: dict[str, str]) -> RecordEnvelope:
    """Rewrite a record's attachment refs through a relocation ``path_map``.

    ``path_map`` maps ``original_attachment_path -> relocated_path`` for the
    package that contributed ``record``. Any ``attachments[].path`` whose value
    was relocated under keep_all is repointed to the relocated path; all other
    paths (and records from packages with no relocations) are unchanged.

    ``attachments[].path`` is the ONLY in-record reference to an artifact path
    in the RecordEnvelope model (record-envelope.schema.json / AttachmentRef);
    entity_refs hold entity URNs, not artifact paths, so they need no rewrite.

    Returns the same record object when ``path_map`` is empty or no ref matched
    (no needless copy); otherwise a deep copy with rewritten attachment paths.
    """
    if not path_map or not record.attachments:
        return record
    if not any(att.path in path_map for att in record.attachments):
        return record
    rewritten = record.model_copy(deep=True)
    for att in rewritten.attachments:
        if att.path in path_map:
            att.path = path_map[att.path]
    return rewritten


def _relocate_attachment_path(att_path: str, pkg_id: str) -> str:
    """Build a deterministic, package-scoped relocation path for keep_all.

    Inserts the owning package's UUID under an ``artifacts/_merged/<uuid>/``
    prefix so a same-path/different-bytes attachment from a second package keeps
    a distinct, schema-valid path (forward slashes, relative, NFC, no ``..``).
    """
    # pkg_id is 'urn:acef:pkg:<uuid>'; fall back to the full id if unparseable.
    uuid_segment = pkg_id.rsplit(":", 1)[-1] if ":" in pkg_id else pkg_id
    if att_path.startswith("artifacts/"):
        remainder = att_path[len("artifacts/") :]
    else:
        remainder = att_path
    return f"artifacts/_merged/{uuid_segment}/{remainder}"


def _hash_disambiguated_target(base_target: str, content: bytes) -> str:
    """Insert a content-hash segment into ``base_target`` for disambiguation.

    Splits ``base_target`` into ``<dir>/<leaf>`` and inserts the SHA-256 hex of
    ``content`` as a path segment before the leaf:
    ``artifacts/_merged/<uuid>/<sha256>/<leaf>``. The hash is a pure function of
    the bytes, so identical bytes always derive the SAME path (idempotent) while
    different bytes derive distinct paths (no SHA-256 second-preimage in
    practice). The inserted segment is lowercase hex — schema-valid (forward
    slashes, relative, NFC, no '..').
    """
    digest = sha256_hex(content)
    head, sep, leaf = base_target.rpartition("/")
    if sep:
        return f"{head}/{digest}/{leaf}"
    # No '/' in base_target (defensive; relocation targets always contain one).
    return f"{digest}/{base_target}"


def _resolve_collision_free_target(
    base_target: str,
    content: bytes,
    merged_attachments: dict[str, tuple[bytes, str]],
) -> str:
    """Resolve a collision-free, deterministic keep_all relocation target.

    The package-scoped ``base_target`` from :func:`_relocate_attachment_path` is
    NOT guaranteed unique: an input package may already hold a real artifact
    there (a re-merge of a prior merged bundle, or a hand-crafted package), OR
    two inputs sharing a package_id derive the SAME target. Assigning
    ``merged_attachments[base_target]`` unconditionally would OVERWRITE the
    pre-existing/colliding bytes and leave records that referenced that target
    pointing at the wrong bytes (roborev MEDIUM).

    Resolution (deterministic — no random/wall-clock component, so two merges of
    the same inputs produce identical targets):

    * ``base_target`` free, or already holding IDENTICAL bytes  -> use it
      (idempotent: identical bytes collapse to one artifact).
    * otherwise -> a content-hash-disambiguated path
      (``.../<sha256>/<leaf>``). Identical bytes always map to the same hashed
      path (idempotent); different bytes get a distinct path. If even the hashed
      path is occupied by DIFFERENT bytes (only possible if an input deliberately
      pre-placed an artifact there), append further hash segments until free —
      guaranteeing a collision-free target for ANY input.

    Returns the final target path; the caller stores ``content`` there and maps
    the original ref to this path so record refs resolve to the correct bytes.
    """
    existing = merged_attachments.get(base_target)
    if existing is None or existing[0] == content:
        # Free target, or identical bytes already there (idempotent reuse).
        return base_target

    # Different bytes occupy base_target: derive a content-hash-disambiguated
    # path. Loop only to defend against an input that pre-placed DIFFERENT bytes
    # at the hashed path itself (a SHA-256 second-preimage otherwise).
    candidate = _hash_disambiguated_target(base_target, content)
    while True:
        occupant = merged_attachments.get(candidate)
        if occupant is None or occupant[0] == content:
            return candidate
        # Occupied by different bytes — extend deterministically by re-hashing.
        candidate = _hash_disambiguated_target(candidate, content)
