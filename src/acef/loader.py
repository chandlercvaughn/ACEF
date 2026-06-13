"""ACEF loader module — bundle deserialization and round-trip.

Loads ACEF Evidence Bundles from directories or .acef.tar.gz archives.
Implements security mitigations: path traversal rejection, tar bomb guards.
"""

from __future__ import annotations

import gzip
import json
import sys
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from acef.errors import ACEFFormatError
from acef.load_rejections import check_load_rejections
from acef.models.entities import Actor, Component, Dataset, EntitiesBlock, Relationship
from acef.models.manifest import AuditTrailEntry, ProfileEntry
from acef.models.metadata import PackageMetadata, ProducerInfo, RetentionPolicy, Versioning
from acef.models.records import (
    RecordEnvelope,
    dict_to_record_envelope,
)
from acef.models.subjects import LifecycleEntry, Subject
from acef.package import Package

# Tar bomb limits
_MAX_EXTRACTED_SIZE = 10 * 1024 * 1024 * 1024  # 10 GB
_MAX_FILE_COUNT = 100_000
_MAX_SINGLE_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB

# Artifact size guards
_MAX_ARTIFACT_FILE_SIZE = _MAX_SINGLE_FILE_SIZE  # 1 GB per file
_MAX_TOTAL_ARTIFACT_SIZE = _MAX_EXTRACTED_SIZE  # 10 GB cumulative (m8 Scout R2)


def _validate_path(path: str) -> None:
    """Validate a path per spec Section 3.1.1 path normalization rules.

    Rejects:
    - Empty paths
    - Paths containing '..' segments (traversal)
    - Paths containing '.' segments (current-dir, spec-forbidden)
    - Absolute paths (starting with '/')
    - Backslash separators (must use forward slash)
    - Embedded NUL bytes
    - Paths that are not strict UTF-8 (e.g. a JSON-decoded lone surrogate such
      as an escaped ``\\udce9`` — NFC-equal yet un-encodable as UTF-8) or not
      NFC-normalized (spec §3.1.1)

    The strict-UTF-8 + NFC text contract is delegated to the single source of
    truth :func:`acef.integrity.path_nfc_utf8_problem`, the same helper the
    producer-side validators use, so the consumer (load/validate) side cannot
    admit a surrogate-bearing manifest ``record_files`` path or record
    attachment path that the producer would reject.

    Raises:
        ACEFFormatError: If path violates normalization rules.
    """
    from acef.integrity import path_nfc_utf8_problem

    if not isinstance(path, str) or path == "":
        raise ACEFFormatError(
            f"Empty or non-string path: {path!r}",
            code="ACEF-052",
        )

    # Reject NUL bytes — these can confuse path APIs on some platforms.
    if "\x00" in path:
        raise ACEFFormatError(
            f"Path contains NUL byte: {path!r}",
            code="ACEF-052",
        )

    # Check for backslash separators
    if "\\" in path:
        raise ACEFFormatError(
            f"Path contains backslash separators (must use forward slash): {path!r}",
            code="ACEF-052",
        )

    # Check for absolute paths
    if path.startswith("/"):
        raise ACEFFormatError(
            f"Absolute path not allowed (must be relative to bundle root): {path!r}",
            code="ACEF-052",
        )

    # Spec §3.1.1: paths MUST be strict UTF-8 AND NFC-normalized. Delegate to
    # the shared helper so the consumer side rejects the same inputs the
    # producer does: a JSON-decoded lone surrogate is NFC-equal but NOT
    # encodable as UTF-8, so an NFC-only check would let it through. Reject non
    # strict-UTF-8 (surrogate) and non-NFC (HFS+ NFD vs ext4 NFC) alike so the
    # determinism contract holds.
    problem = path_nfc_utf8_problem(path)
    if problem is not None:
        raise ACEFFormatError(
            f"Path violates spec §3.1.1 ({problem}): {path!r}",
            code="ACEF-052",
        )

    # Check for . and .. segments per spec: "not contain . or .. segments"
    segments = path.split("/")
    for segment in segments:
        if segment == "..":
            raise ACEFFormatError(
                f"Path traversal detected (.. segment): {path!r}",
                code="ACEF-052",
            )
        if segment == ".":
            raise ACEFFormatError(
                f"Current-directory segment (.) not allowed in paths: {path!r}",
                code="ACEF-052",
            )
        if segment == "":
            # Empty segment from consecutive slashes or trailing slash.
            raise ACEFFormatError(
                f"Empty path segment (consecutive or trailing slash): {path!r}",
                code="ACEF-052",
            )


def _validate_tar_safety(tar: tarfile.TarFile) -> None:
    """Validate tar archive for bomb protection and traversal safety.

    Rejects any member that is not a regular file or a directory. This
    closes the gap noted by the structural review: tarfile's
    ``filter="data"`` is only available on Python 3.12+, and the prior
    implementation accepted device, FIFO, character/block-device, and
    other special members without complaint. On a pre-3.12 runtime that
    would create the special node on disk during extraction.

    Checks:
    - Only regular files and directories permitted (no symlinks, hard
      links, devices, FIFOs, char/block devices, or any other special
      type)
    - Empty member name rejected
    - No NUL byte, no backslash separator, no leading slash, no '..' or
      '.' segment, no empty segment (defense-in-depth alongside
      :func:`_validate_path`)
    - Total extracted size <= 10 GB; file count <= 100,000; no single
      file > 1 GB

    Raises:
        ACEFFormatError: If any safety check fails.
    """
    total_size = 0
    file_count = 0

    for member in tar.getmembers():
        # Reject symlinks, hard links, and ALL special types (device,
        # FIFO, char/block device, anything not a regular file or dir).
        if member.issym() or member.islnk():
            raise ACEFFormatError(
                f"Symlinks/hardlinks not allowed in ACEF archives: {member.name}",
                code="ACEF-052",
            )
        if not (member.isfile() or member.isdir()):
            raise ACEFFormatError(
                f"Special tar member type not allowed (only files/dirs): {member.name!r} type={member.type!r}",
                code="ACEF-052",
            )

        if not member.name:
            raise ACEFFormatError(
                "Tar member has empty name",
                code="ACEF-052",
            )
        if "\x00" in member.name:
            raise ACEFFormatError(
                f"Tar member name contains NUL byte: {member.name!r}",
                code="ACEF-052",
            )
        if "\\" in member.name:
            raise ACEFFormatError(
                f"Tar member uses backslash separator (must use forward slash): {member.name!r}",
                code="ACEF-052",
            )

        # Path traversal + absolute-path check.
        if member.name.startswith("/"):
            raise ACEFFormatError(
                f"Absolute path in archive: {member.name}",
                code="ACEF-052",
            )
        segments = member.name.split("/")
        for seg in segments:
            if seg == "..":
                raise ACEFFormatError(
                    f"Traversal segment (..) in archive: {member.name}",
                    code="ACEF-052",
                )
            if seg == ".":
                raise ACEFFormatError(
                    f"Current-directory segment (.) in archive: {member.name}",
                    code="ACEF-052",
                )
            # The last segment may legitimately be empty when a directory
            # member is written with a trailing slash (some tar tools do
            # this). All earlier empty segments indicate consecutive
            # slashes and are rejected.
        if "//" in member.name:
            raise ACEFFormatError(
                f"Consecutive slashes in archive path: {member.name}",
                code="ACEF-052",
            )

        if member.isfile():
            file_count += 1
            total_size += member.size

            if member.size > _MAX_SINGLE_FILE_SIZE:
                raise ACEFFormatError(
                    f"File exceeds 1 GB limit: {member.name} ({member.size} bytes)",
                    code="ACEF-050",
                )

    if file_count > _MAX_FILE_COUNT:
        raise ACEFFormatError(
            f"Archive contains too many files: {file_count} (limit: {_MAX_FILE_COUNT})",
            code="ACEF-050",
        )

    if total_size > _MAX_EXTRACTED_SIZE:
        raise ACEFFormatError(
            f"Archive total size exceeds 10 GB limit: {total_size} bytes",
            code="ACEF-050",
        )


def _safe_tar_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract ``tar`` into ``dest`` with a containment guard for every member.

    On Python 3.12+ we use the stdlib ``filter='data'`` extraction filter,
    which performs the spec's intended safety checks. On older runtimes
    we extract one member at a time, asserting that the resolved
    destination path stays inside ``dest`` (defense in depth alongside
    :func:`_validate_tar_safety`).
    """
    dest = dest.resolve()
    if sys.version_info >= (3, 12):
        tar.extractall(dest, filter="data")
        return

    for member in tar.getmembers():
        # _validate_tar_safety has already vetted special types and traversal
        # segments, but re-check the resolved destination as a final guard
        # against platform-specific surprises (e.g., Windows path handling).
        member_path = (dest / member.name).resolve()
        try:
            member_path.relative_to(dest)
        except ValueError as exc:
            raise ACEFFormatError(
                f"Tar member escapes extraction root: {member.name}",
                code="ACEF-052",
            ) from exc
        tar.extract(member, dest)


def _resolve_bundle_root(extract_dir: Path) -> Path:
    """Resolve the bundle root inside a freshly extracted archive directory.

    The canonical archive layout nests the whole bundle under a single root
    directory; in that case the root is that nested directory. Otherwise the
    extraction directory itself is the bundle root. Single source of truth for
    the bundle-root rule shared by ``_load_archive`` (load path) and
    :func:`extract_archive_raw` (validate/verify path).
    """
    extracted = list(extract_dir.iterdir())
    if len(extracted) == 1 and extracted[0].is_dir():
        return extracted[0]
    return extract_dir


@contextmanager
def extract_archive_raw(archive_path: str | Path) -> Iterator[Path]:
    """Safely extract an ``.acef.tar.gz`` archive VERBATIM and yield its bundle
    root directory for the duration of the ``with`` block.

    This is the single shared raw-safe-extract primitive used by every consumer
    that must validate the archive's bytes AS RECEIVED — the public
    ``acef.validate`` archive path and the ``validate`` / ``verify`` CLI
    commands. It reuses the loader's vetted safety primitives
    (:func:`_validate_tar_safety` + :func:`_safe_tar_extract`), the SAME
    safe-extract path :func:`load` uses, so no second, unsafe extractor exists.

    Crucially it extracts the archive bytes EXACTLY as received: it does NOT
    round-trip through :func:`load` + :meth:`acef.package.Package.export`, which
    would regenerate ``hashes/content-hashes.json`` / ``hashes/merkle-tree.json``
    from the loaded records and SILENTLY HEAL any tampering (a stripped Merkle
    tree, a content-hash mismatch) before the integrity verifier ran. Validating
    the raw extracted directory makes archive inputs produce the SAME integrity
    verdict as the equivalent directory bundle (ACEF-010 hash mismatch, ACEF-011
    missing/invalid Merkle tree, etc.).

    The temporary directory is removed when the ``with`` block exits, so callers
    MUST run validation against the yielded path inside the block.

    Raises:
        ACEFFormatError: If the archive is malformed/corrupt or fails a tar
            safety check (ACEF-050 / ACEF-052).
    """
    archive = Path(archive_path)
    if not archive.exists():
        raise ACEFFormatError(f"Archive not found: {archive}", code="ACEF-050")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            extract_dir = Path(tmpdir)
            with tarfile.open(str(archive), "r:gz") as tar:
                _validate_tar_safety(tar)
                _safe_tar_extract(tar, extract_dir)
            yield _resolve_bundle_root(extract_dir)
    except ACEFFormatError:
        raise
    except (tarfile.TarError, gzip.BadGzipFile, OSError) as e:
        raise ACEFFormatError(
            f"Malformed or corrupt archive: {archive}: {e}",
            code="ACEF-050",
        ) from e


def _parse_jsonl(path: Path) -> list[dict[str, Any]]:
    """Parse a JSONL file into a list of record dicts.

    Args:
        path: Path to the JSONL file.

    Returns:
        List of parsed JSON objects.

    Raises:
        ACEFFormatError: If a line is not valid JSON.
    """
    records: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ACEFFormatError(
                    f"Malformed JSONL at {path}:{line_num}: {e}",
                    code="ACEF-050",
                ) from e
    return records


def load(path: str) -> Package:
    """Load an ACEF Evidence Bundle from a directory or archive.

    Args:
        path: Path to a bundle directory or .acef.tar.gz archive.

    Returns:
        A Package reconstructed from the bundle.

    Raises:
        ACEFFormatError: If the bundle is malformed.
        ACEFSchemaError: If the manifest is invalid.
    """
    bundle_path = Path(path)

    if bundle_path.suffix == ".gz" or str(bundle_path).endswith(".tar.gz"):
        return _load_archive(bundle_path)
    elif bundle_path.is_dir():
        return _load_directory(bundle_path)
    else:
        raise ACEFFormatError(f"Not a directory or .tar.gz archive: {path}")


def _load_archive(archive_path: Path) -> Package:
    """Load from a .acef.tar.gz archive.

    Raises:
        ACEFFormatError: If the archive is malformed, corrupt, or not a valid
            gzip/tar archive (ACEF-050).
    """
    if not archive_path.exists():
        raise ACEFFormatError(f"Archive not found: {archive_path}", code="ACEF-050")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            with tarfile.open(str(archive_path), "r:gz") as tar:
                _validate_tar_safety(tar)
                _safe_tar_extract(tar, Path(tmpdir))

            # Find the bundle root via the shared resolver.
            bundle_dir = _resolve_bundle_root(Path(tmpdir))

            return _load_directory(bundle_dir)

    except ACEFFormatError:
        raise
    except (tarfile.TarError, gzip.BadGzipFile, OSError) as e:
        raise ACEFFormatError(
            f"Malformed or corrupt archive: {archive_path}: {e}",
            code="ACEF-050",
        ) from e


def _load_directory(bundle_dir: Path) -> Package:
    """Load from a directory bundle."""
    manifest_path = bundle_dir / "acef-manifest.json"
    if not manifest_path.exists():
        raise ACEFFormatError(
            f"No acef-manifest.json found in {bundle_dir}",
            code="ACEF-002",
        )

    try:
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ACEFFormatError(f"Invalid JSON in manifest: {e}", code="ACEF-050") from e

    def _extras(raw: dict[str, Any], known: set[str]) -> dict[str, Any]:
        """Return a dict of keys in ``raw`` that are not in ``known``.

        With models inheriting :class:`ACEFBaseModel` (``extra='allow'``),
        these extra keys are preserved on the constructed model and emit
        unchanged on round-trip, satisfying spec §6.4 rule 5
        ("ACEF Evidence Bundle export MUST be lossless to the open core").
        """
        return {k: v for k, v in raw.items() if k not in known}

    # Parse manifest
    metadata_raw = manifest_data.get("metadata", {})
    producer_raw = metadata_raw.get("producer", {})
    producer = ProducerInfo(**producer_raw)

    retention_raw = metadata_raw.get("retention_policy")
    retention = RetentionPolicy(**retention_raw) if retention_raw else None

    # Build metadata. Pass through any unknown metadata-object keys (vendor
    # x-* extensions, the spec's own metadata.created_at, future fields) via
    # **_extras so they survive load→export round-trip — PackageMetadata is an
    # ACEFBaseModel (extra='allow'). Without this passthrough the metadata
    # layer silently drops vendor extensions (loader-roundtrip-2 / §6.4).
    metadata_known = {
        "package_id",
        "timestamp",
        "producer",
        "prior_package_ref",
        "retention_policy",
    }
    metadata = PackageMetadata(
        producer=producer,
        retention_policy=retention,
        prior_package_ref=metadata_raw.get("prior_package_ref"),
        **_extras(metadata_raw, metadata_known),
    )
    metadata.package_id = metadata_raw.get("package_id", metadata.package_id)
    metadata.timestamp = metadata_raw.get("timestamp", metadata.timestamp)

    # Set versioning
    versioning_raw = manifest_data.get("versioning", {})
    versioning = Versioning(**versioning_raw)

    # Capture the v1.1 open-core manifest fields (X5 analysis_mode, X6
    # namespaces) and every unknown top-level manifest key (vendor x-*
    # extensions, future fields). The loader rebuilds the Manifest via
    # Package.build_manifest(), so these must be stored on the Package and
    # re-emitted there; otherwise they are dropped on re-export, violating
    # the §6.4/§6.5 lossless round-trip MUST (loader-roundtrip-1,
    # envelope-manifest-2). analysis_mode is load-bearing — it gates the
    # v1.1 conditional-required record-type rules.
    analysis_mode = manifest_data.get("analysis_mode")
    namespaces = manifest_data.get("namespaces")
    manifest_top_known = {
        "metadata",
        "versioning",
        "subjects",
        "entities",
        "profiles",
        "record_files",
        "audit_trail",
        "analysis_mode",
        "namespaces",
    }
    manifest_extras = _extras(manifest_data, manifest_top_known)

    # Parse subjects
    subjects: list[Subject] = []
    subject_known = {
        "subject_id",
        "subject_type",
        "name",
        "version",
        "provider",
        "risk_classification",
        "modalities",
        "lifecycle_phase",
        "lifecycle_timeline",
    }
    for sub_data in manifest_data.get("subjects", []):
        timeline = [LifecycleEntry(**e) for e in sub_data.get("lifecycle_timeline", [])]
        subject = Subject(
            subject_id=sub_data.get("subject_id", ""),
            subject_type=sub_data.get("subject_type", "ai_system"),
            name=sub_data.get("name", ""),
            version=sub_data.get("version", "1.0.0"),
            provider=sub_data.get("provider", ""),
            risk_classification=sub_data.get("risk_classification", "minimal-risk"),
            modalities=sub_data.get("modalities", []),
            lifecycle_phase=sub_data.get("lifecycle_phase", "development"),
            lifecycle_timeline=timeline,
            **_extras(sub_data, subject_known),
        )
        subjects.append(subject)

    # Parse entities
    entities_raw = manifest_data.get("entities", {})
    entities = EntitiesBlock()

    component_known = {"component_id", "name", "type", "version", "subject_refs", "provider"}
    for comp_data in entities_raw.get("components", []):
        comp = Component(
            component_id=comp_data.get("component_id", ""),
            name=comp_data.get("name", ""),
            type=comp_data.get("type", "model"),
            version=comp_data.get("version", "1.0.0"),
            subject_refs=comp_data.get("subject_refs", []),
            provider=comp_data.get("provider", ""),
            **_extras(comp_data, component_known),
        )
        entities.components.append(comp)

    dataset_known = {"dataset_id", "name", "version", "source_type", "modality", "size", "subject_refs"}
    for ds_data in entities_raw.get("datasets", []):
        ds = Dataset(
            dataset_id=ds_data.get("dataset_id", ""),
            name=ds_data.get("name", ""),
            version=ds_data.get("version", "1.0.0"),
            source_type=ds_data.get("source_type", "licensed"),
            modality=ds_data.get("modality", "text"),
            size=ds_data.get("size", {"records": 0, "size_gb": 0.0}),
            subject_refs=ds_data.get("subject_refs", []),
            **_extras(ds_data, dataset_known),
        )
        entities.datasets.append(ds)

    actor_known = {"actor_id", "role", "name", "organization"}
    for act_data in entities_raw.get("actors", []):
        actor = Actor(
            actor_id=act_data.get("actor_id", ""),
            role=act_data.get("role", "provider"),
            name=act_data.get("name", ""),
            organization=act_data.get("organization", ""),
            **_extras(act_data, actor_known),
        )
        entities.actors.append(actor)

    rel_known = {"source_ref", "target_ref", "relationship_type", "description"}
    for rel_data in entities_raw.get("relationships", []):
        rel = Relationship(
            source_ref=rel_data.get("source_ref", ""),
            target_ref=rel_data.get("target_ref", ""),
            relationship_type=rel_data.get("relationship_type", "calls"),
            description=rel_data.get("description", ""),
            **_extras(rel_data, rel_known),
        )
        entities.relationships.append(rel)

    # Parse profiles
    profiles: list[ProfileEntry] = []
    for prof_data in manifest_data.get("profiles", []):
        profiles.append(ProfileEntry(**prof_data))

    # Parse audit trail
    audit_trail: list[AuditTrailEntry] = []
    for at_data in manifest_data.get("audit_trail", []):
        audit_trail.append(AuditTrailEntry(**at_data))

    # Load records from JSONL files.
    #
    # Two-pass strategy:
    #   Pass 1: read every JSONL record into a raw dict list.
    #   Pass 2: run load-time rejection checks (VAL-LOAD-001..004) on the
    #           raw dicts BEFORE Pydantic envelope construction — the
    #           checks need to inspect payload contents that the strict
    #           Pydantic models would not accept (e.g., persona/llm
    #           verifier_class fails the HarnessVerifier Literal enum).
    #   Pass 3: convert each raw dict into a validated RecordEnvelope.
    #
    # Rejection raises :class:`acef.errors.LoadRejection` carrying the
    # ACEF-NNN code that named the rule; the same conditions are also
    # caught by :func:`acef.validation.engine.validate_bundle` as
    # ValidationDiagnostics (VAL-LOAD-005 agreement).
    raw_record_dicts: list[dict[str, Any]] = []
    for rf_entry in manifest_data.get("record_files", []):
        rf_path_str = rf_entry.get("path")
        if not rf_path_str:
            raise ACEFFormatError(
                "record_files entry missing 'path' field",
                code="ACEF-050",
            )
        _validate_path(rf_path_str)
        rf_path = bundle_dir / rf_path_str
        # M-IMPL-2: Raise error when manifest-listed record files are missing
        if not rf_path.exists():
            raise ACEFFormatError(
                f"Record file listed in manifest but not found on disk: {rf_entry['path']}",
                code="ACEF-022",
            )
        raw_record_dicts.extend(_parse_jsonl(rf_path))

    # Run VAL-LOAD-001..004 checks BEFORE Pydantic envelope construction.
    # Order matters: persona/llm verifier_class would crash
    # HarnessAttestationPayload's Literal enum if we deferred this check
    # below dict_to_record_envelope. (Envelope construction stores payload
    # as a raw dict so the persona/llm cases survive envelope build, but
    # downstream code paths that parse payload via the typed model would
    # blow up with a generic ValidationError — by raising LoadRejection
    # here we give callers a structured ACEF-NNN handle.)
    check_load_rejections(manifest_data, raw_record_dicts)

    records: list[RecordEnvelope] = [dict_to_record_envelope(rec_data) for rec_data in raw_record_dicts]

    # Load attachments with size guards (M-SCOUT-5, m8 Scout R2)
    attachments: dict[str, bytes] = {}
    artifacts_dir = bundle_dir / "artifacts"
    if artifacts_dir.exists():
        cumulative_artifact_size = 0
        for file_path in artifacts_dir.rglob("*"):
            if file_path.is_file():
                file_size = file_path.stat().st_size
                if file_size > _MAX_ARTIFACT_FILE_SIZE:
                    raise ACEFFormatError(
                        f"Artifact file exceeds 1 GB limit: "
                        f"{file_path.relative_to(bundle_dir).as_posix()} "
                        f"({file_size} bytes)",
                        code="ACEF-050",
                    )
                cumulative_artifact_size += file_size
                if cumulative_artifact_size > _MAX_TOTAL_ARTIFACT_SIZE:
                    raise ACEFFormatError(
                        f"Cumulative artifact size exceeds 10 GB limit: {cumulative_artifact_size} bytes",
                        code="ACEF-050",
                    )
                rel_path = file_path.relative_to(bundle_dir).as_posix()
                attachments[rel_path] = file_path.read_bytes()

    # Construct Package via the public classmethod (M-ARCH-1). Thread the
    # open-core v1.1 manifest fields (X5/X6) and any top-level manifest
    # extras (vendor x-*) so Package.build_manifest() re-emits them on
    # export, preserving the §6.4/§6.5 lossless round-trip MUST.
    return Package._init_from_parts(
        metadata=metadata,
        versioning=versioning,
        subjects=subjects,
        entities=entities,
        profiles=profiles,
        records=records,
        audit_trail=audit_trail,
        attachments=attachments,
        analysis_mode=analysis_mode,
        namespaces=namespaces,
        manifest_extras=manifest_extras,
    )
