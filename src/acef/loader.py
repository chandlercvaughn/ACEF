"""ACEF loader module — bundle deserialization and round-trip.

Loads ACEF Evidence Bundles from directories or .acef.tar.gz archives.
Implements security mitigations: path traversal rejection, tar bomb guards.
"""

from __future__ import annotations

import errno
import gzip
import json
import os
import stat
import sys
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydantic import ValidationError as PydanticValidationError

from acef.errors import ACEFFormatError, ACEFSchemaError
from acef.load_rejections import check_load_rejections
from acef.models.entities import Actor, Component, Dataset, EntitiesBlock, Relationship
from acef.models.manifest import AuditTrailEntry, ProfileEntry
from acef.models.metadata import PackageMetadata, ProducerInfo, RetentionPolicy, Versioning
from acef.models.records import (
    RecordEnvelope,
    dict_to_record_envelope,
)
from acef.models.subjects import LifecycleEntry, Subject
from acef.package import Package, validate_analysis_mode, validate_namespaces

# Tar bomb limits
_MAX_EXTRACTED_SIZE = 10 * 1024 * 1024 * 1024  # 10 GB
_MAX_FILE_COUNT = 100_000
_MAX_SINGLE_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB

# Artifact size guards
_MAX_ARTIFACT_FILE_SIZE = _MAX_SINGLE_FILE_SIZE  # 1 GB per file
_MAX_TOTAL_ARTIFACT_SIZE = _MAX_EXTRACTED_SIZE  # 10 GB cumulative (m8 Scout R2)

# No-follow / non-blocking open flags for the TOCTOU-safe artifact read. Absent on
# non-POSIX platforms (Windows), where they degrade to 0 (no-op) and the lstat-based
# symlink rejection remains the first-line guard. ``O_NOFOLLOW`` makes ``open()``
# fail with ``ELOOP`` if the final path component is a symlink (closing a regular-file
# -> symlink swap race); ``O_NONBLOCK`` avoids blocking if it is swapped for a FIFO.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


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

    # Keep the temp directory alive for the WHOLE ``with`` block, but scope the
    # corruption-rewriting ``try/except`` to ONLY the extraction + bundle-root
    # resolution that happens BEFORE the ``yield``. If the ``yield`` lived inside
    # that ``try``, a generator-based context manager would re-raise a CALLER's
    # exception at the ``yield`` point, where ``except (... OSError)`` would catch
    # it and MASK it as an archive-corruption error — hiding the caller's real
    # failure. Resolving the bundle root inside the guard and yielding OUTSIDE it
    # lets any caller-raised exception (e.g. ``OSError``) propagate UNCHANGED.
    with tempfile.TemporaryDirectory() as tmpdir:
        extract_dir = Path(tmpdir)
        try:
            with tarfile.open(str(archive), "r:gz") as tar:
                _validate_tar_safety(tar)
                _safe_tar_extract(tar, extract_dir)
            bundle_root = _resolve_bundle_root(extract_dir)
        except ACEFFormatError:
            raise
        except (tarfile.TarError, gzip.BadGzipFile, OSError) as e:
            raise ACEFFormatError(
                f"Malformed or corrupt archive: {archive}: {e}",
                code="ACEF-050",
            ) from e

        yield bundle_root


def _parse_jsonl(path: Path) -> list[dict[str, Any]]:
    """Parse a JSONL file into a list of record dicts.

    Args:
        path: Path to the JSONL file.

    Returns:
        List of parsed JSON objects.

    Raises:
        ACEFFormatError: If a line is not valid JSON (ACEF-050), or is
            well-formed JSON but not a JSON object (ACEF-050). A bare scalar,
            array, or ``null`` line is valid JSON yet cannot be a record; left
            unguarded it would reach ``dict_to_record_envelope`` and leak a raw
            ``AttributeError`` (``'int'/'list'/'NoneType'/'str' object has no
            attribute 'get'``) out of the public ``load()`` API on
            attacker-controlled bytes. This mirrors the validation engine's
            structured ACEF-050 verdict for the identical input so ``load()``
            and ``validate_bundle()`` converge (never diverge) on malicious
            records.
    """
    records: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec_data = json.loads(line)
            except json.JSONDecodeError as e:
                raise ACEFFormatError(
                    f"Malformed JSONL at {path}:{line_num}: {e}",
                    code="ACEF-050",
                ) from e
            # JSONL lines must be JSON objects — null, arrays, strings, and
            # numbers are well-formed JSON but cannot be records.
            if not isinstance(rec_data, dict):
                raise ACEFFormatError(
                    f"JSONL line at {path}:{line_num} is not a JSON object (got {type(rec_data).__name__})",
                    code="ACEF-050",
                )
            records.append(rec_data)
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
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        # The public ``acef.load()`` API must surface a malformed/unreadable
        # manifest as a structured ACEF-050 verdict, never a raw exception
        # traceback. ``read_text(encoding="utf-8")`` raises ``UnicodeDecodeError``
        # (a ``ValueError`` subclass, NOT a ``json.JSONDecodeError``) on non-UTF-8
        # manifest bytes and ``OSError`` on a read race / unreadable path; both
        # escaped the prior ``json.JSONDecodeError``-only arm. Mirror the same
        # caught set the integrity checker / CLI use for the manifest read. This
        # is the SINGLE manifest decode for BOTH the directory and the archive
        # load paths (``_load_archive`` funnels through ``_load_directory``).
        raise ACEFFormatError(f"Invalid JSON in manifest: {e}", code="ACEF-050") from e

    def _extras(raw: dict[str, Any], known: set[str]) -> dict[str, Any]:
        """Return a dict of keys in ``raw`` that are not in ``known``.

        With models inheriting :class:`ACEFBaseModel` (``extra='allow'``),
        these extra keys are preserved on the constructed model and emit
        unchanged on round-trip, satisfying spec §6.4 rule 5
        ("ACEF Evidence Bundle export MUST be lossless to the open core").
        """
        return {k: v for k, v in raw.items() if k not in known}

    # ------------------------------------------------------------------
    # Adversarial / malformed-manifest robustness (loader-roundtrip-8).
    #
    # ``acef.load()`` is a documented public DESERIALIZATION API
    # (exported in ``acef.__all__``). Every manifest section it consumes
    # is attacker-controlled, so each is type-guarded BEFORE it is fed to
    # ``dict.get(...)``, ``**``-unpacked into a Pydantic model, or
    # iterated — otherwise a hostile/malformed manifest (e.g. ``metadata``
    # is a list, ``subjects`` is a dict, ``versioning`` is a string)
    # escapes as a RAW ``AttributeError`` / ``TypeError`` / Pydantic
    # ``ValidationError`` instead of a structured ACEF diagnostic.
    #
    # We use STRUCTURAL type-guards (not full manifest-schema validation):
    # ``load`` is intentionally LENIENT — it loads bundles the strict
    # conformance schema rejects (empty ``subjects`` = minItems:1,
    # non-strict ``namespaces`` keys, ...). The conformance gate is
    # :func:`acef.validation.engine.validate_bundle`, NOT ``load``.
    # Imposing full-schema validation here would over-reject and break the
    # §6.4/§6.5 lossless round-trip MUST. So we reject only the structural
    # type-confusion the loader itself cannot consume, mapping it to
    # ACEF-002 (schema-structural) / ACEF-050 (format), and re-raise model
    # construction failures (Pydantic) as ACEF-002.
    # ------------------------------------------------------------------
    def _require_object(value: Any, section: str) -> dict[str, Any]:
        """Return ``value`` if it is a JSON object, else raise ACEF-002.

        Mirrors the JSON-Schema ``"type": "object"`` constraint for a
        manifest section the loader must ``.get(...)`` / ``**``-unpack.
        ``bool`` is a subclass of ``int`` but never of ``dict``, so the
        ``isinstance(..., dict)`` check rejects every non-object scalar.
        """
        if not isinstance(value, dict):
            raise ACEFSchemaError(
                f"Manifest section {section!r} must be a JSON object, got {type(value).__name__}",
                code="ACEF-002",
            )
        return value

    def _require_array(value: Any, section: str) -> list[Any]:
        """Return ``value`` if it is a JSON array, else raise ACEF-002.

        Mirrors the JSON-Schema ``"type": "array"`` constraint for a
        manifest section the loader iterates. A ``str`` is iterable but is
        NOT a JSON array, so it is rejected here rather than silently
        iterated character-by-character.
        """
        if not isinstance(value, list):
            raise ACEFSchemaError(
                f"Manifest section {section!r} must be a JSON array, got {type(value).__name__}",
                code="ACEF-002",
            )
        return value

    def _build_model(factory: Any, raw: dict[str, Any], section: str) -> Any:
        """Construct a Pydantic model, re-raising failures as ACEF-002.

        ``raw`` is the caller-guarded object; ``factory`` is the model
        class invoked as ``factory(**raw)``. A Pydantic ``ValidationError``
        (e.g. a ``producer`` missing the required ``name``/``version``)
        is wrapped as :class:`ACEFSchemaError` so callers see a structured
        ACEF-002 instead of a leaked framework exception.
        """
        try:
            return factory(**raw)
        except PydanticValidationError as e:
            raise ACEFSchemaError(
                f"Manifest section {section!r} failed model validation: {e}",
                code="ACEF-002",
            ) from e

    # Parse manifest — the manifest root itself must be an object so the
    # ``.get(...)`` accesses below cannot raise a raw ``AttributeError``.
    manifest_data = _require_object(manifest_data, "<manifest root>")

    metadata_raw = _require_object(manifest_data.get("metadata", {}), "metadata")
    producer_raw = _require_object(metadata_raw.get("producer", {}), "metadata.producer")
    producer = _build_model(ProducerInfo, producer_raw, "metadata.producer")

    # ``retention_policy`` is OPTIONAL: an absent key, an explicit ``null``, or
    # an empty object ``{}`` means "no policy" (the pre-existing semantics —
    # preserved so a bundle without retention still loads and round-trips
    # identically). The guard branches on ABSENCE/null/empty-object ONLY, never
    # on TRUTHINESS: a PRESENT but falsy non-object (``[]``, ``""``, ``0``,
    # ``false``) is NOT "absent" — it is malformed and MUST be rejected via
    # ``_require_object`` (ACEF-002), not silently coerced to ``None`` and
    # dropped on re-export. Truthy-gating (``if retention_raw:``) would let
    # every falsy non-object bypass the type-guard, so we test presence
    # explicitly: ``None`` (absent / ``null``) and ``{}`` (empty object) are
    # the only "no policy" forms; any other present value flows through
    # ``_require_object`` and a non-dict raises ACEF-002.
    retention_raw = metadata_raw.get("retention_policy")
    retention = (
        None
        if retention_raw is None or retention_raw == {}
        else _build_model(
            RetentionPolicy,
            _require_object(retention_raw, "metadata.retention_policy"),
            "metadata.retention_policy",
        )
    )

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
    # Construct PackageMetadata WITH the inbound package_id/timestamp directly
    # (audit envelope-manifest-7). The prior code built metadata WITHOUT these
    # identity scalars and then MUTATED them post-construction; when either was
    # absent from the manifest, PackageMetadata's default_factory silently minted
    # a FRESH random urn:acef:pkg: / wall-clock timestamp — repairing a
    # malformed/forged bundle into a syntactically valid one whose identity does
    # not match the on-disk bytes (a load-path non-determinism + identity-forgery
    # hazard). Identity is required by the manifest schema, so a missing
    # package_id/timestamp is surfaced as ACEF-002 here rather than fabricated.
    if "package_id" not in metadata_raw:
        raise ACEFSchemaError(
            "Manifest section 'metadata' is missing required field 'package_id'.",
            code="ACEF-002",
        )
    if "timestamp" not in metadata_raw:
        raise ACEFSchemaError(
            "Manifest section 'metadata' is missing required field 'timestamp'.",
            code="ACEF-002",
        )
    try:
        metadata = PackageMetadata(
            package_id=metadata_raw["package_id"],
            timestamp=metadata_raw["timestamp"],
            producer=producer,
            retention_policy=retention,
            prior_package_ref=metadata_raw.get("prior_package_ref"),
            **_extras(metadata_raw, metadata_known),
        )
    except PydanticValidationError as e:
        raise ACEFSchemaError(
            f"Manifest section 'metadata' failed model validation: {e}",
            code="ACEF-002",
        ) from e

    # Set versioning — guard the object shape before ``**``-unpacking so a
    # non-object ``versioning`` (e.g. the string ``"v1"``) surfaces ACEF-002
    # rather than a raw ``TypeError: argument after ** must be a mapping``.
    versioning_raw = _require_object(manifest_data.get("versioning", {}), "versioning")
    versioning = _build_model(Versioning, versioning_raw, "versioning")

    # Capture the v1.1 open-core manifest fields (X5 analysis_mode, X6
    # namespaces) and every unknown top-level manifest key (vendor x-*
    # extensions, future fields). The loader rebuilds the Manifest via
    # Package.build_manifest(), so these must be stored on the Package and
    # re-emitted there; otherwise they are dropped on re-export, violating
    # the §6.4/§6.5 lossless round-trip MUST (loader-roundtrip-1,
    # envelope-manifest-2). analysis_mode is load-bearing — it gates the
    # v1.1 conditional-required record-type rules.
    # Validate analysis_mode/namespaces at LOAD time using the SAME structural
    # domain checks the builder setters (set_analysis_mode/add_namespace) apply,
    # so the loader reconstructs only VALID package state — matching the
    # setters' documented invariant ("the builder cannot store invalid package
    # state that would otherwise surface only as a raw Pydantic error at
    # build_manifest/export time"). Without this, an out-of-domain value
    # (analysis_mode="bogus_mode" / 5, namespaces="oops" / [...] / non-object
    # value) loads silently but makes build_manifest()'s Manifest(...)
    # construction raise a RAW pydantic.ValidationError that escapes uncaught
    # from the public export()/export_directory()/export_archive(), breaking
    # both the load→export round-trip and the "public surface raises structured
    # ACEF errors, never raw framework exceptions" invariant. validate_* raise
    # ACEFSchemaError (ACEF-002) here, naming the offending field+value.
    #
    # The loader is a documented LENIENT deserializer (test_loader_adversarial_
    # manifest.test_valid_lenient_bundle_with_extensions_still_loads): it
    # preserves non-strict ``namespaces`` keys (e.g. ``x-test/extension``) for
    # round-trip. Such a key does NOT cause the raw-Pydantic crash (the Manifest
    # model does not enforce the key pattern; strict ``validate_manifest`` does),
    # so we pass strict_keys=False to enforce ONLY the dict-container/dict-value
    # domain the model checks — the actual crash source — while keeping the
    # lenient-key boundary intact.
    analysis_mode_raw = manifest_data.get("analysis_mode")
    analysis_mode = None if analysis_mode_raw is None else validate_analysis_mode(analysis_mode_raw)
    namespaces_raw = manifest_data.get("namespaces")
    namespaces = None if namespaces_raw is None else validate_namespaces(namespaces_raw, strict_keys=False)
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
    for idx, sub_data in enumerate(_require_array(manifest_data.get("subjects", []), "subjects")):
        sub_data = _require_object(sub_data, f"subjects[{idx}]")
        timeline_raw = _require_array(
            sub_data.get("lifecycle_timeline", []),
            f"subjects[{idx}].lifecycle_timeline",
        )
        timeline = [
            _build_model(
                LifecycleEntry,
                _require_object(e, f"subjects[{idx}].lifecycle_timeline[{j}]"),
                f"subjects[{idx}].lifecycle_timeline[{j}]",
            )
            for j, e in enumerate(timeline_raw)
        ]
        subject = _build_model(
            Subject,
            {
                "subject_id": sub_data.get("subject_id", ""),
                "subject_type": sub_data.get("subject_type", "ai_system"),
                "name": sub_data.get("name", ""),
                "version": sub_data.get("version", "1.0.0"),
                "provider": sub_data.get("provider", ""),
                "risk_classification": sub_data.get("risk_classification", "minimal-risk"),
                "modalities": sub_data.get("modalities", []),
                "lifecycle_phase": sub_data.get("lifecycle_phase", "development"),
                "lifecycle_timeline": timeline,
                **_extras(sub_data, subject_known),
            },
            f"subjects[{idx}]",
        )
        subjects.append(subject)

    # Parse entities
    entities_raw = _require_object(manifest_data.get("entities", {}), "entities")
    entities = EntitiesBlock()

    component_known = {"component_id", "name", "type", "version", "subject_refs", "provider"}
    for idx, comp_data in enumerate(_require_array(entities_raw.get("components", []), "entities.components")):
        comp_data = _require_object(comp_data, f"entities.components[{idx}]")
        comp = _build_model(
            Component,
            {
                "component_id": comp_data.get("component_id", ""),
                "name": comp_data.get("name", ""),
                "type": comp_data.get("type", "model"),
                "version": comp_data.get("version", "1.0.0"),
                "subject_refs": comp_data.get("subject_refs", []),
                "provider": comp_data.get("provider", ""),
                **_extras(comp_data, component_known),
            },
            f"entities.components[{idx}]",
        )
        entities.components.append(comp)

    dataset_known = {"dataset_id", "name", "version", "source_type", "modality", "size", "subject_refs"}
    for idx, ds_data in enumerate(_require_array(entities_raw.get("datasets", []), "entities.datasets")):
        ds_data = _require_object(ds_data, f"entities.datasets[{idx}]")
        ds = _build_model(
            Dataset,
            {
                "dataset_id": ds_data.get("dataset_id", ""),
                "name": ds_data.get("name", ""),
                "version": ds_data.get("version", "1.0.0"),
                "source_type": ds_data.get("source_type", "licensed"),
                "modality": ds_data.get("modality", "text"),
                "size": ds_data.get("size", {"records": 0, "size_gb": 0.0}),
                "subject_refs": ds_data.get("subject_refs", []),
                **_extras(ds_data, dataset_known),
            },
            f"entities.datasets[{idx}]",
        )
        entities.datasets.append(ds)

    actor_known = {"actor_id", "role", "name", "organization"}
    for idx, act_data in enumerate(_require_array(entities_raw.get("actors", []), "entities.actors")):
        act_data = _require_object(act_data, f"entities.actors[{idx}]")
        actor = _build_model(
            Actor,
            {
                "actor_id": act_data.get("actor_id", ""),
                "role": act_data.get("role", "provider"),
                "name": act_data.get("name", ""),
                "organization": act_data.get("organization", ""),
                **_extras(act_data, actor_known),
            },
            f"entities.actors[{idx}]",
        )
        entities.actors.append(actor)

    rel_known = {"source_ref", "target_ref", "relationship_type", "description"}
    for idx, rel_data in enumerate(_require_array(entities_raw.get("relationships", []), "entities.relationships")):
        rel_data = _require_object(rel_data, f"entities.relationships[{idx}]")
        rel = _build_model(
            Relationship,
            {
                "source_ref": rel_data.get("source_ref", ""),
                "target_ref": rel_data.get("target_ref", ""),
                "relationship_type": rel_data.get("relationship_type", "calls"),
                "description": rel_data.get("description", ""),
                **_extras(rel_data, rel_known),
            },
            f"entities.relationships[{idx}]",
        )
        entities.relationships.append(rel)

    # Parse profiles
    profiles: list[ProfileEntry] = []
    for idx, prof_data in enumerate(_require_array(manifest_data.get("profiles", []), "profiles")):
        profiles.append(
            _build_model(
                ProfileEntry,
                _require_object(prof_data, f"profiles[{idx}]"),
                f"profiles[{idx}]",
            )
        )

    # Parse audit trail
    audit_trail: list[AuditTrailEntry] = []
    for idx, at_data in enumerate(_require_array(manifest_data.get("audit_trail", []), "audit_trail")):
        audit_trail.append(
            _build_model(
                AuditTrailEntry,
                _require_object(at_data, f"audit_trail[{idx}]"),
                f"audit_trail[{idx}]",
            )
        )

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
    record_files_raw = manifest_data.get("record_files", [])
    if not isinstance(record_files_raw, list):
        raise ACEFFormatError(
            f"Manifest section 'record_files' must be a JSON array, got {type(record_files_raw).__name__}",
            code="ACEF-050",
        )
    for rf_idx, rf_entry in enumerate(record_files_raw):
        if not isinstance(rf_entry, dict):
            raise ACEFFormatError(
                f"record_files[{rf_idx}] must be a JSON object, got {type(rf_entry).__name__}",
                code="ACEF-050",
            )
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
    # SECURITY: reject symlinks under artifacts/ WITHOUT following them. A directory
    # bundle whose ``artifacts/`` (or any entry below it) is a symlink to a path
    # OUTSIDE the bundle would otherwise read arbitrary local files into
    # ``Package.attachments`` — a path-escape / data-exposure vector. The archive
    # (tar) load path (``_validate_tar_safety``) and the integrity hash domain
    # already forbid symlinks (ACEF-052); the directory load path matches.
    #
    # This top-level check MUST run BEFORE ``exists()``: ``Path.exists()`` FOLLOWS
    # symlinks and returns False for a DANGLING ``artifacts`` symlink, which would
    # otherwise silently bypass rejection. ``is_symlink()`` uses lstat (no-follow),
    # so a dangling symlink is still caught.
    if artifacts_dir.is_symlink():
        raise ACEFFormatError(
            f"Bundle 'artifacts' is a symlink, which is not allowed: "
            f"{artifacts_dir.relative_to(bundle_dir).as_posix()!r}",
            code="ACEF-052",
        )
    if artifacts_dir.exists():
        cumulative_artifact_size = 0

        # Read every artifact under artifacts/. The public load() must surface a
        # structured ACEFError, never a raw OSError, AND must never SILENTLY skip a
        # present-but-unreadable artifact. ``Path.rglob`` is unsafe on BOTH counts:
        # it suppresses directory-scan OSErrors, so an unreadable SUBDIRECTORY is
        # silently OMITTED (an incomplete bundle, not a clean failure). Traverse
        # explicitly with ``os.walk`` + an ``onerror`` callback that raises
        # ACEF-050 on any scan failure, and guard each file's ``stat()`` /
        # ``read_bytes()`` the same way. The intentional 1 GB / 10 GB size-limit
        # ``ACEFFormatError`` raises are NOT ``OSError``, so they propagate
        # unwrapped (and are not re-stamped) through the per-file guards.
        def _on_scan_error(exc: OSError) -> None:
            raise ACEFFormatError(
                f"Failed to scan bundle artifacts directory: {exc}",
                code="ACEF-050",
            ) from exc

        for dir_path, subdirs, file_names in os.walk(artifacts_dir, onerror=_on_scan_error):
            dir_path_p = Path(dir_path)
            # Reject symlinked subdirectories. os.walk (followlinks=False) does NOT
            # DESCEND into them, but the symlink itself is a path-escape vector and
            # must be rejected, not silently ignored.
            for subdir_name in subdirs:
                subdir_path = dir_path_p / subdir_name
                if subdir_path.is_symlink():
                    raise ACEFFormatError(
                        f"Bundle artifact directory is a symlink, which is not allowed: "
                        f"{subdir_path.relative_to(bundle_dir).as_posix()!r}",
                        code="ACEF-052",
                    )
            for file_name in file_names:
                file_path = dir_path_p / file_name
                rel_path = file_path.relative_to(bundle_dir).as_posix()
                # Pre-filter with ``lstat()`` (NO-follow): reject symlinks (ACEF-052)
                # and SKIP non-regular special files (FIFO/socket/device) WITHOUT
                # opening them — opening a device/FIFO can block or have side effects.
                # Do NOT use ``stat()`` / ``Path.is_file()``: ``stat()`` follows
                # symlinks (the path-escape vector) and ``Path.is_file()`` SUPPRESSES
                # OSError on Python >=3.12, silently dropping a present-but-unstattable
                # artifact. Any other stat failure (permission denied, vanished
                # mid-load) -> structured ACEF-050.
                try:
                    pre_stat = file_path.lstat()
                except OSError as exc:
                    raise ACEFFormatError(
                        f"Failed to stat bundle artifact {rel_path!r}: {exc}",
                        code="ACEF-050",
                    ) from exc
                if stat.S_ISLNK(pre_stat.st_mode):
                    raise ACEFFormatError(
                        f"Bundle artifact is a symlink, which is not allowed: {rel_path!r}",
                        code="ACEF-052",
                    )
                if not stat.S_ISREG(pre_stat.st_mode):
                    continue
                # Open ONCE with O_NOFOLLOW|O_NONBLOCK to close the TOCTOU window
                # between the probe above and the read below: a mutable bundle dir
                # could swap the regular file for a symlink (path-escape), a FIFO
                # (blocking read), or grow it past the size limit. O_NOFOLLOW makes
                # open() fail with ELOOP if the leaf was swapped to a symlink ->
                # ACEF-052; O_NONBLOCK avoids blocking on a ->FIFO swap. The
                # AUTHORITATIVE type and size come from fstat() on the opened inode,
                # and the bytes are read from the SAME descriptor — never a re-resolved
                # path. (On non-POSIX the O_* flags are 0; the lstat reject above and
                # the fstat S_ISREG check below remain the guards.)
                try:
                    fd = os.open(file_path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK)
                except OSError as exc:
                    if exc.errno == errno.ELOOP:
                        raise ACEFFormatError(
                            f"Bundle artifact is a symlink, which is not allowed: {rel_path!r}",
                            code="ACEF-052",
                        ) from exc
                    raise ACEFFormatError(
                        f"Failed to open bundle artifact {rel_path!r}: {exc}",
                        code="ACEF-050",
                    ) from exc
                try:
                    fd_stat = os.fstat(fd)
                    if not stat.S_ISREG(fd_stat.st_mode):
                        # Swapped to a non-regular file between the probe and open.
                        raise ACEFFormatError(
                            f"Bundle artifact is not a regular file (changed during load?): {rel_path!r}",
                            code="ACEF-052",
                        )
                    file_size = fd_stat.st_size
                    if file_size > _MAX_ARTIFACT_FILE_SIZE:
                        raise ACEFFormatError(
                            f"Artifact file exceeds 1 GB limit: {rel_path} ({file_size} bytes)",
                            code="ACEF-050",
                        )
                    cumulative_artifact_size += file_size
                    if cumulative_artifact_size > _MAX_TOTAL_ARTIFACT_SIZE:
                        raise ACEFFormatError(
                            f"Cumulative artifact size exceeds 10 GB limit: {cumulative_artifact_size} bytes",
                            code="ACEF-050",
                        )
                    with os.fdopen(fd, "rb", closefd=False) as fh:
                        attachments[rel_path] = fh.read()
                except OSError as exc:
                    # fstat() or read() failure on the opened fd. The size-limit /
                    # type ACEFFormatError raises above are NOT OSError, so they
                    # propagate unwrapped through this handler.
                    raise ACEFFormatError(
                        f"Failed to read bundle artifact {rel_path!r}: {exc}",
                        code="ACEF-050",
                    ) from exc
                finally:
                    os.close(fd)

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
