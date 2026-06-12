"""ACEF export module — directory layout, JSONL writing, sharding, deterministic tar.gz.

Implements bundle serialization per spec Section 3.1.1:
- Directory bundle layout
- JSONL record files with RFC 8785 canonicalization
- Deterministic sharding (100k records or 256 MB)
- Deterministic tar.gz archives
"""

from __future__ import annotations

import gzip
import json
import os
import shutil
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from acef.errors import ACEFExportError
from acef.integrity import (
    build_merkle_tree,
    canonicalize,
    compute_content_hashes,
    path_nfc_utf8_problem,
)
from acef.records_util import canonicalize_record, compute_shard_boundaries, sort_records

if TYPE_CHECKING:
    from acef.package import Package


def _write_jsonl(records: list[Any], path: Path) -> None:
    """Write records to a JSONL file with RFC 8785 canonicalization.

    Each line is independently canonicalized, followed by \\n.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        for rec in records:
            data = rec.to_jsonl_dict()
            canonical = canonicalize_record(data)
            f.write(canonical)
            f.write(b"\n")


def _validate_export_attachment_path(att_path: str) -> None:
    """Validate an attachment path before writing during export.

    Defense-in-depth check to prevent path traversal even if
    add_attachment() validation was bypassed.

    Raises:
        ACEFExportError: If the path is unsafe.
    """
    if "\\" in att_path:
        raise ACEFExportError(
            f"Backslash separators not allowed in attachment path during export: {att_path!r}",
            code="ACEF-052",
        )
    if att_path.startswith("/"):
        raise ACEFExportError(
            f"Absolute attachment path not allowed during export: {att_path!r}",
            code="ACEF-052",
        )
    # Spec §3.1.1: hash-domain paths MUST be UTF-8 with NFC normalization.
    # Reject a non-UTF-8 (surrogate-bearing) or non-NFC path at export time so
    # such a tar member name / content-hash key can never be written even if
    # upstream validation was bypassed. Shares the rule with the package
    # validators and the integrity discovered-key check via
    # ``path_nfc_utf8_problem``; carries ACEF-052 (the designated path code)
    # rather than the ACEFExportError default.
    problem = path_nfc_utf8_problem(att_path)
    if problem is not None:
        raise ACEFExportError(
            f"Attachment path violates spec §3.1.1 during export ({problem}): {att_path!r}",
            code="ACEF-052",
        )
    segments = att_path.split("/")
    for segment in segments:
        if segment in (".", ".."):
            raise ACEFExportError(
                f"Traversal/dot segment in attachment path during export: {att_path!r}",
            )
    if not att_path.startswith("artifacts/"):
        raise ACEFExportError(
            f"Attachment path must be under artifacts/: {att_path!r}",
        )


# USTAR (POSIX.1-1988) caps the ``name`` field at 100 bytes. The
# cross-language TypeScript writer
# (packages/sdk-typescript/src/bundle_export.ts ``assertShortName``) REJECTS
# any FULL member name (the ``<bundle_name>/<relpath>`` string, with a trailing
# ``/`` for directories) whose UTF-8 length is ``>= 100`` bytes rather than
# emitting GNU/PAX long-name machinery. Python's ``tarfile`` would instead
# either split such a name across the USTAR ``name``/``prefix`` fields (silent
# byte-divergence from the TS writer) or raise a raw ``ValueError`` when the
# leaf alone is too long. To preserve the §3.1.3 byte-identical-archive MUST we
# mirror the TS domain EXACTLY: a structured ``ACEFExportError`` for any full
# member name ``>= 100`` UTF-8 bytes, applied to the root dir, every
# subdirectory, and every file.
_USTAR_NAME_MAX_BYTES = 100


def _validate_ustar_member_name(member_name: str) -> None:
    """Reject a tar member name that exceeds the USTAR short-name domain.

    Mirrors the TS ``assertShortName`` boundary: the FULL member name
    (including the ``<bundle_name>/`` prefix and any trailing ``/``) must be
    ``< 100`` UTF-8 bytes. ``>= 100`` is rejected, identical to the TS writer,
    so both runtimes share one permitted member-name domain.

    Args:
        member_name: The full tar member name as it will be written.

    Raises:
        ACEFExportError: If the UTF-8 byte length is ``>= 100``.
    """
    byte_len = len(member_name.encode("utf-8"))
    if byte_len >= _USTAR_NAME_MAX_BYTES:
        raise ACEFExportError(
            "Tar member name reaches the 100-byte USTAR short-name limit "
            f"({byte_len} UTF-8 bytes); long-name (GNU/PAX) extension handling "
            "is not portable across the ACEF reference writers and would break "
            f"cross-language byte parity: {member_name!r}",
            code="ACEF-052",
        )


def export_directory(package: Package, output_path: str) -> Path:
    """Export a package as a directory bundle.

    Args:
        package: The Package to export.
        output_path: Path to the output directory.

    Returns:
        Path to the created directory.

    Raises:
        ACEFExportError: If export fails.
    """
    bundle_dir = Path(output_path)

    try:
        bundle_dir.mkdir(parents=True, exist_ok=True)

        # Clear ALL managed subdirectories to prevent stale files (M-IMPL-1, M3)
        for subdir_name in ("records", "artifacts", "hashes", "signatures"):
            subdir = bundle_dir / subdir_name
            if subdir.exists():
                shutil.rmtree(subdir)

        # Create subdirectories
        (bundle_dir / "records").mkdir(exist_ok=True)
        (bundle_dir / "artifacts").mkdir(exist_ok=True)
        (bundle_dir / "hashes").mkdir(exist_ok=True)
        (bundle_dir / "signatures").mkdir(exist_ok=True)

        # Write attachment files with path validation (C-IMPL-1)
        for att_path, content in package.attachments.items():
            _validate_export_attachment_path(att_path)
            full_path = bundle_dir / att_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_bytes(content)

        # Write record files
        records_by_type: dict[str, list[Any]] = {}
        for rec in package.records:
            records_by_type.setdefault(rec.record_type, []).append(rec)

        for record_type, recs in sorted(records_by_type.items()):
            sorted_recs = sort_records(recs)
            shards = compute_shard_boundaries(sorted_recs)

            if len(shards) == 1:
                path = bundle_dir / "records" / f"{record_type}.jsonl"
                _write_jsonl(shards[0], path)
            else:
                shard_dir = bundle_dir / "records" / record_type
                shard_dir.mkdir(parents=True, exist_ok=True)
                for i, shard in enumerate(shards):
                    shard_num = str(i + 1).zfill(4)
                    path = shard_dir / f"{record_type}.{shard_num}.jsonl"
                    _write_jsonl(shard, path)

        # Write manifest
        manifest = package.build_manifest()
        manifest_data = manifest.to_dict()
        manifest_bytes = canonicalize(manifest_data)
        (bundle_dir / "acef-manifest.json").write_bytes(manifest_bytes)

        # Compute and write content hashes
        content_hashes = compute_content_hashes(bundle_dir)
        hashes_bytes = canonicalize(content_hashes)
        (bundle_dir / "hashes" / "content-hashes.json").write_bytes(hashes_bytes)

        # Compute and write Merkle tree
        merkle_tree = build_merkle_tree(content_hashes)
        merkle_bytes = canonicalize(merkle_tree)
        (bundle_dir / "hashes" / "merkle-tree.json").write_bytes(merkle_bytes)

        # Sign if requested (M-R2-4: use public properties instead of privates)
        if package.is_signed and package.signing_key:
            from acef.signing import sign_bundle

            sign_bundle(bundle_dir, package.signing_key)

    except OSError as e:
        raise ACEFExportError(f"Failed to export bundle: {e}") from e

    return bundle_dir


def export_archive(package: Package, output_path: str) -> Path:
    """Export a package as a .acef.tar.gz archive.

    Per spec: deterministic archive with gzip level 6, mtime=0, OS=0xFF,
    owner 0/0, permissions 0644/0755, lexicographic file order.

    Args:
        package: The Package to export.
        output_path: Path to the output archive.

    Returns:
        Path to the created archive.

    Raises:
        ACEFExportError: If archive creation fails.
    """
    try:
        # First export as directory to a temp location
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_name = Path(output_path).name.replace(".tar.gz", "").replace(".acef", "") + ".acef"
            bundle_dir = Path(tmpdir) / bundle_name
            export_directory(package, str(bundle_dir))

            # Get the manifest timestamp for deterministic mtime
            manifest_path = bundle_dir / "acef-manifest.json"
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            timestamp_str = manifest_data.get("metadata", {}).get("timestamp", "")
            try:
                mtime = int(datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp())
            except (ValueError, AttributeError):
                mtime = 0

            # Collect all files in lexicographic order using forward slashes
            # (per spec: all paths MUST use forward slashes)
            all_files: list[str] = []
            for root, dirs, files in os.walk(str(bundle_dir)):
                dirs.sort()  # Ensure deterministic walk order
                for f in sorted(files):
                    # Use PurePosixPath to ensure forward slashes on all platforms
                    rel = PurePosixPath(Path(root).relative_to(bundle_dir)) / f
                    all_files.append(str(rel))
            all_files.sort()

            # Collect all directories
            all_dirs: list[str] = []
            for root, dirs, files in os.walk(str(bundle_dir)):
                dirs.sort()
                for d in sorted(dirs):
                    rel = PurePosixPath(Path(os.path.join(root, d)).relative_to(bundle_dir))
                    all_dirs.append(str(rel))
            all_dirs.sort()

            # Create deterministic tar.gz
            output = Path(output_path)
            output.parent.mkdir(parents=True, exist_ok=True)

            # Write tar to a temp file first, then gzip with deterministic settings (M-SCOUT-2)
            tar_tmp_path = Path(tmpdir) / "_archive.tar"
            # Pin USTAR_FORMAT explicitly. Python's tarfile default is
            # PAX_FORMAT (tarfile.DEFAULT_FORMAT == 2); PAX emits an extended
            # header ("x" typeflag) block for any member name with non-ASCII
            # UTF-8 bytes — which §3.1.1 permits (paths use UTF-8 NFC, so
            # non-ASCII names are valid). The cross-language TypeScript writer
            # (packages/sdk-typescript/src/bundle_export.ts) emits POSIX.1-1988
            # USTAR headers only, so a PAX default here would diverge from it
            # for any non-ASCII artifact name, breaking the §3.1.3 byte-
            # identical-archive MUST. USTAR stores the raw UTF-8 bytes directly
            # in the name[0:100] field (no extended header), matching the TS
            # writer. USTAR caps member names at 100 bytes (prefix 155); the TS
            # writer rejects names >= 100 bytes, so both runtimes share the same
            # permitted member-name domain and produce byte-identical output
            # within it. ``_validate_ustar_member_name`` enforces that shared
            # domain here so Python never silently prefix-splits (or raises a
            # raw ValueError for) a name the TS writer would reject.
            #
            # Pin ``encoding="utf-8", errors="strict"`` explicitly. Without it
            # tarfile falls back to ``TarFile.encoding`` — the process default
            # derived from the filesystem encoding at interpreter start — so on
            # a non-UTF-8 locale a non-ASCII member name would be written with
            # latin-1 (or other) bytes, diverging from the TS writer (which
            # always emits ``Buffer.from(name, "utf-8")``) and breaking the
            # §3.1.1 UTF-8-NFC-path / §3.1.3 byte-identical-archive MUSTs in an
            # environment-dependent way. ``errors="strict"`` fails loudly rather
            # than silently substituting bytes if a name is somehow non-encodable
            # (NFC paths are already validated upstream).
            with tarfile.open(
                str(tar_tmp_path),
                mode="w",
                format=tarfile.USTAR_FORMAT,
                encoding="utf-8",
                errors="strict",
            ) as tar:
                # Add root directory
                root_member = bundle_name + "/"
                _validate_ustar_member_name(root_member)
                root_info = tarfile.TarInfo(name=root_member)
                root_info.type = tarfile.DIRTYPE
                root_info.mode = 0o755
                root_info.mtime = mtime
                root_info.uid = 0
                root_info.gid = 0
                root_info.uname = ""
                root_info.gname = ""
                tar.addfile(root_info)

                # Add directories
                for d in all_dirs:
                    dir_member = f"{bundle_name}/{d}/"
                    _validate_ustar_member_name(dir_member)
                    dir_info = tarfile.TarInfo(name=dir_member)
                    dir_info.type = tarfile.DIRTYPE
                    dir_info.mode = 0o755
                    dir_info.mtime = mtime
                    dir_info.uid = 0
                    dir_info.gid = 0
                    dir_info.uname = ""
                    dir_info.gname = ""
                    tar.addfile(dir_info)

                # Add files — stream from disk instead of reading into memory (m9)
                for f in all_files:
                    full_path = bundle_dir / f
                    file_size = full_path.stat().st_size

                    file_member = f"{bundle_name}/{f}"
                    _validate_ustar_member_name(file_member)
                    file_info = tarfile.TarInfo(name=file_member)
                    file_info.size = file_size
                    file_info.mode = 0o644
                    file_info.mtime = mtime
                    file_info.uid = 0
                    file_info.gid = 0
                    file_info.uname = ""
                    file_info.gname = ""
                    with open(str(full_path), "rb") as file_obj:
                        tar.addfile(file_info, file_obj)

            # Stream-gzip the tar file to a sibling temp file, then atomically
            # rename to the final output. This protects against a SIGKILL
            # between the gzip write and the OS-byte patch leaving a
            # half-written archive at the user-visible path.
            staging = output.with_name(output.name + ".tmp")
            try:
                _stream_gzip(tar_tmp_path, staging, mtime=0, level=6)

                # Patch the OS byte in the gzip header to 0xFF (unknown) per
                # spec §3.1.3. Gzip header layout:
                #   bytes[0:2]=magic, [2]=method, [3]=flags,
                #   [4:8]=mtime, [8]=xfl, [9]=OS
                # Python sets OS to platform default; deterministic archives
                # MUST use 0xFF.
                with open(str(staging), "r+b") as gz:
                    gz.seek(9)
                    gz.write(b"\xff")

                # os.replace is atomic on POSIX and Windows when source and
                # destination are on the same filesystem (which they are
                # here — both in output.parent).
                os.replace(str(staging), str(output))
            except BaseException:
                # On any failure, remove the staging file so we don't leave
                # debris next to the user's intended output path.
                try:
                    staging.unlink()
                except FileNotFoundError:
                    pass
                raise

            return output

    except ACEFExportError:
        raise
    except OSError as e:
        raise ACEFExportError(f"Failed to create archive: {e}") from e


def _stream_gzip(input_path: Path, output_path: Path, *, mtime: int, level: int) -> None:
    """Stream-gzip a file to output without buffering the entire contents.

    Reads the input file in chunks and writes compressed data incrementally.

    Args:
        input_path: Path to the uncompressed file to read.
        output_path: Path to write the gzipped output.
        mtime: Gzip mtime value for determinism.
        level: Gzip compression level.
    """
    chunk_size = 65536
    with open(str(output_path), "wb") as out_f:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            compresslevel=level,
            fileobj=out_f,
            mtime=mtime,
        ) as gz:
            with open(str(input_path), "rb") as in_f:
                while True:
                    chunk = in_f.read(chunk_size)
                    if not chunk:
                        break
                    gz.write(chunk)
