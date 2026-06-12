"""ACEF integrity module — RFC 8785 canonicalization, SHA-256 hashing, Merkle tree.

Implements the integrity model from spec Section 3.1.3:
- RFC 8785 (JCS) canonicalization for all JSON in hash domain
- SHA-256 content hashing
- content-hashes.json generation
- Merkle tree construction with odd-leaf promotion
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any

import rfc8785

# Chunk size for streaming binary file hashing (64 KB)
_HASH_CHUNK_SIZE = 65536

# UTF-8 BOM — spec §3.1.3 #1 forbids its presence in any JSON in the hash domain.
_UTF8_BOM = "﻿"


class ACEFCanonicalizationError(ValueError):
    """Raised when a file in the hash domain violates RFC 8785 / spec §3.1.3
    canonicalization rules (BOM present, non-NFC text, illegal JSONL whitespace,
    missing trailing newline, etc.).

    The validation engine maps this to error code ACEF-051 ("JSON not
    canonicalized per RFC 8785") at validation time.
    """

    def __init__(self, message: str, *, path: Path | None = None) -> None:
        super().__init__(message)
        self.path = path


def path_nfc_utf8_problem(value: str) -> str | None:
    """Return a human-readable reason if ``value`` violates the hash-domain
    path text contract (spec §3.1.1), else ``None``.

    Single source of truth for the two text constraints every hash-domain path
    MUST satisfy, reused at all four enforcement sites (the two
    :mod:`acef.package` attachment validators, the :mod:`acef.export`
    export-time validator, and the discovered-key check in
    :func:`compute_content_hashes`). Each caller maps the returned reason to its
    own module-specific error type/code; centralizing the *logic* here keeps the
    rule identical everywhere.

    Two checks, in order:

    1. **Strict UTF-8.** A Python ``str`` may hold lone UTF-16 surrogates (e.g.
       ``"a\\udce9.txt"`` from a POSIX filename decoded with ``surrogateescape``,
       or a caller-supplied literal). Such a string can be *already NFC*
       (``unicodedata.normalize("NFC", value) == value``) yet is NOT encodable
       as UTF-8. Spec §3.1.1 requires hash-domain paths to be UTF-8; an
       un-encodable path could never be written to ``content-hashes.json`` /
       a tar member name consistently, so reject it before the NFC test (which
       would otherwise pass it through).
    2. **NFC normalization.** Reject paths whose NFC form differs from the
       supplied form (e.g. an HFS+ NFD-decomposed name) so a conformant
       NFC-normalizing exporter and this one produce identical keys.

    Args:
        value: The hash-domain path string to validate.

    Returns:
        ``None`` when the path is strict-UTF-8 and NFC; otherwise a reason
        string describing the first violation found.
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return "path is not valid UTF-8 (contains surrogate or un-encodable code points)"
    if unicodedata.normalize("NFC", value) != value:
        return "path is not UTF-8 NFC normalized"
    return None


def canonicalize(data: Any) -> bytes:
    """Canonicalize a Python object to RFC 8785 (JCS) bytes.

    Args:
        data: Any JSON-serializable Python object.

    Returns:
        RFC 8785 canonicalized bytes.
    """
    return rfc8785.dumps(data)


def canonicalize_json_str(json_str: str) -> bytes:
    """Parse a JSON string and re-canonicalize via RFC 8785.

    Args:
        json_str: A JSON string.

    Returns:
        RFC 8785 canonicalized bytes.
    """
    data = json.loads(json_str)
    return canonicalize(data)


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash of bytes, return lowercase hex.

    Args:
        data: Raw bytes to hash.

    Returns:
        Lowercase hex-encoded SHA-256 digest.
    """
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hash of a file.

    For .json files, the content is parsed and re-canonicalized via RFC 8785
    before hashing. For .jsonl files, each line is independently canonicalized.
    For all other files, raw bytes are hashed using chunked streaming to
    avoid loading the entire file into memory.

    Args:
        path: Path to the file.

    Returns:
        Lowercase hex-encoded SHA-256 digest.
    """
    if path.suffix == ".json":
        # Per spec §3.1.3 #1: JSON in the hash domain MUST be valid UTF-8 with
        # NFC normalization and no BOM (U+FEFF). Verify these constraints
        # before hashing rather than silently accepting non-conformant input.
        raw_bytes = path.read_bytes()
        if raw_bytes.startswith(b"\xef\xbb\xbf"):
            raise ACEFCanonicalizationError(
                f"JSON file has UTF-8 BOM (forbidden by spec §3.1.3 #1): {path}",
                path=path,
            )
        try:
            content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ACEFCanonicalizationError(
                f"JSON file is not valid UTF-8 (spec §3.1.3 #1): {path}: {exc}",
                path=path,
            ) from exc
        # NFC enforcement: spec §3.1.3 #1 requires NFC normalization.
        # Parsing + re-canonicalizing via RFC 8785 normalizes string values
        # the same way for any input, but we still reject non-NFC source
        # files because the bytes-on-disk identity should match what a
        # spec-conformant producer would emit.
        if unicodedata.normalize("NFC", content) != content:
            raise ACEFCanonicalizationError(
                f"JSON file is not UTF-8 NFC normalized (spec §3.1.3 #1): {path}",
                path=path,
            )
        canonical = canonicalize_json_str(content)
        return sha256_hex(canonical)
    elif path.suffix == ".jsonl":
        return sha256_jsonl_file(path)
    else:
        # Stream binary files in chunks to avoid loading potentially large
        # artifacts entirely into memory.
        return _sha256_file_streaming(path)


def _sha256_file_streaming(path: Path) -> str:
    """Compute SHA-256 hash of a file using chunked streaming.

    Reads the file in 64 KB chunks and updates the hasher incrementally,
    avoiding loading the entire file into memory.

    Args:
        path: Path to the file.

    Returns:
        Lowercase hex-encoded SHA-256 digest.
    """
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_HASH_CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def sha256_jsonl_file(path: Path) -> str:
    """Compute SHA-256 of a JSONL file with per-line canonicalization.

    Per spec §3.1.3 #2 the file MUST end with ``\\n`` after the last record,
    MUST NOT contain empty lines, and MUST NOT contain leading or trailing
    whitespace on any line. There MUST be no UTF-8 BOM. This function
    enforces those constraints rather than silently sanitizing the input,
    so that two producers cannot accidentally produce the same hash from
    inputs that the spec defines as forbidden.

    Args:
        path: Path to the JSONL file.

    Returns:
        Lowercase hex-encoded SHA-256 digest.

    Raises:
        ACEFCanonicalizationError: If the file violates spec §3.1.3 #2.
    """
    raw_bytes = path.read_bytes()
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raise ACEFCanonicalizationError(
            f"JSONL file has UTF-8 BOM (forbidden by spec §3.1.3 #2): {path}",
            path=path,
        )
    if raw_bytes and not raw_bytes.endswith(b"\n"):
        raise ACEFCanonicalizationError(
            f"JSONL file does not end with newline (spec §3.1.3 #2): {path}",
            path=path,
        )
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ACEFCanonicalizationError(
            f"JSONL file is not valid UTF-8 (spec §3.1.3 #2): {path}: {exc}",
            path=path,
        ) from exc

    hasher = hashlib.sha256()
    if not text:
        return hasher.hexdigest()

    # Split on '\n'; with a trailing newline this yields N+1 elements where
    # the last is the empty string after the final newline. Iterate up to
    # the last real line; reject any blank or whitespace-only line.
    lines = text.split("\n")
    # The trailing newline produces an empty final element; drop it.
    if lines and lines[-1] == "":
        lines = lines[:-1]
    for line_number, line in enumerate(lines, start=1):
        if not line:
            raise ACEFCanonicalizationError(
                f"JSONL line {line_number} is empty (forbidden by spec §3.1.3 #2): {path}",
                path=path,
            )
        if line != line.strip():
            raise ACEFCanonicalizationError(
                f"JSONL line {line_number} has leading or trailing whitespace (forbidden by spec §3.1.3 #2): {path}",
                path=path,
            )
        if unicodedata.normalize("NFC", line) != line:
            raise ACEFCanonicalizationError(
                f"JSONL line {line_number} is not UTF-8 NFC normalized (spec §3.1.3 #1): {path}",
                path=path,
            )
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ACEFCanonicalizationError(
                f"JSONL line {line_number} is not valid JSON (spec §3.1.3 #2): {path}: {exc}",
                path=path,
            ) from exc
        canonical = canonicalize(data)
        hasher.update(canonical)
        hasher.update(b"\n")
    return hasher.hexdigest()


def compute_content_hashes(bundle_dir: Path) -> dict[str, str]:
    """Compute content-hashes.json for all files in the hash domain.

    Hash domain includes:
    - acef-manifest.json
    - Everything in records/
    - Everything in artifacts/

    UTF-8 NFC enforcement is consistent across the hash domain (spec §3.1.1 and
    §3.1.3 #1): file CONTENT is NFC-verified for text-bearing JSON/JSONL (see
    ``sha256_file`` / ``sha256_jsonl_file``), and file PATHS (the
    content-hashes.json keys and the Merkle leaf paths derived from them) are
    NFC-verified here in ``_add_if_real_file``. Binary artifacts are hashed
    byte-for-byte as-is (no content NFC check applies to non-text bytes), but
    their path keys are still NFC-checked. A non-NFC path or non-NFC text
    content raises :class:`ACEFCanonicalizationError` (ACEF-051) so no non-NFC
    bytes can silently enter the bundle digest.

    Args:
        bundle_dir: Path to the bundle root directory.

    Returns:
        Dict mapping relative paths (sorted) to hex SHA-256 hashes.
    """
    hashes: dict[str, str] = {}

    bundle_root_resolved = bundle_dir.resolve()

    def _add_if_real_file(file_path: Path) -> None:
        """Add ``file_path`` to the hash domain if it is a regular file
        whose resolved location stays inside ``bundle_root_resolved``.

        Symlinks anywhere in the hash domain are forbidden: spec §3.1.1
        requires paths to be relative to the bundle root with no ``.``
        or ``..`` segments, and symlinks encode traversal in filesystem
        state. We raise :class:`ACEFCanonicalizationError` (mapped to
        ACEF-051) so the calling validator surfaces the issue as a
        structured diagnostic rather than silently skipping the file
        (which would leave the bundle's content-hashes.json incomplete
        and confuse downstream verifiers).
        """
        if file_path.is_symlink():
            raise ACEFCanonicalizationError(
                f"Symlink in bundle hash domain (forbidden by spec §3.1.1): {file_path}",
                path=file_path,
            )
        if not file_path.is_file():
            return
        try:
            resolved = file_path.resolve()
            resolved.relative_to(bundle_root_resolved)
        except (ValueError, OSError) as exc:
            raise ACEFCanonicalizationError(
                f"File in hash domain escapes bundle root: {file_path}: {exc}",
                path=file_path,
            ) from exc
        rel = file_path.relative_to(bundle_dir).as_posix()
        # Spec §3.1.1: paths in the manifest AND hashes MUST be UTF-8 with NFC
        # normalization. Files are discovered here by rglob and the on-disk
        # relative path is used directly as the content-hashes.json key and the
        # Merkle leaf path. Unlike manifest-declared paths (NFC-enforced in
        # loader/package), these discovered keys would otherwise bypass NFC and
        # strict-UTF-8 enforcement, so a non-NFC filename (e.g. an HFS+
        # NFD-decomposed name) or a surrogate-bearing name (POSIX bytes decoded
        # via surrogateescape) could enter the hash domain and produce a
        # different bundle digest than a conformant producer. We share the rule
        # with the package/export validators via ``path_nfc_utf8_problem`` and
        # surface it as a structured diagnostic (ACEF-051) mirroring the
        # content-side NFC checks above.
        problem = path_nfc_utf8_problem(rel)
        if problem is not None:
            raise ACEFCanonicalizationError(
                f"File path in hash domain violates spec §3.1.1 ({problem}): {rel!r}",
                path=file_path,
            )
        hashes[rel] = sha256_file(file_path)

    # Check is_symlink BEFORE exists() — a broken symlink reports
    # exists() == False on its target but is still a forbidden symlink.
    manifest_path = bundle_dir / "acef-manifest.json"
    if manifest_path.is_symlink():
        raise ACEFCanonicalizationError(
            "acef-manifest.json is a symlink (forbidden by spec §3.1.1)",
            path=manifest_path,
        )
    if manifest_path.exists():
        hashes["acef-manifest.json"] = sha256_file(manifest_path)

    records_dir = bundle_dir / "records"
    if records_dir.is_symlink():
        # A broken symlink at records/ has is_symlink True but
        # exists() False. Reject it explicitly so a malicious bundle
        # cannot put a symlink to anywhere and skirt detection.
        raise ACEFCanonicalizationError(
            "records/ is a symlink (forbidden by spec §3.1.1)",
            path=records_dir,
        )
    if records_dir.exists():
        for file_path in sorted(records_dir.rglob("*")):
            _add_if_real_file(file_path)

    artifacts_dir = bundle_dir / "artifacts"
    if artifacts_dir.is_symlink():
        raise ACEFCanonicalizationError(
            "artifacts/ is a symlink (forbidden by spec §3.1.1)",
            path=artifacts_dir,
        )
    if artifacts_dir.exists():
        for file_path in sorted(artifacts_dir.rglob("*")):
            _add_if_real_file(file_path)

    return dict(sorted(hashes.items()))


def build_merkle_tree(content_hashes: dict[str, str]) -> dict[str, Any]:
    """Build a Merkle tree from content-hashes.json entries.

    Per spec Section 3.1.3:
    - Leaf nodes: SHA-256(path || 0x00 || hash) where both are UTF-8 bytes
    - Inner nodes: SHA-256(left_hash || right_hash) using raw 32-byte digests
    - Odd leaf: promoted unchanged (NOT duplicated)
    - Root: single remaining hash

    Args:
        content_hashes: Dict mapping paths to hex SHA-256 hashes.

    Returns:
        Dict with 'leaves' and 'root' keys matching spec JSON shape.
    """
    if not content_hashes:
        empty_root = sha256_hex(b"")
        return {"leaves": [], "root": empty_root}

    sorted_entries = sorted(content_hashes.items())
    leaves: list[dict[str, str]] = []
    current_level: list[bytes] = []

    for path, hash_hex in sorted_entries:
        # Validate the key text before encoding it as UTF-8. content-hashes.json
        # is untrusted input on the consumer side: a JSON-decoded lone surrogate
        # key (e.g. an escaped "\udce9") is NFC-equal yet NOT encodable as UTF-8,
        # so ``path.encode("utf-8")`` below would raise a RAW UnicodeEncodeError.
        # Surface a structured diagnostic (mapped to ACEF-051 by the integrity
        # checker) instead, reusing the same strict-UTF-8+NFC rule as every other
        # hash-domain path site. This is a key-text check only; leaf ordering is
        # unchanged.
        problem = path_nfc_utf8_problem(path)
        if problem is not None:
            raise ACEFCanonicalizationError(
                f"content-hashes.json key violates spec §3.1.1 ({problem}): {path!r}",
            )
        leaves.append({"path": path, "hash": hash_hex})
        path_bytes = path.encode("utf-8")
        hash_bytes = hash_hex.encode("utf-8")
        leaf_hash = hashlib.sha256(path_bytes + b"\x00" + hash_bytes).digest()
        current_level.append(leaf_hash)

    while len(current_level) > 1:
        next_level: list[bytes] = []
        i = 0
        while i < len(current_level):
            if i + 1 < len(current_level):
                combined = current_level[i] + current_level[i + 1]
                next_level.append(hashlib.sha256(combined).digest())
                i += 2
            else:
                # Odd leaf: promoted unchanged
                next_level.append(current_level[i])
                i += 1
        current_level = next_level

    root_hex = current_level[0].hex()
    return {"leaves": leaves, "root": root_hex}


def verify_content_hashes(bundle_dir: Path, expected_hashes: dict[str, str]) -> list[str]:
    """Verify file hashes against expected content-hashes.json.

    Args:
        bundle_dir: Path to the bundle root directory.
        expected_hashes: The content-hashes.json entries.

    Returns:
        List of error messages. Empty list means all OK.
    """
    errors: list[str] = []
    actual_hashes = compute_content_hashes(bundle_dir)

    # Check for files in expected but not on disk
    for path in expected_hashes:
        if path not in actual_hashes:
            errors.append(f"File listed in content-hashes.json but not found: {path}")

    # Check for files on disk but not in expected
    for path in actual_hashes:
        if path not in expected_hashes:
            errors.append(f"File in hash domain but not listed in content-hashes.json: {path}")

    # Check hash values
    for path in expected_hashes:
        if path in actual_hashes:
            if actual_hashes[path] != expected_hashes[path]:
                errors.append(f"Hash mismatch for {path}: expected {expected_hashes[path]}, got {actual_hashes[path]}")

    return errors


def verify_merkle_root(content_hashes: dict[str, str], expected_root: str) -> bool:
    """Verify the Merkle root against content-hashes.json.

    Args:
        content_hashes: The content-hashes.json entries.
        expected_root: The expected Merkle root hash.

    Returns:
        True if the Merkle root matches.
    """
    tree = build_merkle_tree(content_hashes)
    return bool(tree["root"] == expected_root)


def compute_bundle_digest(content_hashes: dict[str, str]) -> str:
    """Compute the canonical bundle identity.

    Per spec: SHA-256 hash of the RFC 8785-canonicalized content-hashes.json.

    Args:
        content_hashes: The content-hashes.json entries.

    Returns:
        Hex-encoded SHA-256 digest prefixed with 'sha256:'.
    """
    canonical = canonicalize(content_hashes)
    digest = sha256_hex(canonical)
    return f"sha256:{digest}"
