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


def utf16_collation_key(value: str) -> bytes:
    """Return the RFC 8785 object-key collation key for ``value``.

    RFC 8785 §3.2.3 mandates that canonical-JSON object keys be sorted by their
    **UTF-16 code units**, which is exactly the order :func:`rfc8785.dumps`
    emits. Python's built-in ``sorted`` / ``str`` comparison orders by Unicode
    **code point** instead. The two collations are IDENTICAL for the Basic
    Multilingual Plane (U+0000..U+FFFF, which includes all ASCII), but DIVERGE
    for supplementary-plane characters (U+10000 and above): such a character
    encodes as a UTF-16 surrogate pair whose first code unit lies in
    0xD800..0xDBFF, so it sorts *before* any BMP character at or above U+E000
    under UTF-16 collation, yet *after* it under code-point collation.

    Encoding the string as big-endian UTF-16 yields a byte sequence whose
    lexicographic order is precisely the UTF-16 code-unit order (each code unit
    becomes two bytes, most-significant first), so ``sorted(keys,
    key=utf16_collation_key)`` reproduces ``rfc8785.dumps``'s key order exactly.

    This is the single source of truth for the hash-domain collation, reused by
    both :func:`build_merkle_tree` (leaf order) and :func:`compute_content_hashes`
    (content-hashes.json key order) so the Merkle leaves can never drift from the
    canonical content-hashes.json they are built from. The strings reaching this
    function are already strict-UTF-8 NFC paths (validated via
    :func:`path_nfc_utf8_problem` before they are used), so the UTF-16 encoding
    below cannot encounter a lone surrogate.

    Args:
        value: A hash-domain path / key string (strict UTF-8, NFC).

    Returns:
        The big-endian UTF-16 byte encoding, usable directly as a sort key.
    """
    return value.encode("utf-16-be")


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

    Raises the raw :class:`rfc8785.CanonicalizationError` (subclasses
    ``IntegerDomainError`` / ``FloatDomainError``) for values outside the
    RFC 8785 / I-JSON domain. The hash-domain *file* readers
    (:func:`canonicalize_json_str`, :func:`sha256_file`,
    :func:`sha256_jsonl_file`) wrap this in :class:`ACEFCanonicalizationError`
    so a malformed artifact yields a structured ACEF-051 rather than crashing
    the validator (spec §3.1.3 #6f). Callers that pass already-validated
    in-memory structures (e.g. :func:`compute_bundle_digest` over a
    ``dict[str, str]``) keep the raw RFC 8785 exception contract.

    Args:
        data: Any JSON-serializable Python object.

    Returns:
        RFC 8785 canonicalized bytes.
    """
    return rfc8785.dumps(data)


def _canonicalize_hash_domain(data: Any, *, path: Path | None = None) -> bytes:
    """Canonicalize hash-domain JSON, mapping RFC 8785 domain faults to ACEF-051.

    ``json.loads`` accepts tokens that RFC 8785 REJECTS: an integer whose
    magnitude exceeds 2^53 and the non-standard ``NaN`` / ``Infinity`` float
    literals. Feeding such a value to ``rfc8785.dumps`` raises a
    :class:`rfc8785.CanonicalizationError` (``IntegerDomainError`` /
    ``FloatDomainError``), which is NOT an :class:`ACEFCanonicalizationError`,
    so without this wrapper a malicious or malformed hash-domain artifact like
    ``{"big":100000000000000000000}`` would leak the raw exception and crash the
    validator — an availability/DoS defect and a violation of the "report ALL
    errors" MUST (spec §3.1.3 #6f). Wrapping it as
    :class:`ACEFCanonicalizationError` routes it to the integrity checker's
    existing ACEF-051 handler.

    A second, distinct escape is an object **KEY** that holds a lone UTF-16
    surrogate, e.g. the file bytes ``{"\\udce9":1}`` (an escaped ``\\udce9``).
    Those bytes are valid UTF-8, NFC, and BOM-free, so every text-level check in
    :func:`sha256_file` / :func:`sha256_jsonl_file` passes; but ``rfc8785.dumps``
    sorts object keys by UTF-16 code units and must ``str.encode("utf-16-be")``
    each key, which CANNOT encode a lone surrogate and raises a raw
    :class:`UnicodeEncodeError` (NOT an :class:`rfc8785.CanonicalizationError`).
    Without catching it here that exception leaks through
    :func:`check_integrity` and crashes the validator — the same availability/DoS
    and "report ALL errors" defect — so it is wrapped as ACEF-051 too.

    Args:
        data: The JSON-decoded hash-domain value to canonicalize.
        path: Optional source path, attached to the raised diagnostic.

    Returns:
        RFC 8785 canonicalized bytes.

    Raises:
        ACEFCanonicalizationError: If ``data`` contains a number outside the
            RFC 8785 domain (>2^53, NaN, or Infinity), or an object key holding a
            lone UTF-16 surrogate (not encodable for RFC 8785's UTF-16 key sort).
    """
    try:
        return rfc8785.dumps(data)
    except rfc8785.CanonicalizationError as exc:
        raise ACEFCanonicalizationError(
            f"JSON not canonicalizable per RFC 8785 (out-of-domain number / NaN / Infinity): {exc}",
            path=path,
        ) from exc
    except UnicodeEncodeError as exc:
        raise ACEFCanonicalizationError(
            f"JSON not canonicalizable per RFC 8785 "
            f"(object key holds a lone UTF-16 surrogate, not encodable for the "
            f"UTF-16 key sort): {exc}",
            path=path,
        ) from exc


def canonicalize_json_str(json_str: str, *, path: Path | None = None) -> bytes:
    """Parse a JSON string and re-canonicalize via RFC 8785.

    Used on hash-domain JSON, so an out-of-domain number / NaN / Infinity is
    surfaced as a structured :class:`ACEFCanonicalizationError` (mapped to
    ACEF-051) rather than a raw ``rfc8785.CanonicalizationError``.

    Args:
        json_str: A JSON string.
        path: Optional source path, attached to a raised
            :class:`ACEFCanonicalizationError` for diagnostics.

    Returns:
        RFC 8785 canonicalized bytes.

    Raises:
        ACEFCanonicalizationError: If the parsed JSON contains a number outside
            the RFC 8785 domain (>2^53, NaN, or Infinity).
    """
    # A hash-domain ``.json`` file that is syntactically BROKEN JSON (or non-UTF-8
    # when read as a string) must surface as a structured ACEF-051, NOT a raw
    # ``json.JSONDecodeError``/``UnicodeDecodeError``. Otherwise hashing a corrupt
    # ``.json`` file (e.g. a tampered acef-manifest.json during ``acef doctor``'s
    # integrity check) crashes with a raw traceback — the same availability /
    # "report ALL errors" defect the domain-fault wrapper below already guards.
    try:
        data = json.loads(json_str)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ACEFCanonicalizationError(
            f"JSON not canonicalizable per RFC 8785 (file is not well-formed JSON): {exc}",
            path=path,
        ) from exc
    return _canonicalize_hash_domain(data, path=path)


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
        canonical = canonicalize_json_str(content, path=path)
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
        canonical = _canonicalize_hash_domain(data, path=path)
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

    # Order keys by RFC 8785 UTF-16 collation (the same order ``rfc8785.dumps``
    # writes content-hashes.json in) via the shared ``utf16_collation_key``
    # helper, so the returned dict's iteration order is byte-identical to the
    # canonical content-hashes.json key order AND to the Merkle leaf order built
    # from it. ``sorted`` (code-point) and the UTF-16 collation coincide for all
    # ASCII/BMP paths but diverge for supplementary-plane (U+10000+) paths; using
    # the shared key keeps content-hashes.json, the returned dict, and the Merkle
    # leaves provably in one order.
    return dict(sorted(hashes.items(), key=lambda kv: utf16_collation_key(kv[0])))


def build_merkle_tree(content_hashes: dict[str, str]) -> dict[str, Any]:
    """Build a Merkle tree from content-hashes.json entries.

    Per spec Section 3.1.3:
    - Leaf nodes: SHA-256(path || 0x00 || hash) where both are UTF-8 bytes
    - Inner nodes: SHA-256(left_hash || right_hash) using raw 32-byte digests
    - Odd leaf: promoted unchanged (NOT duplicated)
    - Root: single remaining hash

    Leaf order is the **RFC 8785 UTF-16 code-unit collation** of the paths (via
    :func:`utf16_collation_key`), i.e. the exact key order ``rfc8785.dumps``
    writes ``content-hashes.json`` in. This is what spec §3.1.3 #4 means by
    "the sorted entries of content-hashes.json": the Merkle tree is built over
    the entries IN THE ORDER they appear in the canonical content-hashes.json,
    not Python's default code-point order. The two orders coincide for all
    ASCII/BMP paths but diverge for supplementary-plane (U+10000+) paths; using
    code-point order there would make the leaves[] disagree with their own
    content-hashes.json and make this exporter compute a different root than any
    other spec-conformant exporter (a determinism / round-trip break).

    Args:
        content_hashes: Dict mapping paths to hex SHA-256 hashes. MUST be
            non-empty — every valid bundle has at least ``acef-manifest.json``
            in its hash domain (spec §3.1.3 #3).

    Returns:
        Dict with 'leaves' and 'root' keys matching spec JSON shape.

    Raises:
        ACEFCanonicalizationError: If ``content_hashes`` is empty. The spec's
            Merkle construction (§3.1.3 #4: "the single remaining hash is the
            Merkle root") assumes at least one leaf and defines no zero-leaf
            root, so an empty hash domain is not a valid bundle. Raising here
            (mapped to ACEF-051 by the integrity checker) keeps the previous
            implementation-defined ``SHA-256("")`` sentinel from ever being
            load-bearing for interop. Reached only for a malformed bundle whose
            content-hashes.json is ``{}`` (no real export path produces one).
    """
    if not content_hashes:
        raise ACEFCanonicalizationError(
            "Empty hash domain: a valid ACEF bundle MUST contain at least "
            "acef-manifest.json (spec §3.1.3 #3); the Merkle root of an empty "
            "domain is undefined.",
        )

    # Validate every key's text BEFORE the collation sort. content-hashes.json
    # is untrusted input on the consumer side: a JSON-decoded lone surrogate key
    # (e.g. an escaped "\udce9") is NFC-equal yet NOT encodable as UTF-8 — and,
    # critically, NOT encodable as UTF-16 either, so ``utf16_collation_key``
    # (which calls ``str.encode("utf-16-be")``) would itself raise a RAW
    # UnicodeEncodeError during the sort, before any per-leaf check could run.
    # Validating up front with the shared strict-UTF-8+NFC rule
    # (:func:`path_nfc_utf8_problem`) guarantees the sort key and the leaf
    # ``path.encode("utf-8")`` below both see only encodable keys, and surfaces a
    # structured diagnostic (mapped to ACEF-051 by the integrity checker) instead
    # of a raw exception. This is a key-text check only; it does not affect leaf
    # ordering.
    for path in content_hashes:
        problem = path_nfc_utf8_problem(path)
        if problem is not None:
            raise ACEFCanonicalizationError(
                f"content-hashes.json key violates spec §3.1.1 ({problem}): {path!r}",
            )

    sorted_entries = sorted(content_hashes.items(), key=lambda kv: utf16_collation_key(kv[0]))
    leaves: list[dict[str, str]] = []
    current_level: list[bytes] = []

    for path, hash_hex in sorted_entries:
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
