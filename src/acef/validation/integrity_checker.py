"""ACEF integrity checker — hash, Merkle tree, and signature verification.

Phase 2 of the 4-phase validation pipeline.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from acef.errors import ValidationDiagnostic
from acef.integrity import (
    verify_content_hashes,
    verify_merkle_root,
)


def check_integrity(bundle_dir: Path) -> list[ValidationDiagnostic]:
    """Run all integrity checks on a bundle directory.

    Steps per spec Section 3.1.3:
    a. Verify content hashes
    b. Verify Merkle root
    c. Verify signatures (if present)

    Returns:
        List of diagnostics.
    """
    diagnostics: list[ValidationDiagnostic] = []

    # Check content-hashes.json exists
    content_hashes_path = bundle_dir / "hashes" / "content-hashes.json"
    if not content_hashes_path.exists():
        diagnostics.append(
            ValidationDiagnostic(
                "ACEF-014",
                "content-hashes.json not found in hashes/",
                path="/hashes/content-hashes.json",
            )
        )
        return diagnostics

    # Load expected hashes
    try:
        expected_hashes = json.loads(content_hashes_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        diagnostics.append(
            ValidationDiagnostic(
                "ACEF-014",
                f"Invalid JSON in content-hashes.json: {e}",
                path="/hashes/content-hashes.json",
            )
        )
        return diagnostics

    # Verify content hashes. The hashing routines (sha256_file,
    # sha256_jsonl_file) raise ACEFCanonicalizationError on files that
    # violate spec §3.1.3 canonicalization rules (BOM, non-NFC, illegal
    # JSONL whitespace, missing trailing newline). Catch and map to
    # ACEF-051 so the validator surfaces a structured diagnostic rather
    # than propagating a raw exception.
    from acef.integrity import ACEFCanonicalizationError as _CanonErr

    try:
        hash_errors = verify_content_hashes(bundle_dir, expected_hashes)
    except _CanonErr as exc:
        rel = str(exc.path.relative_to(bundle_dir)) if exc.path else "?"
        diagnostics.append(
            ValidationDiagnostic("ACEF-051", str(exc), path=f"/{rel}")
        )
        hash_errors = []
    for error_msg in hash_errors:
        if "mismatch" in error_msg.lower():
            diagnostics.append(
                ValidationDiagnostic("ACEF-010", error_msg)
            )
        else:
            diagnostics.append(
                ValidationDiagnostic("ACEF-014", error_msg)
            )

    # Check Merkle tree
    merkle_path = bundle_dir / "hashes" / "merkle-tree.json"
    if merkle_path.exists():
        try:
            merkle_data = json.loads(merkle_path.read_text(encoding="utf-8"))
            expected_root = merkle_data.get("root", "")
            if not verify_merkle_root(expected_hashes, expected_root):
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-011",
                        "Merkle root mismatch",
                        path="/hashes/merkle-tree.json",
                    )
                )
        except json.JSONDecodeError as e:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-011",
                    f"Invalid JSON in merkle-tree.json: {e}",
                    path="/hashes/merkle-tree.json",
                )
            )

    # Check signatures
    sig_diagnostics = _check_signatures(bundle_dir, content_hashes_path.read_bytes())
    diagnostics.extend(sig_diagnostics)

    return diagnostics


def _check_signatures(bundle_dir: Path, content_hashes_bytes: bytes) -> list[ValidationDiagnostic]:
    """Verify all JWS signatures in ``signatures/``.

    For every ``.jws`` file:

    1. Parse the header. Emit ACEF-012 on malformed JWS.
    2. Reject algorithms outside the {RS256, ES256} whitelist
       (ACEF-013, spec §3.1.3 #5).
    3. Attempt cryptographic verification using the public key carried
       by the JWS itself — either an embedded ``jwk`` or the first
       certificate in ``x5c``. If neither is present, emit ACEF-012:
       a bundle that claims a signature but provides no key cannot be
       verified by an offline reader.
    4. Re-canonicalize ``content-hashes.json`` via RFC 8785 and use that
       as the signing input (spec §3.1.3 #5 — the signature is over the
       canonicalized bytes, NOT the raw on-disk bytes, so a producer
       that writes pretty-printed JSON still produces a verifiable
       signature).
    5. On invalid signature, emit ACEF-012.
    """
    from acef.errors import ACEFSigningError
    from acef.integrity import ACEFCanonicalizationError, canonicalize_json_str
    from acef.signing import verify_detached_jws

    diagnostics: list[ValidationDiagnostic] = []
    sig_dir = bundle_dir / "signatures"

    if not sig_dir.exists():
        return diagnostics  # Unsigned bundles are valid

    # Read manifest timestamp to anchor cert validity against (spec §3.1.3).
    manifest_timestamp: str | None = None
    manifest_path = bundle_dir / "acef-manifest.json"
    if manifest_path.exists():
        try:
            mdata = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_timestamp = mdata.get("metadata", {}).get("timestamp")
        except json.JSONDecodeError:
            manifest_timestamp = None

    try:
        canonical_input = canonicalize_json_str(
            content_hashes_bytes.decode("utf-8")
        )
    except (ValueError, UnicodeDecodeError) as exc:
        diagnostics.append(
            ValidationDiagnostic(
                "ACEF-012",
                f"Cannot re-canonicalize content-hashes.json for sig verify: {exc}",
                path="/hashes/content-hashes.json",
            )
        )
        return diagnostics

    for sig_file in sorted(sig_dir.glob("*.jws")):
        jws_str = sig_file.read_text(encoding="utf-8").strip()
        if not jws_str:
            continue

        # Parse JWS header to check algorithm before full verification so
        # we emit the precise spec-mandated code (ACEF-013) for an
        # unsupported algorithm.
        parts = jws_str.split(".")
        if len(parts) != 3:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-012",
                    f"Invalid JWS format in {sig_file.name}",
                    path=f"/signatures/{sig_file.name}",
                )
            )
            continue

        try:
            header_bytes = base64.urlsafe_b64decode(parts[0] + "==")
            header = json.loads(header_bytes)
        except Exception as e:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-012",
                    f"Invalid JWS header in {sig_file.name}: {e}",
                    path=f"/signatures/{sig_file.name}",
                )
            )
            continue

        alg = header.get("alg", "")
        if alg not in ("RS256", "ES256"):
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-013",
                    f"Unsupported JWS algorithm in {sig_file.name}: {alg!r}",
                    path=f"/signatures/{sig_file.name}",
                )
            )
            continue

        # Per spec §3.1.3 #5 the header MUST carry x5c or jwk so an
        # offline verifier can do the work. Reject bundles that ship a
        # signature without an in-band key.
        if "x5c" not in header and "jwk" not in header:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-012",
                    f"Signature {sig_file.name} has no x5c or jwk header "
                    "— offline verifier cannot resolve a public key",
                    path=f"/signatures/{sig_file.name}",
                )
            )
            continue

        try:
            verify_detached_jws(
                jws_str,
                canonical_input,
                manifest_timestamp=manifest_timestamp,
            )
        except ACEFSigningError as exc:
            code = exc.code if exc.code in ("ACEF-012", "ACEF-013") else "ACEF-012"
            diagnostics.append(
                ValidationDiagnostic(
                    code,
                    f"Signature verification failed for {sig_file.name}: {exc}",
                    path=f"/signatures/{sig_file.name}",
                )
            )

    return diagnostics


def get_signature_info(bundle_dir: Path) -> tuple[int, list[str]]:
    """Get signature count and algorithms from a bundle.

    Returns:
        Tuple of (signature_count, list_of_algorithms).
    """
    sig_dir = bundle_dir / "signatures"
    if not sig_dir.exists():
        return 0, []

    count = 0
    algorithms: list[str] = []

    for sig_file in sorted(sig_dir.glob("*.jws")):
        jws_str = sig_file.read_text(encoding="utf-8").strip()
        if not jws_str:
            continue

        parts = jws_str.split(".")
        if len(parts) != 3:
            continue

        try:
            header_bytes = base64.urlsafe_b64decode(parts[0] + "==")
            header = json.loads(header_bytes)
            algorithms.append(header.get("alg", ""))
            count += 1
        except Exception:
            continue

    return count, algorithms
