"""ACEF integrity checker — hash, Merkle tree, and signature verification.

Phase 2 of the 4-phase validation pipeline.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import TYPE_CHECKING

from acef.errors import ValidationDiagnostic
from acef.integrity import (
    verify_content_hashes,
    verify_merkle_root,
)

if TYPE_CHECKING:
    from cryptography.x509 import Certificate


def check_integrity(
    bundle_dir: Path,
    *,
    trust_anchors: list[Certificate] | None = None,
) -> list[ValidationDiagnostic]:
    """Run all integrity checks on a bundle directory.

    Steps per spec Section 3.1.3:
    a. Verify content hashes
    b. Verify Merkle root
    c. Verify signatures (if present)

    Args:
        bundle_dir: Path to the bundle directory.
        trust_anchors: Locally configured trust-anchor certificates for x5c
            chain termination (spec §3.1.3 "Signature trust model": "If x5c
            is present, verifiers MUST validate the full certificate chain
            against a locally configured set of trust anchors"). Default
            ``None`` preserves the historical behavior EXACTLY — absent
            anchors yield self-attested trust per the trust model: chain
            links and manifest-timestamp expiry are still verified, but no
            external root anchoring is enforced, so the signature proves
            data integrity, not organizational identity.

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

    # Load expected hashes. Be defensive: malformed JSON, unreadable
    # files, non-UTF-8 bytes, and non-object top-level values all surface
    # as ACEF-014 rather than crashing the validator.
    try:
        expected_hashes = json.loads(content_hashes_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        diagnostics.append(
            ValidationDiagnostic(
                "ACEF-014",
                f"Invalid JSON in content-hashes.json: {e}",
                path="/hashes/content-hashes.json",
            )
        )
        return diagnostics
    if not isinstance(expected_hashes, dict):
        diagnostics.append(
            ValidationDiagnostic(
                "ACEF-014",
                "content-hashes.json must be a JSON object",
                path="/hashes/content-hashes.json",
            )
        )
        return diagnostics
    # Every value MUST be a hex SHA-256 string. Reject non-string values
    # early so downstream code (Merkle tree builder) doesn't crash on
    # something like {"a.txt": ["bad"]} with AttributeError on .encode().
    bad_value_keys = [k for k, v in expected_hashes.items() if not isinstance(v, str)]
    if bad_value_keys:
        diagnostics.append(
            ValidationDiagnostic(
                "ACEF-014",
                f"content-hashes.json values must be hex strings; non-string values for keys: {bad_value_keys!r}",
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
        diagnostics.append(ValidationDiagnostic("ACEF-051", str(exc), path=f"/{rel}"))
        hash_errors = []
    for error_msg in hash_errors:
        if "mismatch" in error_msg.lower():
            diagnostics.append(ValidationDiagnostic("ACEF-010", error_msg))
        else:
            diagnostics.append(ValidationDiagnostic("ACEF-014", error_msg))

    # Check Merkle tree
    merkle_path = bundle_dir / "hashes" / "merkle-tree.json"
    if merkle_path.exists():
        try:
            merkle_data = json.loads(merkle_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-011",
                    f"Invalid JSON in merkle-tree.json: {e}",
                    path="/hashes/merkle-tree.json",
                )
            )
        else:
            if not isinstance(merkle_data, dict):
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-011",
                        "merkle-tree.json must be a JSON object",
                        path="/hashes/merkle-tree.json",
                    )
                )
            else:
                expected_root = merkle_data.get("root", "")
                # verify_merkle_root() -> build_merkle_tree() raises
                # ACEFCanonicalizationError when a content-hashes.json key
                # violates spec §3.1.1 (surrogate / non-NFC), because the key is
                # encoded as UTF-8 to build the leaf. Catch and map to ACEF-051
                # (the key text, not the Merkle root, is the canonicalization
                # fault) — mirroring the content-hash verification above — so
                # callers get a structured diagnostic rather than a raw
                # exception, and validate_bundle() does not fall into its generic
                # ACEF-001 backstop. The faulting key lives in
                # content-hashes.json; build_merkle_tree raises with path=None,
                # so the diagnostic path is that file.
                try:
                    merkle_ok = verify_merkle_root(expected_hashes, expected_root)
                except _CanonErr as exc:
                    diagnostics.append(
                        ValidationDiagnostic(
                            "ACEF-051",
                            str(exc),
                            path="/hashes/content-hashes.json",
                        )
                    )
                else:
                    if not merkle_ok:
                        diagnostics.append(
                            ValidationDiagnostic(
                                "ACEF-011",
                                "Merkle root mismatch",
                                path="/hashes/merkle-tree.json",
                            )
                        )

    # Check signatures
    sig_diagnostics = _check_signatures(
        bundle_dir,
        content_hashes_path.read_bytes(),
        trust_anchors=trust_anchors,
    )
    diagnostics.extend(sig_diagnostics)

    return diagnostics


def _check_signatures(
    bundle_dir: Path,
    content_hashes_bytes: bytes,
    *,
    trust_anchors: list[Certificate] | None = None,
) -> list[ValidationDiagnostic]:
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

    When ``trust_anchors`` is provided and a signature carries an ``x5c``
    header, the chain MUST terminate at one of the configured anchors
    (spec §3.1.3 trust model); a non-terminating chain surfaces through
    the existing ACEF-012 signature-failure diagnostic path. ``None``
    (the default) preserves the historical self-attested behavior: no
    anchor enforcement. Signatures carrying only a ``jwk`` are unaffected
    by anchors — per the trust model they prove data integrity, not
    organizational identity.
    """
    from acef.errors import ACEFSigningError
    from acef.integrity import canonicalize_json_str
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
            _md = mdata.get("metadata") if isinstance(mdata, dict) else None
            _ts = _md.get("timestamp") if isinstance(_md, dict) else None
            # ``metadata.timestamp`` is untrusted external JSON and may be a
            # non-string (list/dict/int/bool). It is forwarded as
            # ``manifest_timestamp`` into the JWS cert-validity check, which
            # calls ``.endswith("Z")`` on it — a non-string would raise
            # AttributeError. Only accept a real string; ``None`` skips the
            # cert-anchor check (the manifest schema flags the wrong type).
            manifest_timestamp = _ts if isinstance(_ts, str) else None
        except json.JSONDecodeError:
            manifest_timestamp = None

    try:
        canonical_input = canonicalize_json_str(content_hashes_bytes.decode("utf-8"))
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
        try:
            jws_str = sig_file.read_text(encoding="utf-8").strip()
        except (UnicodeDecodeError, OSError) as exc:
            # A signature file that exists but is unreadable / invalid
            # UTF-8 is a present-but-broken signature, not absence.
            # Emit ACEF-012 so the bundle does not appear "unsigned".
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-012",
                    f"Signature file {sig_file.name} is unreadable: {exc}",
                    path=f"/signatures/{sig_file.name}",
                )
            )
            continue
        if not jws_str:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-012",
                    f"Signature file {sig_file.name} is empty",
                    path=f"/signatures/{sig_file.name}",
                )
            )
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

        # The JWS header MUST decode to a JSON object (per RFC 7515).
        # A header like `[]` parses successfully but cannot carry alg/kid/
        # x5c/jwk; reject as ACEF-012.
        if not isinstance(header, dict):
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-012",
                    f"JWS header in {sig_file.name} is not a JSON object",
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
                trust_anchors=trust_anchors,
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


def get_signature_info(
    bundle_dir: Path,
    *,
    trust_anchors: list[Certificate] | None = None,
) -> tuple[int, list[str]]:
    """Get count and algorithms of CRYPTOGRAPHICALLY VERIFIED signatures.

    Counts only signatures that pass full JWS verification against the
    bundle's content-hashes.json (re-canonicalized per spec §3.1.3 #5),
    using x5c or jwk from the JWS header itself. Signatures whose format
    is valid but whose signature does not verify (tampered, expired x5c
    chain, key mismatch) are NOT counted.

    This is what ``op_bundle_signed`` relies on to decide whether a
    bundle is "signed", and what the v1.1 causation-chain check reads;
    counting unverified signatures would let a tampered bundle satisfy
    ``bundle_signed`` rules.

    Args:
        bundle_dir: Path to the bundle directory.
        trust_anchors: Locally configured trust-anchor certificates —
            the SAME trust configuration the Phase-2 integrity check
            applies. When provided, an x5c signature whose chain does
            not terminate at any anchor is NOT counted, so the count
            here always agrees with ``check_integrity``'s verdict on
            the same bundle (cross-phase consistency: a signature that
            Phase 2 rejects with ACEF-012 must not satisfy
            ``bundle_signed`` rules or vouch for causation chains).
            Default ``None`` preserves the historical self-attested
            behavior exactly. ``jwk``-only signatures are unaffected.

    Returns:
        Tuple of (verified_signature_count, list_of_algorithms).
        Algorithms list is parallel to the count — each verified
        signature contributes its alg.
    """
    sig_dir = bundle_dir / "signatures"
    if not sig_dir.exists():
        return 0, []

    # Read content-hashes.json once for verification input.
    content_hashes_path = bundle_dir / "hashes" / "content-hashes.json"
    if not content_hashes_path.exists():
        return 0, []

    from acef.errors import ACEFSigningError
    from acef.integrity import canonicalize_json_str
    from acef.signing import verify_detached_jws

    try:
        canonical_input = canonicalize_json_str(content_hashes_path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError):
        return 0, []

    # Read manifest timestamp for cert expiry checks.
    manifest_timestamp: str | None = None
    manifest_path = bundle_dir / "acef-manifest.json"
    if manifest_path.exists():
        try:
            mdata = json.loads(manifest_path.read_text(encoding="utf-8"))
            _md = mdata.get("metadata") if isinstance(mdata, dict) else None
            _ts = _md.get("timestamp") if isinstance(_md, dict) else None
            # Untrusted external JSON: a non-string ``metadata.timestamp`` must
            # not reach the JWS cert-validity ``.endswith("Z")`` string op (see
            # the sibling guard in the signature-verification path above).
            manifest_timestamp = _ts if isinstance(_ts, str) else None
        except json.JSONDecodeError:
            manifest_timestamp = None

    count = 0
    algorithms: list[str] = []

    for sig_file in sorted(sig_dir.glob("*.jws")):
        try:
            jws_str = sig_file.read_text(encoding="utf-8").strip()
        except (UnicodeDecodeError, OSError):
            # A signature file with invalid UTF-8 / unreadable bytes
            # cannot be verified. Skip it rather than crashing.
            continue
        if not jws_str:
            continue

        parts = jws_str.split(".")
        if len(parts) != 3:
            continue

        try:
            header_bytes = base64.urlsafe_b64decode(parts[0] + "==")
            header = json.loads(header_bytes)
        except Exception:
            continue

        alg = header.get("alg", "")
        try:
            verify_detached_jws(
                jws_str,
                canonical_input,
                manifest_timestamp=manifest_timestamp,
                trust_anchors=trust_anchors,
            )
        except ACEFSigningError:
            continue

        algorithms.append(alg)
        count += 1

    return count, algorithms
