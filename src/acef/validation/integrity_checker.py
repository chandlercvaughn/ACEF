"""ACEF integrity checker — hash, Merkle tree, and signature verification.

Phase 2 of the 4-phase validation pipeline.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
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
    expected_producer: str | None = None,
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

    # Check Merkle tree.
    #
    # Spec §3.1.3 step (d) mandates recomputing the Merkle tree from
    # content-hashes.json and comparing the root against merkle-tree.json
    # ("Mismatch is FATAL (ACEF-011)"); §3.1.3 layout (line 501/528) lists
    # hashes/merkle-tree.json as a required bundle file. Because the file
    # lives OUTSIDE the hash domain, content-hashes.json does NOT list it,
    # so deleting it is otherwise undetectable. If we only verified the
    # root when the file happens to be present, a malicious or buggy
    # producer could strip merkle-tree.json to bypass step (d) entirely
    # with zero diagnostics. We therefore require the file's presence
    # whenever content-hashes.json exists (i.e. this is a real bundle with
    # an integrity layer — the no-content-hashes case already returned an
    # ACEF-014 above and never reaches here, so this branch never
    # double-reports). A missing required Merkle file cannot satisfy the
    # mandatory root comparison, so it is the step-(d) FATAL code ACEF-011.
    merkle_path = bundle_dir / "hashes" / "merkle-tree.json"
    if not merkle_path.exists():
        diagnostics.append(
            ValidationDiagnostic(
                "ACEF-011",
                "merkle-tree.json not found in hashes/ — mandatory Merkle root "
                "comparison (spec §3.1.3 step d) cannot be performed",
                path="/hashes/merkle-tree.json",
            )
        )
    else:
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
        expected_producer=expected_producer,
    )
    diagnostics.extend(sig_diagnostics)

    return diagnostics


def _check_signatures(
    bundle_dir: Path,
    content_hashes_bytes: bytes,
    *,
    trust_anchors: list[Certificate] | None = None,
    expected_producer: str | None = None,
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
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            # The manifest-timestamp is an OPTIONAL cert-validity anchor. A
            # malformed (bad JSON), non-UTF-8 (UnicodeDecodeError, a ValueError
            # subclass — NOT a json.JSONDecodeError), or unreadable (OSError on a
            # read race after .exists()) manifest must degrade gracefully here:
            # the anchor becomes unavailable and cert-validity falls back to its
            # no-timestamp behavior, NEVER a raw traceback escaping the checker.
            # Mirrors the sibling reads in this module (content-hashes.json,
            # merkle-tree.json, the .jws files), which catch the same tuple.
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
            continue

        # The signature verified. When a deployment configures an EXPECTED
        # producer binding (spec Appendix D.3), an ANCHORED signature whose leaf
        # subject does not match that producer is the "valid signature, wrong
        # signer" case — emit ACEF-012 so attributable validation fails closed.
        # No expectation configured → no diagnostic (integrity-only, as before).
        if expected_producer is not None and trust_anchors:
            binding = classify_signature_binding(
                jws_str,
                canonical_input,
                manifest_timestamp=manifest_timestamp,
                trust_anchors=trust_anchors,
                expected_producer=expected_producer,
            )
            if binding.binding_level == "anchored" and binding.matches_expected_producer is False:
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-012",
                        f"Signature {sig_file.name} is anchored but its certificate subject "
                        f"{binding.signer_subject!r} does not match the expected producer "
                        f"{expected_producer!r} (valid signature, wrong signer)",
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
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            # Optional cert-validity anchor — degrade gracefully on malformed
            # JSON, non-UTF-8 bytes (UnicodeDecodeError), or a read race
            # (OSError), exactly as the sibling reads in this module do. See the
            # matching guard in _check_signatures above.
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


@dataclass(frozen=True)
class SignatureBinding:
    """The identity-binding status of one detached JWS over ``content-hashes.json``.

    Closes PhD-review finding 2 (spec Appendix D.3): a valid signature proves
    *someone* signed the hash domain, not that the signer is the manifest's
    declared producer. This record makes the distinction explicit and reportable.

    Attributes:
        binding_level: ``"anchored"`` (x5c chain validates to a configured trust
            anchor — identity is vouched to the extent the anchor vouches for the
            subject), ``"self-attested"`` (cryptographically valid but jwk-only,
            x5c without configured anchors, or an x5c that does not chain to one —
            integrity holds, attribution does NOT), or ``"unverified"`` (the
            signature does not cryptographically verify the content-hashes bytes).
        algorithm: the JWS ``alg`` (``RS256``/``ES256``), or ``None`` if unparseable.
        signer_subject: the leaf certificate subject DN (RFC 4514) when an ``x5c``
            is present; ``None`` for jwk-only signatures (no asserted identity).
        matches_expected_producer: ``True``/``False`` when an ``expected_producer``
            was supplied AND the signature is ``anchored`` with a subject — whether
            the configured expected producer string occurs in the subject DN
            (case-insensitive). ``None`` when no expectation was configured or the
            signature is not an anchored, subject-bearing signature.
        signature_file: the ``signatures/*.jws`` filename (empty for the pure
            ``classify_signature_binding`` helper).
    """

    binding_level: str
    algorithm: str | None
    signer_subject: str | None
    matches_expected_producer: bool | None
    signature_file: str = ""


def classify_signature_binding(
    jws_str: str,
    canonical_input: bytes,
    *,
    manifest_timestamp: str | None = None,
    trust_anchors: list[Certificate] | None = None,
    expected_producer: str | None = None,
) -> SignatureBinding:
    """Classify a single detached JWS's identity binding (spec Appendix D.3).

    Pure function over the JWS string and the canonical ``content-hashes.json``
    bytes — no filesystem access — so it is directly testable. ``signature_bindings``
    is the bundle-directory wrapper. Determining the level NEVER weakens
    verification: a signature is ``anchored`` only if it cryptographically verifies
    AND its x5c chain terminates at a configured trust anchor.
    """
    from acef.errors import ACEFSigningError
    from acef.signing import _base64url_decode, _parse_x5c_chain, verify_detached_jws

    # Parse the protected header (first dot-separated segment). ``_base64url_decode``
    # raises ACEFSigningError on a malformed segment — catch it too so a malformed
    # header returns "unverified" rather than propagating (roborev on 04efe61).
    try:
        header = json.loads(_base64url_decode(jws_str.split(".", 1)[0]))
    except (ACEFSigningError, ValueError, json.JSONDecodeError, UnicodeDecodeError, IndexError):
        return SignatureBinding("unverified", None, None, None)
    alg = header.get("alg") if isinstance(header, dict) else None
    alg = alg if isinstance(alg, str) else None

    # Surface the leaf certificate subject (the asserted identity) when present.
    # Keep both the full DN (for reporting) and the Common-Name value(s) (for an
    # EXACT identity match — never a substring, which would let `acme` match
    # `CN=not-acme` / `CN=evil-acme-signer`).
    from cryptography.x509.oid import NameOID

    signer_subject: str | None = None
    signer_cns: list[str] = []
    x5c = header.get("x5c") if isinstance(header, dict) else None
    if isinstance(x5c, list) and x5c:
        try:
            leaf = _parse_x5c_chain(x5c)[0]
            signer_subject = leaf.subject.rfc4514_string()
            signer_cns = [str(attr.value) for attr in leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        except (ACEFSigningError, ValueError, IndexError):
            signer_subject = None
            signer_cns = []

    # Cryptographic validity is necessary for any non-"unverified" level. This is
    # the SAME check the integrity phase runs; we never accept a binding the
    # integrity phase would reject.
    try:
        verify_detached_jws(jws_str, canonical_input, manifest_timestamp=manifest_timestamp, trust_anchors=None)
    except ACEFSigningError:
        return SignatureBinding("unverified", alg, signer_subject, None)

    # Anchored iff it ALSO verifies under the configured trust anchors with an x5c.
    # When anchors ARE configured and an x5c does NOT chain to one, that is an
    # integrity FAILURE per §3.1.3 (ACEF-012), NOT a self-attested pass — so report
    # it as "unverified", matching the integrity gate (roborev on 04efe61). With NO
    # anchors configured, an x5c (or jwk) is self-attested.
    binding_level = "self-attested"
    if isinstance(x5c, list) and x5c and trust_anchors:
        try:
            verify_detached_jws(
                jws_str, canonical_input, manifest_timestamp=manifest_timestamp, trust_anchors=trust_anchors
            )
            binding_level = "anchored"
        except ACEFSigningError:
            binding_level = "unverified"

    matches: bool | None = None
    if expected_producer is not None and binding_level == "anchored" and signer_subject is not None:
        # EXACT (case-insensitive) identity match. Primary form: the FULL leaf
        # subject DN (so two certs sharing a CN but differing elsewhere — e.g.
        # CN=acme,O=Good vs CN=acme,O=Evil — are distinguished). A bare CN is also
        # accepted as a convenience; security-sensitive deployments SHOULD configure
        # the full subject DN to get an unambiguous binding (roborev on 04efe61).
        want = expected_producer.casefold()
        matches = want == signer_subject.casefold() or any(cn.casefold() == want for cn in signer_cns)

    return SignatureBinding(binding_level, alg, signer_subject, matches)


def signature_bindings(
    bundle_dir: Path,
    *,
    trust_anchors: list[Certificate] | None = None,
    expected_producer: str | None = None,
) -> list[SignatureBinding]:
    """Report the identity binding of every ``signatures/*.jws`` in a bundle.

    The reportable counterpart to the boolean ``get_signature_info`` count: it tells
    a consumer not just *whether* a bundle is signed but *by whom and how strongly*
    (anchored vs self-attested vs unverified), and — when an ``expected_producer`` is
    configured — flags an anchored signature whose subject does not match it (the
    "valid signature, wrong signer" case, spec Appendix D.3). Returns an empty list
    when no ``signatures/`` directory or ``content-hashes.json`` is present.
    """
    sig_dir = bundle_dir / "signatures"
    content_hashes_path = bundle_dir / "hashes" / "content-hashes.json"
    if not sig_dir.exists() or not content_hashes_path.exists():
        return []

    from acef.integrity import canonicalize_json_str

    try:
        canonical_input = canonicalize_json_str(content_hashes_path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError, OSError):
        return []

    manifest_timestamp: str | None = None
    manifest_path = bundle_dir / "acef-manifest.json"
    if manifest_path.exists():
        try:
            mdata = json.loads(manifest_path.read_text(encoding="utf-8"))
            _md = mdata.get("metadata") if isinstance(mdata, dict) else None
            _ts = _md.get("timestamp") if isinstance(_md, dict) else None
            manifest_timestamp = _ts if isinstance(_ts, str) else None
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            manifest_timestamp = None

    bindings: list[SignatureBinding] = []
    for sig_file in sorted(sig_dir.glob("*.jws")):
        try:
            jws_str = sig_file.read_text(encoding="utf-8").strip()
        except (UnicodeDecodeError, OSError):
            bindings.append(SignatureBinding("unverified", None, None, None, sig_file.name))
            continue
        b = classify_signature_binding(
            jws_str,
            canonical_input,
            manifest_timestamp=manifest_timestamp,
            trust_anchors=trust_anchors,
            expected_producer=expected_producer,
        )
        bindings.append(
            SignatureBinding(b.binding_level, b.algorithm, b.signer_subject, b.matches_expected_producer, sig_file.name)
        )
    return bindings
