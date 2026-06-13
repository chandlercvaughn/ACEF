"""ACEF Assessment Builder — Assessment Bundle creation, signing, and export.

Renamed from assessment.py per eng review to prevent import confusion
with models/assessment.py.
"""

from __future__ import annotations

from pathlib import Path

from acef.integrity import canonicalize
from acef.models.assessment import AssessmentBundle
from acef.package import Package
from acef.validation.engine import validate_bundle


def validate(
    package_or_path: Package | str | Path,
    *,
    profiles: list[str] | None = None,
    evaluation_instant: str | None = None,
    timestamp: str | None = None,
    assessment_id: str | None = None,
) -> AssessmentBundle:
    """Validate a package or bundle and produce an Assessment Bundle.

    This is the top-level validation API.

    Args:
        package_or_path: A Package object or path to a bundle directory/archive.
        profiles: List of profile IDs to evaluate.
        evaluation_instant: Override evaluation timestamp (ISO 8601) — pins the
            evaluation results per spec §3.7.
        timestamp: Override the Assessment Bundle's creation ``timestamp``.
            Default ``None`` keeps the wall-clock creation time (intentionally
            non-reproducible). Supply an explicit value (with ``assessment_id``)
            to stabilize the assessment PAYLOAD — the canonical RFC-8785 bytes
            signed by ``sign_assessment`` become byte-identical across runs.
            Byte equality of the SIGNED ``.acef-assessment.json`` ALSO requires
            a deterministic signing algorithm: an RS256-signed export of the
            pinned payload is byte-reproducible, but an ES256-signed export is
            NOT (random ECDSA nonce). See ``validate_bundle`` and audit
            findings assessment-rollup-5 and export-determinism-4.
        assessment_id: Override the Assessment Bundle's ``assessment_id`` URN.
            Default ``None`` mints a fresh random URN per run. Pin it alongside
            ``timestamp`` to stabilize the payload; the resulting signed
            assessment is byte-reproducible only under RS256, not ES256.

    Returns:
        An AssessmentBundle with all results.
    """
    import tempfile

    if isinstance(package_or_path, Package):
        # Export to temp dir, then validate
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = Path(tmpdir) / "bundle.acef"
            package_or_path.export(str(bundle_dir))
            return validate_bundle(
                bundle_dir,
                profiles=profiles,
                evaluation_instant=evaluation_instant,
                timestamp=timestamp,
                assessment_id=assessment_id,
            )
    else:
        path = Path(package_or_path)
        if path.suffix == ".gz" or str(path).endswith(".tar.gz"):
            # Archive input: safely extract the archive bytes VERBATIM and
            # validate the extracted directory as-received. We deliberately do
            # NOT round-trip through ``load`` → ``Package.export`` here: that
            # regenerates ``hashes/content-hashes.json`` / ``hashes/merkle-tree.json``
            # from the loaded records and SILENTLY HEALS any tampering (a
            # stripped Merkle tree, a content-hash mismatch) before the integrity
            # verifier ran — so SDK callers never received the FATAL integrity
            # verdict (ACEF-010 / ACEF-011) the equivalent directory bundle
            # produces. ``extract_archive_raw`` (the shared loader primitive, the
            # SAME one the ``validate`` / ``verify`` CLI commands use) extracts
            # the raw bytes so archive and directory inputs agree. Validation
            # runs INSIDE the ``with`` block, while the extracted files exist.
            from acef.loader import extract_archive_raw

            with extract_archive_raw(path) as bundle_dir:
                return validate_bundle(
                    bundle_dir,
                    profiles=profiles,
                    evaluation_instant=evaluation_instant,
                    timestamp=timestamp,
                    assessment_id=assessment_id,
                )
        else:
            return validate_bundle(
                path,
                profiles=profiles,
                evaluation_instant=evaluation_instant,
                timestamp=timestamp,
                assessment_id=assessment_id,
            )


def export_assessment(
    assessment: AssessmentBundle,
    output_path: str,
    *,
    key_path: str | None = None,
    signer: str = "",
    kid: str | None = None,
) -> Path:
    """Export an Assessment Bundle to a JSON file.

    Args:
        assessment: The AssessmentBundle to export.
        output_path: Path to the output .acef-assessment.json file.
        key_path: Optional path to private key for signing.
        signer: Signer identity threaded into ``integrity.signature.signer``
            when signing — a URN (e.g. ``urn:acef:act:...``) or X.509 subject,
            per the spec §4 example. Ignored when ``key_path`` is None. Default
            ``""`` (no fabricated identity).
        kid: JWS key identifier threaded into the signature header when signing.
            Default ``None`` derives a stable per-key identifier from the key
            (RFC 7638 JWK thumbprint). Ignored when ``key_path`` is None.

    Returns:
        Path to the created file.
    """
    data = assessment.to_dict()

    if key_path:
        from acef.signing import sign_assessment

        data = sign_assessment(data, key_path, signer=signer, kid=kid)

    canonical = canonicalize(data)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical)

    return output
