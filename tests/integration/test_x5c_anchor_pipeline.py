"""Integration tests — trust-anchor threading through the bundle-validation
pipeline (VAL-FIX-LOADER-005, audit finding loader-roundtrip-5).

Spec §3.1.3 "Signature trust model (normative)": "If x5c is present,
verifiers MUST validate the full certificate chain against a locally
configured set of trust anchors."

Before this fix, ``validate_bundle`` / ``check_integrity`` accepted no
trust-anchor configuration and called ``verify_detached_jws`` without
``trust_anchors`` — anchor termination was structurally unreachable from the
standard validation pipeline, so a self-issued internally-consistent x5c
chain passed the integrity phase with no anchor enforcement (RED proof:
``validate_bundle(..., trust_anchors=[...])`` raised TypeError before the
threading existed).

After the fix:
- ``validate_bundle(bundle, trust_anchors=[root])`` on a bundle signed with
  an x5c chain terminating at ``root`` -> clean (no signature diagnostics).
- The same call against a self-issued chain NOT terminating at any
  configured anchor -> ACEF-012 signature diagnostic.
- Default (``trust_anchors`` omitted) preserves today's behavior EXACTLY:
  self-attested trust, no anchor enforcement (backward compatibility — the
  frozen golden bundles carry no x5c, so default-None is behavior-neutral).
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acef.integrity import canonicalize_json_str
from acef.package import Package
from acef.signing import create_detached_jws
from acef.validation.engine import validate_bundle
from acef.validation.integrity_checker import check_integrity

_SIGNATURE_CODES = ("ACEF-012", "ACEF-013")


def _make_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _make_cert(
    subject_cn: str,
    *,
    public_key: ec.EllipticCurvePublicKey,
    signing_key: ec.EllipticCurvePrivateKey,
    issuer_cn: str | None = None,
) -> x509.Certificate:
    """Build a cert whose validity window covers the bundle's (wall-clock)
    manifest timestamp — exported bundles stamp metadata.timestamp at export
    time, and verify_x5c_chain checks cert validity against that value."""
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or subject_cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=365))
        .not_valid_after(now + timedelta(days=3650))
        .sign(signing_key, hashes.SHA256())
    )


def _b64(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")


def _export_bundle(tmp_path: Path) -> Path:
    """Export a minimal valid bundle (unsigned)."""
    pkg = Package(producer={"name": "x5c-anchor-test", "version": "1.0.0"})
    system = pkg.add_subject(
        "ai_system",
        name="Anchor Test System",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )
    pkg.record(
        "risk_register",
        provisions=["article-9"],
        payload={"description": "Test risk", "likelihood": "medium", "severity": "high"},
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    bundle_dir = tmp_path / "bundle.acef"
    pkg.export(str(bundle_dir))
    return bundle_dir


def _sign_bundle_with_x5c(
    bundle_dir: Path,
    leaf_key: ec.EllipticCurvePrivateKey,
    x5c: list[str],
) -> None:
    """Write an x5c detached JWS over the bundle's canonicalized
    content-hashes.json into signatures/ (mirrors signing.sign_bundle, which
    only supports jwk headers). signatures/ is OUTSIDE the hash domain, so
    adding it post-export does not perturb content hashes."""
    content_hashes_path = bundle_dir / "hashes" / "content-hashes.json"
    payload = canonicalize_json_str(content_hashes_path.read_text(encoding="utf-8"))
    jws = create_detached_jws(payload, leaf_key, kid="x5c-anchor-key", x5c=x5c)
    sig_dir = bundle_dir / "signatures"
    sig_dir.mkdir(exist_ok=True)
    (sig_dir / "x5c-anchor-key.jws").write_text(jws, encoding="utf-8")


def _build_anchored_chain() -> tuple[ec.EllipticCurvePrivateKey, list[str], x509.Certificate]:
    """leaf <- intermediate <- root. Returns (leaf_key, x5c, root_cert)."""
    root_key = _make_key()
    inter_key = _make_key()
    leaf_key = _make_key()
    root = _make_cert("pipeline-root", public_key=root_key.public_key(), signing_key=root_key)
    inter = _make_cert(
        "pipeline-intermediate",
        public_key=inter_key.public_key(),
        signing_key=root_key,
        issuer_cn="pipeline-root",
    )
    leaf = _make_cert(
        "pipeline-leaf",
        public_key=leaf_key.public_key(),
        signing_key=inter_key,
        issuer_cn="pipeline-intermediate",
    )
    return leaf_key, [_b64(leaf), _b64(inter), _b64(root)], root


def _build_self_issued_chain() -> tuple[ec.EllipticCurvePrivateKey, list[str]]:
    """A self-signed single-cert chain — internally consistent, anyone can
    mint one. Returns (leaf_key, x5c)."""
    key = _make_key()
    cert = _make_cert("self-issued-signer", public_key=key.public_key(), signing_key=key)
    return key, [_b64(cert)]


def _signature_diags(assessment_errors: list[dict[str, object]]) -> list[dict[str, object]]:
    return [e for e in assessment_errors if e.get("code") in _SIGNATURE_CODES]


class TestValidateBundleTrustAnchors:
    def test_anchored_x5c_bundle_validates_clean(self, tmp_path: Path) -> None:
        """End-to-end plumbing: a bundle signed with an x5c chain terminating
        at the configured anchor produces NO signature diagnostics."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = validate_bundle(str(bundle_dir), trust_anchors=[root])
        assert _signature_diags(assessment.structural_errors) == []

    def test_self_issued_x5c_rejected_when_anchors_configured(self, tmp_path: Path) -> None:
        """THE pipeline fix (RED-first): a self-issued, internally-consistent
        x5c chain MUST be rejected when trust anchors are configured and the
        chain does not terminate at any of them. Before the threading existed
        this call raised TypeError (no ``trust_anchors`` parameter) — anchor
        enforcement was structurally unreachable from validate_bundle."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        # An unrelated root is configured — the self-issued chain must NOT
        # anchor to it.
        _, _, unrelated_root = _build_anchored_chain()
        assessment = validate_bundle(str(bundle_dir), trust_anchors=[unrelated_root])

        diags = _signature_diags(assessment.structural_errors)
        assert len(diags) == 1, f"expected exactly one signature diagnostic, got: {diags!r}"
        assert diags[0]["code"] == "ACEF-012"
        assert "trust anchor" in str(diags[0]["message"])
        assert "x5c-anchor-key.jws" in str(diags[0]["message"])

    def test_default_no_anchors_preserves_self_attested_behavior(self, tmp_path: Path) -> None:
        """Backward compatibility: WITHOUT trust_anchors the same self-issued
        bundle still passes the integrity phase (self-attested trust per the
        spec trust model — absent locally configured anchors, the signature
        proves data integrity, not organizational identity)."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = validate_bundle(str(bundle_dir))
        assert _signature_diags(assessment.structural_errors) == []

    def test_anchored_and_default_produce_identical_diagnostics(self, tmp_path: Path) -> None:
        """For a properly anchored bundle, validating WITH anchors yields the
        same diagnostic set as validating WITHOUT (the anchor check adds no
        false positives)."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        with_anchors = validate_bundle(str(bundle_dir), trust_anchors=[root])
        without_anchors = validate_bundle(str(bundle_dir))
        assert with_anchors.structural_errors == without_anchors.structural_errors


class TestCheckIntegrityTrustAnchors:
    def test_check_integrity_rejects_unanchored_chain(self, tmp_path: Path) -> None:
        """Phase-2 entry point: check_integrity itself enforces anchor
        termination when anchors are supplied."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        _, _, unrelated_root = _build_anchored_chain()
        diagnostics = check_integrity(bundle_dir, trust_anchors=[unrelated_root])
        sig_diags = [d for d in diagnostics if d.code == "ACEF-012"]
        assert len(sig_diags) == 1
        assert "trust anchor" in sig_diags[0].message

    def test_check_integrity_default_unchanged(self, tmp_path: Path) -> None:
        """Default call (no anchors) — no signature diagnostics for the same
        self-issued bundle, preserving today's behavior exactly."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        diagnostics = check_integrity(bundle_dir)
        assert [d for d in diagnostics if d.code in _SIGNATURE_CODES] == []

    def test_check_integrity_accepts_anchored_chain(self, tmp_path: Path) -> None:
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        diagnostics = check_integrity(bundle_dir, trust_anchors=[root])
        assert [d for d in diagnostics if d.code in _SIGNATURE_CODES] == []
