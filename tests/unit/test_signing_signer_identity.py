"""Tests for real signer/kid identity threading through sign_assessment /
export_assessment / sign_bundle (assessment-rollup-6 + signing-jws-6).

Before the fix, ``sign_assessment`` hardcoded ``signer=""`` and a fixed
``kid="assessor-key"`` regardless of key identity, so the produced assessment
carried NO signer identity and the kid could never reflect the real key. The
spec §4 Assessment Bundle example shows ``"signer": "urn:acef:act:..."``. The
fix threads an optional ``signer`` (URN / cert subject) and a caller-supplied
``kid`` through ``sign_assessment`` AND ``export_assessment``; when no ``kid`` is
supplied the default is derived deterministically from the key (RFC 7638 JWK
thumbprint), NOT the fixed literal ``"assessor-key"``.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from acef.signing import sign_assessment, verify_assessment


def _write_rsa_key(tmp_dir: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_dir / "rsa_private.pem"
    path.write_bytes(pem)
    return path


def _write_ec_key(tmp_dir: Path) -> Path:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_dir / "ec_private.pem"
    path.write_bytes(pem)
    return path


def _jws_header(jws: str) -> dict:
    header_b64 = jws.split(".", 1)[0]
    padding = "=" * (-len(header_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(header_b64 + padding))


def _minimal_assessment() -> dict:
    return {
        "acef_assessment_version": "1.0.0",
        "assessment_id": "urn:acef:asx:00000000-0000-4000-8000-000000000000",
        "evaluation_instant": "2026-01-01T00:00:00Z",
        "timestamp": "2026-01-01T00:00:00Z",
        "results": [],
        "provision_summary": [],
        "structural_errors": [],
    }


class TestSignAssessmentSignerIdentity:
    def test_signer_param_populates_integrity_signer(self, tmp_dir: Path) -> None:
        """An explicit signer URN appears in integrity.signature.signer."""
        key_path = _write_rsa_key(tmp_dir)
        signer = "urn:acef:act:11111111-1111-4111-8111-111111111111"
        signed = sign_assessment(_minimal_assessment(), str(key_path), signer=signer)
        assert signed["integrity"]["signature"]["signer"] == signer

    def test_kid_param_threads_into_jws_header(self, tmp_dir: Path) -> None:
        """A caller-supplied kid is the kid in the produced JWS header — not the
        fixed literal 'assessor-key'."""
        key_path = _write_rsa_key(tmp_dir)
        signed = sign_assessment(_minimal_assessment(), str(key_path), kid="my-rotation-key-2026")
        header = _jws_header(signed["integrity"]["signature"]["value"])
        assert header["kid"] == "my-rotation-key-2026"

    def test_default_kid_is_thumbprint_not_assessor_key(self, tmp_dir: Path) -> None:
        """With no kid supplied, the default kid is derived from the key (RFC 7638
        thumbprint), NOT the fixed literal 'assessor-key'."""
        key_path = _write_rsa_key(tmp_dir)
        signed = sign_assessment(_minimal_assessment(), str(key_path))
        header = _jws_header(signed["integrity"]["signature"]["value"])
        assert header["kid"] != "assessor-key", (
            "default kid must be key-derived (thumbprint), not the fixed 'assessor-key' literal"
        )
        # A thumbprint is a non-empty base64url SHA-256 (43 chars, no padding).
        assert len(header["kid"]) == 43

    def test_default_kid_is_stable_for_same_key(self, tmp_dir: Path) -> None:
        """The key-derived default kid is deterministic for the same key."""
        key_path = _write_rsa_key(tmp_dir)
        a = sign_assessment(_minimal_assessment(), str(key_path))
        b = sign_assessment(_minimal_assessment(), str(key_path))
        assert (
            _jws_header(a["integrity"]["signature"]["value"])["kid"]
            == (_jws_header(b["integrity"]["signature"]["value"])["kid"])
        )

    def test_default_kid_differs_for_different_keys(self, tmp_dir: Path) -> None:
        """Two different keys produce different default thumbprint kids."""
        k1 = _write_rsa_key(tmp_dir)
        # second key in a distinct file
        key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem2 = key2.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        k2 = tmp_dir / "rsa_private2.pem"
        k2.write_bytes(pem2)

        kid1 = _jws_header(sign_assessment(_minimal_assessment(), str(k1))["integrity"]["signature"]["value"])["kid"]
        kid2 = _jws_header(sign_assessment(_minimal_assessment(), str(k2))["integrity"]["signature"]["value"])["kid"]
        assert kid1 != kid2

    def test_default_signer_is_empty_string(self, tmp_dir: Path) -> None:
        """No fabricated identity: default signer is the empty string (schema-valid)."""
        key_path = _write_rsa_key(tmp_dir)
        signed = sign_assessment(_minimal_assessment(), str(key_path))
        assert signed["integrity"]["signature"]["signer"] == ""

    def test_signed_assessment_still_verifies_with_explicit_identity(self, tmp_dir: Path) -> None:
        """Threading signer/kid does not break the JWS — it still verifies."""
        key_path = _write_rsa_key(tmp_dir)
        signed = sign_assessment(
            _minimal_assessment(),
            str(key_path),
            signer="urn:acef:act:22222222-2222-4222-8222-222222222222",
            kid="auditor-key-A",
        )
        assert verify_assessment(signed) is True

    def test_ec_default_kid_is_thumbprint(self, tmp_dir: Path) -> None:
        """EC keys also get a key-derived thumbprint kid by default."""
        key_path = _write_ec_key(tmp_dir)
        signed = sign_assessment(_minimal_assessment(), str(key_path))
        header = _jws_header(signed["integrity"]["signature"]["value"])
        assert header["kid"] != "assessor-key"
        assert len(header["kid"]) == 43


class TestExportAssessmentSignerIdentity:
    def test_export_assessment_threads_signer_and_kid(self, tmp_dir: Path) -> None:
        """export_assessment(signer=..., kid=...) flows both into the signed file."""
        from acef.assessment_builder import export_assessment, validate
        from tests.conformance.conftest import build_minimal_package

        key_path = _write_rsa_key(tmp_dir)
        pkg = build_minimal_package()
        assessment = validate(
            pkg,
            evaluation_instant="2026-01-01T00:00:00Z",
            timestamp="2026-01-01T00:00:00Z",
            assessment_id="urn:acef:asx:55555555-5555-4555-8555-555555555555",
        )
        signer = "urn:acef:act:99999999-9999-4999-8999-999999999999"
        out = export_assessment(
            assessment,
            str(tmp_dir / "signed.json"),
            key_path=str(key_path),
            signer=signer,
            kid="export-key-2026",
        )
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["integrity"]["signature"]["signer"] == signer
        header = _jws_header(data["integrity"]["signature"]["value"])
        assert header["kid"] == "export-key-2026"

    def test_export_assessment_default_kid_is_thumbprint(self, tmp_dir: Path) -> None:
        """export_assessment with no kid uses the key-derived thumbprint default."""
        from acef.assessment_builder import export_assessment, validate
        from tests.conformance.conftest import build_minimal_package

        key_path = _write_rsa_key(tmp_dir)
        pkg = build_minimal_package()
        assessment = validate(
            pkg,
            evaluation_instant="2026-01-01T00:00:00Z",
            timestamp="2026-01-01T00:00:00Z",
            assessment_id="urn:acef:asx:66666666-6666-4666-8666-666666666666",
        )
        out = export_assessment(assessment, str(tmp_dir / "signed_default.json"), key_path=str(key_path))
        data = json.loads(out.read_text(encoding="utf-8"))
        header = _jws_header(data["integrity"]["signature"]["value"])
        assert header["kid"] != "assessor-key"


class TestSignBundleKid:
    """``sign_bundle`` ALREADY accepts an overridable ``kid`` (signing-jws-6
    verifier note); the real fixed-identity defect was ``sign_assessment``. The
    ``sign_bundle`` DEFAULT kid is DELIBERATELY kept as ``"provider-key"`` because
    the archive-export preflight (``export.py``) predicts the
    ``signatures/<safe_kid>.jws`` member name from that exact default literal, and
    ``export.py`` is owned by another feature. Threading the thumbprint default
    there would desync the predicted archive member name. So here we pin the
    overridable contract: an explicit kid is honored, and the default is the
    stable ``provider-key`` literal the export preflight depends on.
    """

    def test_sign_bundle_explicit_kid_is_honored(self, tmp_dir: Path) -> None:
        """An explicit kid is used verbatim by sign_bundle (rotation/identity)."""
        from acef.signing import sign_bundle
        from tests.conformance.conftest import build_minimal_package

        key_path = _write_rsa_key(tmp_dir)
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "bundle2.acef"
        pkg.export(str(bundle_dir))

        sig_path = sign_bundle(bundle_dir, str(key_path), kid="provider-rotation-7")
        jws = Path(sig_path).read_text(encoding="utf-8")
        assert _jws_header(jws)["kid"] == "provider-rotation-7"

    def test_sign_bundle_default_kid_stays_provider_key_for_export_preflight(self, tmp_dir: Path) -> None:
        """The default kid stays the 'provider-key' literal the export-archive
        preflight (export.py) predicts the signature filename from — changing it
        would desync the archive member name (owned by another feature)."""
        from acef.signing import sign_bundle
        from tests.conformance.conftest import build_minimal_package

        key_path = _write_rsa_key(tmp_dir)
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "bundle3.acef"
        pkg.export(str(bundle_dir))

        sig_path = sign_bundle(bundle_dir, str(key_path))
        assert Path(sig_path).name == "provider-key.jws"
        assert _jws_header(Path(sig_path).read_text(encoding="utf-8"))["kid"] == "provider-key"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
