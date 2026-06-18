"""F42: the spec flagship example (planning §5.1, lines 1602-1603) calls
``assessment.sign(key=..., method="jws")`` and ``assessment.export(path)`` as
METHODS, paralleling ``package.sign()`` / ``package.export()`` — but
AssessmentBundle exposed only ``summary()`` / ``errors()``; signing/export were
free functions (``acef.sign_assessment`` / ``acef.export_assessment``). The
flagship example therefore did not run. These methods make it real.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import acef
from acef.package import Package


def _rsa_key(tmp_path: Path) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    p = tmp_path / "rsa_private.pem"
    p.write_bytes(pem)
    return str(p)


class TestAssessmentBundleSignExport:
    def test_export_method_writes_a_valid_file(self, minimal_package: Package, tmp_path: Path) -> None:
        assessment = acef.validate(minimal_package)
        out = assessment.export(str(tmp_path / "a.acef-assessment.json"))
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["versioning"]["assessment_version"] == "1.0.0"

    def test_sign_then_export_embeds_a_signature(self, minimal_package: Package, tmp_path: Path) -> None:
        assessment = acef.validate(minimal_package)
        assessment.sign(key=_rsa_key(tmp_path), method="jws")
        out = assessment.export(str(tmp_path / "signed.acef-assessment.json"))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data.get("integrity") is not None, "signed export must carry an integrity block"
        assert data["integrity"].get("signature"), "signed export must carry a signature"

    def test_sign_rejects_non_jws_method(self, minimal_package: Package) -> None:
        assessment = acef.validate(minimal_package)
        with pytest.raises(ValueError):
            assessment.sign(key="ignored.pem", method="cms")

    def test_method_export_matches_free_function_bytes(self, minimal_package: Package, tmp_path: Path) -> None:
        """The method delegates to the free function — unsigned export of the
        SAME instance is byte-identical via either path."""
        from acef.assessment_builder import export_assessment

        assessment = acef.validate(minimal_package)
        via_method = assessment.export(str(tmp_path / "m.json"))
        via_free = export_assessment(assessment, str(tmp_path / "f.json"))
        assert via_method.read_bytes() == via_free.read_bytes()
