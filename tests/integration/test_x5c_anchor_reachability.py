"""Integration tests — x5c trust-anchor enforcement reachability through the
SHIPPED public surfaces (audit finding F4).

Finding F4: the trust-anchor threading (audit loader-roundtrip-5, commit
d80198b) wired ``trust_anchors`` through ``validate_bundle`` →
``check_integrity`` → ``verify_x5c_chain``, but NO shipped public surface let
an operator populate it:

* ``acef.validate()`` (the top-level SDK API, ``assessment_builder.validate``)
  had no ``trust_anchors`` parameter — ``acef.validate(bundle, trust_anchors=[])``
  raised ``TypeError: validate() got an unexpected keyword argument
  'trust_anchors'``.
* ``acef validate`` / ``acef verify`` (the CLI) had no ``--trust-anchor`` option,
  so anchor enforcement was unreachable from the command line.

Net effect: spec §3.1.3 ("verifiers MUST validate the full certificate chain
against a locally configured set of trust anchors") was implementable only by
reaching past every public API into ``validate_bundle`` directly — dead-end
capability for the documented adopter.

After the fix:
* ``acef.validate(bundle, trust_anchors=[root])`` forwards the anchors to the
  pipeline; a self-issued chain not terminating at a configured anchor surfaces
  ACEF-012.
* ``acef validate --trust-anchor PATH`` / ``acef verify --trust-anchor PATH``
  load PEM/DER certs via ``signing.load_trust_anchors`` and forward them.
* Default (no anchors) preserves self-attested behavior exactly.

Cert/bundle fixtures are reused from ``test_x5c_anchor_pipeline`` (the existing
engine-level test) so the reachability layer is exercised against the SAME
anchored / self-issued chains the lower layer is.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization

import acef
from acef.cli.main import cli
from acef.errors import ACEFSigningError
from acef.signing import load_trust_anchors

from .test_x5c_anchor_pipeline import (
    _SIGNATURE_CODES,
    _build_anchored_chain,
    _build_self_issued_chain,
    _export_bundle,
    _sign_bundle_with_x5c,
)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _pem(cert: object) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)  # type: ignore[attr-defined]


def _der(cert: object) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)  # type: ignore[attr-defined]


def _sig_codes(structural_errors: list[dict[str, object]]) -> list[object]:
    return [e.get("code") for e in structural_errors if e.get("code") in _SIGNATURE_CODES]


# --------------------------------------------------------------------------
# Public SDK API — acef.validate(..., trust_anchors=...)
# --------------------------------------------------------------------------


class TestPublicValidateTrustAnchors:
    def test_validate_accepts_trust_anchors_kwarg(self, tmp_path: Path) -> None:
        """RED proof of the API gap: before F4, this raised
        ``TypeError: validate() got an unexpected keyword argument
        'trust_anchors'``. An empty anchor list is behavior-neutral."""
        bundle_dir = _export_bundle(tmp_path)
        assessment = acef.validate(str(bundle_dir), trust_anchors=[])
        # Unsigned bundle, no anchors enforced → no signature diagnostics.
        assert _sig_codes(assessment.structural_errors) == []

    def test_self_issued_rejected_via_public_api(self, tmp_path: Path) -> None:
        """A self-issued x5c chain that does not terminate at the configured
        anchor surfaces ACEF-012 through the TOP-LEVEL ``acef.validate`` API —
        not just the lower-level ``validate_bundle``."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        _, _, unrelated_root = _build_anchored_chain()
        assessment = acef.validate(str(bundle_dir), trust_anchors=[unrelated_root])

        sig = [e for e in assessment.structural_errors if e.get("code") == "ACEF-012"]
        assert len(sig) == 1, f"expected one ACEF-012, got {sig!r}"
        assert "trust anchor" in str(sig[0]["message"])

    def test_anchored_chain_clean_via_public_api(self, tmp_path: Path) -> None:
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = acef.validate(str(bundle_dir), trust_anchors=[root])
        assert _sig_codes(assessment.structural_errors) == []

    def test_default_unchanged_via_public_api(self, tmp_path: Path) -> None:
        """Backward compatibility: omitting ``trust_anchors`` preserves
        self-attested behavior — the self-issued signature still passes."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = acef.validate(str(bundle_dir))
        assert _sig_codes(assessment.structural_errors) == []


# --------------------------------------------------------------------------
# CLI — acef validate --trust-anchor / acef verify --trust-anchor
# --------------------------------------------------------------------------


class TestValidateCliTrustAnchors:
    def test_self_issued_rejected_with_anchor_pem(self, runner: CliRunner, tmp_path: Path) -> None:
        """RED-first for the CLI gap: ``acef validate --trust-anchor`` rejects a
        self-issued chain that does not terminate at the supplied anchor.
        Before F4 the option did not exist (click exit 2, "No such option")."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        _, _, unrelated_root = _build_anchored_chain()
        anchor_pem = tmp_path / "anchor.pem"
        anchor_pem.write_bytes(_pem(unrelated_root))

        result = runner.invoke(
            cli,
            ["validate", str(bundle_dir), "--trust-anchor", str(anchor_pem), "--format", "json"],
        )
        payload = json.loads(result.output)
        codes = [e.get("code") for e in payload["structural_errors"]]
        assert "ACEF-012" in codes, f"expected ACEF-012, got {codes!r}"

    def test_anchored_chain_clean_with_anchor_pem(self, runner: CliRunner, tmp_path: Path) -> None:
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        anchor_pem = tmp_path / "anchor.pem"
        anchor_pem.write_bytes(_pem(root))

        result = runner.invoke(
            cli,
            ["validate", str(bundle_dir), "--trust-anchor", str(anchor_pem), "--format", "json"],
        )
        payload = json.loads(result.output)
        codes = [e.get("code") for e in payload["structural_errors"]]
        assert "ACEF-012" not in codes, f"unexpected ACEF-012: {codes!r}"

    def test_anchor_der_accepted(self, runner: CliRunner, tmp_path: Path) -> None:
        """A DER-encoded anchor file is accepted, not only PEM."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        _, _, unrelated_root = _build_anchored_chain()
        anchor_der = tmp_path / "anchor.der"
        anchor_der.write_bytes(_der(unrelated_root))

        result = runner.invoke(
            cli,
            ["validate", str(bundle_dir), "--trust-anchor", str(anchor_der), "--format", "json"],
        )
        payload = json.loads(result.output)
        codes = [e.get("code") for e in payload["structural_errors"]]
        assert "ACEF-012" in codes, f"expected ACEF-012, got {codes!r}"

    def test_invalid_anchor_file_clean_error(self, runner: CliRunner, tmp_path: Path) -> None:
        """A non-certificate ``--trust-anchor`` file surfaces a clean error +
        non-zero exit, never a raw traceback."""
        bundle_dir = _export_bundle(tmp_path)
        garbage = tmp_path / "not-a-cert.pem"
        garbage.write_text("this is not a certificate\n", encoding="utf-8")

        result = runner.invoke(
            cli,
            ["validate", str(bundle_dir), "--trust-anchor", str(garbage)],
        )
        assert result.exit_code != 0
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert "ACEF-012" in result.output or "trust anchor" in result.output.lower()


class TestVerifyCliTrustAnchors:
    def test_self_issued_rejected_with_anchor(self, runner: CliRunner, tmp_path: Path) -> None:
        """``acef verify --trust-anchor`` enforces anchor termination too."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        _, _, unrelated_root = _build_anchored_chain()
        anchor_pem = tmp_path / "anchor.pem"
        anchor_pem.write_bytes(_pem(unrelated_root))

        result = runner.invoke(
            cli,
            ["verify", str(bundle_dir), "--trust-anchor", str(anchor_pem), "--format", "json"],
        )
        payload = json.loads(result.output)
        codes = [d.get("code") for d in payload["diagnostics"]]
        assert "ACEF-012" in codes, f"expected ACEF-012, got {codes!r}"

    def test_anchored_chain_clean_with_anchor(self, runner: CliRunner, tmp_path: Path) -> None:
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        anchor_pem = tmp_path / "anchor.pem"
        anchor_pem.write_bytes(_pem(root))

        result = runner.invoke(
            cli,
            ["verify", str(bundle_dir), "--trust-anchor", str(anchor_pem), "--format", "json"],
        )
        payload = json.loads(result.output)
        codes = [d.get("code") for d in payload["diagnostics"]]
        assert "ACEF-012" not in codes, f"unexpected ACEF-012: {codes!r}"


# --------------------------------------------------------------------------
# Loader unit — signing.load_trust_anchors
# --------------------------------------------------------------------------


class TestLoadTrustAnchors:
    def test_empty_returns_empty(self) -> None:
        assert load_trust_anchors([]) == []

    def test_loads_pem(self, tmp_path: Path) -> None:
        _, _, root = _build_anchored_chain()
        pem = tmp_path / "root.pem"
        pem.write_bytes(_pem(root))
        anchors = load_trust_anchors([str(pem)])
        assert len(anchors) == 1
        assert anchors[0] == root

    def test_loads_der(self, tmp_path: Path) -> None:
        _, _, root = _build_anchored_chain()
        der = tmp_path / "root.der"
        der.write_bytes(_der(root))
        anchors = load_trust_anchors([str(der)])
        assert len(anchors) == 1
        assert anchors[0] == root

    def test_preserves_order(self, tmp_path: Path) -> None:
        _, _, root_a = _build_anchored_chain()
        _, _, root_b = _build_anchored_chain()
        pem_a = tmp_path / "a.pem"
        pem_b = tmp_path / "b.pem"
        pem_a.write_bytes(_pem(root_a))
        pem_b.write_bytes(_pem(root_b))
        anchors = load_trust_anchors([str(pem_a), str(pem_b)])
        assert anchors == [root_a, root_b]

    def test_missing_file_raises_acef012(self, tmp_path: Path) -> None:
        with pytest.raises(ACEFSigningError) as exc:
            load_trust_anchors([str(tmp_path / "nope.pem")])
        assert exc.value.code == "ACEF-012"

    def test_garbage_raises_acef012(self, tmp_path: Path) -> None:
        garbage = tmp_path / "garbage.pem"
        garbage.write_text("not a cert", encoding="utf-8")
        with pytest.raises(ACEFSigningError) as exc:
            load_trust_anchors([str(garbage)])
        assert exc.value.code == "ACEF-012"
