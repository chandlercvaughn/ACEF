"""Conformance tests for signed-artifact determinism honesty (F-M3-DET-MISC).

Covers two audit findings:

* export-determinism-4 (ES256 determinism honesty): ES256 uses a random
  ECDSA nonce, so a re-export of the SAME ES256-signed package produces
  DIFFERENT ``signatures/*.jws`` bytes and therefore a different
  ``.acef.tar.gz``. RS256 (PKCS1v15) IS deterministic. The signing/export
  docstrings must state this honestly; these tests pin the actual behavior.

* assessment-rollup-5 (AssessmentBundle reproducibility): the Assessment
  Bundle carries wall-clock ``timestamp`` and a random ``assessment_id`` as
  default-factory fields, both of which land inside the RFC-8785 bytes that
  ``sign_assessment`` signs. Without an explicit, reproducibility-pinning
  input a signed assessment is NOT byte-reproducible. ``validate_bundle``
  must accept explicit ``timestamp``/``assessment_id`` so a caller CAN
  produce a byte-reproducible signed assessment, while preserving the
  wall-clock/random default for callers who do not pass them.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from acef.assessment_builder import export_assessment, validate
from acef.export import export_archive
from acef.validation.engine import validate_bundle
from tests.conformance.conftest import build_minimal_package


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


# --- export-determinism-4: signed-archive reproducibility honesty ----------


class TestSignedArchiveReproducibility:
    """Pin the (a)symmetry between RS256 and ES256 signed-archive determinism.

    The bundle root name is derived from the output basename, so byte-equality
    is only expected when the SAME basename is used twice (matching the
    existing ``test_same_name_archives_byte_identical`` contract). Both exports
    below use ``bundle.acef.tar.gz`` in separate directories.
    """

    def test_rs256_signed_archive_is_byte_reproducible(self, tmp_dir: Path) -> None:
        """RS256 (PKCS1v15) is deterministic → re-export is byte-identical.

        Spec §3.1.1 places ``signatures/`` OUTSIDE the hash domain, but RS256
        signatures are themselves deterministic, so a re-export of the same
        RS256-signed package is byte-for-byte identical end-to-end.
        """
        key_path = _write_rsa_key(tmp_dir)
        pkg = build_minimal_package()
        pkg.sign(str(key_path))

        a1 = tmp_dir / "ra" / "bundle.acef.tar.gz"
        a2 = tmp_dir / "rb" / "bundle.acef.tar.gz"
        a1.parent.mkdir(parents=True)
        a2.parent.mkdir(parents=True)

        export_archive(pkg, str(a1))
        export_archive(pkg, str(a2))

        assert a1.read_bytes() == a2.read_bytes(), (
            "RS256-signed archives must be byte-identical (PKCS1v15 is deterministic)"
        )

    def test_es256_signed_archive_is_not_byte_reproducible(self, tmp_dir: Path) -> None:
        """ES256 uses a random ECDSA nonce → re-export differs (honesty test).

        This is NOT a spec MUST violation (``signatures/`` is outside the hash
        domain and the spec never claims reproducible signatures). It documents
        that anyone relying on byte-equality of ES256-signed archives is
        mistaken: the cryptography library does not use RFC 6979 deterministic
        k, so two exports differ. The UNSIGNED bundle is fully reproducible
        (proven by the existing determinism tests); only the signature bytes
        differ here.
        """
        key_path = _write_ec_key(tmp_dir)
        pkg = build_minimal_package()
        pkg.sign(str(key_path))

        a1 = tmp_dir / "ea" / "bundle.acef.tar.gz"
        a2 = tmp_dir / "eb" / "bundle.acef.tar.gz"
        a1.parent.mkdir(parents=True)
        a2.parent.mkdir(parents=True)

        export_archive(pkg, str(a1))
        export_archive(pkg, str(a2))

        assert a1.read_bytes() != a2.read_bytes(), (
            "ES256-signed archives are expected to differ (random ECDSA nonce). "
            "If this assertion fails, the signing path switched to deterministic "
            "k (RFC 6979) and the honesty docstrings must be revisited."
        )


# --- assessment-rollup-5: reproducible signed assessment -------------------


class TestSignedAssessmentReproducibility:
    """A signed Assessment Bundle is reproducible IFF identity scalars are pinned.

    ``AssessmentBundle.timestamp`` (wall-clock) and ``assessment_id`` (random
    URN) are both default-factory fields inside the RFC-8785 bytes that
    ``sign_assessment`` signs. ``validate_bundle`` accepts explicit values for
    both so a caller can produce a byte-reproducible signed assessment.
    """

    def test_explicit_identity_yields_byte_identical_signed_assessment(self, tmp_dir: Path) -> None:
        """Same evaluation_instant + timestamp + assessment_id + key → identical bytes."""
        key_path = _write_rsa_key(tmp_dir)
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "bundle.acef"
        pkg.export(str(bundle_dir))

        fixed_instant = "2026-01-01T00:00:00Z"
        fixed_ts = "2026-01-01T00:00:00Z"
        fixed_id = "urn:acef:asx:00000000-0000-4000-8000-000000000000"

        a1 = validate_bundle(
            bundle_dir,
            evaluation_instant=fixed_instant,
            timestamp=fixed_ts,
            assessment_id=fixed_id,
        )
        a2 = validate_bundle(
            bundle_dir,
            evaluation_instant=fixed_instant,
            timestamp=fixed_ts,
            assessment_id=fixed_id,
        )

        assert a1.timestamp == fixed_ts
        assert a1.assessment_id == fixed_id
        assert a2.timestamp == fixed_ts
        assert a2.assessment_id == fixed_id

        out1 = export_assessment(a1, str(tmp_dir / "a1.json"), key_path=str(key_path))
        out2 = export_assessment(a2, str(tmp_dir / "a2.json"), key_path=str(key_path))

        assert out1.read_bytes() == out2.read_bytes(), (
            "Signed assessment with pinned identity scalars must be byte-reproducible"
        )

    def test_default_timestamp_is_creation_time_and_documented_nonreproducible(self, tmp_dir: Path) -> None:
        """Without explicit identity, timestamp is creation-time (wall-clock).

        This documents the default contract: a caller who does NOT pin
        ``timestamp``/``assessment_id`` gets a non-reproducible signed artifact.
        ``assessment_id`` is a random URN, so two default validations differ
        even within the same wall-clock second.
        """
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "bundle2.acef"
        pkg.export(str(bundle_dir))

        a1 = validate_bundle(bundle_dir, evaluation_instant="2026-01-01T00:00:00Z")
        a2 = validate_bundle(bundle_dir, evaluation_instant="2026-01-01T00:00:00Z")

        # evaluation_instant is pinned (reproducible evaluation results)...
        assert a1.evaluation_instant == a2.evaluation_instant
        # ...but assessment_id is a fresh random URN each run (documented
        # non-reproducibility of the creation-identity scalars).
        assert a1.assessment_id != a2.assessment_id

    def test_es256_signed_assessment_payload_identical_signature_differs(self, tmp_dir: Path) -> None:
        """ES256 honesty mirror: pinned identity stabilizes the PAYLOAD only.

        Pinning ``timestamp`` + ``assessment_id`` makes the canonical
        assessment PAYLOAD (the RFC-8785 bytes ``sign_assessment`` signs)
        byte-identical across runs. But byte-equality of the SIGNED artifact
        (``.acef-assessment.json`` including its JWS) ALSO requires a
        DETERMINISTIC signing algorithm. ES256 draws a fresh random ECDSA
        nonce (no RFC 6979 deterministic-k), so two ES256-signed exports over
        the identical pinned payload have IDENTICAL payload bytes but DIFFERENT
        signature bytes — and therefore different file bytes. This mirrors the
        archive ES256 honesty test and the qualified docstrings on
        ``AssessmentBundle`` / ``validate_bundle`` / ``assessment_builder.validate``.

        If this assertion ever flips (signed files become identical), the
        signing path switched to deterministic-k and the reproducibility
        docstrings must be revisited.
        """
        ec_key = _write_ec_key(tmp_dir)
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "es_bundle.acef"
        pkg.export(str(bundle_dir))

        fixed_instant = "2026-01-01T00:00:00Z"
        fixed_ts = "2026-01-01T00:00:00Z"
        fixed_id = "urn:acef:asx:33333333-3333-4333-8333-333333333333"

        a1 = validate_bundle(
            bundle_dir,
            evaluation_instant=fixed_instant,
            timestamp=fixed_ts,
            assessment_id=fixed_id,
        )
        a2 = validate_bundle(
            bundle_dir,
            evaluation_instant=fixed_instant,
            timestamp=fixed_ts,
            assessment_id=fixed_id,
        )

        # PAYLOAD (unsigned canonical bytes) is byte-identical — pinned identity
        # fully stabilizes the assessment content that ``sign_assessment`` signs.
        payload1 = export_assessment(a1, str(tmp_dir / "es_payload1.json"))
        payload2 = export_assessment(a2, str(tmp_dir / "es_payload2.json"))
        assert payload1.read_bytes() == payload2.read_bytes(), (
            "Unsigned assessment payload must be byte-identical with pinned identity"
        )

        # SIGNED artifact differs: ES256 random nonce perturbs the JWS bytes.
        signed1 = export_assessment(a1, str(tmp_dir / "es_signed1.json"), key_path=str(ec_key))
        signed2 = export_assessment(a2, str(tmp_dir / "es_signed2.json"), key_path=str(ec_key))
        assert signed1.read_bytes() != signed2.read_bytes(), (
            "ES256-signed assessments are expected to differ (random ECDSA nonce); "
            "pinned identity stabilizes the payload, NOT the signature"
        )

    def test_rs256_signed_assessment_is_byte_reproducible(self, tmp_dir: Path) -> None:
        """RS256 counterpart: deterministic signing → identical signed file.

        Explicit RS256-key companion to the ES256 honesty test above, making
        the (a)symmetry between RS256 (deterministic, byte-reproducible) and
        ES256 (random nonce, NOT byte-reproducible) signed-assessment exports
        unambiguous — mirroring the archive RS256/ES256 pair.
        """
        rsa_key = _write_rsa_key(tmp_dir)
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "rs_bundle.acef"
        pkg.export(str(bundle_dir))

        fixed_instant = "2026-01-01T00:00:00Z"
        fixed_ts = "2026-01-01T00:00:00Z"
        fixed_id = "urn:acef:asx:44444444-4444-4444-8444-444444444444"

        a1 = validate_bundle(
            bundle_dir,
            evaluation_instant=fixed_instant,
            timestamp=fixed_ts,
            assessment_id=fixed_id,
        )
        a2 = validate_bundle(
            bundle_dir,
            evaluation_instant=fixed_instant,
            timestamp=fixed_ts,
            assessment_id=fixed_id,
        )

        signed1 = export_assessment(a1, str(tmp_dir / "rs_signed1.json"), key_path=str(rsa_key))
        signed2 = export_assessment(a2, str(tmp_dir / "rs_signed2.json"), key_path=str(rsa_key))
        assert signed1.read_bytes() == signed2.read_bytes(), (
            "RS256-signed assessment with pinned identity must be byte-reproducible (PKCS1v15 is deterministic)"
        )

    def test_explicit_timestamp_propagates_through_builder_validate(self, tmp_dir: Path) -> None:
        """The high-level ``validate()`` builder forwards explicit identity scalars."""
        pkg = build_minimal_package()
        fixed_ts = "2026-02-02T12:00:00Z"
        fixed_id = "urn:acef:asx:11111111-1111-4111-8111-111111111111"

        assessment = validate(
            pkg,
            evaluation_instant="2026-02-02T12:00:00Z",
            timestamp=fixed_ts,
            assessment_id=fixed_id,
        )
        assert assessment.timestamp == fixed_ts
        assert assessment.assessment_id == fixed_id


@pytest.mark.parametrize("scalar", ["timestamp", "assessment_id"])
def test_validate_bundle_explicit_scalar_overrides_default(scalar: str, tmp_dir: Path) -> None:
    """Each explicit identity scalar overrides its default factory exactly."""
    pkg = build_minimal_package()
    bundle_dir = tmp_dir / "bundle3.acef"
    pkg.export(str(bundle_dir))

    fixed = {
        "timestamp": "2030-12-31T23:59:59Z",
        "assessment_id": "urn:acef:asx:22222222-2222-4222-8222-222222222222",
    }[scalar]

    assessment = validate_bundle(
        bundle_dir,
        evaluation_instant="2030-12-31T23:59:59Z",
        **{scalar: fixed},
    )
    data = assessment.to_dict()
    assert data[scalar] == fixed
