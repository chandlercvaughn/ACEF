"""Cross-language JWS sign/verify interop test (VAL-TS-006).

Exercises all four combinations:
  1. Python signs (RS256), TS verifies
  2. Python signs (ES256), TS verifies
  3. TS signs (RS256), Python verifies
  4. TS signs (ES256), Python verifies

The TS side is driven via subprocess against
`packages/sdk-typescript/dist-test/test/jws-cli.js`. If the TS SDK is not
built, the test skips with a clear pointer to the build step.

Skipped (not failed) when the TS artifacts are missing so M1 conformance
tier ships clean before M2 lands. Once M2 is in place, the test runs as
part of the conformance tier.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from acef.signing import create_detached_jws, verify_detached_jws

REPO_ROOT = Path(__file__).resolve().parents[2]
TS_CLI = REPO_ROOT / "packages" / "sdk-typescript" / "dist-test" / "test" / "jws-cli.js"


def _skip_if_no_ts() -> None:
    if not TS_CLI.exists():
        pytest.skip(
            f"TS jws-cli not built (run `cd packages/sdk-typescript && npm run build:test`). Looked for {TS_CLI}",
        )


def _write_pem(tmpdir: Path, name: str, data: bytes) -> Path:
    p = tmpdir / name
    p.write_bytes(data)
    return p


def _make_rsa_keypair() -> tuple[rsa.RSAPrivateKey, bytes, bytes]:
    """Return (private_key_obj, private_pem, public_pem)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, priv_pem, pub_pem


def _make_ec_keypair() -> tuple[ec.EllipticCurvePrivateKey, bytes, bytes]:
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, priv_pem, pub_pem


def _ts_sign(priv_pem_path: Path, payload_path: Path, kid: str) -> str:
    result = subprocess.run(
        [
            "node",
            str(TS_CLI),
            "sign-stdin",
            "--privkey",
            str(priv_pem_path),
            "--kid",
            kid,
            "--payload-path",
            str(payload_path),
        ],
        capture_output=True,
        timeout=30,
        check=True,
    )
    return result.stdout.decode("utf-8")


def _ts_verify(pub_pem_path: Path, payload_path: Path, jws: str) -> bool:
    result = subprocess.run(
        [
            "node",
            str(TS_CLI),
            "verify-jws-stdin",
            "--pubkey",
            str(pub_pem_path),
            "--payload-path",
            str(payload_path),
        ],
        input=jws.encode("utf-8"),
        capture_output=True,
        timeout=30,
    )
    if result.returncode == 0:
        return True
    return False


@pytest.mark.conformance
def test_python_signs_rs256_ts_verifies(tmp_path: Path) -> None:
    """VAL-TS-006: Python-signed RS256 JWS verifies under TS."""
    _skip_if_no_ts()
    priv, priv_pem, pub_pem = _make_rsa_keypair()
    payload = b"the quick brown fox jumps over the lazy dog"
    payload_path = tmp_path / "payload.bin"
    payload_path.write_bytes(payload)
    pub_pem_path = _write_pem(tmp_path, "pub.pem", pub_pem)

    jws = create_detached_jws(payload, priv, kid="py-rs256")
    assert _ts_verify(pub_pem_path, payload_path, jws), "TS failed to verify Python RS256 JWS"


@pytest.mark.conformance
def test_python_signs_es256_ts_verifies(tmp_path: Path) -> None:
    """VAL-TS-006: Python-signed ES256 JWS verifies under TS."""
    _skip_if_no_ts()
    priv, priv_pem, pub_pem = _make_ec_keypair()
    payload = b'{"some":"acef-shaped-bytes"}'
    payload_path = tmp_path / "payload.bin"
    payload_path.write_bytes(payload)
    pub_pem_path = _write_pem(tmp_path, "pub.pem", pub_pem)

    jws = create_detached_jws(payload, priv, kid="py-es256")
    assert _ts_verify(pub_pem_path, payload_path, jws), "TS failed to verify Python ES256 JWS"


@pytest.mark.conformance
def test_ts_signs_rs256_python_verifies(tmp_path: Path) -> None:
    """VAL-TS-006: TS-signed RS256 JWS verifies under Python."""
    _skip_if_no_ts()
    _, priv_pem, pub_pem = _make_rsa_keypair()
    payload = b"hello-from-typescript"
    payload_path = tmp_path / "payload.bin"
    payload_path.write_bytes(payload)
    priv_pem_path = _write_pem(tmp_path, "priv.pem", priv_pem)

    jws = _ts_sign(priv_pem_path, payload_path, "ts-rs256")

    pub_key = serialization.load_pem_public_key(pub_pem)
    header = verify_detached_jws(jws, payload, pub_key)
    assert header["alg"] == "RS256"
    assert header["kid"] == "ts-rs256"


@pytest.mark.conformance
def test_ts_signs_es256_python_verifies(tmp_path: Path) -> None:
    """VAL-TS-006: TS-signed ES256 JWS verifies under Python."""
    _skip_if_no_ts()
    _, priv_pem, pub_pem = _make_ec_keypair()
    payload = b"hello-from-typescript-ec"
    payload_path = tmp_path / "payload.bin"
    payload_path.write_bytes(payload)
    priv_pem_path = _write_pem(tmp_path, "priv.pem", priv_pem)

    jws = _ts_sign(priv_pem_path, payload_path, "ts-es256")

    pub_key = serialization.load_pem_public_key(pub_pem)
    header = verify_detached_jws(jws, payload, pub_key)
    assert header["alg"] == "ES256"
    assert header["kid"] == "ts-es256"
