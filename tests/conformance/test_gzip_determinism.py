"""Cross-language gzip determinism parity test (VAL-PARITY-001).

Given the same byte input from a committed fixture, both implementations
MUST produce gzip output (level 6, mtime=0, OS=0xFF) whose SHA-256 hashes
are equal.

This is the M2 entry-point assertion for cross-language archive byte
equality. VAL-PARITY-002 and VAL-PARITY-003 (archive-level parity for pass
bundles and v1.0 golden bundles respectively) inherit from this primitive.

The TS side is exercised via a subprocess driver at
`packages/sdk-typescript/dist-test/test/gzip-cli.js` that reads the fixture
and writes deterministic gzip bytes to stdout. If the driver has not been
built (i.e., `cd packages/sdk-typescript && npm run build:test` has not
run), the test SKIPS — this prevents the Python conformance tier from
hard-failing during M1 ship before M2 lands.

To exercise locally:

    cd packages/sdk-typescript && npm install && npm run build:test
    pytest tests/conformance/test_gzip_determinism.py -v
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from acef.exporter_gzip import deterministic_gzip
from tests.conformance._crosslang import require_ts_cli

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "tests" / "conformance" / "fixtures" / "gzip-test-vector.bin"
TS_GZIP_CLI = REPO_ROOT / "packages" / "sdk-typescript" / "dist-test" / "test" / "gzip-cli.js"


def _node_gzip(fixture_path: Path) -> bytes:
    """Invoke the TS gzip-cli subprocess on `fixture_path` and capture raw bytes."""
    # FAIL (not silently skip) when the TS driver is absent, unless opted out
    # (ACEF_SKIP_CROSSLANG=1) — gzip parity is a reference-SDK guarantee (finding 32).
    require_ts_cli(TS_GZIP_CLI, what="TS gzip-cli")
    result = subprocess.run(
        ["node", str(TS_GZIP_CLI), str(fixture_path)],
        capture_output=True,
        timeout=30,
        check=True,
    )
    return result.stdout


@pytest.mark.conformance
def test_fixture_exists_and_is_non_empty() -> None:
    """The committed fixture must exist and have non-trivial size for the
    parity comparison to be meaningful."""
    assert FIXTURE.exists(), f"missing fixture {FIXTURE}"
    data = FIXTURE.read_bytes()
    assert len(data) >= 64, "fixture too small to exercise DEFLATE meaningfully"


@pytest.mark.conformance
def test_python_deterministic_gzip_header_bytes_are_spec_compliant() -> None:
    """Pin the first 10 bytes of the Python helper output to confirm
    mtime=0 and OS=0xFF per spec §3.1.3."""
    out = deterministic_gzip(b"hello world\n")
    assert out[:10] == b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff", f"Python header bytes mismatch: {out[:10].hex()}"


@pytest.mark.conformance
def test_python_deterministic_gzip_round_trips() -> None:
    """The Python helper output must decompress back to the input."""
    import gzip

    payload = FIXTURE.read_bytes()
    gz = deterministic_gzip(payload)
    restored = gzip.decompress(gz)
    assert restored == payload


@pytest.mark.conformance
def test_python_and_node_gzip_byte_equal_on_committed_fixture() -> None:
    """VAL-PARITY-001: sha256(python_gzip(fixture)) == sha256(node_gzip(fixture)).

    This is the primary assertion the feature fulfils. Both SDKs read the
    same committed fixture, gzip it with level=6 / mtime=0 / OS=0xFF, and
    must produce SHA-256-equal output.
    """
    fixture = FIXTURE.read_bytes()

    py_out = deterministic_gzip(fixture)
    py_hash = hashlib.sha256(py_out).hexdigest()

    node_out = _node_gzip(FIXTURE)
    node_hash = hashlib.sha256(node_out).hexdigest()

    assert py_hash == node_hash, (
        f"Cross-language gzip hash mismatch:\n"
        f"  python sha256 = {py_hash}\n"
        f"  node   sha256 = {node_hash}\n"
        f"  python len    = {len(py_out)}\n"
        f"  node   len    = {len(node_out)}\n"
        f"  python first 16 = {py_out[:16].hex()}\n"
        f"  node   first 16 = {node_out[:16].hex()}"
    )


@pytest.mark.conformance
def test_python_and_node_gzip_byte_equal_on_small_inputs() -> None:
    """Cross-language byte-equality must hold for short / pathological inputs
    too. We exercise empty, single-byte, and short-utf8 inputs by feeding
    them through the same TS subprocess driver via a temp file."""
    import tempfile

    require_ts_cli(TS_GZIP_CLI, what="TS gzip-cli")

    cases = [
        ("empty", b""),
        ("single-byte", b"x"),
        ("short-ascii", b"hello world\n"),
        ("short-utf8", "café\n".encode()),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for name, data in cases:
            f = tmp_path / f"{name}.bin"
            f.write_bytes(data)

            py_out = deterministic_gzip(data)
            node_out = _node_gzip(f)

            assert py_out == node_out, (
                f"case {name!r} ({len(data)} bytes) diverged:\n  python = {py_out.hex()}\n  node   = {node_out.hex()}"
            )
