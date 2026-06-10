"""Cross-language JCS canonicalization parity test (VAL-TS-005).

For each RFC 8785 reference test vector, this test runs the TypeScript
SDK's `canonicalize` via the `dist-test/test/jcs-cli.js` subprocess driver
and compares the byte-output to Python's `acef.integrity.canonicalize`.
Byte-equality across all vectors satisfies VAL-TS-005.

The test is skipped (not failed) if the TypeScript SDK has not been built
yet — this prevents the Python conformance tier from regressing during M1
ship before M2 lands. To exercise locally:

    cd packages/sdk-typescript && npm install && npm run build && npm run build:test
    pytest tests/conformance/test_cross_lang_jcs.py -v

The vectors are inlined here (rather than read from a separate fixture
file) so the test is self-contained — every vector is a small Python
literal whose byte-equal Python output we can compute deterministically.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from acef.integrity import canonicalize

REPO_ROOT = Path(__file__).resolve().parents[2]
TS_CLI = REPO_ROOT / "packages" / "sdk-typescript" / "dist-test" / "test" / "jcs-cli.js"

# RFC 8785 reference + ACEF-specific canonicalization scenarios.
# Each vector: (id, value). Both Python and TS must produce byte-equal
# canonical output.
_VECTORS: list[tuple[str, Any]] = [
    ("primitive-null", None),
    ("primitive-true", True),
    ("primitive-false", False),
    ("primitive-empty-string", ""),
    ("primitive-integer", 42),
    ("primitive-negative-integer", -7),
    ("primitive-zero", 0),
    ("empty-object", {}),
    ("empty-array", []),
    ("object-key-sort-ascii", {"b": 1, "a": 2}),
    ("object-key-sort-deep", {"b": {"d": 1, "c": 2}, "a": [{"z": 1, "y": 2}]}),
    ("object-key-sort-unicode", {"ä": 1, "b": 2, "a": 3}),
    ("array-preserves-order", [3, 1, 2]),
    ("nested-arrays", [[1, 2], [3, 4]]),
    ("string-escape-quote-backslash", {"s": 'a"b\\c'}),
    ("string-escape-controls", {"s": "a\nb\tc\rd"}),
    (
        "acef-manifest-shape",
        {
            "metadata": {
                "package_id": "urn:acef:pkg:abc",
                "created_at": "2025-01-01T00:00:00Z",
            },
            "versioning": {"core_version": "1.1.0"},
            "subjects": [{"subject_id": "urn:acef:sub:s1", "subject_type": "ai_system"}],
        },
    ),
    (
        "acef-record-envelope-with-x1-x4",
        {
            "record_id": "urn:acef:rec:abc",
            "record_type": "harness_attestation",
            "timestamp": "2025-01-01T00:00:00Z",
            "confidentiality": "redacted",
            "redaction_policy_version": "1.0.0",
            "redaction_attestation_ref": "urn:acef:rec:red-1",
            "tenant_label": "urn:acef:tenant:test",
            "causation_chain": ["urn:acef:rec:up-1", "urn:acef:rec:up-2"],
        },
    ),
]


def _ts_canonicalize(value: Any) -> bytes:
    """Run the TS jcs-cli subprocess and capture raw bytes from stdout."""
    if not TS_CLI.exists():
        pytest.skip(
            f"TS jcs-cli not built (run `cd packages/sdk-typescript && npm run build:test`). Looked for {TS_CLI}",
        )
    result = subprocess.run(
        ["node", str(TS_CLI)],
        input=json.dumps(value).encode("utf-8"),
        capture_output=True,
        timeout=30,
        check=True,
    )
    return result.stdout


@pytest.mark.conformance
@pytest.mark.parametrize("vector_id,value", _VECTORS, ids=[v[0] for v in _VECTORS])
def test_cross_lang_jcs_byte_equal(vector_id: str, value: Any) -> None:
    """VAL-TS-005: TS RFC 8785 output is byte-equal to Python's for every vector."""
    py_bytes = canonicalize(value)
    ts_bytes = _ts_canonicalize(value)
    assert py_bytes == ts_bytes, f"Vector {vector_id!r} differs:\n  Python: {py_bytes!r}\n  TS    : {ts_bytes!r}"
