"""Cross-language archive byte-parity tests (VAL-PARITY-002 / VAL-PARITY-003).

For each Freddy pass bundle (9) and each v1.0 golden bundle (6), this test
regenerates the ``.acef.tar.gz`` archive from BOTH SDKs and asserts the
resulting bytes are SHA-256-equal:

    sha256(python_export.acef.tar.gz) == sha256(typescript_export.acef.tar.gz)

Both sides regenerate from the SAME on-disk bundle, with the SAME tar root
``bundle_name`` and the SAME ``mtime`` (the mtime is derived independently by
each exporter from the bundle's own ``manifest.metadata.timestamp`` — there is
a single source of truth, so the two derivations agree by construction).

Why a re-export comparison rather than comparing to the on-disk archive?
There is no committed on-disk ``.acef.tar.gz`` for these bundles. Python's
load → ``Package.build_manifest()`` round-trip is LOSSLESS to the open core
(spec §6.4 rule 5 / §6.5): it preserves manifest-level ``analysis_mode`` (X5),
``namespaces`` (X6), top-level vendor ``x-*`` extensions, and extra metadata
keys (``metadata.created_at``, vendor ``x-*``). The TypeScript exporter mirrors
the same preservation, so the parity contract — that the TWO SDKs agree
byte-for-byte — holds with both sides spec-correct
(``python_reexport == ts_reexport``).

The TS side is exercised via the built CLI at
``packages/sdk-typescript/dist/cli/export-cli.js``. If that artifact has not
been built (``cd packages/sdk-typescript && npm run build``), the
archive-parity tests SKIP — this keeps the Python conformance tier from
hard-failing before the TS SDK is built locally.

To exercise locally::

    cd packages/sdk-typescript && npm install && npm run build
    pytest tests/conformance/test_freddy_cross_language_parity.py -v
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

import acef
from acef.export import export_archive

REPO_ROOT = Path(__file__).resolve().parents[2]
FREDDY_PASS_DIR = REPO_ROOT / "test-vectors" / "freddy" / "pass"
GOLDEN_DIR = REPO_ROOT / "tests" / "conformance" / "golden-bundles"
TS_EXPORT_CLI = REPO_ROOT / "packages" / "sdk-typescript" / "dist" / "cli" / "export-cli.js"


def _bundle_name(bundle_dir: Path) -> str:
    """Compute the agreed tar-root bundle name for a bundle directory.

    Mirrors Python's ``export_archive`` derivation
    (``name.replace('.tar.gz','').replace('.acef','') + '.acef'``): strip a
    trailing ``.acef`` from the directory name, then re-append ``.acef``.
    Freddy bundle dirs already end in ``.acef`` (idempotent); v1.0 golden
    bundle dirs do not (so ``.acef`` is appended).
    """
    base = bundle_dir.name
    if base.endswith(".acef"):
        base = base[: -len(".acef")]
    return base + ".acef"


def _python_archive(bundle_dir: Path, bundle_name: str) -> bytes:
    """Load ``bundle_dir`` via acef.loader and re-export via export_archive.

    The output path's name is chosen so Python's internal bundle-name
    derivation yields ``bundle_name`` exactly.
    """
    pkg = acef.load(str(bundle_dir))
    base = bundle_name[: -len(".acef")] if bundle_name.endswith(".acef") else bundle_name
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, f"{base}.acef.tar.gz")
        # Sanity: Python derives the same bundle_name we hand the TS side.
        derived = Path(out).name.replace(".tar.gz", "").replace(".acef", "") + ".acef"
        assert derived == bundle_name, f"bundle_name mismatch: {derived!r} != {bundle_name!r}"
        export_archive(pkg, out)
        return Path(out).read_bytes()


def _ts_archive(bundle_dir: Path, bundle_name: str) -> bytes:
    """Invoke the TS export CLI and capture the raw ``.acef.tar.gz`` bytes."""
    result = subprocess.run(
        ["node", str(TS_EXPORT_CLI), str(bundle_dir), bundle_name],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"TS export-cli failed (exit {result.returncode}) for {bundle_dir.name}:\n"
            f"{result.stderr.decode('utf-8', errors='replace')}"
        )
    return result.stdout


def _diff_report(py: bytes, ts: bytes, *, label: str) -> str:
    """Produce a diagnostic string locating the first differing byte.

    Compares the gzipped bytes directly, and if those differ, also the
    decompressed tar bytes (which localizes header/content divergence far
    better than the compressed stream).
    """
    import gzip

    lines = [
        f"Cross-language archive mismatch for {label}:",
        f"  python sha256 = {hashlib.sha256(py).hexdigest()}",
        f"  ts     sha256 = {hashlib.sha256(ts).hexdigest()}",
        f"  python len    = {len(py)}",
        f"  ts     len    = {len(ts)}",
    ]
    try:
        pt = gzip.decompress(py)
        tt = gzip.decompress(ts)
    except OSError:
        return "\n".join(lines)
    lines.append(f"  tar python len = {len(pt)}")
    lines.append(f"  tar ts     len = {len(tt)}")
    first = None
    for i in range(min(len(pt), len(tt))):
        if pt[i] != tt[i]:
            first = i
            break
    if first is None:
        lines.append(f"  tar common prefix identical to {min(len(pt), len(tt))} bytes (length differs)")
    else:
        lo = max(0, first - 32)
        lines.append(f"  first tar diff at byte {first} (block {first // 512}, offset {first % 512})")
        lines.append(f"    python: {pt[lo : first + 32]!r}")
        lines.append(f"    ts    : {tt[lo : first + 32]!r}")
    return "\n".join(lines)


def _discover(base: Path) -> list[Path]:
    return sorted(p for p in base.iterdir() if p.is_dir())


FREDDY_PASS_BUNDLES = _discover(FREDDY_PASS_DIR) if FREDDY_PASS_DIR.exists() else []
GOLDEN_BUNDLES = _discover(GOLDEN_DIR) if GOLDEN_DIR.exists() else []


@pytest.mark.conformance
def test_expected_bundle_counts() -> None:
    """Guard: the parity matrix covers 9 Freddy pass + 6 v1.0 golden bundles.

    If a bundle is added/removed this fails loudly so the parity coverage
    count (VAL-PARITY-002 = 9 sub-tests, VAL-PARITY-003 = 6 sub-tests) stays
    honest.
    """
    assert len(FREDDY_PASS_BUNDLES) == 9, [p.name for p in FREDDY_PASS_BUNDLES]
    assert len(GOLDEN_BUNDLES) == 6, [p.name for p in GOLDEN_BUNDLES]


@pytest.mark.conformance
@pytest.mark.parametrize("bundle_dir", FREDDY_PASS_BUNDLES, ids=lambda p: p.name)
def test_freddy_pass_bundle_archive_parity(bundle_dir: Path) -> None:
    """VAL-PARITY-002: each of the 9 Freddy pass bundles re-exports to a
    byte-equal ``.acef.tar.gz`` across the Python and TypeScript SDKs."""
    if not TS_EXPORT_CLI.exists():
        pytest.skip(
            f"TS export-cli not built (run `cd packages/sdk-typescript && npm run build`). Looked for {TS_EXPORT_CLI}"
        )
    bundle_name = _bundle_name(bundle_dir)
    py = _python_archive(bundle_dir, bundle_name)
    ts = _ts_archive(bundle_dir, bundle_name)
    assert hashlib.sha256(py).hexdigest() == hashlib.sha256(ts).hexdigest(), _diff_report(py, ts, label=bundle_dir.name)


@pytest.mark.conformance
@pytest.mark.parametrize("bundle_dir", GOLDEN_BUNDLES, ids=lambda p: p.name)
def test_golden_bundle_archive_parity(bundle_dir: Path) -> None:
    """VAL-PARITY-003: each of the 6 v1.0 golden bundles re-exports to a
    byte-equal ``.acef.tar.gz`` across the Python and TypeScript SDKs."""
    if not TS_EXPORT_CLI.exists():
        pytest.skip(
            f"TS export-cli not built (run `cd packages/sdk-typescript && npm run build`). Looked for {TS_EXPORT_CLI}"
        )
    bundle_name = _bundle_name(bundle_dir)
    py = _python_archive(bundle_dir, bundle_name)
    ts = _ts_archive(bundle_dir, bundle_name)
    assert hashlib.sha256(py).hexdigest() == hashlib.sha256(ts).hexdigest(), _diff_report(py, ts, label=bundle_dir.name)
