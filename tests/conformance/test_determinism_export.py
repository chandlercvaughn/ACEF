"""Determinism tests for Package(clock, urn_generator) injection.

Fulfills:
- VAL-SDK-007: Package(clock=fixed, urn_generator=fixed) produces byte-equal
  .acef.tar.gz across two independent runs given the same logical input.
- VAL-SDK-DETERMINISM-ORDERING-001: Records exported sorted by
  (timestamp, record_id); two builds with shuffled add-order produce
  byte-equal .acef.tar.gz.
- VAL-SDK-DETERMINISM-HASH-001: Package.record_finding(...) dedupe_key
  byte-equal across two identical-input calls.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from acef.errors import ACEFExportError
from acef.loader import load
from acef.models.urns import URNType
from acef.package import Package
from tests.conformance.fixtures.deterministic_input_vector import build

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fixed_clock(
    base_iso: str = "2025-01-01T00:00:00Z",
) -> Callable[[], datetime]:
    """Return a clock callable that advances by 1 second per call."""
    base = datetime.fromisoformat(base_iso.replace("Z", "+00:00"))
    counter = itertools.count()

    def _clock() -> datetime:
        return base + timedelta(seconds=next(counter))

    return _clock


def _make_fixed_urn_generator() -> Callable[[URNType], str]:
    """Return a URN generator that produces sequential URNs.

    Format matches the regex in src/acef/models/urns.py:19-22.
    """
    counter = itertools.count(1)

    def _gen(urn_type: URNType) -> str:
        n = next(counter)
        return f"urn:acef:{urn_type.value}:00000000-0000-0000-0000-{n:012x}"

    return _gen


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# VAL-SDK-007 — injected clock + URN generator yields byte-equal archive
# ---------------------------------------------------------------------------


def test_val_sdk_007_byte_equal_archive_across_two_runs(tmp_path: Path) -> None:
    """Two independent Package builds with identical injection and identical
    logical input produce byte-equal .acef.tar.gz.

    Both archives use the SAME filename (in separate directories) because
    export.py:177 embeds the output filename in the tar bundle directory
    name (``<stem>.acef/``); different filenames would naturally diverge
    in that one path field. The byte-equality contract is about identical
    logical input + identical filename → identical archive bytes.
    """
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    archive_a = dir_a / "deterministic.acef.tar.gz"
    archive_b = dir_b / "deterministic.acef.tar.gz"

    pkg_a = Package(
        producer={"name": "det-test", "version": "1.0.0"},
        clock=_make_fixed_clock(),
        urn_generator=_make_fixed_urn_generator(),
    )
    build(pkg_a)
    pkg_a.export(str(archive_a))

    pkg_b = Package(
        producer={"name": "det-test", "version": "1.0.0"},
        clock=_make_fixed_clock(),
        urn_generator=_make_fixed_urn_generator(),
    )
    build(pkg_b)
    pkg_b.export(str(archive_b))

    sha_a = _sha256_file(archive_a)
    sha_b = _sha256_file(archive_b)
    assert sha_a == sha_b, (
        "Two builds with same injection and same input must be byte-equal.\n"
        f"  archive_a sha256={sha_a}\n  archive_b sha256={sha_b}"
    )


# ---------------------------------------------------------------------------
# VAL-SDK-DETERMINISM-ORDERING-001 — shuffled add-order yields byte-equal
# ---------------------------------------------------------------------------


def test_val_sdk_determinism_ordering_001_shuffled_add_order_byte_equal(
    tmp_path: Path,
) -> None:
    """Records exported sorted by (timestamp, record_id) per spec §3.1.1.

    The fixture passes explicit timestamp + record_id per logical record,
    so two builds with shuffled add-order produce the same multiset of
    records — and the export sort normalizes ordering — yielding
    byte-equal output.
    """
    dir_in = tmp_path / "inorder"
    dir_sh = tmp_path / "shuffled"
    dir_in.mkdir()
    dir_sh.mkdir()
    # Same basename in both dirs so export.py:177's bundle_name derivation
    # produces the same tar directory prefix for both archives. See
    # VAL-SDK-007 test docstring above.
    archive_inorder = dir_in / "deterministic.acef.tar.gz"
    archive_shuffled = dir_sh / "deterministic.acef.tar.gz"

    pkg_in = Package(
        producer={"name": "det-test", "version": "1.0.0"},
        clock=_make_fixed_clock(),
        urn_generator=_make_fixed_urn_generator(),
    )
    build(pkg_in, shuffle=False)
    pkg_in.export(str(archive_inorder))

    pkg_sh = Package(
        producer={"name": "det-test", "version": "1.0.0"},
        clock=_make_fixed_clock(),
        urn_generator=_make_fixed_urn_generator(),
    )
    build(pkg_sh, shuffle=True, shuffle_seed=42)
    pkg_sh.export(str(archive_shuffled))

    sha_in = _sha256_file(archive_inorder)
    sha_sh = _sha256_file(archive_shuffled)
    assert sha_in == sha_sh, (
        "Shuffled add-order must produce byte-equal export under the\n"
        "(timestamp, record_id) sort (spec §3.1.1).\n"
        f"  in-order sha256={sha_in}\n  shuffled sha256={sha_sh}"
    )


# ---------------------------------------------------------------------------
# VAL-SDK-DETERMINISM-HASH-001 — dedupe_key stable across runs
# ---------------------------------------------------------------------------


def test_val_sdk_determinism_hash_001_dedupe_key_stable() -> None:
    """Two identical-input calls to Package.record_finding produce
    byte-equal dedupe_key. The hash is computed from input fields only,
    with no clock or randomness.
    """
    pkg = Package(producer={"name": "det", "version": "1.0.0"})

    common_kwargs = dict(
        class_="safety_failure",
        subject_ref="urn:acef:sub:11111111-1111-1111-1111-111111111111",
        expected_behavior="agent refuses out-of-scope action",
        reproduction_steps_ref_content_hash="sha256:" + "0" * 64,
        severity={
            "severity_level": "high",
            "severity_rationale": "production-capable scope",
        },
        reproduction={
            "expected_behavior": "agent refuses out-of-scope action",
            "observed_behavior": "agent attempted unauthorized action",
            "reproduction_steps_ref": "urn:acef:rec:22222222-2222-2222-2222-222222222222",
            "evidence_commit_ref": "sha256:" + "a" * 64,
        },
        attribution={
            "persona_ref": "urn:acef:rec:33333333-3333-3333-3333-333333333333",
            "scenario_ref": "urn:acef:rec:33333333-3333-3333-3333-333333333334",
            "scope_ref": "urn:acef:rec:33333333-3333-3333-3333-333333333335",
        },
        discovered_at="2025-01-01T00:00:00Z",
        discovered_in_run_ref="urn:acef:rec:44444444-4444-4444-4444-444444444444",
    )

    rec_a = pkg.record_finding(**common_kwargs)
    rec_b = pkg.record_finding(**common_kwargs)

    dk_a = rec_a.payload["dedupe_key"]
    dk_b = rec_b.payload["dedupe_key"]

    assert dk_a == dk_b, f"dedupe_key must be byte-equal across identical-input calls.\n  a={dk_a!r}\n  b={dk_b!r}"
    assert dk_a.startswith("sha256:"), f"dedupe_key must be sha256-prefixed; got {dk_a!r}"
    assert len(dk_a) == len("sha256:") + 64, f"dedupe_key wrong length: {dk_a!r}"


def test_archive_export_rejects_non_rfc3339_timestamp(tmp_path: Path) -> None:
    """F6 (audit high): the .acef.tar.gz member ``mtime`` is derived from
    ``metadata.timestamp`` via ``datetime.fromisoformat``, which is LENIENT — it accepts
    basic-form / non-RFC3339 ISO-8601 (e.g. ``20240115T103000Z``) that the TypeScript
    exporter rejects, so the same logical bundle would yield DIVERGENT archive bytes across
    languages; and a silently-caught parse failure fell back to ``mtime=0``. Export must
    instead REJECT a non-strict-RFC3339 ``metadata.timestamp`` with a structured
    ``ACEFExportError`` (ACEF-002), so Python and TS agree (both reject)."""
    pkg = Package(producer={"name": "acef-sdk", "version": "0.1.0"})
    pkg.add_subject("ai_system", name="S", risk_classification="high-risk", modalities=["text"])
    bundle_dir = tmp_path / "dir.acef"
    pkg.export(str(bundle_dir))

    # Tamper the manifest timestamp to a non-RFC3339 BASIC form, reload, re-export as archive.
    manifest_path = bundle_dir / "acef-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["metadata"]["timestamp"] = "20240115T103000Z"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    reloaded = load(str(bundle_dir))

    with pytest.raises(ACEFExportError) as exc_info:
        reloaded.export(str(tmp_path / "out.acef.tar.gz"))
    assert exc_info.value.code == "ACEF-002", exc_info.value
    assert "RFC 3339" in str(exc_info.value)

    # A strict RFC 3339 timestamp still exports cleanly (no over-rejection).
    manifest["metadata"]["timestamp"] = "2024-01-15T10:30:00Z"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    load(str(bundle_dir)).export(str(tmp_path / "ok.acef.tar.gz"))
    assert (tmp_path / "ok.acef.tar.gz").exists()

    # A LOWERCASE-'z' zone is VALID RFC 3339 (the strict checker normalizes case before
    # validating), so it must EXPORT cleanly — not surface a raw ValueError from
    # datetime.fromisoformat, which only accepts an uppercase 'Z' (roborev MEDIUM on c3251d8).
    manifest["metadata"]["timestamp"] = "2024-01-15T10:30:00z"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    load(str(bundle_dir)).export(str(tmp_path / "lower-z.acef.tar.gz"))
    assert (tmp_path / "lower-z.acef.tar.gz").exists()

    # FRACTIONAL seconds are rejected (roborev on 796ceb4): the tar member mtime is
    # whole-second and Python's float datetime.timestamp() truncation cannot be reproduced
    # byte-identically in the TS SDK at all magnitudes, so BOTH SDKs reject a fractional
    # metadata.timestamp -> identical accepted set + identical mtime.
    manifest["metadata"]["timestamp"] = "2024-01-15T10:30:00.999Z"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    reloaded_fractional = load(str(bundle_dir))
    with pytest.raises(ACEFExportError) as frac_exc:
        reloaded_fractional.export(str(tmp_path / "fractional.acef.tar.gz"))
    assert frac_exc.value.code == "ACEF-002"
    assert "fractional" in str(frac_exc.value).lower()
