"""VAL-CONFORMANCE-003 — fake-green bundles fail validation (7 bundles).

For each ``test-vectors/freddy/fake-green/*/`` directory, asserts that
:func:`acef.validation.engine.validate_bundle` emits at least one
ERROR or FATAL diagnostic. Per brief §7.2, the whole point of a
fake-green test is to prove that the named state CANNOT be reached
without the intentionally-absent precursor evidence — so the bundle
MUST fail validation. No specific ACEF-NNN code is asserted; any
ERROR/FATAL is acceptable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acef.validation.engine import validate_bundle

FAKE_GREEN_DIR = Path(__file__).parent.parent.parent / "test-vectors" / "freddy" / "fake-green"


def _fake_green_bundles() -> list[Path]:
    if not FAKE_GREEN_DIR.exists():
        return []
    return sorted(p for p in FAKE_GREEN_DIR.iterdir() if p.is_dir())


@pytest.mark.plumbing
@pytest.mark.conformance
@pytest.mark.parametrize(
    "bundle_dir",
    _fake_green_bundles(),
    ids=lambda p: p.name,
)
def test_fake_green_bundle_fails_validation(bundle_dir: Path) -> None:
    """The fake-green bundle MUST emit at least one ERROR/FATAL diagnostic."""
    assessment = validate_bundle(bundle_dir)
    blocking = [d for d in assessment.structural_errors if str(d.get("severity", "")).lower() in ("error", "fatal")]
    assert blocking, (
        f"Fake-green bundle {bundle_dir.name!r} validated clean — but the "
        "whole point of a fake-green vector is to prove the named state "
        "CANNOT be reached without the intentionally-absent precursor "
        "evidence. At least one ERROR/FATAL diagnostic was expected."
    )


def test_fake_green_dir_contains_seven_bundles() -> None:
    """Brief §7.1 inventory: exactly 7 fake-green bundles (one per state_class)."""
    bundles = _fake_green_bundles()
    assert len(bundles) == 7, (
        f"Expected 7 fake-green bundles per brief §7.1 (one per state_class); "
        f"got {len(bundles)}: {[b.name for b in bundles]!r}"
    )
