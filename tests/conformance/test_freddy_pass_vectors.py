"""VAL-CONFORMANCE-001 — Pass bundles validate clean (9 bundles).

For each ``test-vectors/freddy/pass/*.acef/`` directory, calls
:func:`acef.validation.engine.validate_bundle` and asserts that no
ERROR or FATAL diagnostics are emitted. INFO-severity diagnostics
(e.g., the v1.1 version-compat note) are permitted.

Per VAL-CONFORMANCE-005, the conformance sub-tier wall-clock budget is
≤40 seconds combined with VAL-CONFORMANCE-002/003.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acef.validation.engine import validate_bundle

PASS_DIR = Path(__file__).parent.parent.parent / "test-vectors" / "freddy" / "pass"


def _pass_bundles() -> list[Path]:
    if not PASS_DIR.exists():
        return []
    return sorted(p for p in PASS_DIR.iterdir() if p.is_dir() and p.name.endswith(".acef"))


@pytest.mark.plumbing
@pytest.mark.conformance
@pytest.mark.parametrize(
    "bundle_dir",
    _pass_bundles(),
    ids=lambda p: p.name,
)
def test_pass_bundle_validates_clean(bundle_dir: Path) -> None:
    """The bundle MUST produce zero ERROR/FATAL diagnostics."""
    assessment = validate_bundle(bundle_dir)
    blocking = [d for d in assessment.structural_errors if str(d.get("severity", "")).lower() in ("error", "fatal")]
    assert not blocking, (
        f"Pass bundle {bundle_dir.name!r} emitted ERROR/FATAL diagnostics "
        f"(expected zero):\n"
        + "\n".join(f"  {d.get('severity', '?')} {d.get('code', '?')}: {d.get('message', '')[:200]}" for d in blocking)
    )


def test_pass_dir_contains_nine_bundles() -> None:
    """Brief §7.1 inventory: exactly 9 pass bundles."""
    bundles = _pass_bundles()
    assert len(bundles) == 9, (
        f"Expected 9 pass bundles per brief §7.1; got {len(bundles)}: {[b.name for b in bundles]!r}"
    )
