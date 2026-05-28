"""VAL-CONFORMANCE-002 — Fail bundles emit the expected ACEF-NNN (11 bundles).

For each ``test-vectors/freddy/fail/*/`` directory, parses the bundle's
``README.md`` for a line of the form ``**Expected code:** ACEF-NNN`` and
asserts that ACEF-NNN is among the codes emitted by
:func:`acef.validation.engine.validate_bundle`. The fail bundle may emit
additional diagnostic codes (e.g., a schema-layer ACEF-004 alongside a
cross-record ACEF-071) — the contract is membership, not exclusivity:
per VAL-CONFORMANCE-002 the declared code MUST be present.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from acef.validation.engine import validate_bundle

FAIL_DIR = Path(__file__).parent.parent.parent / "test-vectors" / "freddy" / "fail"

_EXPECTED_RE = re.compile(r"^\*\*Expected code(?:\(s\))?:\*\*\s*(ACEF-\d+)", re.MULTILINE)


def _fail_bundles() -> list[Path]:
    if not FAIL_DIR.exists():
        return []
    return sorted(p for p in FAIL_DIR.iterdir() if p.is_dir())


def _expected_code(bundle_dir: Path) -> str:
    readme = bundle_dir / "README.md"
    if not readme.exists():
        return ""
    m = _EXPECTED_RE.search(readme.read_text(encoding="utf-8"))
    return m.group(1) if m else ""


@pytest.mark.plumbing
@pytest.mark.conformance
@pytest.mark.parametrize(
    "bundle_dir",
    _fail_bundles(),
    ids=lambda p: p.name,
)
def test_fail_bundle_emits_expected_code(bundle_dir: Path) -> None:
    expected = _expected_code(bundle_dir)
    assert expected, (
        f"Fail bundle {bundle_dir.name!r} README.md missing the "
        f"'**Expected code:** ACEF-NNN' declaration required by brief §7.2."
    )

    assessment = validate_bundle(bundle_dir)
    codes_emitted = sorted({str(d.get("code", "")) for d in assessment.structural_errors})
    assert expected in codes_emitted, (
        f"Fail bundle {bundle_dir.name!r} expected {expected} but it was not "
        f"emitted. Codes emitted: {codes_emitted!r}. Full diagnostics:\n"
        + "\n".join(
            f"  {d.get('severity', '?')} {d.get('code', '?')}: {d.get('message', '')[:200]}"
            for d in assessment.structural_errors
        )
    )


def test_fail_dir_contains_eleven_bundles() -> None:
    """Brief §7.1 inventory: exactly 11 fail bundles."""
    bundles = _fail_bundles()
    assert len(bundles) == 11, (
        f"Expected 11 fail bundles per brief §7.1; got {len(bundles)}: {[b.name for b in bundles]!r}"
    )
