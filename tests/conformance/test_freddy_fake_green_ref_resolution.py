"""VAL-CONFORMANCE-FAKE-GREEN-REF-001 — every ``fake_green_test_ref``
URN in any test bundle resolves to a real fake-green bundle directory.

For each bundle under ``test-vectors/freddy/{pass,fail,fake-green}/``,
scans every harness_attestation record's
``payload.fake_green_test_ref`` and asserts that the URN is present in
the canonical map ``FAKE_GREEN_URN_MAP`` AND that the named fake-green
bundle directory actually exists under
``test-vectors/freddy/fake-green/``. No invented-at-runtime URNs.

Also implements VAL-CONFORMANCE-FAKE-GREEN-REF-002: every fake-green
bundle is well-formed at the JSON-Schema layer (manifest + records pass
their per-schema validation). Failures occur at the higher-level
cross-record / integrity layer, not at the schema layer.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from acef.validation.engine import validate_bundle

REPO_ROOT = Path(__file__).parent.parent.parent
FREDDY_ROOT = REPO_ROOT / "test-vectors" / "freddy"
FAKE_GREEN_DIR = FREDDY_ROOT / "fake-green"

# Import the canonical URN map from the bundle builders. The map lives
# under test-vectors/freddy/_builders/ which is not a Python package
# importable via dotted notation (the leading ``test-vectors`` segment
# contains a hyphen). Push the parent on sys.path at module load.
_BUILDERS_PARENT = FREDDY_ROOT
if str(_BUILDERS_PARENT) not in sys.path:
    sys.path.insert(0, str(_BUILDERS_PARENT))

from _builders._common import FAKE_GREEN_URN_MAP  # noqa: E402


def _iter_records(bundle_dir: Path) -> list[dict]:
    """Yield every record dict in the bundle's JSONL files."""
    records_dir = bundle_dir / "records"
    if not records_dir.exists():
        return []
    out: list[dict] = []
    for jsonl in sorted(records_dir.rglob("*.jsonl")):
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _iter_all_bundles() -> list[Path]:
    """Every bundle directory under pass/, fail/, fake-green/."""
    bundles: list[Path] = []
    for sub in ("pass", "fail", "fake-green"):
        sub_dir = FREDDY_ROOT / sub
        if sub_dir.exists():
            bundles.extend(sorted(p for p in sub_dir.iterdir() if p.is_dir()))
    return bundles


@pytest.mark.plumbing
@pytest.mark.conformance
@pytest.mark.parametrize(
    "bundle_dir",
    _iter_all_bundles(),
    ids=lambda p: f"{p.parent.name}/{p.name}",
)
def test_fake_green_test_ref_urns_resolve(bundle_dir: Path) -> None:
    """Every fake_green_test_ref URN in a harness_attestation record MUST
    resolve to a real fake-green bundle directory."""
    for rec in _iter_records(bundle_dir):
        if rec.get("record_type") != "harness_attestation":
            continue
        payload = rec.get("payload")
        if not isinstance(payload, dict):
            continue
        urn = payload.get("fake_green_test_ref")
        if not isinstance(urn, str) or not urn:
            continue

        assert urn in FAKE_GREEN_URN_MAP, (
            f"Bundle {bundle_dir.name!r} record {rec.get('record_id')!r} "
            f"declares fake_green_test_ref={urn!r} which is not in the "
            f"canonical FAKE_GREEN_URN_MAP. Per VAL-CONFORMANCE-FAKE-GREEN-REF-001 "
            "no invented-at-runtime URNs are permitted."
        )

        target_dir = FAKE_GREEN_DIR / FAKE_GREEN_URN_MAP[urn]
        assert target_dir.exists() and target_dir.is_dir(), (
            f"Bundle {bundle_dir.name!r} record {rec.get('record_id')!r} "
            f"declares fake_green_test_ref={urn!r} mapped to "
            f"{target_dir!r}, but that fake-green bundle directory does "
            "not exist."
        )


def test_every_canonical_fake_green_urn_has_a_directory() -> None:
    """VAL-CONFORMANCE-FAKE-GREEN-REF-001 inverse: every URN in the
    canonical map MUST correspond to a real fake-green bundle."""
    missing: list[str] = []
    for urn, dir_name in FAKE_GREEN_URN_MAP.items():
        if not (FAKE_GREEN_DIR / dir_name).is_dir():
            missing.append(f"{urn} -> {dir_name}")
    assert not missing, "Canonical FAKE_GREEN_URN_MAP entries with no matching directory:\n" + "\n".join(
        f"  {m}" for m in missing
    )


@pytest.mark.plumbing
@pytest.mark.conformance
@pytest.mark.parametrize(
    "bundle_dir",
    sorted((p for p in FAKE_GREEN_DIR.iterdir() if p.is_dir()) if FAKE_GREEN_DIR.exists() else []),
    ids=lambda p: p.name,
)
def test_fake_green_bundle_is_schema_valid(bundle_dir: Path) -> None:
    """VAL-CONFORMANCE-FAKE-GREEN-REF-002: fake-green bundles MUST be
    well-formed at the JSON-Schema layer. Failures are at the
    integrity / reference / rule level, not schema level."""
    assessment = validate_bundle(bundle_dir)
    # Schema-layer diagnostics are ACEF-002 (manifest) and ACEF-004 (record).
    schema_layer_codes = {"ACEF-002", "ACEF-004"}
    schema_diags = [d for d in assessment.structural_errors if d.get("code") in schema_layer_codes]
    assert not schema_diags, (
        f"Fake-green bundle {bundle_dir.name!r} emitted schema-layer "
        f"diagnostics (expected zero — failures must be at the higher "
        f"integrity/reference/rule layer per VAL-CONFORMANCE-FAKE-GREEN-REF-002):\n"
        + "\n".join(f"  {d.get('code')}: {d.get('message', '')[:200]}" for d in schema_diags)
    )
