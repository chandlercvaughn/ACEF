"""PhD re-review W2: the §3.7 'Canonical evaluation instant' must DOCUMENT the
omitted-caller default and its producer-control caveat.

When the calling API does not pin an explicit ``evaluation_instant``, the engine
derives it deterministically from the Evidence Bundle's ``metadata.timestamp``
(NOT wall-clock, per §3.7 reproducibility). That timestamp is producer-controlled,
so the spec must say so and direct a consumer who needs producer-independent
freshness/effective-date gating to pass an explicit ``evaluation_instant`` — the
same limitation Appendix D.4 discloses as a non-goal.
"""

from __future__ import annotations

import json
from pathlib import Path

from acef.package import Package
from acef.validation.engine import validate_bundle


def test_omitted_evaluation_instant_defaults_to_metadata_timestamp(tmp_path: Path) -> None:
    """With no caller-supplied evaluation_instant, the engine pins it to the
    bundle's metadata.timestamp (reproducible, NOT wall-clock)."""
    pkg = Package(producer={"name": "ts-default", "version": "1.0.0"})
    pkg.add_subject("ai_system", name="S", risk_classification="high-risk", modalities=["text"])
    bundle_dir = tmp_path / "b.acef"
    pkg.export(str(bundle_dir))

    manifest = json.loads((bundle_dir / "acef-manifest.json").read_text(encoding="utf-8"))
    pkg_ts = manifest["metadata"]["timestamp"]
    assert isinstance(pkg_ts, str) and pkg_ts

    assessment = validate_bundle(bundle_dir)  # no evaluation_instant supplied
    assert assessment.evaluation_instant == pkg_ts, (
        "omitted evaluation_instant must derive from metadata.timestamp (§3.7 default), not wall-clock"
    )


def test_explicit_evaluation_instant_overrides_metadata_timestamp(tmp_path: Path) -> None:
    """A caller-supplied evaluation_instant is used verbatim (the producer-
    independent path a regulator assessing at filing time must use)."""
    pkg = Package(producer={"name": "ts-override", "version": "1.0.0"})
    pkg.add_subject("ai_system", name="S", risk_classification="high-risk", modalities=["text"])
    bundle_dir = tmp_path / "b.acef"
    pkg.export(str(bundle_dir))

    explicit = "2099-01-01T00:00:00Z"
    assessment = validate_bundle(bundle_dir, evaluation_instant=explicit)
    assert assessment.evaluation_instant == explicit


def test_spec_documents_evaluation_instant_producer_control_caveat() -> None:
    """§3.7 must document the omitted-caller default + producer-control caveat +
    the D.4 cross-reference."""
    spec = (Path(__file__).resolve().parents[2] / "planning" / "ACEF-Spec-Outline-v0.1.md").read_text(encoding="utf-8")
    idx = spec.find("Default when the caller omits `evaluation_instant`")
    assert idx != -1, "spec must document the omitted-caller evaluation_instant default"
    section = spec[idx : idx + 1500]
    assert "producer-controlled" in section, "must flag metadata.timestamp as producer-controlled"
    assert "pass an explicit `evaluation_instant`" in section, "must direct consumers to pass an explicit instant"
    assert "D.4" in section, "must cross-reference the Appendix D.4 freshness non-goal"
