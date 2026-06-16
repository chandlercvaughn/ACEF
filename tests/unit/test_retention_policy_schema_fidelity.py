"""Stability-shakedown (pass 2): RetentionPolicy.min_retention_days was
model-REQUIRED but schema-OPTIONAL (the frozen v1 manifest schema's
retention_policy object has no ``required`` array), so acef.load() over-rejected a
schema-VALID manifest carrying retention_policy without min_retention_days — a
load/validate divergence. The model now mirrors the schema's optionality.
"""

from __future__ import annotations

import glob
import json
import shutil
from pathlib import Path

import acef
from acef.models.metadata import RetentionPolicy

_GOLDEN = next(p for p in sorted(glob.glob("tests/conformance/golden-bundles/*")) if Path(p).is_dir())


def test_retention_policy_min_days_optional_at_model_layer() -> None:
    rp = RetentionPolicy(personal_data_interplay="GDPR Art. 17")
    assert rp.min_retention_days is None
    assert rp.personal_data_interplay == "GDPR Art. 17"


def test_load_accepts_retention_policy_without_min_days(tmp_path: Path) -> None:
    dst = tmp_path / "b"
    shutil.copytree(_GOLDEN, dst)
    manifest = json.loads((dst / "acef-manifest.json").read_text(encoding="utf-8"))
    manifest["metadata"]["retention_policy"] = {"personal_data_interplay": "GDPR Art. 17"}
    (dst / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    # Must LOAD cleanly (was rejected with ACEF-002 before the model fidelity fix).
    pkg = acef.load(str(dst))
    assert pkg.metadata.retention_policy is not None
    assert pkg.metadata.retention_policy.min_retention_days is None


def test_present_min_days_still_loads(tmp_path: Path) -> None:
    dst = tmp_path / "b"
    shutil.copytree(_GOLDEN, dst)
    manifest = json.loads((dst / "acef-manifest.json").read_text(encoding="utf-8"))
    manifest["metadata"]["retention_policy"] = {"min_retention_days": 180}
    (dst / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    pkg = acef.load(str(dst))
    assert pkg.metadata.retention_policy.min_retention_days == 180
