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

import pytest
from pydantic import ValidationError as PydanticValidationError

import acef
from acef.errors import ACEFSchemaError
from acef.models.metadata import RetentionPolicy

_GOLDEN = next(p for p in sorted(glob.glob("tests/conformance/golden-bundles/*")) if Path(p).is_dir())


def _golden_with_retention(tmp_path: Path, retention: object) -> Path:
    """Copy the golden bundle, set ``metadata.retention_policy`` to ``retention``,
    and return the bundle dir (for load-layer assertions)."""
    dst = tmp_path / "b"
    shutil.copytree(_GOLDEN, dst)
    manifest = json.loads((dst / "acef-manifest.json").read_text(encoding="utf-8"))
    manifest["metadata"]["retention_policy"] = retention
    (dst / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return dst


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


# --- roborev follow-up (033cc07 Medium): OPTIONAL must not become NULLABLE. ---
# The frozen v1 manifest schema types ``retention_policy.min_retention_days`` as a
# NON-nullable ``integer`` and ``personal_data_interplay`` as a NON-nullable
# ``string`` (neither is ``[..., "null"]``), and the object has no ``required``
# array. So OPTIONAL (absent key → default) is correct, but a PRESENT explicit
# ``null`` is a type violation — and a numeric STRING / ``float`` / ``bool`` for
# ``min_retention_days`` is a type violation Pydantic's lax ``int`` would silently
# COERCE-and-mutate on re-export. Mirrors RecordRetention's StrictInt + present-null
# guard.


def test_retention_policy_rejects_present_null_min_days() -> None:
    with pytest.raises(PydanticValidationError):
        RetentionPolicy.model_validate({"min_retention_days": None})


def test_retention_policy_rejects_present_null_personal_data_interplay() -> None:
    with pytest.raises(PydanticValidationError):
        RetentionPolicy.model_validate({"personal_data_interplay": None})


@pytest.mark.parametrize("bad", ["180", 1.5, True, False])
def test_retention_policy_rejects_coerced_min_days(bad: object) -> None:
    # StrictInt: a numeric string, a float, or a bool (lax int → 1/0) must NOT be
    # silently coerced into an integer that then re-exports as a mutated value.
    with pytest.raises(PydanticValidationError):
        RetentionPolicy.model_validate({"min_retention_days": bad})


def test_retention_policy_accepts_real_integer_min_days() -> None:
    rp = RetentionPolicy.model_validate({"min_retention_days": 180})
    assert rp.min_retention_days == 180


def test_retention_policy_rejects_negative_min_days() -> None:
    # ge=0 still rejects an out-of-range VALUE (distinct from a type violation).
    with pytest.raises(PydanticValidationError):
        RetentionPolicy.model_validate({"min_retention_days": -1})


def test_load_rejects_retention_policy_present_null_min_days(tmp_path: Path) -> None:
    dst = _golden_with_retention(tmp_path, {"min_retention_days": None})
    with pytest.raises(ACEFSchemaError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-002"


def test_load_rejects_retention_policy_present_null_pdi(tmp_path: Path) -> None:
    dst = _golden_with_retention(tmp_path, {"personal_data_interplay": None})
    with pytest.raises(ACEFSchemaError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-002"


def test_load_rejects_retention_policy_coerced_min_days(tmp_path: Path) -> None:
    dst = _golden_with_retention(tmp_path, {"min_retention_days": "180"})
    with pytest.raises(ACEFSchemaError) as exc:
        acef.load(str(dst))
    assert exc.value.code == "ACEF-002"


def test_load_accepts_retention_policy_whole_null(tmp_path: Path) -> None:
    # Regression guard: the schema types ``retention_policy`` itself as
    # ``["object", "null"]``, so an explicit whole ``null`` is "no policy" and MUST
    # still load (None), unaffected by the property-level present-null guard.
    dst = _golden_with_retention(tmp_path, None)
    pkg = acef.load(str(dst))
    assert pkg.metadata.retention_policy is None
