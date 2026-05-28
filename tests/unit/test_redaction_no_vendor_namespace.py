"""VAL-REDACTION-004 — no vendor namespace artifacts for redaction attestation.

The codex scope-creep removal mandates that the redaction-attestation
plumbing reuse the Core ``event_log`` record type and the existing
``RecordEnvelope.redaction_attestation_ref`` envelope field. No new
``x-freddy/redaction-attestation`` schema file under
``acef-conventions/v1.1/`` and no new vendor model under
``src/acef/models/`` are permitted.
"""

from __future__ import annotations

from pathlib import Path

# Repo root resolution: this test file lives at
#   <repo>/tests/unit/test_redaction_no_vendor_namespace.py
# so two parents up is the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_no_redaction_attestation_schema_under_v1_1() -> None:
    """No file matching '*redaction-attestation*' under acef-conventions/v1.1/."""
    schemas_root = _REPO_ROOT / "acef-conventions" / "v1.1"
    matches: list[str] = []
    if schemas_root.exists():
        matches = [str(p.relative_to(_REPO_ROOT)) for p in schemas_root.rglob("*redaction-attestation*")]
    assert matches == [], (
        f"VAL-REDACTION-004 violated: forbidden schema artifacts found under "
        f"acef-conventions/v1.1/: {matches!r}. The redaction attestation MUST "
        "reuse the Core event_log record type."
    )


def test_no_redaction_attestation_model_under_src() -> None:
    """No file matching '*redaction_attestation*' under src/acef/models/."""
    models_root = _REPO_ROOT / "src" / "acef" / "models"
    matches: list[str] = []
    if models_root.exists():
        matches = [str(p.relative_to(_REPO_ROOT)) for p in models_root.rglob("*redaction_attestation*")]
    assert matches == [], (
        f"VAL-REDACTION-004 violated: forbidden model artifacts found under "
        f"src/acef/models/: {matches!r}. The X2 envelope field "
        "redaction_attestation_ref lives on RecordEnvelope; no standalone "
        "model file should exist."
    )
