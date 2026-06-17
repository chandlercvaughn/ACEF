"""F1 regression — the SDK's own construction flow + ``acef init`` MUST emit a bundle
the SDK's own validator accepts.

Before the fix, ``Package.__init__`` stamped the initial CREATED audit entry with no
``actor_ref`` (defaulting to ``""``), which violates the frozen manifest schema's
required ``^urn:acef:act:<uuid>$`` pattern → FATAL ACEF-002 at ``/audit_trail/0/actor_ref``
on EVERY SDK-built bundle, and ``add_subject`` without ``modalities`` emitted an
``minItems:1``-violating empty array. The reference SDK produced bundles its own
validator rejects — disqualifying for a reference implementation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from click.testing import CliRunner

from acef.cli.main import cli
from acef.package import Package
from acef.validation.engine import validate_bundle

_ACTOR_URN = re.compile(r"^urn:acef:act:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _structural_errors(bundle_dir: Path) -> list[tuple[str | None, str | None]]:
    assessment = validate_bundle(str(bundle_dir))
    return [(e.get("code"), e.get("path")) for e in assessment.structural_errors]


def test_happy_path_sdk_package_validates_clean(tmp_path: Path) -> None:
    """A subject-bearing Package built through the public API exports a bundle with
    ZERO structural errors (no FATAL ACEF-002 on actor_ref or modalities)."""
    pkg = Package(producer={"name": "acef-sdk", "version": "0.1.0"})
    pkg.add_subject(
        "ai_system",
        name="S",
        version="1.0.0",
        provider="P",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )
    bundle_dir = tmp_path / "happy.acef"
    pkg.export(str(bundle_dir))
    assert _structural_errors(bundle_dir) == [], "a happy-path SDK-built bundle must validate with no structural errors"


def test_created_audit_entry_carries_a_schema_valid_producer_actor_urn(tmp_path: Path) -> None:
    """The auto-minted CREATED audit entry carries a pattern-valid ``urn:acef:act:<uuid>``
    derived deterministically from the producer (same producer → same URN)."""
    pkg = Package(producer={"name": "acef-sdk", "version": "0.1.0"})
    bundle_dir = tmp_path / "audit.acef"
    pkg.export(str(bundle_dir))
    manifest = json.loads((bundle_dir / "acef-manifest.json").read_text(encoding="utf-8"))
    actor_ref = manifest["audit_trail"][0]["actor_ref"]
    assert _ACTOR_URN.match(actor_ref), f"CREATED entry actor_ref must be a urn:acef:act:<uuid>, got {actor_ref!r}"
    # Deterministic in the producer identity: a second build with the same producer
    # yields the same actor URN (byte-identical audit_trail across exporters).
    pkg2 = Package(producer={"name": "acef-sdk", "version": "0.1.0"})
    bundle_dir2 = tmp_path / "audit2.acef"
    pkg2.export(str(bundle_dir2))
    manifest2 = json.loads((bundle_dir2 / "acef-manifest.json").read_text(encoding="utf-8"))
    assert manifest2["audit_trail"][0]["actor_ref"] == actor_ref


def test_subject_without_modalities_is_flagged_by_the_validator(tmp_path: Path) -> None:
    """modalities is REQUIRED (schema: ``subjects[].modalities`` minItems:1). A caller who
    OMITS it gets a clean bundle on every other axis (the auto-minted actor_ref is valid),
    with the modalities omission surfaced by ``validate`` as ACEF-002 — the validator is
    the safety net for caller omissions (the SDK no longer auto-emits invalid content of
    its own, which was the F1 critical)."""
    pkg = Package(producer={"name": "acef-sdk", "version": "0.1.0"})
    pkg.add_subject("ai_system", name="S", risk_classification="high-risk")  # caller omits modalities
    bundle_dir = tmp_path / "no-modalities.acef"
    pkg.export(str(bundle_dir))  # the SDK faithfully builds what the caller supplied
    errs = _structural_errors(bundle_dir)
    # The ONLY structural error is the caller's modalities omission — NOT the SDK's own
    # audit_trail actor_ref (that is now always valid).
    assert errs == [("ACEF-002", "/subjects/0/modalities")], errs


def test_acef_init_emits_a_validating_bundle(tmp_path: Path) -> None:
    """``acef init`` documents its output as a 'minimal valid bundle'; the bundle it
    writes (with a subject) MUST pass ``acef validate`` with exit 0."""
    runner = CliRunner()
    out = str(tmp_path / "init-bundle.acef")
    init = runner.invoke(cli, ["init", out, "--subject-name", "Test System"])
    assert init.exit_code == 0, init.output
    validate = runner.invoke(cli, ["validate", out])
    assert validate.exit_code == 0, (
        f"acef init output must validate clean; got exit {validate.exit_code}\n{validate.output}"
    )


def test_bare_acef_init_emits_a_validating_bundle(tmp_path: Path) -> None:
    """Even WITHOUT --subject-name, ``acef init`` must emit a VALID bundle: the schema
    requires subjects[] minItems:1, so a no-subject scaffold is schema-invalid. init now
    always scaffolds a (renameable) default subject (roborev on 3753e54)."""
    runner = CliRunner()
    out = str(tmp_path / "bare-init.acef")
    init = runner.invoke(cli, ["init", out])
    assert init.exit_code == 0, init.output
    validate = runner.invoke(cli, ["validate", out])
    assert validate.exit_code == 0, (
        f"bare `acef init` output must validate clean; got exit {validate.exit_code}\n{validate.output}"
    )
