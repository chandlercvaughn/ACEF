"""Test VAL-VALIDATION-LINT-REGISTRY-001: registry is extensible without
modifying core validator code.

A vendor can register a new namespace via the public ``register_namespace_lint``
API and have its lint fire end-to-end through ``validate_bundle``, without
editing ``src/acef/validation/engine.py`` or any other core module.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from acef.errors import ValidationDiagnostic
from acef.validation.engine import validate_bundle
from acef.validation.namespace_lints import (
    NamespaceLintPattern,
    register_namespace_lint,
    unregister_namespace,
)
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
    write_bundle,
)

PROBE_NAMESPACE = "x-testvendor/probe"
PROBE_CODE = "ACEF-053"


def _probe_lint(
    manifest: dict[str, Any],
    payload: dict[str, Any],
    all_records: list[Any],
) -> list[ValidationDiagnostic]:
    if payload.get("tripwire") is True:
        return [
            ValidationDiagnostic(
                PROBE_CODE,
                "x-testvendor/probe tripwire fired",
            )
        ]
    return []


def test_third_party_namespace_can_register_and_fire(tmp_path: Path) -> None:
    """A vendor registers a lint, builds a v1.1 bundle with a triggering
    record, runs the validator, and the diagnostic is in the result.

    This proves the registry is extensible without modifying validator core
    code (VAL-VALIDATION-LINT-REGISTRY-001).
    """
    pattern = NamespaceLintPattern(
        namespace=PROBE_NAMESPACE,
        pattern_id="probe-tripwire",
        description="Probe — fires on payload.tripwire=true",
        lint=_probe_lint,
        emitted_codes=[PROBE_CODE],
    )

    bundle_dir = tmp_path / "third-party-namespace"
    write_bundle(
        bundle_dir,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:11000000-0000-0000-0000-000000000001",
                record_type=PROBE_NAMESPACE,
                payload={"tripwire": True},
            ),
        ],
    )

    try:
        register_namespace_lint(pattern)
        assessment = validate_bundle(bundle_dir)
        found = codes(assessment.structural_errors)
        assert PROBE_CODE in found, f"Probe lint should fire ACEF-053 from third-party registration; got: {found!r}"
    finally:
        # Always unregister so test isolation holds.
        unregister_namespace(PROBE_NAMESPACE)


def test_documentation_file_exists() -> None:
    """The registration API is documented in docs/namespace-lints.md."""
    repo_root = Path(__file__).resolve().parents[2]
    doc = repo_root / "docs" / "namespace-lints.md"
    assert doc.is_file(), f"Expected docs/namespace-lints.md to exist at {doc!s}"
    contents = doc.read_text(encoding="utf-8")
    # Must describe the registration API.
    assert "register_namespace_lint" in contents, "docs/namespace-lints.md must describe register_namespace_lint API"
    # Must describe the bundled freddy pattern.
    assert "voice-rubric-emission" in contents, (
        "docs/namespace-lints.md must reference the bundled x-freddy/voice-rubric-emission lint"
    )
    # Must describe graceful no-op for unregistered namespaces.
    assert "unregistered" in contents.lower(), (
        "docs/namespace-lints.md must document graceful no-op for unregistered namespaces"
    )
