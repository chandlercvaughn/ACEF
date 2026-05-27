"""Unit tests for the namespace-lint registry (F-M1-NAMESPACE-LINT-HOOK).

Exercises the public registration API:

- ``register_namespace_lint`` adds entries (idempotent on (namespace, pattern_id))
- ``unregister_namespace`` removes ALL patterns for a namespace
- ``list_registered_namespaces`` returns a sorted snapshot
- ``run_namespace_lints`` dispatches only to registered namespaces

These tests do NOT depend on the bundled ``x-freddy`` patterns; they stand
alone so the registry primitive can be reviewed independently from the
default-registered Freddy lint module.
"""

from __future__ import annotations

from typing import Any

from acef.errors import ValidationDiagnostic
from acef.validation.namespace_lints import (
    NamespaceLintPattern,
    list_registered_namespaces,
    register_namespace_lint,
    run_namespace_lints,
    unregister_namespace,
)


def _make_pattern(
    *,
    namespace: str = "x-testns/probe",
    pattern_id: str = "probe-fires-on-tripwire",
    code: str = "ACEF-053",
) -> NamespaceLintPattern:
    def _lint(
        manifest: dict[str, Any],
        payload: dict[str, Any],
        all_records: list[Any],
    ) -> list[ValidationDiagnostic]:
        # Fires when payload contains tripwire=True
        if payload.get("tripwire") is True:
            return [ValidationDiagnostic(code, f"{namespace} tripwire fired")]
        return []

    return NamespaceLintPattern(
        namespace=namespace,
        pattern_id=pattern_id,
        description="Test probe — fires when payload.tripwire is True",
        lint=_lint,
        emitted_codes=[code],
    )


def test_register_namespace_lint_adds_entry() -> None:
    namespace = "x-regtest1/probe"
    try:
        assert namespace not in list_registered_namespaces()
        register_namespace_lint(_make_pattern(namespace=namespace))
        assert namespace in list_registered_namespaces()
    finally:
        unregister_namespace(namespace)


def test_register_idempotent_on_same_namespace_and_pattern_id() -> None:
    namespace = "x-regtest2/probe"
    pattern_id = "p1"
    try:
        register_namespace_lint(_make_pattern(namespace=namespace, pattern_id=pattern_id))
        # Re-registering the SAME (namespace, pattern_id) should NOT create
        # a duplicate entry — idempotency contract per design.
        register_namespace_lint(_make_pattern(namespace=namespace, pattern_id=pattern_id))
        # Run with a tripwire payload; one diagnostic should emerge, not two.
        records = [{"record_type": namespace, "payload": {"tripwire": True}}]
        diags = run_namespace_lints({}, records)
        codes = [d.code for d in diags]
        assert codes.count("ACEF-053") == 1, f"Idempotent re-registration should produce one diagnostic; got: {codes!r}"
    finally:
        unregister_namespace(namespace)


def test_unregister_namespace_removes_all_patterns() -> None:
    namespace = "x-regtest3/probe"
    try:
        register_namespace_lint(_make_pattern(namespace=namespace, pattern_id="p1"))
        register_namespace_lint(_make_pattern(namespace=namespace, pattern_id="p2", code="ACEF-053"))
        assert namespace in list_registered_namespaces()
        unregister_namespace(namespace)
        assert namespace not in list_registered_namespaces()
        # Re-running lint on a tripwire payload yields zero diagnostics.
        records = [{"record_type": namespace, "payload": {"tripwire": True}}]
        diags = run_namespace_lints({}, records)
        assert not any(d.code == "ACEF-053" for d in diags)
    finally:
        # safety
        unregister_namespace(namespace)


def test_list_registered_namespaces_returns_sorted_snapshot() -> None:
    a = "x-zzz-probe/x"
    b = "x-aaa-probe/x"
    try:
        register_namespace_lint(_make_pattern(namespace=a))
        register_namespace_lint(_make_pattern(namespace=b))
        listed = list_registered_namespaces()
        # Both present
        assert a in listed and b in listed
        # Sub-list of the registered names is sorted lexicographically
        subset = [n for n in listed if n in (a, b)]
        assert subset == sorted(subset)
    finally:
        unregister_namespace(a)
        unregister_namespace(b)


def test_unregistered_namespace_does_not_fire() -> None:
    """A record whose namespace is NOT registered produces no diagnostics."""
    namespace = "x-not-registered/probe"
    # Pre-condition: nothing registered.
    assert namespace not in list_registered_namespaces()
    records = [{"record_type": namespace, "payload": {"tripwire": True}}]
    diags = run_namespace_lints({}, records)
    assert diags == []


def test_run_namespace_lints_passes_manifest_and_records_to_lint() -> None:
    """The lint callable receives the manifest, payload, and full records list."""
    namespace = "x-regtest4/probe"
    captured: dict[str, Any] = {}

    def _capture_lint(
        manifest: dict[str, Any],
        payload: dict[str, Any],
        all_records: list[Any],
    ) -> list[ValidationDiagnostic]:
        captured["manifest"] = manifest
        captured["payload"] = payload
        captured["all_records"] = all_records
        return []

    pattern = NamespaceLintPattern(
        namespace=namespace,
        pattern_id="capture",
        description="capture inputs",
        lint=_capture_lint,
        emitted_codes=[],
    )
    try:
        register_namespace_lint(pattern)
        manifest = {"analysis_mode": "subscriber"}
        records = [
            {"record_type": namespace, "payload": {"k": "v"}},
            {"record_type": "event_log", "payload": {}},
        ]
        run_namespace_lints(manifest, records)
        assert captured["manifest"] is manifest
        assert captured["payload"] == {"k": "v"}
        assert captured["all_records"] is records
    finally:
        unregister_namespace(namespace)
