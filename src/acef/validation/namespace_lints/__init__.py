"""Vendor-extension namespace lint registry (F-M1-NAMESPACE-LINT-HOOK / WS3.10).

Per ACEF spec §1 "Open boundary enforcement", vendor extensions live under
``x-<vendor>/*`` namespaces and MUST be safely ignorable by standard
validators. However, some Core error codes (notably ACEF-077,
``voice_rubric_emission contains claim-lexicon token without paired
harness_attestation``) describe violating *content* that only appears in a
vendor namespace. This registry resolves the seeming contradiction:

- **Core** defines the error code.
- **Vendor namespaces** that opt in to lint enforcement register lint
  patterns whose violations emit Core error codes.
- **Unregistered namespaces** are silently no-op (graceful degradation per
  VAL-VALIDATION-013), so a bundle that exercises an extension whose home
  repo has not registered its lint patterns validates clean rather than
  fails with a false-negative ACEF code.

Public surface:

- :class:`NamespaceLintPattern` — dataclass describing one lint pattern.
- :func:`register_namespace_lint` — idempotent registration on
  ``(namespace, pattern_id)``.
- :func:`unregister_namespace` — remove all patterns for a namespace
  (used by tests and by vendors who want to opt their namespace out at
  runtime).
- :func:`list_registered_namespaces` — sorted list of registered namespace
  strings (introspection / debugging).
- :func:`run_namespace_lints` — dispatch entry point invoked by the
  validation engine for v1.1 bundles.

Bundled patterns: importing the sibling submodule
:mod:`acef.validation.namespace_lints.bundled_freddy` auto-registers the
``x-freddy/voice-rubric-emission`` claim-lexicon lint. Deployments that
want to opt out simply don't import that submodule. The validation engine
imports it as part of its v1.1 wiring (so ``x-freddy/*`` works out of the
box for any ACEF SDK consumer); tests that need the registration to be
load-order-independent import the submodule explicitly.

Extensibility for VAL-VALIDATION-LINT-REGISTRY-001: new namespaces can be
registered without modifying any code in this module. A vendor constructs
a :class:`NamespaceLintPattern` and calls :func:`register_namespace_lint`.
See ``docs/namespace-lints.md`` for the documented contract.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from acef.errors import ValidationDiagnostic

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

#: Type alias for a lint callable. Receives the bundle manifest dict, the
#: triggering record's payload dict, and the full records list (so cross-
#: record checks like "is there a paired harness_attestation in this
#: bundle?" remain possible). Returns a list of diagnostics — empty when
#: the pattern does not fire.
LintCallable = Callable[[dict[str, Any], dict[str, Any], list[dict[str, Any]]], list[ValidationDiagnostic]]


@dataclass(frozen=True)
class NamespaceLintPattern:
    """One lint pattern registered against one vendor namespace.

    Attributes:
        namespace: The namespace string (e.g.,
            ``"x-freddy/voice-rubric-emission"``). Matched against a
            record's ``record_type`` field for dispatch.
        pattern_id: Identifier unique within the namespace. Used for
            idempotent registration — re-registering on the same
            ``(namespace, pattern_id)`` replaces the prior entry.
        description: Human-readable description; surfaces in debugging
            output but not in emitted diagnostics.
        lint: Callable invoked with ``(manifest, payload, all_records)``.
        emitted_codes: ACEF-NNN codes this pattern may emit. Used for
            introspection and to keep tests honest about which Core codes
            a namespace can produce.
    """

    namespace: str
    pattern_id: str
    description: str
    lint: LintCallable
    emitted_codes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Registry state — module-level, explicit
# ---------------------------------------------------------------------------

# Maps namespace string → list of patterns (preserving registration order
# within a namespace, useful for deterministic diagnostic order when one
# namespace has multiple patterns).
_REGISTRY: dict[str, list[NamespaceLintPattern]] = {}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def register_namespace_lint(pattern: NamespaceLintPattern) -> None:
    """Register a lint pattern for a vendor namespace.

    Idempotent on ``(namespace, pattern_id)``: re-registering with the
    same identity REPLACES the prior entry (does not duplicate). This
    matches the spec §1 "open boundary" expectation that vendors can
    iterate on their lint definitions without leaking stale registrations.
    """
    bucket = _REGISTRY.setdefault(pattern.namespace, [])
    # Replace any prior pattern with the same pattern_id; otherwise append.
    for idx, existing in enumerate(bucket):
        if existing.pattern_id == pattern.pattern_id:
            bucket[idx] = pattern
            return
    bucket.append(pattern)


def unregister_namespace(namespace: str) -> None:
    """Remove all registered lint patterns for ``namespace``.

    No-op when the namespace was never registered. Tests use this to keep
    isolation when they register a probe namespace and want to clean up.
    Production deployments that want to opt a namespace out at runtime can
    also call this.
    """
    _REGISTRY.pop(namespace, None)


def list_registered_namespaces() -> list[str]:
    """Return the sorted list of currently-registered namespace strings."""
    return sorted(_REGISTRY.keys())


def run_namespace_lints(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    """Invoke registered lint patterns and return aggregated diagnostics.

    Iterates ``records``; for each record whose ``record_type`` matches a
    registered namespace string, invokes every pattern in that namespace's
    bucket with ``(manifest, payload, records)``.

    Records whose ``record_type`` is NOT in the registry produce zero
    diagnostics — this is the graceful no-op behavior required by
    VAL-VALIDATION-013 ("unregistered namespace produces no ACEF-077").

    Defensive: non-dict records are skipped (the schema-validation phase
    already emits diagnostics for them); non-dict payloads are coerced to
    an empty dict for the lint callable.
    """
    diags: list[ValidationDiagnostic] = []
    if not _REGISTRY:
        return diags  # fast path — no lints registered, nothing to do

    for rec in records:
        if not isinstance(rec, dict):
            continue
        record_type = rec.get("record_type")
        if not isinstance(record_type, str) or not record_type:
            continue
        bucket = _REGISTRY.get(record_type)
        if bucket is None:
            continue
        payload = rec.get("payload")
        if not isinstance(payload, dict):
            payload = {}
        for pattern in bucket:
            try:
                result = pattern.lint(manifest, payload, records)
            except Exception as exc:
                # A misbehaving vendor lint must NOT crash the validator —
                # surface its failure as an evaluation diagnostic so the
                # producer can fix their registration.
                diags.append(
                    ValidationDiagnostic(
                        "ACEF-053",
                        (
                            f"Namespace lint {pattern.namespace}/"
                            f"{pattern.pattern_id} raised {type(exc).__name__}: "
                            f"{exc}. Vendor extensions MUST NOT crash the "
                            "validator (spec §1 open-boundary rule)."
                        ),
                    )
                )
                continue
            if result:
                diags.extend(result)
    return diags


__all__ = [
    "LintCallable",
    "NamespaceLintPattern",
    "register_namespace_lint",
    "unregister_namespace",
    "list_registered_namespaces",
    "run_namespace_lints",
]
