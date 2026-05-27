# Namespace Lint Registry

The namespace lint registry resolves a tension between ACEF Core's open-boundary
rule and Core's own error taxonomy:

- The ACEF spec §1 ("Open boundary enforcement") requires that vendor
  extensions live under `x-<vendor>/*` namespaces and MUST be safely
  ignorable by standard validators.
- Yet some Core error codes describe violating *content* that only appears
  inside vendor namespaces. The canonical example is
  [`ACEF-077`](../src/acef/errors.py) — "voice_rubric_emission contains
  claim-lexicon token without paired harness_attestation" — which by name
  references the `x-freddy/voice-rubric-emission` extension.

The registry resolves this by giving Core a way to delegate the **detection**
of a violating pattern to the vendor namespace, while keeping the **error
code** owned by Core. Vendors register lint patterns; the validator dispatches
to those patterns only for records whose `record_type` matches a registered
namespace.

Bundles that do not opt into a given namespace (or whose namespace is not
registered at validation time) validate cleanly with respect to the lint —
this **graceful no-op** is required by
[`VAL-VALIDATION-013`](../../.ops-runtime/acef-v0.4-freddy-adoption/contract.md).

## Public API

The registry lives at `acef.validation.namespace_lints`. The public surface is:

```python
from acef.validation.namespace_lints import (
    NamespaceLintPattern,
    register_namespace_lint,
    unregister_namespace,
    list_registered_namespaces,
    run_namespace_lints,
)
```

### `NamespaceLintPattern`

A frozen dataclass:

| Field           | Type                              | Meaning                                                                                                |
|-----------------|-----------------------------------|--------------------------------------------------------------------------------------------------------|
| `namespace`     | `str`                             | Namespace string (e.g., `"x-freddy/voice-rubric-emission"`). Matched against records' `record_type`.   |
| `pattern_id`    | `str`                             | Identifier unique within `namespace`. Re-registering on same `(namespace, pattern_id)` replaces.       |
| `description`   | `str`                             | Human-readable; for debugging only — does not surface in diagnostics.                                  |
| `lint`          | `LintCallable`                    | Callable invoked with `(manifest, payload, all_records)`. Returns `list[ValidationDiagnostic]`.        |
| `emitted_codes` | `list[str]`                       | ACEF-NNN codes this pattern may emit; for introspection.                                               |

### `LintCallable` signature

```python
def my_lint(
    manifest: dict[str, Any],
    payload: dict[str, Any],
    all_records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    ...
```

The callable receives the parsed manifest, the triggering record's payload,
and the full list of records (so cross-record checks like "is there a paired
harness_attestation in this bundle?" remain possible). It returns an empty
list when the pattern does not fire.

If your lint raises an exception, the validator surfaces it as an
`ACEF-053` ("Vendor extension field affects conformance outcome") diagnostic
with the namespace and pattern_id in the message. The validator continues —
vendor code MUST NOT crash the validator (spec §1 open-boundary rule).

## Registering a new namespace

Vendors register lint patterns by constructing a `NamespaceLintPattern` and
calling `register_namespace_lint`. No core validator code needs to be modified.

```python
from typing import Any
from acef.errors import ValidationDiagnostic
from acef.validation.namespace_lints import (
    NamespaceLintPattern,
    register_namespace_lint,
)


def my_vendor_lint(
    manifest: dict[str, Any],
    payload: dict[str, Any],
    all_records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    if payload.get("forbidden_field"):
        return [
            ValidationDiagnostic(
                "ACEF-053",
                f"x-myvendor/widget: forbidden_field set in {payload.get('id')}",
            )
        ]
    return []


_PATTERN = NamespaceLintPattern(
    namespace="x-myvendor/widget",
    pattern_id="forbidden-field-detected",
    description="Reject records carrying the forbidden_field marker.",
    lint=my_vendor_lint,
    emitted_codes=["ACEF-053"],
)

register_namespace_lint(_PATTERN)
```

Place this code in a module that is imported by your vendor SDK or your
deployment's entry point. The registration is process-global; once
registered, every `validate_bundle` call in the same process picks it up.

### Idempotency

`register_namespace_lint` is **idempotent on `(namespace, pattern_id)`**:
re-registering with the same identity REPLACES the prior entry (no
duplicates). Vendors can iterate on their lint definitions during dev
without leaking stale registrations.

### Opting out

To remove a namespace at runtime, call:

```python
from acef.validation.namespace_lints import unregister_namespace

unregister_namespace("x-myvendor/widget")
```

This removes ALL patterns for that namespace. The graceful no-op contract
then applies — bundles that previously fired the lint validate cleanly
with respect to that namespace.

### Introspection

To see what is currently registered:

```python
from acef.validation.namespace_lints import list_registered_namespaces

print(list_registered_namespaces())
# ['x-freddy/voice-rubric-emission', 'x-myvendor/widget']
```

Returns a sorted list of namespace strings (process-global state).

## Bundled patterns

### `x-freddy/voice-rubric-emission` → `ACEF-077`

ACEF v0.4 ships a default registration for the `x-freddy/voice-rubric-emission`
namespace, lazily loaded by the validation engine the first time it
processes a v1.1 bundle.

Implementation: [`src/acef/validation/namespace_lints/bundled_freddy.py`](../src/acef/validation/namespace_lints/bundled_freddy.py)

Trigger (per brief §5.2 and the [`ACEF-077`](../src/acef/errors.py)
description):

ACEF-077 fires when ALL of the following hold:

- `payload.claim_lexicon_scan_result.tokens_found` is a non-empty list, AND
- `payload.rejection_state` is NOT `"rejected_invalid_voice_rubric_emission"`
  (i.e., the producer did not properly reject the record), AND
- `payload.harness_attestation_ref` is absent or empty (no paired harness
  attestation in the record itself).

Producers can avoid ACEF-077 by any of:

- Ensuring the claim-lexicon scan finds no banned tokens (clean output).
- Properly rejecting the record via
  `rejection_state: "rejected_invalid_voice_rubric_emission"`.
- Pairing the record with a `harness_attestation_ref` in the payload.

**Opt-out:** call `unregister_namespace("x-freddy/voice-rubric-emission")`
after the validation engine has initialized. Alternatively, downstream SDK
builds may exclude the `bundled_freddy` submodule from their distribution.

## Graceful no-op for unregistered namespaces

A bundle containing a record whose `record_type` is an `x-<vendor>/*` string
NOT in the registry produces ZERO lint diagnostics for that record. This is
the graceful-degradation behavior required by
[`VAL-VALIDATION-013`](../../.ops-runtime/acef-v0.4-freddy-adoption/contract.md):

> A bundle containing `x-unregistered-vendor/some_record` with content that
> would trigger ACEF-077 if registered does NOT emit ACEF-077.

This ensures that an extension whose home repo has not yet shipped its lint
registration does not produce a false-negative ACEF code against a bundle that
exercises that extension. The lint registry's discovery is opt-in by design —
Core never assumes content semantics it cannot validate.

Other diagnostic categories (schema validation, integrity verification,
reference checking) operate independently and may still emit codes for an
unregistered namespace's record — they don't know about the vendor's
semantics, so they enforce only the structural rules Core can prove.

## Test pattern for vendors

To verify your registration fires end-to-end:

```python
from acef.validation.engine import validate_bundle
from acef.validation.namespace_lints import (
    register_namespace_lint,
    unregister_namespace,
)
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest, base_record, codes, write_bundle,
)

# Register your pattern (in setup / module import)
register_namespace_lint(_PATTERN)

try:
    bundle = tmp_path / "my-vendor-test"
    write_bundle(
        bundle,
        manifest=base_manifest(),  # v1.1 default
        records=[
            base_record(
                record_id="urn:acef:rec:00000000-0000-0000-0000-000000000001",
                record_type="x-myvendor/widget",
                payload={"forbidden_field": True, "id": "w-001"},
            ),
        ],
    )
    assessment = validate_bundle(bundle)
    assert "ACEF-053" in codes(assessment.structural_errors)
finally:
    unregister_namespace("x-myvendor/widget")
```

The `try/finally unregister_namespace(...)` pattern keeps test isolation —
process-global registry state does not leak between tests.

## Operation provenance

This module implements feature `F-M1-NAMESPACE-LINT-HOOK` of operation
`acef-v0.4-freddy-adoption` (plan workstream WS3.10). Assertions fulfilled:

- `VAL-VALIDATION-012` — `x-freddy/voice-rubric-emission` lint emits ACEF-077.
- `VAL-VALIDATION-013` — Unregistered namespace produces no ACEF-077.
- `VAL-VALIDATION-LINT-REGISTRY-001` — Registry is extensible without
  modifying core validator code; documented here.
- `VAL-VALIDATION-LINT-INVOCATION-001` — Lint hooks fire before validation
  returns success.
