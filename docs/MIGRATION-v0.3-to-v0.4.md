# Migrating from ACEF v0.3 to v0.4

This document is the migration guide for ACEF v0.4, the "Freddy adoption"
release. It describes what changed, how to opt in, and (critically) what does
**not** change for existing v1.0 producers and consumers.

The companion design document is
[`planning/ACEF-RFC-0001-agent-reliability-primitives.md`](../planning/ACEF-RFC-0001-agent-reliability-primitives.md);
the normative source brief is
[`planning/freddy-on-acef-requirements-v0.1.md`](../planning/freddy-on-acef-requirements-v0.1.md).

---

## Summary

ACEF v0.4 is a **purely additive minor release** that introduces agent-
reliability primitives needed by continuous-verification products. It adds:

- 5 new Core (Evidence) record types, plus the Assessment-side `coverage_cell` field
- 5 new payload variants on existing record types
- 6 cross-cutting envelope/manifest fields (X1-X6) implemented as
  **version-gated, conditional-required**
- 11 new error codes (ACEF-070 through ACEF-080)
- A namespace-scoped lint hook that lets registered `x-vendor/*` extensions
  emit Core error codes
- A `subscriber-mode-full-loop` canonical reference bundle and a 27-bundle
  Freddy conformance battery (9 pass / 11 fail / 7 fake-green)

Existing ACEF v0.3 producers, consumers, and bundles are not impacted. The
v1.0 schemas in `acef-conventions/v1/` are frozen and byte-identical to the
v0.3 release. New schemas live in `acef-conventions/v1.1/`. A bundle is
treated as v1.1 only when its manifest declares `core_version: 1.1.0`; all
other bundles validate against v1.0 schemas with v1.0 semantics.

The compatibility commitment is documented in the source brief §8.1 and is
the load-bearing invariant for this release. The "Version Gating Semantics"
section below explains the mechanism.

---

## What's New in v0.4

### New Record Types

ACEF Core gains five new Evidence record types under `acef-conventions/v1.1/`
(the Assessment-side `coverage_cell` field, described below, is not one of them —
it has no Evidence-record schema and no `Package` builder). Their
SDK builders are exposed on `acef.Package` as typed methods (see "Tooling
Changes" → "SDK" below). The corresponding Pydantic payload models live in
`src/acef/models/agent_reliability.py`.

- **`authorized_test_scope`** — Declares what testing is authorized against
  an AI system: authorized surfaces, identities, side-effect policy, sandbox
  boundary, ownership proof, kill-switch reference. Required when an
  agent-reliability product tests a third-party AI system. Cross-vendor
  concept; lives in Core (not in `x-freddy/*`).

- **`scope_boundary_event`** — A control-plane integrity event recording
  that a test attempted to act outside its authorized scope. Distinct from
  `event_log` (routine) and `incident_report` (post-market operational).
  Pairs with `harness_attestation` when `hard_stop_triggered: true`.

- **`finding_record`** — A reproducible defect with evidence, distinct
  from `incident_report` (which is operator-facing and post-market).
  Carries a normative `dedupe_key` computed as
  `"sha256:" + sha256(JCS({class, subject_ref, expected_behavior, reproduction_steps_ref_content_hash}))`,
  so two findings with the same canonical reproduction recipe collapse to
  the same key across SDK runs.

- **`delivery_verdict`** — Records that evidence was shipped to a downstream
  system AND verified to have arrived. The `verified_delivered` state
  requires all of: `read_back` block present, `read_back.digest_match: true`,
  byte-equal `read_back.read_back_digest == write_attempt.request_digest`,
  and a paired `harness_attestation_ref`. Provider acknowledgment alone
  (HTTP 2xx) is **not** verified delivery.

- **`coverage_cell`** — An Assessment Bundle entry expressing "for this
  subject, across this scenario set, within this time window, the bound
  evidence is fresh and covers the cell". Lives inside
  `acef-conventions/v1.1/assessment-bundle.schema.json` as an optional
  array field, **not** as a standalone record type. Constructed via the
  `acef.models.agent_reliability.CoverageCellPayload` Pydantic model.

- **`harness_attestation`** — A per-state-transition signed attestation
  generalizing the bundle-level JWS already in `src/acef/signing.py`. Carries
  a `state_class` (one of seven hard-coded values), `bound_evidence_refs`
  (non-empty), a `verifier` block (NEVER `persona` or `llm` — rejected at
  load and at SDK build time), a `fake_green_test_ref`, and a JWS detached
  signature over the 9 normative fields enumerated in
  `acef.signing.HARNESS_ATTESTATION_SIGNED_FIELDS`.

### New Variant Entries

Five new entries land in `acef-conventions/v1.1/variant-registry.json`,
extending the existing discriminator pattern. The 12 v1.0 variant entries
are byte-identical to the v0.3 release and continue to resolve unchanged.

| artifact_name | Parent record_type | Discriminator (JSON Pointer) | Purpose |
|---|---|---|---|
| `human_oversight_kill_switch` | `human_oversight_action` | `/payload/oversight_subtype == "kill_switch"` | Operator-triggered hard stop with audit trail. |
| `regression_definition` | `risk_treatment` | `/payload/treatment_subtype == "regression_definition"` | A persistent regression test whose passing is risk mitigation. |
| `disposition_record` | `risk_treatment` | `/payload/treatment_subtype == "external_disposition"` | Customer-asserted classification of a finding (false positive, accepted risk, scheduled fix). `internal_state_unchanged` MUST be true. |
| `badge_state` | `transparency_disclosure` | `/payload/variant == "verification_badge"` | Public display of verification status against a particular evidence chain. |
| `evidence_freshness_window` | `evidence_gap` | `/payload/gap_subtype == "freshness_window"` | Time-bound expression of when evidence stops being current. |

### New Envelope/Manifest Fields (X1-X6)

Six new fields are introduced. All six are **optional in the v1.1 schemas**;
conditional-required enforcement happens at validator level, keyed on
`manifest.versioning.core_version` and `manifest.analysis_mode`. See
"Version Gating Semantics" below.

| ID | Field | Location | Required when | Validator error on absence |
|---|---|---|---|---|
| X1 | `redaction_policy_version` | record envelope | `core_version >= 1.1.0` AND `confidentiality != "public"` | ACEF-074 |
| X2 | `redaction_attestation_ref` | record envelope | `core_version >= 1.1.0` AND `confidentiality != "public"` | ACEF-078 |
| X3 | `tenant_label` | record envelope | `core_version >= 1.1.0` AND `manifest.analysis_mode` set | ACEF-075 (on mismatch across bundle) |
| X4 | `causation_chain` | record envelope | `core_version >= 1.1.0` AND `record_type == "harness_attestation"` (>=1 element) | ACEF-073 (on unresolvable URN) |
| X5 | `analysis_mode` | manifest | `core_version >= 1.1.0` | ACEF-080 (on mode-gated rule violation) |
| X6 | `namespaces` | manifest | optional (vendor extension container) | n/a (graceful degradation per VAL-VALIDATION-013) |

X5 is an enum: `subscriber`, `public_artifact`, `canary`, or
`unattributed_artifact`. Each mode has its own gate matrix; see the
`acef-conventions/v1.1/state-class-taxonomy.json` and the "Freddy Profile
Conformance" section of [`CONFORMANCE.md`](CONFORMANCE.md#freddy-profile-conformance).

X6 holds vendor extensions of the form `x-<vendor>/<extension>`. Registered
namespaces may emit Core error codes via the new namespace-scoped lint hook.
Unregistered namespaces are preserved through round-trip but cannot affect
Core conformance outcomes (per spec §3.7).

### New Error Codes

Eleven new codes added to `src/acef/errors.py` `ERROR_REGISTRY` in the
ACEF-070..ACEF-080 range. The v1.0 reserved range (ACEF-001..ACEF-060)
remains byte-identical to v0.3 and is verified by the
`tests/conformance/fixtures/v1.0-errors.json` snapshot.

| Code | Severity | Category | Description |
|---|---|---|---|
| ACEF-070 | FATAL | INTEGRITY | `harness_attestation` cites missing or unverifiable required evidence. |
| ACEF-071 | FATAL | INTEGRITY | `delivery_verdict` claims `verified_delivered` without a read-back digest. |
| ACEF-072 | FATAL | INTEGRITY | `delivery_verdict` read-back digest does not match write-back digest. |
| ACEF-073 | FATAL | REFERENCE | `causation_chain` cites an unknown or unsigned URN. |
| ACEF-074 | ERROR | SCHEMA | Record missing `redaction_policy_version` when `confidentiality != "public"`. |
| ACEF-075 | FATAL | REFERENCE | `tenant_label` mismatch across records in a single bundle. |
| ACEF-076 | ERROR | SCHEMA | `state_class` record lacks fake-green test reference (or `state_class` not in the seven-entry taxonomy). |
| ACEF-077 | FATAL | INTEGRITY | `voice_rubric_emission` contains a claim-lexicon token without a paired `harness_attestation` (fires via the registered namespace lint for `x-freddy/voice-rubric-emission`). |
| ACEF-078 | ERROR | REFERENCE | `redaction_attestation_ref` points to an unresolvable URN. Replaces previously-overloaded ACEF-022 use for this condition. |
| ACEF-079 | ERROR | SCHEMA | `coverage_cell.claim_language` contains a banned token (`compliant`, `certified`, `AI Act-approved`, `guaranteed`). Replaces previously-overloaded ACEF-053 use. |
| ACEF-080 | ERROR | REFERENCE | Bundle declares `analysis_mode` but lacks required envelope fields for that mode, OR contains forbidden record types for that mode. |

Three of these (ACEF-078, ACEF-079, ACEF-080) were added during codex review
of the implementation plan after the brief's original eight (ACEF-070..077);
they prevent semantic overloading of existing codes (ACEF-022, ACEF-053) for
distinct failure modes.

---

## Version Gating Semantics

This is the load-bearing strategic correction that makes v0.4 a non-breaking
release. Readers familiar with the brief should note that the brief §6.4
and §6.6 say "required on every record" / "required" while §8.1 says
"conditional-required". ACEF honors §8.1.

**The core invariant:**

> A bundle declaring `manifest.versioning.core_version: "1.0.0"` (or any
> 1.0.x version) validates **identically** to pre-v0.4 behavior. None of the
> new X1-X6 fields are required, no new error codes fire, no schema selects
> from `acef-conventions/v1.1/`. The six existing v1.0 golden bundles in
> `tests/conformance/golden-bundles/` are byte-equal to their v0.3 release
> snapshots and pass v0.4 validation cleanly (per VAL-REGRESSION-001 and
> VAL-REGRESSION-003 in the operation contract).

**How the validator decides:**

1. Read `manifest.versioning.core_version` from the manifest.
2. If `core_version` is `1.0.x`, select schemas from `acef-conventions/v1/`.
   None of the v1.1 conditional-required validators run.
3. If `core_version` is `1.1.x`, select schemas from
   `acef-conventions/v1.1/`. The v1.1 conditional-required validators
   activate. Mode-gated rules consult `manifest.analysis_mode`.
4. If `core_version` is anything else, the validator emits a structural
   error (no compatibility commitment exists for unknown versions).

**Operational summary:**

```text
Existing bundle (no analysis_mode in manifest, core_version: 1.0.0)
  -> v1.0 schemas selected
  -> no v1.1 envelope requirements apply
  -> regression R1 passes byte-equal to pre-v0.4

New bundle (manifest declares analysis_mode + core_version: 1.1.0)
  -> v1.1 schemas selected, v1.1 conditional-required semantics apply
  -> X1 (redaction_policy_version) required when confidentiality != "public"
  -> X2 (redaction_attestation_ref) required when confidentiality != "public"
  -> X3 (tenant_label) uniformity enforced bundle-wide
  -> X4 (causation_chain) required on harness_attestation with >=1 element
  -> X5 (analysis_mode) gates mode-specific record-type requirements
  -> harness_attestation.state_class enforced against the 7-entry taxonomy
```

The SDK's `Package.record()` auto-populates X1/X2 on non-public records
only when the package's `_versioning.core_version` is `1.1` or later. v1.0
producers see no behavior change.

**Mixed-version handling:** A bundle declaring `core_version: 1.0.0` that
happens to include a v1.1 field (e.g., `analysis_mode`) is permitted
under lenient round-trip semantics (VAL-VALIDATION-VERSION-COMPAT-001):
the field is preserved through load → re-export but does not affect
validation. This permits Pydantic round-trip parity for vendor tooling
that round-trips unknown fields. A diagnostic-severity informational
notice may be emitted but does not raise.

---

## §6.4 vs §8.1 Resolution

The source brief carries an internal tension. §6.4 introduces X3
`tenant_label` with the words "required on every record"; §6.6 introduces X5
`analysis_mode` with "required". §8.1, the compatibility commitments
section, says new envelope fields are "conditional-required, not
absolute-required, on existing record types — they become required only
when `confidentiality != 'public'` (X1, X2), when a new state-class record
is present (X4 for `harness_attestation`), or when the validator runs in
`subscriber`/`public_artifact`/`canary` mode (X3, X5, X6)."

Taken at face value, the §6.4/§6.6 reading is a breaking change against
v1.0 bundles, which carry neither field. The six existing v1.0 golden
bundles would fail v1.1 validation under that reading. That is
incompatible with the rest of the brief and with ACEF's stated
purely-additive intent.

**ACEF resolves this on the §8.1 side.** §8.1 is the written compatibility
commitment in the very section titled "Backward Compatibility and
Migration". §6.4 and §6.6 are field-level descriptions whose "required"
prose is best read as "required in the v1.1-opt-in path" rather than
"required absolutely". The version-gating design above is the mechanism
that makes the §8.1 reading executable.

**Recommendation back to the brief team:** amend §6.4 and §6.6 to read
"conditional-required when manifest declares `analysis_mode`" or
"conditional-required when `core_version >= 1.1.0`", so the brief text is
internally consistent and matches §8.1's compatibility commitment. Until
the brief is amended, ACEF's version-gating semantics above are the
authoritative interpretation.

This resolution is recorded in `ACEF-RFC-0001` §"Version-Gating Design"
and is verified by VAL-REGRESSION-001..004 in the v0.4 conformance suite.

---

## Migration Path

### Existing v0.3 Consumers (No Changes Needed)

If you currently produce or consume ACEF v0.3 bundles:

- Your existing bundles continue to validate without modification.
- Your existing producer code continues to emit byte-identical bundles.
- Your existing v1.0 templates and variant resolutions are unchanged.
- Your existing test vectors (china-cac, eu-ai-act, eu-gpai-cop, nist-rmf)
  pass without changes.

No action is required to remain on v1.0. The v1.1 features are opt-in.

### Producers Opting Into v1.1

To use the new agent-reliability primitives:

1. **Bump `core_version`.** Set `manifest.versioning.core_version` to
   `"1.1.0"`. With the reference SDK, that means setting
   `pkg._versioning.core_version = "1.1.0"` (or constructing a
   `Versioning(core_version="1.1.0")` and assigning it).
2. **Declare `analysis_mode`.** Add the manifest-level
   `analysis_mode` field with one of: `subscriber`, `public_artifact`,
   `canary`, `unattributed_artifact`. The mode determines which mode-gated
   rules apply.
3. **Tag every non-public record.** When `confidentiality != "public"`,
   either attach a `RedactionPolicy` to the `Package` (the SDK then
   auto-populates X1 and X2) or supply `redaction_policy_version` and
   `redaction_attestation_ref` explicitly.
4. **Set `tenant_label` uniformly.** When `analysis_mode` is set, every
   record in the bundle MUST carry the same `tenant_label`. The SDK does
   not auto-populate this; callers are responsible.
5. **Pair state transitions with attestations.** For each state-class
   record (`harness_attestation`, `finding_record`, `coverage_cell`,
   `regression_definition` (active), `delivery_verdict` (verified),
   `badge_state` (green/provisional)), emit a `harness_attestation`
   binding the precursor evidence. The `causation_chain` envelope field
   is required on the attestation with at least one URN.

For a worked end-to-end producer example, see
[`USER_GUIDE.md`](USER_GUIDE.md#v11-agent-reliability-record-types).

### Schema Directory Layout

```text
acef-conventions/
├── v1/                          # FROZEN — byte-identical to v0.3
│   ├── manifest.schema.json
│   ├── record-envelope.schema.json
│   ├── *.schema.json            # 16 v1.0 record-type schemas
│   ├── assessment-bundle.schema.json
│   └── variant-registry.json    # 12 v1.0 variant entries
└── v1.1/                        # New in v0.4
    ├── manifest.schema.json     # Adds analysis_mode, namespaces
    ├── record-envelope.schema.json  # Adds X1-X4 as optional
    ├── authorized_test_scope.schema.json
    ├── scope_boundary_event.schema.json
    ├── finding_record.schema.json
    ├── delivery_verdict.schema.json
    ├── harness_attestation.schema.json
    ├── assessment-bundle.schema.json  # Embeds coverage_cell
    ├── state-class-taxonomy.json      # 7 hard-coded entries
    └── variant-registry.json    # 12 v1.0 + 5 new = 17 entries
```

The v1/ tree is frozen for the lifetime of v1.x. v1.1 schemas live
alongside v1, not in a v2 subdirectory. The validator's
`acef.schemas.registry.resolve_variant()` consults v1.1 first then falls
back to v1.0 for unchanged entries (a single resolver, two backing files).

---

## Tooling Changes

### SDK

The reference Python SDK at `src/acef/` gains the following public surface
in v0.2.0:

**Typed builders on `acef.Package`** (each runs SDK-side pre-flight checks
that mirror the corresponding validator rules, so invalid records are
rejected before they enter the bundle):

- `Package.authorize_test_scope(...)` — emits `authorized_test_scope`.
  Enforces the `production_capable_owner_authorized` → ownership-proof-method
  rule and the `kill_switch_ref` requirement.
- `Package.record_scope_boundary_event(...)` — emits `scope_boundary_event`.
  Enforces the `hard_stop_triggered: true` → `hard_stop_attestation_ref`
  pairing.
- `Package.record_finding(...)` — emits `finding_record` and auto-computes
  the normative `dedupe_key` per brief Q5.
- `Package.record_delivery_verdict(...)` — emits `delivery_verdict`.
  Enforces both the read-back digest equality rule (rule 1) and the
  `verified_delivered` triple-requirement (rule 2) before append.
- `Package.attest(...)` — emits `harness_attestation`. Enforces the
  7-value state-class taxonomy, the persona/LLM verifier ban, the
  non-empty `bound_evidence_refs` requirement, and the non-empty
  `fake_green_test_ref` requirement.

**Clock + URN injection** (VAL-SDK-007):

`Package(clock=..., urn_generator=...)` accepts deterministic factories.
When both are supplied, two independent runs of identical builder calls
produce byte-equal `.acef.tar.gz` archives. The defaults
(`datetime.now(UTC)` and `uuid4`) preserve v0.3 behavior when no injection
is given.

**Redaction policy attachment** (VAL-REDACTION-003):

`Package(redaction_policy=RedactionPolicy(version="1.0.0"))` attaches a
versioned policy. `Package.record()` then auto-populates X1
(`redaction_policy_version`) and X2 (`redaction_attestation_ref`) on any
non-public record, generating a Core `event_log` attestation record (NOT
a vendor namespace — see VAL-REDACTION-004).

**Harness attestation signing** (VAL-SIGNATURE-001..004):

`acef.signing.sign_harness_attestation(payload, private_key=..., signer_kid=...)`
produces a JWS detached signature over the 9 normative fields enumerated
in `acef.signing.HARNESS_ATTESTATION_SIGNED_FIELDS`. Fields outside the
9-field scope are explicitly NOT trusted by the verifier. Companion
verifier: `acef.signing.verify_harness_attestation`.

### CLI

The `acef` CLI gains a `verify` subcommand alongside the existing
`validate` subcommand:

```bash
acef verify path/to/bundle.acef/      # structural + integrity + signature
acef validate path/to/bundle.acef/    # all of verify, plus rule evaluation
```

`acef verify` returns exit 0 on every v1.0 golden bundle and on the
`subscriber-mode-full-loop` v1.1 reference bundle. For each of the 11
Freddy fail-vector bundles, `acef verify` exits non-zero and prints the
expected ACEF-NNN code to stdout or stderr (VAL-CLI-001..003).

### Test Vectors

A new top-level directory `test-vectors/freddy/` mirrors the existing
per-regulation layout:

```text
test-vectors/freddy/
├── pass/             # 9 bundles — each validates clean
├── fail/             # 11 bundles — each emits an expected ACEF-NNN
└── fake-green/       # 7 bundles — each fails (one per state class),
                      #              proving the state is unreachable
                      #              without precursor evidence
```

The `subscriber-mode-full-loop.acef/` bundle under `pass/` is the
canonical reference bundle. It contains at least one record of each new
record type, at least one record per new variant discriminator, X1-X6
populated correctly, and a signed `harness_attestation` per state class
shown in the loop. New ACEF consumers should read this bundle first.

The test driver is `pytest tests/conformance/test_freddy_*.py`.

---

## Known Limitations

- **TypeScript SDK lands in v0.4.1.** ACEF v0.4.0 ships Python-only. The
  TypeScript SDK at `packages/sdk-typescript/`, the Python ↔ TypeScript
  byte-equality parity tests, and the cross-language conformance battery
  are tracked under milestone M2 of the operation contract and will land
  in a follow-on minor release. Until v0.4.1, cross-language byte parity
  for the new record types is owned by downstream consumers per brief §6.1.

- **§14.5 authority matrix is inlined in the operation contract.** The
  brief's §14.5 disposition authority matrix (which authority classes
  granted to which actor types) is inlined verbatim in the v0.4 operation
  contract at `~/.ops-runtime/acef-v0.4-freddy-adoption/contract.md` under
  "Brief §14.5 Authority Matrix" and is enforced by VAL-LOAD-001..005
  and VAL-VALIDATION-LOAD-AUTHORITY-MATRIX-001. The spec-side amendment
  to inline the matrix into the published ACEF spec is pending upstream
  Freddy spec reconciliation; until that lands, the operation contract is
  the authoritative source.

- **Relay vendor pin re-pinning is post-tag.** Once the v0.4 release tag is
  cut, the `epochly-relay` project must bump its ACEF vendor pin per the
  workflow documented in `epochly-relay/relay/packages/acef/README.md`.
  This is tracked under VAL-RELAY-001..002 (M3 in the operation contract)
  and is not gating for the v0.4.0 tag.

- **Brief §6.4 / §6.6 wording.** The brief still reads "required" rather
  than "conditional-required" in those sections. ACEF's version-gating
  design (above) is the authoritative interpretation. A brief amendment is
  recommended; see "§6.4 vs §8.1 Resolution".
