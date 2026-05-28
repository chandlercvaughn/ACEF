# ACEF Conformance Testing Guide

This guide describes what "ACEF-compatible" means, how to run the conformance test suite, and how to verify that your tool produces valid ACEF bundles.

---

## Table of Contents

1. [What "ACEF-Compatible" Means](#1-what-acef-compatible-means)
2. [Running the Conformance Test Suite](#2-running-the-conformance-test-suite)
3. [Golden Bundles](#3-golden-bundles)
4. [Test Vectors](#4-test-vectors)
5. [Round-Trip Determinism](#5-round-trip-determinism)
6. [Archive Canonicalization](#6-archive-canonicalization)
7. [Verifying Your Tool](#7-verifying-your-tool)

---

## 1. What "ACEF-Compatible" Means

An implementation claiming ACEF compatibility must satisfy these requirements:

### Producer Requirements (tools that create ACEF bundles)

1. **Valid manifest.** `acef-manifest.json` conforms to `acef-conventions/v1/manifest.schema.json`.
2. **Valid records.** All record envelopes conform to `record-envelope.schema.json`. All payloads conform to their record-type-specific schemas.
3. **Correct integrity.** `content-hashes.json` contains correct SHA-256 hashes for all files in the hash domain (manifest, records, artifacts). `merkle-tree.json` contains a valid Merkle tree built from `content-hashes.json`.
4. **Correct canonicalization.** All JSON in the hash domain uses RFC 8785 (JCS). All JSONL files have independently canonicalized lines.
5. **Deterministic output.** Two exports of the same logical record set produce byte-identical JSONL files (records sorted by timestamp, then record_id).
6. **Correct sharding.** Shards split at the earlier of 100,000 records or 256 MB.
7. **Path normalization.** All paths use forward slashes, are relative, use UTF-8 NFC, and contain no `.` or `..` segments.
8. **Valid URNs.** All identifiers use the `urn:acef:{type}:{uuid}` format.

### Consumer Requirements (tools that read ACEF bundles)

1. **Accept both formats.** Must load directory bundles and `.acef.tar.gz` archives.
2. **Validate integrity.** Must verify content hashes, Merkle root, and signatures (if present).
3. **Reject unsafe paths.** Must reject bundles with path traversal, symlinks, or absolute paths.
4. **Handle unknown record types.** Unknown record types (including `x-` prefixed) must not cause failures. They should be preserved during round-trip.

### Validator Requirements (tools that evaluate ACEF bundles)

1. **4-phase pipeline.** Must run schema, integrity, reference, and evaluation phases.
2. **Report all errors per phase.** Per spec Section 3.6, validators must report ALL errors within each phase.
3. **Correct operator semantics.** All 10 DSL operators must follow the spec's empty-set semantics (existential vs. universal).
4. **Correct rollup.** The 7-step provision rollup algorithm must produce the same outcomes as the reference implementation.
5. **Use evaluation_instant.** All date-sensitive logic must use `evaluation_instant`, not wall-clock time.

---

## 2. Running the Conformance Test Suite

### Prerequisites

```bash
git clone https://github.com/ai-commons/acef.git
cd acef
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Run All Conformance Tests

```bash
pytest tests/conformance/ -v
```

### Run Specific Test Categories

```bash
# Golden bundle tests (6 bundles with expected assessments)
pytest tests/conformance/test_golden_bundles.py -v

# Round-trip determinism tests
pytest tests/conformance/test_roundtrip.py -v

# DSL operator tests
pytest tests/conformance/test_dsl_operators.py -v

# Provision rollup tests
pytest tests/conformance/test_provision_rollup.py -v

# Schema conformance tests
pytest tests/conformance/test_schema_conformance.py -v

# Integrity verification tests
pytest tests/conformance/test_integrity.py -v

# Error taxonomy tests
pytest tests/conformance/test_error_taxonomy.py -v

# Extension handling tests
pytest tests/conformance/test_extension_handling.py -v

# Redaction tests
pytest tests/conformance/test_redaction.py -v

# Review findings tests
pytest tests/conformance/test_review_findings.py -v
```

### Expected Output

All tests should pass:

```
tests/conformance/test_golden_bundles.py::TestGoldenBundles::test_eu_high_risk_core PASSED
tests/conformance/test_golden_bundles.py::TestGoldenBundles::test_gpai_provider PASSED
tests/conformance/test_golden_bundles.py::TestGoldenBundles::test_china_cac_labeling PASSED
...
```

---

## 3. Golden Bundles

Golden bundles are pre-built ACEF bundles with known-correct Assessment Bundles. They serve as the ground truth for conformance testing.

### Available Golden Bundles

Located in `tests/conformance/golden-bundles/`:

| Bundle | Description | Profile |
|---|---|---|
| `eu-high-risk-core` | EU AI Act high-risk system with risk management, data governance, evaluation, transparency, and event logging evidence | `eu-ai-act-2024` |
| `gpai-provider-annex-xi-xii` | GPAI model provider evidence per Annex XI/XII including model documentation, training data summary, and energy consumption | `eu-gpai-code-of-practice-2025` |
| `china-cac-labeling` | Chinese CAC labeling compliance with explicit labels, implicit metadata, and log retention | `china-cac-labeling-2025` |
| `multi-subject-composed` | Composed system with multiple subjects (AI system + AI model) demonstrating per-subject evaluation | `eu-ai-act-2024` |
| `synthetic-content-marking` | EU Labelling Code of Practice compliance with C2PA metadata, watermarking, and detection APIs | `eu-labelling-code-of-practice-2026` |
| `us-federal-governance` | US OMB M-24-10 federal AI governance with use-case inventory, CAIO designation, and rights/safety classification | `us-omb-m-24-10` |

### Golden Bundle Structure

Each golden bundle consists of:

1. **Bundle directory** -- a valid ACEF Evidence Bundle (e.g., `eu-high-risk-core/`)
2. **Expected assessment** -- the Assessment Bundle JSON that the reference validator should produce (e.g., `eu-high-risk-core.acef-assessment.json`)

### How Golden Bundle Tests Work

The test loads each golden bundle, validates it against the expected profile, and compares the resulting Assessment Bundle against the expected output. Key comparisons:

- Provision outcomes (satisfied/not-satisfied/partially-satisfied/etc.)
- Rule outcomes (passed/failed/skipped/error)
- Structural error codes
- Profile evaluation completeness

The test does not compare timestamps, assessment IDs, or evidence_refs (which contain generated URNs that differ between runs).

---

## 4. Test Vectors

Test vectors are per-template test bundles that verify specific provisions pass or fail as expected.

### Available Test Vectors

Located in `test-vectors/`:

#### EU AI Act (`test-vectors/eu-ai-act/`)

| Vector | Expected Outcome | Tests |
|---|---|---|
| `article-9-minimal-pass.acef` | Pass | Basic Article 9 risk management with risk_register and risk_treatment |
| `article-9-minimal-fail.acef` | Fail | Missing risk_treatment records |
| `article-9-variant-management-review-pass.acef` | Pass | Article 9 with management_review payload variant |
| `article-12-logging-spec-pass.acef` | Pass | Article 12 with logging_spec event_log variant |
| `article-12-retention-fail.acef` | Fail | Article 12 with insufficient retention period |
| `article-50-marking-pass.acef` | Pass | Article 50 transparency marking with C2PA |
| `article-50-marking-no-scheme-id-fail.acef` | Fail | Article 50 marking without scheme_id |
| `article-53-annex-xi-pass.acef` | Pass | GPAI Annex XI model documentation |
| `article-53-annex-xi-missing-energy-fail.acef` | Fail | Annex XI missing energy consumption data |
| `multi-subject-per-subject-eval.acef` | Mixed | Per-subject evaluation with different outcomes per subject |

#### NIST AI RMF (`test-vectors/nist-rmf/`)

| Vector | Expected Outcome | Tests |
|---|---|---|
| `govern-map-measure-manage-pass.acef` | Pass | Complete GOVERN/MAP/MEASURE/MANAGE evidence |
| `govern-missing-policy-fail.acef` | Fail | Missing governance_policy records |

#### China CAC (`test-vectors/china-cac/`)

| Vector | Expected Outcome | Tests |
|---|---|---|
| `cac-explicit-implicit-pass.acef` | Pass | Both explicit and implicit labeling present |
| `cac-missing-implicit-metadata-fail.acef` | Fail | Missing implicit metadata marking |
| `cac-label-exception-retention-pass.acef` | Pass | Label exception with 6-month retention |

#### EU GPAI Code of Practice (`test-vectors/eu-gpai-cop/`)

| Vector | Expected Outcome | Tests |
|---|---|---|
| `transparency-copyright-pass.acef` | Pass | Full transparency and copyright evidence |
| `missing-training-summary-fail.acef` | Fail | Missing training data summary |

#### OMB M-24-10 (`test-vectors/omb-m24-10/`)

| Vector | Expected Outcome | Tests |
|---|---|---|
| `inventory-governance-pass.acef` | Pass | Complete AI use-case inventory with CAIO designation |
| `missing-caio-fail.acef` | Fail | Missing CAIO designation in governance policy |

### Test Vector Naming Convention

```
{provision-or-feature}-{pass|fail}.acef
```

Each test vector directory is paired with an `.acef-assessment.json` file containing the expected assessment output.

---

## 5. Round-Trip Determinism

ACEF bundles must be deterministic: exporting the same logical content must produce byte-identical output.

### What Must Be Deterministic

1. **JSONL files.** Records sorted by `timestamp` ascending, then `record_id` ascending. Each line RFC 8785-canonicalized.
2. **Manifest.** RFC 8785-canonicalized JSON.
3. **Content hashes.** Entries sorted lexicographically by path.
4. **Merkle tree.** Deterministic from sorted content hashes.

### Round-Trip Test

The conformance suite tests round-trip determinism:

1. Create a package and export it.
2. Load the exported bundle.
3. Re-export to a new location.
4. Compare `content-hashes.json` from both exports.

The content hashes must be identical, proving that the bundle content is byte-identical.

### Testing Your Implementation

```python
import acef
import json

# Create and export
pkg = acef.Package(producer={"name": "test", "version": "1.0"})
pkg.add_subject("ai_system", name="Test")
pkg.record("risk_register", payload={"description": "test"})
pkg.export("export1.acef/")

# Load and re-export
pkg2 = acef.load("export1.acef/")
pkg2.export("export2.acef/")

# Compare
h1 = json.loads(open("export1.acef/hashes/content-hashes.json").read())
h2 = json.loads(open("export2.acef/hashes/content-hashes.json").read())
assert h1 == h2, "Round-trip determinism failed"
```

---

## 6. Archive Canonicalization

`.acef.tar.gz` archives must be byte-identical when created from the same bundle content. The spec mandates these settings:

| Property | Required Value |
|---|---|
| File order | Lexicographic by path |
| File timestamps | `metadata.timestamp` (Unix epoch, UTC) |
| Owner/Group | 0/0 |
| Username/Groupname | Empty string |
| File permissions | 0644 |
| Directory permissions | 0755 |
| Gzip compression level | 6 |
| Gzip mtime | 0 |
| Gzip OS byte | 0xFF (unknown) |
| Symlinks | Forbidden |
| Hardlinks | Forbidden |
| Extended attributes | Forbidden |

### Archive Verification

```python
import gzip
from pathlib import Path

archive = Path("my-bundle.acef.tar.gz")

# Verify gzip OS byte is 0xFF
with open(archive, "rb") as f:
    header = f.read(10)
    assert header[9] == 0xFF, f"OS byte is {header[9]:#x}, expected 0xFF"

# Verify gzip mtime is 0
assert header[4:8] == b"\x00\x00\x00\x00", "Gzip mtime must be 0"
```

### Note on Byte-Identical Archives

Byte-identical archives across different runtime environments (Python versions, operating systems) depend on the gzip implementation producing identical output. If your implementation cannot produce identical gzip output, you may:

1. Distribute unpacked directories for conformance verification.
2. Use any gzip settings for transport (the archive is not part of the hash domain).

The conformance test suite verifies archive determinism within the same Python runtime.

---

## 7. Verifying Your Tool

### Step 1: Schema Conformance

Export a bundle from your tool and validate it against the JSON Schemas:

```bash
# Using the ACEF CLI
acef validate my-bundle.acef/

# Or programmatically
python -c "
import acef
assessment = acef.validate('my-bundle.acef/')
for error in assessment.structural_errors:
    print(f\"[{error['code']}] {error['message']}\")
print(f'Structural errors: {len(assessment.structural_errors)}')
"
```

### Step 2: Integrity Verification

Check that content hashes and Merkle tree are correct:

```bash
acef doctor my-bundle.acef/
```

### Step 3: Round-Trip Test

Load a bundle from your tool using the reference SDK and re-export:

```python
import acef
import json

pkg = acef.load("my-tool-output.acef/")
pkg.export("reference-re-export.acef/")

h_original = json.loads(open("my-tool-output.acef/hashes/content-hashes.json").read())
h_reexport = json.loads(open("reference-re-export.acef/hashes/content-hashes.json").read())

if h_original == h_reexport:
    print("PASS: Round-trip determinism verified")
else:
    print("FAIL: Content hashes differ after round-trip")
    for path in set(h_original) | set(h_reexport):
        if h_original.get(path) != h_reexport.get(path):
            print(f"  Mismatch: {path}")
```

### Step 4: Profile Validation

Validate against all profiles your tool supports:

```python
import acef

pkg = acef.load("my-tool-output.acef/")
for profile_id in ["eu-ai-act-2024", "nist-ai-rmf-1.0"]:
    assessment = acef.validate(pkg, profiles=[profile_id])
    print(f"\n{profile_id}:")
    print(f"  {assessment.summary()}")
    for ps in assessment.provision_summary:
        print(f"  {ps.provision_id}: {ps.provision_outcome.value}")
```

### Step 5: Golden Bundle Comparison

Load each golden bundle with your tool and verify it produces valid output:

```python
import acef
from pathlib import Path

golden_dir = Path("tests/conformance/golden-bundles")
for bundle_dir in sorted(golden_dir.iterdir()):
    if bundle_dir.is_dir():
        try:
            pkg = acef.load(str(bundle_dir))
            print(f"PASS: {bundle_dir.name} (subjects={len(pkg.subjects)}, records={len(pkg.records)})")
        except Exception as e:
            print(f"FAIL: {bundle_dir.name}: {e}")
```

### Conformance Checklist

Use this checklist to verify your implementation:

- [ ] `acef-manifest.json` passes manifest JSON Schema validation
- [ ] All record envelopes pass `record-envelope.schema.json` validation
- [ ] All record payloads pass their type-specific schema validation
- [ ] `content-hashes.json` contains correct SHA-256 hashes for all files in hash domain
- [ ] `merkle-tree.json` Merkle root matches recomputed value
- [ ] All JSON in hash domain is RFC 8785 canonicalized
- [ ] All JSONL lines are independently RFC 8785 canonicalized
- [ ] Records within JSONL files are sorted by timestamp, then record_id
- [ ] All paths use forward slashes, are relative, UTF-8 NFC
- [ ] No `.` or `..` path segments
- [ ] All identifiers use `urn:acef:{type}:{uuid}` format
- [ ] Round-trip export produces identical content hashes
- [ ] All 6 golden bundles load successfully
- [ ] All 19 test vectors produce expected assessment outcomes
- [ ] Unknown record types (x- prefix) are preserved during round-trip
- [ ] Symlinks and path traversal in archives are rejected

---

## Freddy Profile Conformance

This section documents the conformance requirements introduced in ACEF v0.4
for agent-reliability and continuous-verification consumers. It complements
the v1.0 conformance machinery above. The normative source is the brief at
[`planning/freddy-on-acef-requirements-v0.1.md`](../planning/freddy-on-acef-requirements-v0.1.md);
the version-gating design is described in
[`MIGRATION-v0.3-to-v0.4.md`](MIGRATION-v0.3-to-v0.4.md#version-gating-semantics).

A bundle is in scope of "Freddy Profile Conformance" when its
`manifest.versioning.core_version` is `1.1.0` or later AND its
`manifest.analysis_mode` is set. Bundles declaring only `core_version: 1.0.x`
remain in scope of the v1.0 conformance rules above.

### Analysis Modes

`manifest.analysis_mode` is a v1.1 manifest field with four enumerated
values. Each mode defines what record types and envelope fields are
required, forbidden, and conditionally permitted. The validator's mode-gate
fires `ACEF-080` when a bundle declares a mode but lacks the mode's
required envelope fields, or contains a forbidden record type for that
mode.

| Mode | Required records | Forbidden records | Notes |
|---|---|---|---|
| `subscriber` | At least one `authorized_test_scope` AND at least one `harness_attestation`. | (none) | Full guarantees. All record types valid. `tenant_label` uniformity enforced bundle-wide (ACEF-075). X1/X2 conditional-required on non-public records (ACEF-074, ACEF-078). |
| `public_artifact` | (none) | `delivery_verdict`, `disposition_record`, `accepted_risk_ref`. | Customer-facing publicly accessible artifact. Attribution confidence on persona observations must be `low` or `medium`. |
| `canary` | (none) | Customer-facing records. `badge_state.page_state` MUST be `unsupported`. | Internal pre-production testing only. Not for customer or auditor consumption. |
| `unattributed_artifact` | (none) | Same as `public_artifact`, plus no `attribution` blocks on any record. | Prospect-side teaser surface. Stricter than `public_artifact`; no actor attribution. |

The mode-gate rule table is exhaustive: any record type not listed as
"forbidden" for a given mode is permitted (subject to the mode's required
envelope fields). The validator implementation lives in
`src/acef/validation/mode_gate.py`; the rule registry follows the WS3.9 table
of the operation plan.

### State-Class Taxonomy

The seven state classes from brief §24.5 are published as a frozen JSON
document at `acef-conventions/v1.1/state-class-taxonomy.json`. Every
`harness_attestation.state_class` value MUST be one of these seven; values
outside the enum emit `ACEF-076`. Promotion to an open registry is deferred
to ACEF v1.2+ per design decision D3.

Each entry declares whether a fake-green test is required for that class
(currently `true` for all seven) and which `record_type` values are
acceptable in `bound_evidence_refs` for transitions to that state.

| state_class_id | Description | fake_green_test_required | required_bound_evidence_types |
|---|---|---|---|
| `step` | A single harness step (probe, scan, evaluation) transitioning between in-progress states. | true | `event_log`, `scope_boundary_event` |
| `finding` | A `finding_record` reaching a reproduced or verified state. | true | `finding_record`, `event_log` |
| `coverage_cell` | A `coverage_cell` reaching `fresh` state with bound evidence. | true | `coverage_cell`, `finding_record`, `event_log` |
| `regression` | A `regression_definition` reaching `active` state with a fix-verification reference. | true | `risk_treatment` (`regression_definition` variant), `finding_record` |
| `delivery` | A `delivery_verdict` reaching `verified_delivered` with a passing read-back. | true | `delivery_verdict`, `harness_attestation` (read-back verifier) |
| `badge` | A `badge_state` reaching `green` or `provisional` state with fresh coverage. | true | `transparency_disclosure` (`badge_state` variant), `coverage_cell` |
| `attestation` | A higher-order `harness_attestation` (attestation-of-attestation). | true | `harness_attestation` |

The 7-entry table is hard-coded; v1.1 does NOT allow community extension.
A validator encountering a `state_class` value not in this table emits
`ACEF-076` and refuses the record.

### Test Vector Battery

ACEF v0.4 ships 27 test bundles under `test-vectors/freddy/`, mirroring the
existing per-regulation layout. The test driver is
`pytest tests/conformance/test_freddy_*.py`.

#### Pass vectors (9 bundles)

Location: `test-vectors/freddy/pass/`.

Every pass bundle validates clean (zero errors emitted). The driver is
`tests/conformance/test_freddy_pass_vectors.py`.

| Bundle | Purpose |
|---|---|
| `subscriber-mode-full-loop.acef/` | Canonical reference bundle. Contains at least one record of each of the 6 new types and each of the 5 new variants. Required by VAL-CONFORMANCE-004 and design decision D7. |
| `public-artifact-mode.acef/` | Demonstrates the `public_artifact` mode without forbidden record types. |
| `canary-mode.acef/` | Demonstrates `canary` mode with `badge_state.page_state: unsupported`. |
| `verified-delivery.acef/` | A `delivery_verdict` reaching `verified_delivered` with passing read-back digest equality. |
| `regression-active-with-fix-verification.acef/` | A `regression_definition` promoted to `active` with a paired `promotion_attestation_ref`. |
| `badge-green-with-fresh-coverage.acef/` | A `badge_state` at `green` with `integrity_state: verified` and a `fresh` coverage cell. |
| `badge-provisional-with-reason.acef/` | A `badge_state` at `provisional` with a populated `provisional_reason`. |
| `accepted-risk-disposition.acef/` | A `disposition_record` with `internal_state_unchanged: true` and `authority_class: accepted_risk_request`. |
| `multi-finding-with-dedupe-collapse.acef/` | Two `finding_record` entries with identical reproduction recipes collapsing to the same `dedupe_key`. |

#### Fail vectors (11 bundles)

Location: `test-vectors/freddy/fail/`.

Every fail bundle emits exactly the ACEF-NNN code declared in its
`README.md` and no other. The driver is
`tests/conformance/test_freddy_fail_vectors.py`.

| Bundle | Expected code |
|---|---|
| `verified-delivery-without-readback/` | ACEF-071 |
| `verified-delivery-digest-mismatch/` | ACEF-072 |
| `harness-attestation-empty-evidence/` | ACEF-070 |
| `harness-attestation-persona-as-verifier/` | LoadRejection ACEF-070 (record rejected at load, not just validation) |
| `badge-green-with-failed-integrity/` | mode-gate / page-state coherence rejection |
| `cross-tenant-references-in-one-bundle/` | ACEF-075 |
| `voice-rubric-with-claim-token/` | ACEF-077 (via the namespace lint for `x-freddy/voice-rubric-emission`) |
| `scope-boundary-event-without-stop-attest/` | schema `allOf` rejection (`hard_stop_triggered: true` without `hard_stop_attestation_ref`) |
| `external-disposition-overrides-internal/` | LoadRejection (`disposition_record.internal_state_unchanged: false`) |
| `public-artifact-with-delivery-verdict/` | ACEF-080 (mode-gate forbidden record) |
| `non-public-record-without-redaction-pol/` | ACEF-074 |

#### Fake-green vectors (7 bundles)

Location: `test-vectors/freddy/fake-green/`.

Every fake-green bundle FAILS validation. The point of the fake-green
battery is to prove no state class can be reached without its precursor
evidence; a passing fake-green bundle would invalidate the Prove-It
Doctrine. The driver is
`tests/conformance/test_freddy_fake_green_vectors.py`, which asserts the
bundle fails (the test passes when validation fails).

| Bundle | State class probed |
|---|---|
| `cannot-reach-step-without-evidence/` | `step` |
| `cannot-reach-finding-without-evidence/` | `finding` |
| `cannot-reach-coverage-cell-without-evidence/` | `coverage_cell` |
| `cannot-reach-active-regression-without-fix-verification/` | `regression` |
| `cannot-reach-verified-delivery-without-readback/` | `delivery` |
| `cannot-reach-green-badge-without-fresh-coverage/` | `badge` |
| `cannot-reach-attestation-without-precursor-attestation/` | `attestation` |

Bundles under `fake-green/` are JSON-Schema valid (per
VAL-CONFORMANCE-FAKE-GREEN-REF-002) — they fail at a higher level
(integrity, reference, or rule layer), not at the schema layer. This
ensures the Prove-It Doctrine is enforced by ACEF semantics, not by
schema bugs.

#### Running the battery

```bash
source venv/bin/activate
pytest tests/conformance/test_freddy_pass_vectors.py \
       tests/conformance/test_freddy_fail_vectors.py \
       tests/conformance/test_freddy_fake_green_vectors.py \
       -v
```

The combined wall-clock budget for the Freddy battery is ≤40 seconds at
the conformance sub-tier (VAL-CONFORMANCE-005), with the v1.0 regression
sub-tier ≤20 seconds (VAL-REGRESSION-LEGACY-BUDGET-001), staying within
the plumbing-tier ≤60 second budget (VAL-TIER-003).

### Cross-Bundle Determinism

ACEF v1.1 producers can guarantee byte-equal `.acef.tar.gz` output across
independent runs by injecting deterministic clock and URN factories into
the `Package` constructor:

```python
from datetime import datetime, UTC
from itertools import count
from acef.package import Package
from acef.models.urns import URNType

# Frozen clock — every timestamp minted by this package is identical.
_FROZEN = datetime(2026, 5, 27, 0, 0, 0, tzinfo=UTC)

def fixed_clock():
    return _FROZEN

# Sequential URN generator — every URN of a given type increments
# deterministically. The counters are stable across runs because the
# factory is constructed from a closure with no entropy source.
def make_urn_generator():
    counters = {URNType.PACKAGE: count(1), URNType.RECORD: count(1),
                URNType.SUBJECT: count(1), URNType.COMPONENT: count(1),
                URNType.DATASET: count(1), URNType.ACTOR: count(1),
                URNType.SCOPE: count(1), URNType.CELL: count(1)}
    prefix = {URNType.PACKAGE: "pkg", URNType.RECORD: "rec",
              URNType.SUBJECT: "sub", URNType.COMPONENT: "cmp",
              URNType.DATASET: "ds",  URNType.ACTOR: "actor",
              URNType.SCOPE: "scope", URNType.CELL: "cell"}
    def gen(urn_type: URNType) -> str:
        n = next(counters[urn_type])
        return f"urn:acef:{prefix[urn_type]}:{n:08d}-0000-0000-0000-000000000000"
    return gen

pkg = Package(
    producer={"name": "deterministic-producer", "version": "1.0.0"},
    clock=fixed_clock,
    urn_generator=make_urn_generator(),
)
```

The contract VAL-SDK-007 verifies that two independent runs of identical
builder calls (same inputs, same factory state) produce SHA-256-equal
`.acef.tar.gz` archives. The archive's gzip stream is held to
`level=6, mtime=0, OS=0xFF` (deterministic gzip), and the tar stream uses
`owner 0/0, permissions 0644/0755, mtime=0` (deterministic tar). Together
with JCS canonicalization on every JSON in the hash domain and the
deterministic record sort order (`timestamp` ascending,
`record_id` lexicographic sub-sort), the entire bundle is byte-equal
across runs.

Cross-language Python ↔ TypeScript byte-equality (VAL-PARITY-001..003)
lands in ACEF v0.4.1 alongside the TypeScript SDK; v0.4.0 ships the
Python-side determinism only.
