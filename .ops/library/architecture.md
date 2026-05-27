# ACEF Architecture — Operation Reference

Quick architectural orientation for workers in `acef-v0.4-freddy-adoption`. For the normative specification, read `planning/ACEF-Spec-Outline-v0.1.md` v0.3 in full. This document is a fast index.

---

## Three-module model (spec §1.0.1)

ACEF v1 is three independently versioned modules. The v0.4 work introduces v1.1 minors across all three.

```
┌─────────────────────────────────────────────────────────────┐
│  ACEF Core                                                   │
│  Envelope schema · entity model · bundle layout ·            │
│  integrity (RFC 8785 + Merkle + JWS) · error taxonomy        │
│                                                              │
│  v0.4 changes:                                               │
│    - X1-X4 envelope fields (conditional-required)            │
│    - X5-X6 manifest fields (conditional)                     │
│    - 8 new error codes (ACEF-070..077 from brief)            │
│    - 3 new error codes (ACEF-078..080 from codex review)     │
│    - JWS signed_fields scope normative                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            │  consumed by
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  ACEF Profiles                                               │
│  Record-type schemas · regulation mapping templates ·         │
│  rule DSL · variant registry                                 │
│                                                              │
│  v0.4 changes:                                               │
│    - 6 new Core record types (authorized_test_scope,         │
│      scope_boundary_event, finding_record, delivery_verdict, │
│      coverage_cell, harness_attestation)                     │
│    - 5 new payload variants (kill_switch, regression_def,    │
│      disposition_record, badge_state, freshness_window)      │
│    - state-class-taxonomy.json (7 hard-coded entries)        │
│    - Per-regulation template extensions (Freddy team)        │
└─────────────────────────────────────────────────────────────┘
                            │
                            │  evaluated by
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  ACEF Assessment                                             │
│  Validation result schema · provision rollup · signed         │
│  conclusions                                                 │
│                                                              │
│  v0.4 changes:                                               │
│    - coverage_cell field group in assessment-bundle schema   │
│    - Optional dedupe_key / variant_group_id /                │
│      reproduction_evidence_ref fields in results[]           │
└─────────────────────────────────────────────────────────────┘
```

---

## Two artifact types (spec §1.0.2)

1. **Evidence Bundle** — raw evidence records + entity graph + integrity. Directory `.acef/` or archive `.acef.tar.gz`. NO pass/fail judgments.
2. **Assessment Bundle** — rule-evaluation results, per-provision outcomes, signed conclusions. Single JSON file `.acef-assessment.json`. References Evidence Bundle by content hash.

Workers writing v0.4 record types must place them in the Evidence Bundle. `coverage_cell` is the lone exception — assessment-time, lives in Assessment Bundle.

---

## Repo layout (key directories)

```
ACEF/
├── acef-conventions/        # JSON schemas, normative
│   ├── v1/                  # FROZEN — do not modify (VAL-SCHEMA-010)
│   └── v1.1/                # NEW in v0.4 — workers add files here
├── src/acef/                # Python SDK
│   ├── models/              # Pydantic models (extend in F-M1-PYDANTIC-MODELS)
│   ├── validation/          # Validator engine + DSL (extend in F-M1-VALIDATOR-*)
│   ├── schemas/registry.py  # Schema lookup (auto-discovers v1.1/ when added)
│   ├── errors.py            # ERROR_REGISTRY dict (extend in F-M1-ERROR-REGISTRY)
│   ├── integrity.py         # RFC 8785 + SHA-256 + Merkle tree (unchanged)
│   ├── signing.py           # JWS RS256/ES256 (extend for harness_attestation scope)
│   ├── package.py           # Package builder (extend in F-M1-SDK-BUILDERS)
│   ├── loader.py            # Bundle loader (extend in F-M1-LOADER-REJECTION)
│   └── redaction.py         # Redaction model (extend with versioning + attestation)
├── tests/
│   ├── conformance/         # Golden bundles + drivers
│   │   ├── golden-bundles/  # FROZEN — six v1.0 bundles
│   │   └── fixtures/        # NEW — snapshot fixtures (F-M1-SNAPSHOT-FIXTURES)
│   ├── integration/
│   └── unit/
├── test-vectors/            # Per-regulation positive/negative bundles
│   ├── eu-ai-act/
│   ├── nist-rmf/
│   └── freddy/              # NEW — 27 bundles (F-M1-CONFORMANCE-VECTORS)
├── docs/                    # User-facing docs (workers add MIGRATION/CONFORMANCE/USER_GUIDE)
├── packages/sdk-typescript/ # NEW in M2 — TS SDK (F-M2-TS-SDK)
├── planning/                # Spec docs + RFCs (F-M1-SPEC-RFC adds RFC)
└── .ops/                    # This directory — operation infrastructure
```

---

## Key invariants

### v1.0 byte-equality (VAL-SCHEMA-010, VAL-REGRESSION-001)
Every file in `acef-conventions/v1/` MUST be byte-identical post-v0.4. Snapshot fixture at `tests/conformance/fixtures/v1.0-schema-hashes.json` (created by F-M1-SNAPSHOT-FIXTURES) is the source of truth.

### Version gating (top-of-plan, VAL-VALIDATION-001)
Bundles declare `manifest.versioning.core_version`. Validator selects schemas from `acef-conventions/v1/` (1.0.x) or `acef-conventions/v1.1/` (1.1.x). Per brief §8.1, new envelope/manifest fields are conditional-required, NOT absolute-required.

### Determinism (VAL-SDK-007, VAL-SDK-DETERMINISM-*, VAL-PARITY-002/003)
Two SDK runs with same logical input must produce byte-equal `.acef.tar.gz`. Same for Python ↔ TS cross-language. Requires:
- Deterministic clock + URN injection in `Package(clock=, urn_generator=)`
- Deterministic record sort: timestamp ascending, record_id lexicographic sub-sort
- Deterministic gzip: level 6, mtime=0, OS=0xFF
- RFC 8785 (JCS) JSON canonicalization

### Open boundary (spec §6.4 rule 4)
Vendor extensions use `x-vendor/*` prefix. `x-freddy/*` lives in the Freddy repo (`/Users/chandlervaughn/Development/freddy/src/freddy/acef_extensions/`). ACEF maintainers do NOT implement F1-F4 — see `m3-coordination.md`.

### Namespace lint hook (VAL-VALIDATION-LINT-REGISTRY-001, VAL-VALIDATION-LINT-INVOCATION-001)
F-M1-NAMESPACE-LINT-HOOK adds the Core-side hook `src/acef/validation/namespace_lints.py`. Registered namespaces (e.g., `x-freddy/voice-rubric-emission`) can declare lint patterns whose violations emit Core error codes (ACEF-077). Unregistered namespaces: no Core errors fire (graceful degradation per VAL-VALIDATION-013).

---

## Critical implementation contracts

| Contract | Spec § | Enforcement |
|---|---|---|
| RFC 8785 (JCS) canonicalization on all JSON in hash domain | §3.1.3 | `src/acef/integrity.py` |
| SHA-256 content hashing | §3.1.3 | `src/acef/integrity.py` |
| Merkle tree leaf: `SHA-256(path || 0x00 || hex_hash)` | §3.1.3 | `src/acef/integrity.py` |
| JWS RS256/ES256 only (other algs → ACEF-013) | §3.1.3 | `src/acef/signing.py` |
| JSONL records sorted by timestamp asc, record_id sub-sort | §3.1.1 | `src/acef/package.py` |
| Sharding at 100K records OR 256MB, whichever earlier | §3.1.1 | `src/acef/package.py` |
| Archive: gzip level 6, mtime=0, OS=0xFF, paths sorted lex | §3.1.3 | `src/acef/export.py` |
| Path normalization: forward slashes, UTF-8 NFC, no `.` or `..` | §3.1.1 | `src/acef/loader.py` |
| Vendor extensions don't affect Core conformance outcomes | §3.7 | namespace_lints.py registry pattern |

Workers MUST honor these even when not directly asserted in their owned features — they are global preconditions.

---

## Where the brief lives in this architecture

The Freddy brief (`planning/freddy-on-acef-requirements-v0.1.md`, commit `020e9e0`) maps onto the three modules:

- **Core additions:** envelope fields X1-X4, manifest fields X5-X6, error codes ACEF-070..080, JWS signature scope
- **Profiles additions:** 6 record types, 5 variants, state-class taxonomy
- **Assessment additions:** coverage_cell field group, optional dedupe fields in results[]

Plus four `x-freddy/*` namespaces in Freddy's own repo (F1-F4 in brief §5).
