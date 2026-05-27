# ACEF Testing — Operation Reference

How workers in `acef-v0.4-freddy-adoption` test their changes. Read this before writing any test.

---

## Surfaces

ACEF has three observable testing surfaces. Workers pick the one that matches the assertion's evidence requirement.

| Surface | What it tests | Tool | Typical use |
|---|---|---|---|
| **Python SDK API** | Library behavior (Package builder, validate, load, export) | `pytest` against `from acef import ...` | Most VAL-SDK-*, VAL-MODEL-*, VAL-REDACTION-* |
| **JSON Schema validator** | Schema conformance of crafted bundle fixtures | `jsonschema.Draft202012Validator` | VAL-SCHEMA-*, VAL-VALIDATION-* schema cases |
| **Standalone CLI** | End-to-end behavior of `acef verify <bundle>` | `subprocess` + exit code + stdout/stderr grep | VAL-CLI-*, VAL-REGRESSION-004, VAL-CONFORMANCE-* |

The TS SDK (M2) adds a fourth surface: `npm test` driving `packages/sdk-typescript/`.

---

## Test tiers

After F-M1-TIER-INFRA lands, pytest markers gate test execution by tier. Per VAL-TIER-003, the plumbing tier has a ≤60s wall-clock budget with sub-tier budgets:

| Tier | Marker | Budget | Contents |
|---|---|---|---|
| **plumbing** | `@pytest.mark.plumbing` | ≤60s (conformance ≤40s + regression ≤20s) | Schema validation, error code emission, golden bundle regression, CLI compat, Freddy pass/fail/fake-green vectors |
| **integration** | `@pytest.mark.integration` | No hard budget | Cross-record validation, end-to-end SDK→validate→Assessment Bundle flows |
| **conformance** | `@pytest.mark.conformance` | Subsumed by plumbing for fast cases; can also run unmarked | Full conformance suite including cross-language parity (M2) |

Tier marks are additive — a test can be both `plumbing` and `conformance`. CI runs the plumbing tier on every commit; integration + full conformance run on PR merge.

---

## Critical testing rules (project CLAUDE.md + ops-plan)

These are non-negotiable. Violating them blocks worker handoff.

1. **Never pipe pytest through `tail` / `head` / `awk`.** Exit code is lost; assertion fails silently. Use `pytest --tb=short` for compact output.
2. **Never use `--no-verify`, `--no-gpg-sign`, or skip pre-commit hooks.** If a hook fails, fix the cause.
3. **Activate venv before pytest.** `source venv/bin/activate` first.
4. **Run tests with `set timeout >= 600000` (10 minutes) for long-running suites** per project CLAUDE.md.
5. **Report the actual exit code in handoff `assertionEvidence[*].exitCode`.** Don't say "passed" if exit was non-zero.
6. **No mocks in `src/acef/`.** Production code is mock-free per project CLAUDE.md. Mocks are permitted only in `tests/` and only when external services would be needed (rare in ACEF — no network deps).

---

## Assertion evidence formats

Each VAL-* assertion in `contract.md` declares a specific evidence shape. Workers MUST produce evidence matching the declared form. Common patterns:

### "exit code 0"
Used for subprocess assertions. Evidence: `{ "exitCode": 0, "stdout": "...", "stderr": "..." }`.

### "pytest exit code 0"
Used for Python test assertions. Evidence: `{ "command": "pytest tests/...", "exitCode": 0, "passed": N, "failed": 0 }`.

### "schema parses; negative fixture fails"
Used for schema assertions. Evidence: positive fixture + jsonschema check passes; named negative fixture + jsonschema check fails with specific error.

### "ACEF-NNN emitted"
Used for error-code assertions. Evidence: `validator.diagnostics` list contains entry with `code == "ACEF-NNN"`. Per VAL-VALIDATION-013, the assertion may also require that OTHER codes are NOT emitted; check the precise wording.

### "two .acef.tar.gz files SHA-256-equal"
Used for determinism + parity assertions. Evidence: two file paths + their SHA-256 hashes + equality assertion.

### "snapshot fixture matches"
Used for v1.0 regression assertions. Evidence: snapshot file path + diff (empty) between fixture and current state.

---

## Fixtures

### Snapshot fixtures (committed in F-M1-SNAPSHOT-FIXTURES)
- `tests/conformance/fixtures/v1.0-schema-hashes.json` — SHA-256 of every file in `acef-conventions/v1/`
- `tests/conformance/fixtures/v1.0-variants.json` — All 13 v1.0 variant tuples
- `tests/conformance/fixtures/v1.0-errors.json` — All 60 v1.0 error code entries
- `tests/conformance/fixtures/gzip-test-vector.bin` — Input bytes for cross-language gzip determinism test (created by F-M1-SNAPSHOT-FIXTURES or F-M2-GZIP-DETERMINISM as needed)
- `tests/conformance/fixtures/deterministic-input-vector.py` — Python module defining a fixed sequence of Package builder calls for VAL-SDK-007

### Golden bundles (FROZEN)
- `tests/conformance/golden-bundles/` — six v1.0 bundles. DO NOT MODIFY.

### Freddy test vectors (NEW in F-M1-CONFORMANCE-VECTORS)
- `test-vectors/freddy/pass/*.acef/` (9 bundles)
- `test-vectors/freddy/fail/*.acef/` (11 bundles, each declares expected ACEF-NNN in README)
- `test-vectors/freddy/fake-green/*.acef/` (7 bundles, one per state class)

---

## TDD workflow (project CLAUDE.md mandate)

Workers MUST follow Red-Green-Refactor:

1. **RED:** write failing test that describes the assertion's expected behavior
2. **GREEN:** write minimal source code to pass the test
3. **REFACTOR:** clean up while keeping tests green

**No code without failing test first** is project policy. Workers writing source code in `src/acef/` without a corresponding failing test risk task termination.

When CI tests fail: assume SOURCE CODE BUG until proven otherwise. Fix source, not tests.

---

## Test isolation rules

- Test files MUST NOT modify ACEF source code (only their own fixtures and the file system within `tests/`).
- Test fixtures (under `tests/fixtures/` or `tests/conformance/fixtures/`) MUST be deterministic — no current-time, no random IDs at construction.
- Cross-cutting field cluster tests (X2 redaction, X3 tenant, X5 mode) MUST run as integration tests against the real validator+model stack, NOT mocks (per pass-1 milestone-boundaries.md §5).

---

## Eval suite gating

ACEF has no LLM evals (no `EVAL=1` gating). All testing is deterministic Python/TS unit + integration + conformance. If a future workstream needs LLM evals, add this section.

---

## When tests are too slow

If a worker introduces a test that blows the ≤60s plumbing budget:

1. Don't suppress it. Don't move it to integration tier unless it genuinely is integration.
2. Profile with `pytest --durations=20` to find the slow specifics.
3. Reshard or factor as needed. The 60-second budget is per VAL-TIER-003.
4. If after profiling the test is genuinely required and cannot be shrunk, escalate via handoff and propose a budget adjustment.

---

## Worker test command quick reference

```bash
# Setup once per session
source venv/bin/activate

# Most common
pytest tests/                           # everything
pytest tests/unit -v                    # unit only
pytest tests/conformance -v             # conformance only
pytest -m plumbing --timeout=60         # plumbing tier (post-F-M1-TIER-INFRA)
pytest tests/conformance/test_golden_bundles.py -v
pytest tests/conformance/test_freddy_pass_vectors.py -v
pytest tests/conformance/test_freddy_fail_vectors.py -v
pytest tests/conformance/test_freddy_fake_green_vectors.py -v
pytest tests/conformance/test_cli_compat.py -v

# Lint + types
ruff check src/ tests/
ruff format src/ tests/
mypy --strict src/acef
```
