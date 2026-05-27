# Active Operation Rules — acef-v0.4-freddy-adoption

These rules apply to ALL workers in this operation regardless of agent type.
They override conflicting global rules. Updated when the active operation
changes.

---

## You are in an active ops-system operation

**Operation:** `acef-v0.4-freddy-adoption`
**Ops directory:** `/Users/chandlervaughn/.ops-runtime/acef-v0.4-freddy-adoption/`
**Working directory:** `/Users/chandlervaughn/Development/ACEF/`
**Base commit:** `020e9e06b03c41e964a2d60f3f326ffd7d9625f5`

If you are reading this and you are NOT a worker dispatched by the
orchestrator: do nothing. The orchestrator owns operation state. Do not
modify ops-dir files outside of normal worker flow.

---

## Required reading on session start

In this order, before any work:

1. Your handoff request file (path in your dispatch prompt). Contains
   `featureId`, `milestone`, `primaryFulfills`, `workerStartCommit`.
2. The operation's `contract.md` — find your `primaryFulfills` assertions.
   These are your definition of done.
3. The operation's `boundaries.md` — every path you may touch is in the
   ownership table. Do not modify paths outside your feature's row.
4. The operation's `features.json` — verify your feature's `dependsOn` are
   all `status: completed`. If any are not, return to orchestrator.
5. `.ops/manifest.yaml` — exact commands. Never improvise.
6. `.ops/library/architecture.md` and `.ops/library/testing.md` — fast
   reference.

---

## Universal rules (apply to every worker)

### File mutation
- NEVER modify `acef-conventions/v1/` (FROZEN per VAL-SCHEMA-010).
- NEVER modify `tests/conformance/golden-bundles/` (FROZEN per VAL-REGRESSION-001).
- NEVER modify `planning/freddy-on-acef-requirements-v0.1.md` (it's the input).
- NEVER modify another feature's files (see boundaries.md ownership table).
- Always stage files by name. Never `git add -A` or `git add .`.

### TDD (project CLAUDE.md mandate)
- Write a failing test first.
- Write minimal source to pass.
- Refactor while keeping tests green.
- No code in `src/acef/` without a corresponding test.

### Testing
- Activate venv before pytest: `source venv/bin/activate`.
- Never pipe pytest through `tail` / `head` / `awk`.
- Run with `timeout >= 600000` (10 minutes) for long suites.
- Report actual exit codes in handoff `assertionEvidence[*].exitCode`.

### Pre-commit
- Run `ruff check src/ tests/`, `ruff format src/ tests/`, `mypy --strict
  src/acef` before commit. All must exit 0.
- Scan staged diff for secrets: `git diff --cached | grep -iE
  "api[_-]?key|password|secret|bearer "`. Known false positives include the
  word "token" in the spec context (claim-lexicon token, voice-rubric-token).
- Never use `--no-verify` to bypass hooks.

### Process safety
- NEVER `pkill`, `killall`, or kill by process name.
- Kill processes only by PID, and only ones you started.
- Port conflicts: report; do not kill the holding process.

### Handoff
- On completion (success, partial, or failure), write JSON handoff to
  `/Users/chandlervaughn/.ops-runtime/acef-v0.4-freddy-adoption/handoffs/`.
- `commitId` is MANDATORY when `successState: "success"`.
- `whatWasLeftUndone` is empty only if truly done; otherwise honest.
- Report what happened, not what you intended. Never claim success when
  output shows failure.

---

## Operation-specific rules

### Version-gating discipline (X1-X6 envelope/manifest)
The brief §6.4 says "required". The brief §8.1 says "conditional-required".
ACEF v0.4 follows §8.1. Implementation:
- v1.1 envelope fields (X1-X4) added as Optional in Pydantic models.
- Conditional-required enforced at validator level keyed on
  `manifest.versioning.core_version` and `manifest.analysis_mode`.
- Existing v1.0 bundles (no `core_version: 1.1.0`) validate identically to
  pre-v0.4 behavior.

### Error code discipline
- Do NOT reuse ACEF-022 for missing redaction attestation refs (use new
  ACEF-078).
- Do NOT reuse ACEF-053 for banned claim language (use new ACEF-079).
- Do NOT introduce new ACEF-NNN codes outside the 070-080 range without
  spec-author RFC approval.

### Assertion ID discipline
- The contract parser regex is `^### VAL-[A-Z0-9_]+(?:-[A-Z0-9_]+)*-\d+:`.
- All new VAL-* IDs must end in `-\d+` (digits). Do NOT use suffixes like
  -X1, -R0, -COMPLETE — they are invisible to the ops engine.

### Cross-cutting field clusters
Three feature groups span schema → model → validation → SDK layers. If you
modify one layer, verify the other layers' tests still pass:
- **X2 redaction_attestation_ref**: schemas/v1.1, models/records.py,
  validation/engine.py, redaction.py.
- **X3 tenant_label**: schemas/v1.1, models/records.py,
  validation/engine.py (tenant uniformity + cross-ref).
- **X5 analysis_mode**: schemas/v1.1/manifest, models/manifest.py,
  validation/engine.py (mode-gated rules), docs.

Integration tests against the real validator+model stack — no mocks.

### Namespace lint hook (WS3.10)
ACEF-077 is a Core error code but its violating content lives in
`x-freddy/voice-rubric-emission` (a namespace that lives in Freddy's repo).
Resolution: Core defines a `namespace_lints.py` registry; registered
namespaces declare lint patterns whose violations emit Core codes. If F2 is
unregistered (e.g., during M1 ship), the bundle gracefully validates without
ACEF-077 firing (VAL-VALIDATION-013).

---

## Status of dependencies

- **Freddy repo work (F1-F4 namespaces)** — tracked in `m3-coordination.md`.
  Not gating ACEF v0.4 ship.
- **Relay re-pin (VAL-RELAY-001/002)** — M3 only. After ACEF v0.4 tag, file
  GitHub issue in `epochly-relay` referencing the new ACEF commit.
- **TypeScript SDK** — M2 only. ACEF v0.4.0 ships Python-only. v0.4.1 (or
  later same minor) ships TS SDK + cross-language parity.

---

## When in doubt

- **Spec-author judgment call?** Refer to spec; if spec is silent, refer to
  brief; if both silent, escalate via handoff.
- **Backend implementation choice?** Refer to plan.md workstream guidance.
- **Frontend gzip determinism question?** ops-worker-frontend.md Phase 2.4
  enumerates the three approaches.

If a rule here conflicts with the orchestrator's runtime instructions in
your dispatch prompt, the runtime instructions win — but flag the conflict
in your handoff so the conflict can be resolved by amending this file.
