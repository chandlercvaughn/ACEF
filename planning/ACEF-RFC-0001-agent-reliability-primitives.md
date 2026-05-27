---
**Title:** ACEF RFC-0001 — Agent Reliability Primitives
**Status:** Working Draft
**Date:** 2026-05-27
**Owner:** ACEF maintainers (AI Commons steering committee)
**Targets:** ACEF Spec v0.4 (extending v0.3 working draft), ACEF SDK v0.2.0
**Source brief:** `planning/freddy-on-acef-requirements-v0.1.md` (commit `020e9e0` — Freddy architecture team)
---

## Summary

This RFC proposes the additive set of ACEF Core record types, payload variants,
envelope/manifest fields, and error taxonomy entries needed to make
agent-reliability and continuous-verification products (Freddy being the first
named consumer, but the design is cross-vendor) first-class ACEF consumers.

The proposal adds:

- **Six new Core record types** — `authorized_test_scope`, `scope_boundary_event`,
  `finding_record`, `delivery_verdict`, `coverage_cell`, `harness_attestation`.
- **Five new payload variants** on existing record types — `human_oversight_kill_switch`,
  `regression_definition`, `disposition_record`, `badge_state`, `evidence_freshness_window`.
- **Six cross-cutting envelope/manifest fields** (X1-X6) implemented as
  **version-gated, conditional-required** under `manifest.versioning.core_version`.
- **Eleven new error codes** ACEF-070 through ACEF-080.
- **A namespace-scoped lint hook** in Core that lets `x-vendor/*` extensions
  register lint patterns whose violations emit Core error codes (resolves the
  spec §3.7 + brief §7.1 internal tension where ACEF-077 must fire on
  `x-freddy/voice-rubric-emission` content).

The freeze rule in spec §3.1.4 is amended so that v1.x minor releases MAY add
new record types, provided v1.0 Evidence Bundles continue to validate clean.
The version-gating design (below) is the load-bearing correction that makes
this additive-minor claim true without breaking the six existing v1.0 golden
bundles.

This RFC is **purely additive** for existing ACEF v0.3 consumers: every new
field is optional or conditional-required gated on a new manifest field
(`analysis_mode`) and on `core_version: 1.1.0`. A consumer producing v1.0
bundles today continues to validate without modification under v1.1
validators.

## Motivation

The Freddy team filed a 997-line requirements brief
(`planning/freddy-on-acef-requirements-v0.1.md`, committed at SHA `020e9e0`)
describing what ACEF v0.4 must deliver so that Freddy's evidence bundles are
verifiable with the stock `acef` validator — no Freddy-specific validator
required. The brief grounds itself in three rules drawn from the upstream ACEF
spec:

1. **The open-boundary rule** (spec §1, §6.4 rule 4). Vendor extensions MUST
   use namespaced prefixes (`x-<vendor>/*`) and MUST be safely ignorable. The
   brief honors this — anything Freddy-private lives under `x-freddy/*`.
   Anything proposed for ACEF Core is justified by cross-vendor reusability.
2. **Evidence-not-assertions** (spec §1.1 design principle 2). Every new record
   type carries verifiable evidence references, not narrative claims. This
   drives the schema shape of each new record type below.
3. **Module separation** (spec §1.0.1). Additions are partitioned across Core,
   Profiles, and Assessment per the three-module model.

The proposal is justified at the regulatory level: every new record type maps
to at least one obligation in EU AI Act, NIST AI RMF, or the GPAI Code of
Practice (see "Regulatory Mapping" below). The brief is the first concrete
demonstration of how a vertical agent-reliability product fits the ACEF
contract; absorbing its requirements as ACEF Core (rather than a vendor
extension) prevents fragmentation across the agent-reliability product
category and avoids regulator confusion when multiple vendors arrive at the
same concepts under different names.

This RFC adopts the brief in full. Where the brief carries internal tension
(notably §6.4 "required on every record" vs §8.1 "conditional-required"), this
RFC resolves the tension on the §8.1 side and recommends a brief amendment to
match.

## Regulatory Mapping

Every new Core record type carries at least one binding regulatory citation.
Without that mapping, the record type would belong in `x-freddy/*`, not Core.

| Record type | EU AI Act | NIST AI RMF | GPAI CoP | Rationale |
|---|---|---|---|---|
| `authorized_test_scope` | Art. 9 (risk management), Art. 17 (QMS) | GOVERN-1, MAP-1 | — | Any agent-reliability product testing a third-party AI system must declare scope, identities, side-effect policy, ownership proof. Foundational to risk-management evidence under Art. 9 and QMS scope under Art. 17. |
| `scope_boundary_event` | Art. 9 (risk management), Art. 12 (logging), Art. 14 (human oversight) | MEASURE-2, MANAGE-4 | — | Out-of-scope test attempts are control-plane integrity events distinct from `event_log` (routine) and `incident_report` (post-market). Required under Art. 9 risk-monitoring and Art. 14 kill-switch evidence. |
| `finding_record` | Art. 9, Art. 15 (accuracy/robustness/cybersecurity) | MEASURE-2.x, MANAGE-4.x | GPAI Art. 55 (when finding rises to systemic-risk threshold) | Reproducible-defect-with-evidence records distinct from `incident_report` (operator-facing, post-market). Per-regulation templates ship in v0.4 (D6) accepting `finding_record` as evidence for Art. 9 risk identification and Art. 15 accuracy/robustness obligations. |
| `delivery_verdict` | Art. 12 (logging), Art. 13 (transparency), Art. 14 (human oversight) | MEASURE-2.x | — | "Provider acknowledgment is not delivery" — verified delivery requires read-back. Evidence for Art. 13/14 obligations that information actually reached the system owner. |
| `coverage_cell` | Art. 15 (continuous robustness/cybersecurity), Art. 17 (QMS continuous improvement) | MEASURE-2.x (ongoing measurement), MANAGE-3 | GPAI CoP commitment to ongoing model evaluation | Assessment-time expression of "for this subject, across this scenario set, within this time window, bound evidence is fresh and covers the cell". Cross-vendor concept for any continuous-verification product. |
| `harness_attestation` | Art. 9, Art. 12, Art. 13, Art. 15, Art. 17 (cross-cutting) | GOVERN-1.3, MEASURE-2.x, MANAGE-1 | GPAI Art. 55 attestation | Per-state-transition signed attestation generalizing the Prove-It Doctrine. The cross-cutting integrity primitive that binds every other new record type to its evidence chain. Foundational to verifiable-evidence claims across all frameworks. |

The §4 cross-regulation alignment matrix in the spec is amended to add one row
per new record type, with at minimum one regulation mapping per row. Per
brief D6, the regulation mapping templates in
`acef-conventions/v1/templates/eu-ai-act-high-risk-v1.json` and
`acef-conventions/v1/templates/nist-rmf-v1.json` are extended in the same v0.4
release to consume these record types as binding evidence for the cited
provisions. The Freddy team owns the template-extension work; ACEF working
groups review and approve before v0.4 freeze.

## Version-Gating Design

The brief carries an internal tension: §6.4 says X3 `tenant_label` is
"required on every record" and §6.6 says X5 `analysis_mode` is "required" on
the manifest, while §8.1 declares the new envelope fields **conditional-required,
not absolute-required**. Taken at face value, the §6.4/§6.6 claim is a
**breaking change** against existing v1.0 Evidence Bundles, which contain
neither field. The six existing v1.0 golden bundles in
`tests/conformance/golden-bundles/` would fail v1.1 validation under that
reading.

§8.1 is the written compatibility commitment. It MUST win. This RFC adopts the
following resolution:

**Version-gated, conditional-required.**

- The spec §3.1.4 freeze rule is amended (text below) so that v1.x minor
  releases MAY add new record types, provided:
  1. v1.0 record-type schemas remain unchanged.
  2. New record types are listed under "v1.x optional" in the registry.
  3. v1.0 Evidence Bundles continue to validate clean against v1.x
     validators.
  4. Any new envelope/manifest fields that are required-in-spec are
     **conditional-required** and gated by `manifest.versioning.core_version`.

- The new envelope fields X1-X4 are **optional in schema** in `v1.1/`.
  Conditional-required enforcement happens at the validator level, keyed on
  `manifest.versioning.core_version` and `manifest.analysis_mode`. Existing
  v1.0 bundles (declaring `core_version: 1.0.0`) are validated against the
  unmodified v1.0 schemas — no new requirements apply.

- The validator reads `manifest.versioning.core_version` first, then selects
  the v1.0 or v1.1 schema set for that bundle. This is the version negotiation
  already documented in spec §6.2 ("Module compatibility matrix") — this RFC
  extends it to apply per minor version as well as per major.

**Operational summary.**

```
Existing bundle (no analysis_mode in manifest)
  -> core_version: 1.0.0 -> v1.0 schemas selected
  -> no v1.1 envelope requirements apply
  -> regression R1 passes byte-equal to pre-v0.4

New bundle (manifest declares analysis_mode + core_version: 1.1.0)
  -> v1.1 schemas selected, v1.1 conditional-required semantics apply
  -> X1/X2 required when confidentiality != "public"
  -> X3 required bundle-wide
  -> X4 required on harness_attestation
  -> X5 required on manifest
  -> X6 (state_class) required on harness_attestation
```

**Items to flag back to Freddy team.** The brief §6.4 vs §8.1 self-tension
should be resolved on the brief side. Recommend brief amendment to make
§6.4/§6.6 explicitly say "conditional-required when manifest declares
`analysis_mode`" so the brief text matches §8.1's compatibility commitment.
Until the brief is amended, this RFC's version-gating design is the
authoritative interpretation for ACEF.

## Open Question Resolutions (Q1-Q7)

The brief leaves seven open questions for ACEF maintainers. This RFC closes
each in turn.

| Brief Q | Resolution |
|---|---|
| **Q1** — `harness_attestation` in Core or Profiles? | **Core.** Per-state-transition attestation is foundational and regulation-agnostic. It is the durable proof that a state transition was earned by evidence, generalizing bundle-level signing (`src/acef/signing.py`) to per-record granularity. Any agent-reliability or compliance-testing product needs this primitive. Splitting bundle-level signing from transition-level attestation across two modules creates an artificial seam. |
| **Q2** — `authorized_test_scope` variant or standalone? | **Standalone Core record type.** The schema has too many specific required fields (authorized surfaces, authorized identities, side-effect policy, sandbox boundary, ownership proof, kill-switch ref) for a variant fit on any existing record type. `governance_policy` covers organizational artifacts (training programs, role definitions, AI use case inventory entries); test scope is operational, not governance. Forcing test scope into `governance_policy` produces misleading auditor semantics and crowds the variant registry with concepts that share no real schema. |
| **Q3** — Seven state classes hard-coded or extensible registry? | **Hard-coded enum for v1.1.** The seven values from brief §24.5 (`step`, `finding`, `coverage_cell`, `regression`, `delivery`, `badge`, `attestation`) are the only state classes any currently-known consumer needs. Premature abstraction to a registry pattern, without a second consumer's state classes in hand, locks in design choices that may turn out wrong. Open registry deferred to v1.2+ when a second vendor's classes are known. Backward compatibility is straightforward — existing values remain valid. |
| **Q4** — ACEF reference signer? | **No.** Verifier and JWS sign/verify helpers stay in ACEF; signing identity (JWKS URL, key, `kid`) stays with consumers. `src/acef/signing.py` already provides RS256/ES256 sign and verify operating on JCS-canonicalized input. That primitive surface is sufficient for both `harness_attestation` and `delivery_verdict`. Identity management is operational and customer-specific. |
| **Q5** — `dedupe_key` normative? | **Recipe normative, hash algorithm fixed at SHA-256 for v1.1.** The four-field canonical recipe (`class`, `subject_ref`, `expected_behavior`, `reproduction_steps_ref_content_hash`) under RFC 8785 (JCS), hashed with SHA-256, prefix `sha256:`. No hash agility in v1.1 — SHA-256 matches every other content-addressed identifier in ACEF v0.3 (`^sha256:[0-9a-f]{64}$`), and cross-vendor dedupe determinism matters more than future hash flexibility. Hash migration, when cryptographic events demand it, will be a separate spec bump. |
| **Q6** — Regulation mappings for `finding_record`? | **Per-regulation templates extended by Freddy team, reviewed by ACEF working groups, in the same v0.4 release.** Required acceptance item per FRD-ACEF-071 (verified by VAL-SPEC-004 against the §4 alignment matrix). `acef-conventions/v1/templates/eu-ai-act-high-risk-v1.json` gains a `findings_evidence_class` rule accepting `finding_record` as evidence for Art. 9 and Art. 15. `acef-conventions/v1/templates/nist-rmf-v1.json` gains the same acceptance for MEASURE-2.x and MANAGE-4.x. These mappings ship in v0.4 — `finding_record` cannot exist in Core without the regulations being able to consume it. |
| **Q7** — Subscriber-mode full-loop golden bundle? | **Yes — mandatory.** `test-vectors/freddy/pass/subscriber-mode-full-loop.acef/` is the canonical reference for "what a complete agent-reliability run looks like in ACEF" and is required, not optional. Every new ACEF consumer reads it first to understand how the new record types compose. Required by FRD-ACEF-050 and VAL-CONFORMANCE-004. |

## Conformance Impact

The brief carries 77 acceptance assertions `FRD-ACEF-001..074` covering schema
existence, validation rules, error code emission, conformance vectors, and
compatibility. These map onto the operation's behavioral contract (114
assertions) at `~/.ops-runtime/acef-v0.4-freddy-adoption/contract.md`.

High-level mapping:

- **Schema acceptance (FRD-ACEF-001..015):** mapped to the SCHEMA area
  (VAL-SCHEMA-001..010) and the MODEL area (VAL-MODEL-001..006) of the
  contract.
- **Variant acceptance (FRD-ACEF-020..026):** mapped to the VARIANT area
  (VAL-VARIANT-001..004).
- **Cross-cutting acceptance (FRD-ACEF-030..037):** mapped to VALIDATION
  (VAL-VALIDATION-003..011) plus the round-trip assertions
  (VAL-MODEL-ROUNDTRIP-001..006).
- **Error taxonomy acceptance (FRD-ACEF-040..048):** mapped to ERROR area
  (VAL-ERROR-001..004) and this RFC's spec amendment to §3.6 (VAL-SPEC-003).
- **Conformance suite acceptance (FRD-ACEF-050..056):** mapped to CONFORMANCE
  area (VAL-CONFORMANCE-001..005) and TIER area (VAL-TIER-001..004).
- **Compatibility acceptance (FRD-ACEF-060..063):** mapped to REGRESSION area
  (VAL-REGRESSION-000..004) — version-gating is the load-bearing mechanism
  preserving these.
- **Documentation acceptance (FRD-ACEF-070..074):** mapped to SPEC area
  (VAL-SPEC-001..005, fulfilled by this RFC and the spec amendments it
  triggers) and DOCS area (VAL-DOCS-001..003).

The brief's 77 FRD-ACEF assertions are fully covered by the contract; the
contract carries additional 37 supplementary assertions covering implementation
reality (regression gates, version-gating semantics, archive-level parity
beyond hash comparison, namespace-lint hook integrity, JWS signature scope,
determinism). The cross-reference table is established in `features.json`
`primaryFulfills` mappings.

ACEF v0.4 acceptance is gated on **all 114** contract assertions passing — the
brief's 77 plus the 37 supplementary. CI MUST gate on all of them before
tagging the v0.4 release.

## Errors Added

Eleven new error codes are introduced under §3.6's error taxonomy. The brief
proposed eight (ACEF-070..077); codex review of the implementation plan
identified that three of those codes were being overloaded onto existing
ACEF-022 / ACEF-053 in earlier drafts, hiding distinct failure modes. Three
new codes (ACEF-078, ACEF-079, ACEF-080) are added to keep semantics clean.

| Code | Severity | Category | Description |
|---|---|---|---|
| `ACEF-070` | `fatal` | Integrity | `harness_attestation` cites missing or unverifiable required evidence (empty `bound_evidence_refs` or URN does not resolve in bundle/external references). |
| `ACEF-071` | `fatal` | Integrity | `delivery_verdict` claims `verified_delivered` without a read-back digest (`read_back` missing, `harness_attestation_ref` missing, or `read_back.digest_match: true` without the matching digest). |
| `ACEF-072` | `fatal` | Integrity | `delivery_verdict` read-back digest does not match write-back digest (`read_back.read_back_digest != write_attempt.request_digest`). |
| `ACEF-073` | `fatal` | Reference | `causation_chain` cites an unknown or unsigned URN (URN does not resolve in-bundle or via declared external references, or its owning bundle is unsigned per spec §3.1.3). |
| `ACEF-074` | `error` | Schema | Record missing `redaction_policy_version` when `confidentiality != "public"` (conditional-required field absent). |
| `ACEF-075` | `fatal` | Reference | `tenant_label` mismatch across records in a single bundle (two distinct values in one bundle). |
| `ACEF-076` | `error` | Schema | `state_class` record lacks fake-green test reference (`harness_attestation.fake_green_test_ref` missing, or `state_class` not in `state-class-taxonomy.json`). |
| `ACEF-077` | `fatal` | Integrity | `voice_rubric_emission` contains claim-lexicon token without a paired `harness_attestation` (fires via the new namespace-scoped lint hook; see "Namespace-Scoped Lint" below). |
| `ACEF-078` | `error` | Reference | `redaction_attestation_ref` points to unresolvable URN (replaces previously-overloaded ACEF-022 use for this condition). |
| `ACEF-079` | `error` | Schema | `coverage_cell.claim_language` contains banned token from the claim lexicon (`compliant`, `certified`, `AI Act-approved`, `guaranteed`). Replaces previously-overloaded ACEF-053 use. |
| `ACEF-080` | `error` | Reference | Bundle declares `analysis_mode` but lacks required envelope fields for that mode, OR contains forbidden record types for that mode (mode-gated rule violation). |

The categories chosen for the new codes follow the existing §3.6 taxonomy:
Integrity for proof-of-evidence failures, Reference for URN/identity
violations, Schema for required-field and enum violations.

### Namespace-Scoped Lint (mechanism enabling ACEF-077)

ACEF-077 is a Core error code but the violating content lives in an
`x-freddy/voice-rubric-emission` namespaced extension. Spec §3.7 says vendor
extensions MUST NOT change Core conformance outcomes. If ACEF Core does not
validate content inside `x-freddy/*`, ACEF-077 can never fire — yet brief §7.1
lists `voice-rubric-with-claim-token` as a Core fail vector.

This RFC resolves the tension by adding to v1.1 Core a **namespace-scoped lint
capability**: registered namespaces declare lint patterns whose violations
emit Core error codes. The registration is via a documented configuration file
(or equivalent API per `src/acef/validation/namespace_lints.py`); the
configuration is part of the spec and reviewed under the §6.1 RFC process.
This preserves §3.7's intent — extension content never silently changes Core
outcomes; Core only lints patterns it has been explicitly told (via spec
amendment) to lint — while enabling ACEF-077.

`x-freddy/voice-rubric-emission`'s claim-lexicon scan is the first registered
namespace lint. Future vendors register their lints the same way via
spec-amendment RFC.

## Spec Amendments Triggered by This RFC

This RFC drives four concrete amendments to `planning/ACEF-Spec-Outline-v0.1.md`:

1. **§3.1.4 freeze rule** — amended to permit v1.x minor record-type
   additions under the version-gating constraints above.
2. **§3.6 error taxonomy table** — extended with eleven new rows
   (ACEF-070..080).
3. **§4 cross-regulation alignment matrix** — extended with six new rows
   (one per new record type).
4. **§6.2 module compatibility matrix** — extended with a Core 1.1.x row.

The spec version header bump from v0.3 to v0.4 is owned by the WS0 spec-freeze
work and is **not** part of this RFC — it lands once all v0.4 schemas, models,
errors, and conformance vectors are in place.

## Status and Next Steps

- **Public comment period:** TBD by ACEF steering committee per spec §6.1
  (typically 2 weeks IETF-style). The user-decision question on whether to run
  a public comment period vs unilateral steward decision is tracked in
  `~/.ops-runtime/acef-v0.4-freddy-adoption/plan.md` "Sequencing questions".
- **Working-group review:** EU, US, UK, China, International Standards working
  groups review the regulatory-mapping additions.
- **Spec amendments:** four amendments listed above land alongside this RFC.
- **Implementation:** WS1-WS9 in `~/.ops-runtime/acef-v0.4-freddy-adoption/plan.md`
  proceed once spec is amended.
- **Brief amendment recommendation:** Freddy team to amend brief §6.4 and §6.6
  to match §8.1's conditional-required commitment, so brief text is internally
  consistent.

---

*End of RFC.*
