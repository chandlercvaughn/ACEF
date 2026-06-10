# Migrating from ACEF v0.4 to v1.1 (Incident Reporting)

This document is the migration guide for the ACEF v1.1 incident-reporting
profile (RFC-0002). It describes the new record types, schemas, templates, error
codes, and SDK helpers, and — as with the v0.4 guide — what does **not** change
for existing v1.0 producers and consumers.

The companion design document is
[`planning/ACEF-RFC-0002-ai-incident-reporting-profile.md`](../planning/ACEF-RFC-0002-ai-incident-reporting-profile.md).
The end-to-end worked example lives in
[`USER_GUIDE.md` §8](USER_GUIDE.md#8-reporting-an-ai-incident-eu-art-73).

---

## Summary

ACEF v1.1 is a **purely additive minor release** that introduces the EU AI Act
Art. 73 serious-incident reporting surface plus a public-disclosure projection.
It adds:

- A private/public **incident partition**: `incident_report` (the regulator-only
  Art. 73 filing) ↔ `incident_card` (the public projection), bridged by the
  `incident_report.card_source` overlay.
- A canonical **`harm_core`** taxonomy and a closed, version-pinned
  **`taxonomy_crosswalk`** to external incident schemes.
- The **`ACEF-SEV:1.0`** severity-vector grammar plus a `band()` projection to a
  coarse `severity` enum.
- **`coordinated_disclosure`** with an Art. 73 `regulatory_timeline`, and two
  crosswalk templates: `eu-ai-act-art73-2026` (binding) and
  `oecd-ai-incidents-2025` (voluntary/advisory).
- The **self-asserted `public_incident_id`** (`id_grade: self-asserted`), the
  `mint_incident_id` one-call helper, and an OPTIONAL online domain-control
  verifier (`verify_domain_control`).
- Eight new error codes, **ACEF-081..088**, each carrying problem + cause + a
  fix-hint.

Existing ACEF v1.0 producers, consumers, and bundles are not impacted. The v1.0
schemas in `acef-conventions/v1/` are frozen and byte-identical. New schemas live
in `acef-conventions/v1.1/`. A bundle is treated as v1.1 only when its manifest
declares `core_version: 1.1.0`; all other bundles validate against v1.0 schemas
with v1.0 semantics, and none of the incident rules fire on them. This is the
load-bearing compatibility invariant (RFC-0002 §11; see "Version Gating" below).

---

## What's New in v1.1

### New Record Types

ACEF Core gains the incident surface under `acef-conventions/v1.1/`. The SDK
builders are exposed on `acef.Package` (see "Tooling Changes" → "SDK").

- **`incident_report`** — the EU Art. 73 regulatory-filing surface. Emitted
  `regulator-only` by default. It carries the private **`card_source`** overlay
  block (`incident_report.card_source.schema.json`) that holds the
  `public_incident_id`, `id_state`, `harm_core`, `publishability_map`, the
  `coordinated_disclosure` block, and a structured **`eu_ai_act_facts`** object.
  The confidential report validates from `card_source.eu_ai_act_facts` **before
  any public card exists** (a RESERVED id, no projection) — this is the Art. 73
  compliance critical path (RFC-0002 §5.1/§5.7).

- **`incident_card`** — the public projection of an incident. Closed
  (`additionalProperties: false`). Structurally requires `public_incident_id` and
  `harm_core`; carries `id_grade`, `severity_vector`, the derived
  `taxonomy_crosswalk`, `coordinated_disclosure`, optional `autonomy_level`,
  `harm_distribution_basis`, `declared_publication_basis`, and `<field>_commitment`
  hash-commitment fields (RFC-0002 §5.4/§5.5/§5.11).

- **`coordinated_disclosure`** — the disclosure/regulatory-timeline block carried
  inside both surfaces (`coordinated_disclosure.schema.json`), holding the
  `eu-ai-act-art73` `regulatory_timeline` entry whose `deadline` equals the
  shortest applicable Art. 73 clock.

### New Supporting Schemas

| Schema (`acef-conventions/v1.1/`) | Purpose |
|---|---|
| `harm-core-taxonomy.json` | The canonical `harm_core` taxonomy: `causality`, `realization`, and a closed `harm_class` enum keyed to EU Art. 3(49)(a–d). |
| `taxonomy_crosswalk.schema.json` | Closed, version-pinned crosswalk member subschemas (each with an `edition` pin) mapping `harm_core` to external schemes. |
| `severity_vector.schema.json` | The `ACEF-SEV:1.0` metric grammar (the `band()` target). |
| `incident_card.schema.json` | The closed public-card record. |
| `incident_report.card_source.schema.json` | The private `card_source` overlay, requiring `eu_ai_act_facts`. |

### The Self-Asserted `public_incident_id` (read this — id-trust honesty)

The `public_incident_id` has the form `AIIC-{ASSIGNER}-{year}-{suffix}` where the
suffix is **≥26 Crockford-base32 characters (≥128 bits of CSPRNG entropy)**. It
is a **self-asserted handle**, not a forgery-resistant credential. Every v1.1 id
carries `id_grade: self-asserted` (the only value on the v1.1 surface;
`registry-canonical` is reserved for v1.2, RFC-0002 §11). A v1.1 validator
rejects `registry-canonical` as out-of-surface.

- **Offline-deterministic validation** checks the id **pattern + JWS signature
  self-consistency ONLY**. It never attributes the id to the assigner domain, so a
  forged `AIIC-OPENAI-…` card with an internally consistent JWS passes the offline
  class **by design** (attribution is out of scope offline).
- **`verify_domain_control` (OPTIONAL, online)** proves the registrant controls
  the assigner domain **at check time** via DNS-01 / `.well-known`. It is
  tri-valued: `verified` / `unverified` / `reject` (ACEF-083). A network timeout
  returns an explicit `unverified` — never a silent pass and never a forgery
  verdict.

There is deliberately **no** offline attribution and **no** durable,
institution-independent proof of identity in v1.1. The handle is durable; the
*attribution* of that handle to a domain is only ever a live, optional check.

### Art. 73 Reporting Clock

The validator computes the Art. 73 deadline as the **shortest applicable clock**:

| Trigger facts | Deadline |
|---|---|
| `death_involved: true` | 10 days |
| `3.49.b` in triggers, or `widespread: true` | 2 days |
| otherwise | 15 days |

Source-backed/confidential validation reads
`incident_report.card_source.eu_ai_act_facts`; public-card validation reads
`incident_card.taxonomy_crosswalk.eu_ai_act`. A deadline that disagrees with the
computed shortest clock raises **ACEF-084**.

### The §5.11 Publishability Gate

Before a special-category or privileged field is projected onto a public
`incident_card`, the card MUST carry a satisfying `declared_publication_basis` (a
declared GDPR Art. 6(1) basis **plus** an Art. 9(2) condition, or a declared
anonymization method); `<field>_commitment` hash-commitment keys MUST be linked;
and in source-backed validation the `publishability_map` RFC 6901 pointers MUST
resolve. Violations raise the reserved **ACEF-08x** codes (notably ACEF-086) —
never the v0.4 ACEF-022.

### New Templates

Two crosswalk templates land in `src/acef/templates/` and load through the
existing template registry:

| Template | Disposition | Purpose |
|---|---|---|
| `eu-ai-act-art73-2026.json` | binding | Encodes the Art. 73 reporting-clock rules (10/2/15-day branches). |
| `oecd-ai-incidents-2025.json` | voluntary / advisory | Keys to the OECD common reporting framework (non-binding outcomes). |

### New Error Codes

Eight new codes occupy the reserved **ACEF-081..088** band (the highest
pre-existing code was ACEF-080). They are registered in `src/acef/errors.py` as
`INCIDENT_ERROR_DETAILS` — kept **separate** from the frozen v0.4 `ERROR_REGISTRY`
so the v1.0 error snapshot stays byte-equal. Each entry carries **problem +
cause + fix** (extending the v0.4 problem-only pattern), surfaced through the SDK
error rendering. No incident code exists outside the 081–088 band; ACEF-022 and
ACEF-053 are **not** reused for incident conditions.

| Code | Severity / Category | Problem (abridged) | Fix hint (abridged) |
|---|---|---|---|
| ACEF-081 | ERROR / PROFILE | Incident profile declared but `taxonomy_crosswalk` missing a mandatory member. | Add the missing crosswalk member at the named path, or drop the profile. |
| ACEF-082 | ERROR / FORMAT | `severity_vector` present but not parseable against `ACEF-SEV:1.0`. | Emit a vector conforming to the §5.4 grammar, or omit `severity_vector`. |
| ACEF-083 | ERROR / INTEGRITY | `public_incident_id` id-trust failure (offline-deterministic pattern/JWS, OR online-conformance proof reject). | Fix the id/JWS for the offline class; present a valid current proof, or drop it to land on `unverified`, for the online class. |
| ACEF-084 | ERROR / EVALUATION | Art. 73 `regulatory_timeline` deadline inconsistent with the shortest applicable clock. | Set the deadline to the shortest applicable clock, or correct the trigger facts. |
| ACEF-085 | ERROR / EVALUATION | A `taxonomy_crosswalk` member contradicts the value derived from `harm_core`. | Re-derive the crosswalk member from `harm_core` per §5.5, or correct `harm_core`. |
| ACEF-086 | ERROR / PROFILE | Public disclosure without satisfying the §5.11 publishability gate. | Add a satisfying `declared_publication_basis`, or change the field disposition in `publishability_map`. |
| ACEF-087 | INFO / PROFILE | `realization: near_miss` — informational marker, never a failure. | None required; suppress at the consumer if unwanted. |
| ACEF-088 | ERROR / EVALUATION | Record carries both `severity` and `severity_vector` and they disagree with the `band()` projection. | Make `severity` equal `band(severity_vector)`, or carry only one of the two. |

The fix-hint text is surfaced through the SDK's error rendering, so a filer sees
problem → cause → fix (e.g. the ACEF-084 fatal-clock hint).

---

## Version Gating Semantics

The incident surface is gated entirely on `manifest.versioning.core_version`:

- A bundle is validated against the v1.1 incident schemas **only** when its
  manifest declares `core_version: 1.1.0`. The loader/registry
  (`src/acef/schemas/registry.py` `schema_version_for_core_version()`) routes
  `1.1.0` bundles to the v1.1 schema set; `acef-conventions/v1.1/manifest.schema.json`
  and `acef-conventions/v1.1/variant-registry.json` register the new record types
  under that gate.
- A v1.0 bundle (no `core_version: 1.1.0`) validates **identically to
  pre-operation behavior** — none of the incident rules (ACEF-081..088, the Art.
  73 clock, the publishability gate) fire. Every existing v1.0 golden
  `incident_report` validates byte-identically.
- `acef-conventions/v1/` and `tests/conformance/golden-bundles/` are frozen and
  byte-unchanged by this release.

The SDK builders call an internal `_ensure_v1_1()` that sets `core_version:
1.1.0` automatically, so a package built via `report_incident(...)` /
`incident_card(...)` is gated correctly without manual versioning.

---

## Migration Path

### Existing v1.0 / v0.4 Consumers (No Changes Needed)

No action required. v1.0 bundles continue to validate against the frozen v1.0
schemas with v1.0 semantics. The incident schemas, templates, and ACEF-081..088
codes do not apply to a bundle that does not declare `core_version: 1.1.0`.

### Producers Filing an Art. 73 Incident

1. **Mint an id.** Call `mint_incident_id(domain, key, year=...)`. It returns, in
   one call, the `AIIC-{ASSIGNER}-{year}-{suffix}` id (`id_grade: self-asserted`),
   the card's public JWK, and the DNS-01 / `.well-known` challenge token plus the
   exact wire locations (`dns_record_name`, `well_known_url`). The domain must
   round-trip through the default `LABEL → "<label>.com"` mapper (e.g.
   `openai.com`); the v1.1 default mapper has no public-suffix list, so a
   non-`.com` eTLD or a multi-label public suffix is rejected with a clear
   `ValueError` rather than emitting a wrong challenge location.

2. **Build the confidential report** with `Package.report_incident(...)`, passing
   `harm_core`, `awareness_date`, and `eu_ai_act_facts`
   (`serious_incident_triggers`, `widespread`, `death_involved`). The builder
   auto-derives `card_source.eu_ai_act_facts`, assembles the `eu-ai-act-art73`
   `regulatory_timeline` with the shortest-clock deadline, computes the coarse
   `severity` via `band()` when a vector is supplied, and declares the
   `eu-ai-act-art73-2026` profile. Attach a `RedactionPolicy(version=...)` so the
   `regulator-only` report's X1/X2 redaction-envelope fields auto-populate.

3. **(Optional) project a public card** with `Package.incident_card(...)`. Thread
   a satisfying `declared_publication_basis` when projecting a special-category
   field; otherwise the publishability gate raises ACEF-086.

4. **Sign + export + validate.** `pkg.sign(key_path)`, `pkg.export(dir)`,
   `validate_bundle(dir, profiles=["eu-ai-act-art73-2026"])`. A clean incident
   surface produces no ACEF-08x diagnostics.

5. **(Optional, online) prove domain control.** Publish the minted
   `challenge_token` at `dns_record_name` (TXT) or `well_known_url`, then call
   `verify_domain_control(public_incident_id, jwk)` to reach `verified` at check
   time.

The full copy-paste recipe is in
[`USER_GUIDE.md` §8](USER_GUIDE.md#8-reporting-an-ai-incident-eu-art-73).

### Known Limitations (Out of Scope for v1.1)

The following are explicitly deferred to v1.2 (RFC-0002 §11) and MUST NOT be
relied on in v1.1:

- The AI Commons registry / id-state service / governance ([NR-1]) and the
  `registry-canonical` id grade.
- Online-uniqueness and public-registry-admission conformance classes.
- The Top-25 corpus and Danger Score analytics.
- The TypeScript `@acef/sdk` incident builder and cross-language parity.

v1.1 conformance does **not** depend on any institution: the offline-deterministic
and source-backed classes (the EU Art. 73 critical path) are fully self-contained.
