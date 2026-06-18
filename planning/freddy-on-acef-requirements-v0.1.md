# Freddy Requirements on ACEF — v0.1

| | |
|---|---|
| **Status** | Working Draft |
| **Date** | 2026-05-26 |
| **Consumer** | Freddy (continuous outside-customer validation product) |
| **Target ACEF spec version** | v0.4 (proposed, expanding the v0.3 working draft) |
| **Target ACEF SDK version** | v0.2.0 (proposed, expanding the v0.1.0 reference SDK) |
| **Authors** | Freddy architecture team |
| **Source spec for downstream requirements** | `freddy_product_spec_v0_8_requirements.md` (3,685 lines, 28 sections) |
| **Source spec for upstream format** | `ACEF-Spec-Outline-v0.1.md` (v0.3 Working Draft, 2026-03-17) |
| **License posture** | Proposed additions land under ACEF's existing Apache 2.0 (SDK) and CC-BY 4.0 (schemas/templates) terms |

---

## 0. Purpose of This Document

This is a **requirements brief from Freddy to the ACEF maintainers**. It describes what Freddy, as the first vertical agent-reliability product built on the ACEF stack, needs from the ACEF spec, reference SDK, and conformance suite so that Freddy's evidence bundles are first-class ACEF bundles — verifiable with the stock `acef` and `rly verify` tools, mappable to the regulations ACEF already targets, and not requiring Freddy customers to install a Freddy-specific validator.

This document is **not** a Freddy implementation spec, not a competing format proposal, and not a request to alter ACEF Core's existing record types. It is an additive workplan: new record types, new payload variants, new cross-cutting fields, new conformance vectors.

It is grounded in three rules drawn from the upstream ACEF spec:

1. **The open-boundary rule** (ACEF spec §1, "Open boundary enforcement"). Vendor extensions MUST use namespaced prefixes (`x-<vendor>/*`) and MUST be safely ignorable by standard validators. Freddy honors this — anything Freddy-private goes under `x-freddy/*`. Anything Freddy proposes for ACEF Core is justified by cross-vendor reusability.
2. **Evidence-not-assertions** (ACEF spec §1.1 design principle 2). Every Freddy-emitted record carries verifiable evidence references, not narrative claims. This drives the schema shape of every new record type below.
3. **Module separation** (ACEF spec §1.0.1). Additions are partitioned across ACEF Core, ACEF Profiles, and ACEF Assessment per the spec's three-module model. Each section below states which module the addition belongs in.

---

## 1. Reference Documents

| Ref | Title | Version | Path |
|---|---|---|---|
| [SPEC-FRD] | Freddy Product Spec | v0.8 | `freddy/planning/freddy_product_spec_v0_8_requirements.md` |
| [SPEC-ACEF] | ACEF Specification Outline | v0.3 Working Draft | `ACEF/planning/ACEF-Spec-Outline-v0.1.md` |
| [SDK-ACEF] | ACEF Reference SDK | v0.1.0 | `ACEF/src/acef/` |
| [SCHEMAS-ACEF] | ACEF v1 schemas | v1 | `ACEF/acef-conventions/v1/` |
| [SPEC-RELAY] | Relay (Epochly) Spec | v0.3 | `epochly-relay/planning/epochly-replay-spec.md` |
| [EXT-RELAY] | Relay x-relay extensions | v1 | `epochly-relay/relay/packages/acef/relay_extensions/` |
| [RFC-8785] | JSON Canonicalization Scheme | RFC 8785 | https://www.rfc-editor.org/rfc/rfc8785 |
| [RFC-7515] | JSON Web Signature | RFC 7515 | https://www.rfc-editor.org/rfc/rfc7515 |
| [RFC-6901] | JSON Pointer | RFC 6901 | https://www.rfc-editor.org/rfc/rfc6901 |

Throughout this document, citations are written as `[SPEC-FRD §N.M]` and `[SPEC-ACEF §N.M]`.

---

## 2. Summary of Requests

### 2.1 New ACEF Core record types (6)

These belong in `acef-conventions/v1/` and the SDK's `src/acef/schemas/` because they describe cross-vendor concepts (any agent-reliability or compliance-testing product would emit them), not Freddy-specific concepts.

| # | record_type | Module | Rationale for Core (not extension) |
|---|---|---|---|
| C1 | `authorized_test_scope` | Profiles | Cross-vendor concept of "what testing is authorized against this AI system". |
| C2 | `scope_boundary_event` | Profiles | Cross-vendor concept of "a test attempted to act outside its authorized scope". |
| C3 | `finding_record` | Profiles | Cross-vendor concept of a reproducible defect with evidence; distinct from `incident_report` (which is operator-facing). |
| C4 | `delivery_verdict` | Profiles | Cross-vendor concept of "evidence was delivered to the system owner and the owner received it". |
| C5 | `coverage_cell` | Assessment | Cross-vendor concept of "what slice of the test surface this evidence covers and how fresh it is". |
| C6 | `harness_attestation` | Core | Cross-vendor concept of "a verifier signed off on a state transition based on bound evidence". Generalizes the Prove-It Doctrine claim chain. |

### 2.2 New ACEF Core payload variants (5)

These belong in `acef-conventions/v1/variant-registry.json` and ride on existing record types:

| # | artifact_name | Parent record_type | Discriminator | Rationale |
|---|---|---|---|---|
| V1 | `human_oversight_kill_switch` | `human_oversight_action` | `/payload/oversight_subtype` = `kill_switch` | Operator-triggered hard stop with audit trail. |
| V2 | `regression_definition` | `risk_treatment` | `/payload/treatment_subtype` = `regression_definition` | A persistent regression test whose passing is risk mitigation. |
| V3 | `disposition_record` | `risk_treatment` | `/payload/treatment_subtype` = `external_disposition` | Customer-asserted classification of a finding (false positive, accepted risk, scheduled fix). |
| V4 | `badge_state` | `transparency_disclosure` | `/payload/variant` = `verification_badge` | Public display of verification status against a particular evidence chain. |
| V5 | `evidence_freshness_window` | `evidence_gap` | `/payload/gap_subtype` = `freshness_window` | Time-bound expression of when a piece of evidence stops being current. |

### 2.3 New `x-freddy/*` extension namespaces (4)

Freddy-private; ride on top of ACEF Core under `bundle.namespaces["x-freddy"]["<name>"]` following the established `x-relay/*` pattern in `epochly-relay/relay/packages/acef/relay_extensions/`:

| # | namespace | Purpose |
|---|---|---|
| F1 | `persona-observation` | A persona's observation of target behavior, post-redaction, with attribution. |
| F2 | `voice-rubric-emission` | Voice-styled prose, validated against rubric and free of claim lexicon. |
| F3 | `roe-attestation` | A signed Rules of Engagement document. |
| F4 | `freddy-internal-incident` | An internal-only event (harness failure, integration health, invalid voice emission). |

### 2.4 Cross-cutting envelope additions

Six additions to the record envelope (`acef-conventions/v1/record-envelope.schema.json`) and/or the bundle manifest:

| # | Field | Module | Purpose |
|---|---|---|---|
| X1 | `redaction_policy_version` | Core (record envelope) | Required on every record. Binds content to the policy that produced it. |
| X2 | `redaction_attestation_ref` | Core (record envelope) | URN reference to the attestation that proves the redaction was applied. |
| X3 | `tenant_label` | Core (record envelope) | Cross-tenant isolation enforced at validator level. |
| X4 | `causation_chain` | Core (record envelope) | Ordered list of upstream record URNs that caused this record. |
| X5 | `analysis_mode` | Core (manifest) | One of `subscriber`, `public_artifact`, `canary`, `unattributed_artifact`. |
| X6 | `state_class` | Profiles | Enumerated taxonomy for harness state class with fake-green binding. |

### 2.5 New error taxonomy entries (8)

Extending the `ACEF-NNN` taxonomy in `src/acef/errors.py` from the current ACEF-001..ACEF-060 range:

| Code | Severity | Category | Description |
|---|---|---|---|
| ACEF-070 | FATAL | INTEGRITY | `harness_attestation` cites missing or unverifiable required evidence. |
| ACEF-071 | FATAL | INTEGRITY | `delivery_verdict` claims `verified_delivered` without a read-back digest. |
| ACEF-072 | FATAL | INTEGRITY | `delivery_verdict` read-back digest does not match write-back digest. |
| ACEF-073 | FATAL | REFERENCE | `causation_chain` cites an unknown or unsigned URN. |
| ACEF-074 | ERROR | SCHEMA | Record missing `redaction_policy_version` when `confidentiality != "public"`. |
| ACEF-075 | FATAL | REFERENCE | `tenant_label` mismatch across records in a single bundle. |
| ACEF-076 | ERROR | SCHEMA | `state_class` record lacks fake-green test reference. |
| ACEF-077 | FATAL | INTEGRITY | `voice_rubric_emission` contains claim-lexicon token without a paired `harness_attestation`. |

### 2.6 Conformance suite additions

A new top-level test-vector directory `test-vectors/freddy/` mirroring the existing per-regulation pattern (`test-vectors/eu-ai-act/`, `test-vectors/nist-rmf/`, etc.), containing positive and negative bundles for each new record type, each new payload variant, and each cross-cutting field. Detailed in §7.

---

## 3. ACEF Core Record Type Additions

Each subsection below contains: rationale, schema, validation rules, golden-bundle requirement, and test criteria. Test criteria use the standard battery defined in §6.1 (TC1–TC10).

### 3.1 `authorized_test_scope` (C1)

**Cite:** [SPEC-FRD §5] Surface Authorization Requirements, [SPEC-FRD §6] Rules of Engagement Requirements.

**Rationale.** Any agent-reliability product that tests a third-party AI system must declare what testing is authorized. The contents of this record (authorized surfaces, identities, side-effect policies, sandbox boundaries, ownership proof) are common across vendors. Placing this in ACEF Core lets any compliance auditor read a `authorized_test_scope` record without a vendor-specific validator.

**Schema (`acef-conventions/v1/authorized_test_scope.schema.json`).**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://acef.ai/schemas/v1/authorized_test_scope.schema.json",
  "title": "ACEF Authorized Test Scope",
  "type": "object",
  "required": [
    "scope_id",
    "scope_version",
    "subject_ref",
    "authorized_surfaces",
    "authorized_identities",
    "side_effect_policy",
    "sandbox_boundary",
    "ownership_proof",
    "effective_from",
    "authorizing_actor_ref"
  ],
  "properties": {
    "scope_id": {
      "type": "string",
      "pattern": "^urn:acef:scope:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    },
    "scope_version": {
      "type": "string",
      "description": "Semver-shaped version of this scope. Required to be present even on initial issue."
    },
    "subject_ref": {
      "type": "string",
      "description": "URN reference to the ai_system or ai_model being tested."
    },
    "authorized_surfaces": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["surface_type", "surface_identifier", "authorization_level"],
        "properties": {
          "surface_type": {
            "enum": ["chat_endpoint", "api_endpoint", "tool_endpoint", "rag_endpoint", "browser_target", "package_target", "cli_target", "container_target", "docs_target"]
          },
          "surface_identifier": {"type": "string"},
          "authorization_level": {
            "enum": ["read_only", "read_write_sandbox", "production_capable_owner_authorized"]
          }
        }
      }
    },
    "authorized_identities": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["identity_type", "identity_ref", "scope_constraint"],
        "properties": {
          "identity_type": {"enum": ["test_account", "service_principal", "delegated_grant", "freddy_managed_mailbox"]},
          "identity_ref": {"type": "string"},
          "scope_constraint": {"type": "string"}
        }
      }
    },
    "side_effect_policy": {
      "type": "object",
      "required": ["default_disposition", "explicit_allowlist", "explicit_denylist"],
      "properties": {
        "default_disposition": {"enum": ["default_deny", "default_allow_sandbox_only"]},
        "explicit_allowlist": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["action_class", "rationale"],
            "properties": {
              "action_class": {"type": "string"},
              "rationale": {"type": "string"}
            }
          }
        },
        "explicit_denylist": {"type": "array", "items": {"type": "string"}}
      }
    },
    "sandbox_boundary": {
      "type": "object",
      "required": ["ownership_ledger_ref", "preflight_method"],
      "properties": {
        "ownership_ledger_ref": {"type": "string"},
        "preflight_method": {"enum": ["resource_naming_scheme", "tenant_label", "dedicated_subaccount", "preflight_probe"]}
      }
    },
    "ownership_proof": {
      "type": "object",
      "required": ["proof_method", "proof_artifact_ref", "verified_at"],
      "properties": {
        "proof_method": {"enum": ["dns_txt", "well_known_file", "http_header", "github_oauth", "sso_assertion"]},
        "proof_artifact_ref": {"type": "string"},
        "verified_at": {"format": "date-time", "type": "string"}
      }
    },
    "effective_from": {"format": "date-time", "type": "string"},
    "effective_until": {"format": "date-time", "type": ["string", "null"]},
    "authorizing_actor_ref": {"type": "string"},
    "kill_switch_ref": {"type": "string", "description": "URN reference to the kill-switch endpoint or actor authorized to halt testing."}
  }
}
```

**Validation rules.**

- `authorization_level: "production_capable_owner_authorized"` is only valid if `ownership_proof.proof_method` is `dns_txt`, `well_known_file`, or `sso_assertion` (the three methods that prove ownership; OAuth and HTTP header prove control of an account but not ownership of the underlying system).
- `effective_until`, if present, must be later than `effective_from`.
- `kill_switch_ref` is REQUIRED when any `authorized_surfaces[*].authorization_level` is `production_capable_owner_authorized`.

**Test criteria.** TC1–TC7 plus:

- **TC-FRD-001-N1**: A bundle with `authorization_level: "production_capable_owner_authorized"` and `ownership_proof.proof_method: "github_oauth"` MUST fail validation with a clear error citing the rule.
- **TC-FRD-001-N2**: A bundle missing `kill_switch_ref` while having `production_capable_owner_authorized` authorization MUST fail validation.

### 3.2 `scope_boundary_event` (C2)

**Cite:** [SPEC-FRD §10.5.1] ScopeBoundaryEvent, [SPEC-FRD §10.5] Hard Stop Conditions.

**Rationale.** Any test harness needs a record type for "the test attempted something outside the authorized scope". This is not the same as an `incident_report` (which is post-market / operational) or an `event_log` entry (which is routine). It is a control-plane integrity event. Cross-vendor.

**Schema (`acef-conventions/v1/scope_boundary_event.schema.json`).**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://acef.ai/schemas/v1/scope_boundary_event.schema.json",
  "title": "ACEF Scope Boundary Event",
  "type": "object",
  "required": [
    "event_id",
    "scope_ref",
    "attempted_action",
    "authorized_scope_snapshot",
    "classification",
    "hard_stop_triggered",
    "detected_at",
    "detector"
  ],
  "properties": {
    "event_id": {"pattern": "^urn:acef:sbe:[0-9a-f-]{36}$", "type": "string"},
    "scope_ref": {
      "type": "string",
      "description": "URN reference to the authorized_test_scope at the time the event occurred."
    },
    "attempted_action": {
      "type": "object",
      "required": ["action_class", "action_target", "action_payload_digest"],
      "properties": {
        "action_class": {"type": "string"},
        "action_target": {"type": "string"},
        "action_payload_digest": {
          "type": "string",
          "pattern": "^sha256:[0-9a-f]{64}$",
          "description": "Digest of the redacted payload that would have been sent. Raw payload MUST NOT be embedded."
        }
      }
    },
    "authorized_scope_snapshot": {
      "type": "object",
      "required": ["scope_id", "scope_version"],
      "description": "Snapshot of the relevant scope fields at the moment of detection, to defend against later scope edits hiding the violation."
    },
    "classification": {
      "enum": [
        "intentional_bypass_attempt",
        "harness_drift",
        "persona_misbehavior",
        "scope_definition_ambiguity",
        "third_party_integration_overreach"
      ]
    },
    "hard_stop_triggered": {"type": "boolean"},
    "hard_stop_attestation_ref": {
      "type": ["string", "null"],
      "description": "URN reference to the harness_attestation recording the stop. REQUIRED if hard_stop_triggered is true."
    },
    "detected_at": {"format": "date-time", "type": "string"},
    "detector": {
      "type": "object",
      "required": ["detector_class", "detector_id"],
      "properties": {
        "detector_class": {"enum": ["preflight_probe", "ownership_ledger_check", "side_effect_policy_check", "post_action_audit", "external_alert"]},
        "detector_id": {"type": "string"}
      }
    }
  },
  "allOf": [
    {
      "if": {"properties": {"hard_stop_triggered": {"const": true}}},
      "then": {"required": ["hard_stop_attestation_ref"]}
    }
  ]
}
```

**Test criteria.** TC1–TC7 plus:

- **TC-FRD-002-N1**: A bundle with `hard_stop_triggered: true` and `hard_stop_attestation_ref: null` MUST fail validation (allOf rule).
- **TC-FRD-002-N2**: A bundle whose `attempted_action.action_payload_digest` does not match `^sha256:[0-9a-f]{64}$` MUST fail validation.
- **TC-FRD-002-FG**: A fake-green test MUST exist proving that a bundle claiming `hard_stop_triggered: true` cannot validate without (a) a `harness_attestation` record present in the same bundle, and (b) that attestation referencing the same `event_id`.

### 3.3 `finding_record` (C3)

**Cite:** [SPEC-FRD §12.4] Finding Definition, [SPEC-FRD §15.7] Finding Identity / Dedupe / Variants, [SPEC-FRD §2.19] Deduplication Compresses Evidence Not Risk.

**Rationale.** ACEF Core already defines `incident_report` for serious post-market events. It does not define a record type for "we tested this AI system and found a defect we can reproduce, with full evidence". That is the cross-vendor concept any agent-reliability product needs. Distinct from `incident_report` because:

- Operator-facing → customer-facing.
- Single occurrence → reproducible.
- Reported once → dedupe + variant tracking across runs.
- Triggered after deployment → produced during testing.

**Schema (`acef-conventions/v1/finding_record.schema.json`).** (Field-level rules below; full schema in the same shape.)

| Field | Required | Description |
|---|---|---|
| `finding_id` | yes | `urn:acef:finding:<uuid>` |
| `finding_class` | yes | Enum: `safety_failure`, `policy_violation`, `accuracy_degradation`, `robustness_failure`, `security_vulnerability`, `transparency_failure`, `oversight_failure`, `data_integrity_failure`. |
| `subject_ref` | yes | URN of the `ai_system` or `ai_model` the finding is about. |
| `severity` | yes | Object with `severity_level` (enum) and `severity_rationale` (string). |
| `dedupe_key` | yes | A stable hash over the canonical reproduction recipe; identical findings across runs share this key. |
| `variant_group_id` | no | URN linking related findings that share a class but differ in surface. |
| `reproduction` | yes | Object with `expected_behavior`, `observed_behavior`, `reproduction_steps_ref`, `evidence_commit_ref`. All four are required and must reference existing artifacts. |
| `attribution` | yes | Object with `persona_ref`, `scenario_ref`, `scope_ref`. Attribution is advisory (per [SPEC-FRD §2.23]) but must be recorded. |
| `regulation_impact` | no | Array of regulation provision IDs (dotted notation as in ACEF Core) this finding may bear on. |
| `discovered_at` | yes | ISO 8601 timestamp. |
| `discovered_in_run_ref` | yes | URN of the run that produced the finding. |
| `disposition_history` | no | Array of URNs pointing to `disposition_record` variants. The *latest* disposition does not transition the finding's internal state — it is advisory per [SPEC-FRD §2.7]. |
| `accepted_risk_ref` | no | URN of an `accepted_risk` record if the finding is in accepted-risk state. |
| `regression_ref` | no | URN of a `regression_definition` if a regression has been promoted from this finding. |

**Validation rules.**

- `reproduction.evidence_commit_ref` must be present in the bundle's content-hashes index, OR be a fully-qualified external URN whose owning bundle is referenced by the manifest.
- `dedupe_key` MUST be a `sha256:` hash over the canonical reproduction recipe; the canonicalization algorithm is `RFC 8785 (JCS)` applied to the object `{class, subject_ref, expected_behavior, reproduction_steps_ref_content_hash}`. The conformance suite MUST publish two minimal findings with the same recipe and show they collapse to one `dedupe_key`.

**Test criteria.** TC1–TC7 plus:

- **TC-FRD-003-FG**: A bundle containing a `finding_record` whose `reproduction.evidence_commit_ref` is not present in `content-hashes.json` AND not a fully-qualified external URN MUST fail validation.
- **TC-FRD-003-DEDUPE**: Two findings whose canonicalized reproduction recipes are byte-equal MUST produce identical `dedupe_key` values across repeated runs of the ACEF Python SDK. (Cross-language parity, where it matters downstream, is verified inside Relay's conformance suite per §8.3, not here.)

### 3.4 `delivery_verdict` (C4)

**Cite:** [SPEC-FRD §13.2] Delivery Verification Tiers, [SPEC-FRD §2.17] Verified Delivery Or It Did Not Happen.

**Rationale.** Provider acknowledgment (HTTP 2xx) is not delivery. Verified delivery requires a read-back. This is a cross-vendor concept — any compliance evidence pipeline that ships records to customer systems should record verified delivery the same way.

**Schema fields.**

| Field | Required | Description |
|---|---|---|
| `verdict_id` | yes | `urn:acef:delivery:<uuid>` |
| `finding_ref` | yes | URN of the `finding_record` being delivered. |
| `destination` | yes | Object with `provider_class` (enum: `plane`, `github_issues`, `linear`, `jira`, `slack`, `email`, `markdown_export`, `custom`), `provider_instance_id`, `provider_object_id` (e.g., ticket URL). |
| `write_attempt` | yes | Object with `attempted_at`, `request_digest` (sha256), `response_status`, `response_digest`. |
| `read_back` | conditional | Object with `read_back_at`, `read_back_digest`, `digest_match` (boolean), required when `delivery_state` is `verified_delivered`. |
| `delivery_state` | yes | Enum: `drafted`, `dispatched`, `acknowledged`, `verified_delivered`, `failed`, `drifted`. |
| `drift_classification` | conditional | Enum: `external_close_without_resolution`, `external_priority_lowered`, `external_reassignment`, `ticket_deleted`. Required when `delivery_state` is `drifted`. |
| `retry_history` | no | Ordered array of `{attempted_at, response_status, response_digest}`. |
| `harness_attestation_ref` | yes | URN of the `harness_attestation` that signed off on the `verified_delivered` transition. Required when `delivery_state` is `verified_delivered`. |

**Validation rules (drive ACEF-071, ACEF-072).**

- `delivery_state: "verified_delivered"` REQUIRES `read_back`, `read_back.digest_match: true`, and `harness_attestation_ref`. Missing any of these emits ACEF-071.
- `read_back.digest_match: true` REQUIRES that `read_back.read_back_digest == write_attempt.request_digest` byte-equal. If not byte-equal, MUST emit ACEF-072 and the bundle is rejected.

**Test criteria.** TC1–TC7 plus:

- **TC-FRD-004-N1**: `delivery_state: "verified_delivered"` with missing `read_back` → ACEF-071.
- **TC-FRD-004-N2**: `delivery_state: "verified_delivered"` with `read_back.digest_match: true` but `read_back.read_back_digest != write_attempt.request_digest` → ACEF-072.
- **TC-FRD-004-FG**: A fake-green test proving a bundle cannot reach `verified_delivered` without all three: read-back, byte-equal digest, signed attestation.

### 3.5 `coverage_cell` (C5)

**Cite:** [SPEC-FRD §16.1] Coverage Cell Model, [SPEC-FRD §16.4] Coverage Ledger, [SPEC-FRD §16.6] Evidence Freshness.

**Rationale.** ACEF Assessment currently expresses assessment results per provision. It does not express "for this subject, across this set of scenarios, within this time window, the bound evidence is fresh and covers the cell". That is the cross-vendor concept any continuous-verification product needs. Belongs in ACEF Assessment because it is an assessment-time computation, not raw evidence.

**Schema fields.**

| Field | Required | Description |
|---|---|---|
| `cell_id` | yes | `urn:acef:cell:<uuid>` |
| `subject_ref` | yes | URN of the subject the cell is about. |
| `dimensions` | yes | Object describing the cell's location in the coverage grid. Required keys: `scenario_class`, `surface_class`, `time_window_start`, `time_window_end`. |
| `bound_evidence_refs` | yes | Array of URNs of records the cell depends on. |
| `freshness_state` | yes | Enum: `fresh`, `stale_within_grace`, `stale_outside_grace`, `unverified`. |
| `freshness_policy_ref` | yes | URN of the freshness policy that classified the state. |
| `claim_language` | yes | Constrained string. The vocabulary is restricted by [SPEC-ACEF banned-copy rule] and [SPEC-FRD §16.2]. See §6.5. |
| `coverage_outcome` | yes | Enum: `covered`, `gap`, `blocked`. |
| `blocker_ref` | conditional | URN of a `coverage_blocker` record. Required when `coverage_outcome` is `blocked`. |

**Validation rules.**

- `claim_language` MUST NOT contain the substrings `compliant`, `certified`, `AI Act-approved`, `guaranteed`. (Matches ACEF's existing banned-copy lint and Freddy's §J.5 / §16.2 rule.) Violations emit ACEF-053 in the customer-facing path.
- `freshness_state: "fresh"` REQUIRES that every URN in `bound_evidence_refs` has a `timestamp` newer than `time_window_start - freshness_policy.max_age`.

### 3.6 `harness_attestation` (C6)

**Cite:** [SPEC-FRD §10.6] Prove-It / Attestation Layer, [SPEC-FRD §2.12] Prove-It Doctrine, [SPEC-FRD §24.5] Fake-Green Test Requirement.

**Rationale.** This is the most important addition. ACEF Core today has `signing.py` for the bundle-level JWS signature. It does not have a per-state-transition attestation. Freddy's harness writes one attestation per state transition (step, finding, coverage cell, regression, delivery, badge, attestation itself). Any agent-reliability product needs this. Strongly cross-vendor.

This belongs in ACEF Core (not Profiles or Assessment) because it is fundamental — it is the durable proof that a state transition was earned by evidence.

**Schema fields.**

| Field | Required | Description |
|---|---|---|
| `attestation_id` | yes | `urn:acef:att:<uuid>` |
| `state_class` | yes | One of: `step`, `finding`, `coverage_cell`, `regression`, `delivery`, `badge`, `attestation`. (See §5.6 for the taxonomy spec.) |
| `state_transition` | yes | Object: `from_state`, `to_state`, `transitioned_at`. |
| `bound_evidence_refs` | yes | Array of URNs of the records that justified the transition. Empty array MUST emit ACEF-070. |
| `verifier` | yes | Object: `verifier_id`, `verifier_class` (enum: `contract_gate`, `read_back_verifier`, `cryptographic_verifier`, `harness_internal`), `verifier_version`. NEVER `persona` or `llm`. Validators MUST reject `verifier_class: "persona"` or `verifier_class: "llm"`. |
| `claim` | yes | String, structured per [SPEC-FRD §10.6] — `<state_class>.<from_state>.<to_state>:<short_reason>`. |
| `fake_green_test_ref` | yes | URN of the fake-green test that proves this state class cannot be reached without the bound evidence. Per [SPEC-FRD §24.5]. |
| `attestation_signature` | yes | JWS over the attestation body using the bundle's signing key. |
| `signed_at` | yes | ISO 8601. |
| `signer_kid` | yes | Key identifier from the JWKS. |

**Validation rules (drive ACEF-070, ACEF-076).**

- `bound_evidence_refs` empty → ACEF-070.
- Missing `fake_green_test_ref` → ACEF-076.
- `verifier.verifier_class` ∈ {`persona`, `llm`} → reject the record outright (not just emit an error — refuse to load).
- `attestation_signature` MUST verify against the bundle's JWKS using `attestation_id`, `state_class`, `state_transition`, `bound_evidence_refs`, `verifier`, `claim`, `fake_green_test_ref`, `signed_at`, `signer_kid` (in that order, JCS canonicalized).

**Test criteria.** TC1–TC10 (all ten). Specifically:

- **TC-FRD-006-N1**: Empty `bound_evidence_refs` → ACEF-070.
- **TC-FRD-006-N2**: Missing `fake_green_test_ref` → ACEF-076.
- **TC-FRD-006-N3**: `verifier_class: "persona"` → bundle rejected at load, not validation (stronger guarantee).
- **TC-FRD-006-N4**: Tampered `bound_evidence_refs` (one URN swapped post-signature) → signature verification fails.
- **TC-FRD-006-FG**: A fake-green test proving NO state-class transition (in any of the seven classes) can validate without a `harness_attestation` referencing it.

---

## 4. ACEF Core Payload Variant Additions

These extend existing record types via the established discriminator pattern in `acef-conventions/v1/variant-registry.json`.

### 4.1 `human_oversight_kill_switch` (V1)

**Parent**: `human_oversight_action`. **Discriminator**: `/payload/oversight_subtype` = `kill_switch`.

**Cite:** [SPEC-FRD §6.2] kill switch, [SPEC-FRD §10.5] Hard Stop Conditions.

**Payload fields.** `oversight_subtype: "kill_switch"`, `triggered_by_actor_ref`, `triggered_at`, `affected_scope_ref`, `affected_runs_refs`, `stop_classification` (enum: `manual_intervention`, `automated_safety_stop`, `policy_violation_detected`, `customer_request`), `stop_attestation_ref`.

**Test criteria.** TC1–TC7. Negative: `stop_attestation_ref` absent → ACEF-076 (state-class missing fake-green binding when paired with a state transition).

### 4.2 `regression_definition` (V2)

**Parent**: `risk_treatment`. **Discriminator**: `/payload/treatment_subtype` = `regression_definition`.

**Cite:** [SPEC-FRD §15.3] Regression Candidate Creation, [SPEC-FRD §15.4] Active Regression Promotion.

**Payload fields.** `treatment_subtype: "regression_definition"`, `regression_id` (`urn:acef:reg:<uuid>`), `source_finding_ref`, `regression_test_specification` (object: `test_kind`, `test_artifact_ref`, `expected_outcome`), `promotion_state` (enum: `candidate`, `active`, `paused`, `retired`), `promotion_attestation_ref` (REQUIRED when `promotion_state` is `active`), `cadence_binding` (object: `cadence_class`, `freshness_window`), `accepted_risk_ref` (optional).

**Test criteria.** TC1–TC7 plus a fake-green test proving `promotion_state: "active"` cannot validate without `promotion_attestation_ref` that itself binds to a fix-verification evidence record.

### 4.3 `disposition_record` (V3)

**Parent**: `risk_treatment`. **Discriminator**: `/payload/treatment_subtype` = `external_disposition`.

**Cite:** [SPEC-FRD §14.2] Disposition Model, [SPEC-FRD §14.5] Disposition Authority Matrix, [SPEC-FRD §2.7] Internal Finding Is Source of Truth, [SPEC-FRD §2.8] Customer Can Overrule Priority Not Evidence.

**Payload fields.** `treatment_subtype: "external_disposition"`, `disposition_id` (`urn:acef:disp:<uuid>`), `finding_ref`, `external_state` (object: `external_state_value`, `external_state_authority`, `external_state_observed_at`), `internal_state_unchanged` (boolean, MUST be `true` — external dispositions are advisory), `authority_check` (object: `authority_class` enum: `priority`, `severity_advisory`, `accepted_risk_request`, `false_positive_assertion`, `evidence_dispute`; `authority_granted` boolean — must follow the §14.5 matrix), `reconciliation_evidence_ref`.

**Validation rule.** `internal_state_unchanged: false` MUST cause record rejection. This enforces the doctrine that external dispositions cannot rewrite internal evidence state.

**Test criteria.** TC1–TC7 plus:
- **TC-FRD-V3-N1**: `internal_state_unchanged: false` → rejected at load.
- **TC-FRD-V3-N2**: `authority_check.authority_granted: true` for `authority_class: "evidence_dispute"` from a non-authorized actor → rejected per the §14.5 matrix.

### 4.4 `badge_state` (V4)

**Parent**: `transparency_disclosure`. **Discriminator**: `/payload/variant` = `verification_badge`.

**Cite:** [SPEC-FRD §17.2] Public Badge Phase, [SPEC-FRD §16.7] Badge Page State vs Integrity State, [SPEC-FRD §2.21] Public Surfaces Earn Their Publicness.

**Payload fields.** `variant: "verification_badge"`, `badge_id`, `subject_ref`, `page_state` (enum: `green`, `provisional`, `red`, `unsupported`, `unknown`), `integrity_state` (enum: `verified`, `failed_integrity`, `degraded`, `unverified`), `evidence_chain_root_ref` (URN of the top-level evidence the badge depends on), `freshness_state_ref` (URN of the most-recent `coverage_cell` freshness state), `provisional_reason` (REQUIRED when `page_state: "provisional"`; enum: `partial_coverage`, `pending_freshness_reconciliation`, `accepted_risk_in_effect`), `public_artifact_link` (URL, REQUIRED when `page_state` is `green` or `provisional`).

**Validation rule.** Page state and integrity state are independent enums (per §16.7). A bundle MUST permit `page_state: "green"` only when `integrity_state: "verified"` AND the freshness state is `fresh` (per the most-recent `coverage_cell`). The validator enforces this at the bundle level, not the record level.

**Test criteria.** TC1–TC7 plus:
- **TC-FRD-V4-N1**: `page_state: "green"` with `integrity_state: "failed_integrity"` → bundle rejected.
- **TC-FRD-V4-N2**: `page_state: "provisional"` without `provisional_reason` → bundle rejected.

### 4.5 `evidence_freshness_window` (V5)

**Parent**: `evidence_gap`. **Discriminator**: `/payload/gap_subtype` = `freshness_window`.

**Cite:** [SPEC-FRD §16.6] Evidence Freshness Claim-Bound Not Artifact-Bound, [SPEC-FRD §17.5.x] FreshnessCadenceBinding.

**Payload fields.** `gap_subtype: "freshness_window"`, `window_id`, `claim_ref` (URN of the claim whose freshness this expresses), `cadence_class` (enum: `daily`, `weekly`, `per_release`, `per_change`, `manual`), `max_age_seconds`, `grace_period_seconds`, `current_state` (enum: `fresh`, `stale_within_grace`, `stale_outside_grace`), `next_required_refresh_at`.

**Test criteria.** TC1–TC7 plus consistency check: `current_state: "fresh"` REQUIRES `next_required_refresh_at > now()` at validation time.

---

## 5. `x-freddy/*` Extension Namespace Specifications

Each namespace ships under `bundle.namespaces["x-freddy"]["<name>"]`. Schema files in Freddy's repo at `src/freddy/acef_extensions/schemas/<name>.v1.json`; Python models at `src/freddy/acef_extensions/models/<name>.py`. Conformance suite at `tests/conformance/freddy_extensions/`. Pattern mirrors `x-relay/*` exactly.

### 5.1 `x-freddy/persona-observation` (F1)

**Cite:** [SPEC-FRD §10] Runner Harness Requirements, [SPEC-FRD §10.7] Persona Voice Rubric, [SPEC-FRD §12.2] Event Class Enum.

**Why x-freddy (not Core).** The persona/scenario/voice-rubric model is Freddy-specific. Other agent-reliability products may have very different harness models. Goes under `x-freddy/*`.

**Fields.** `observation_id`, `persona_ref`, `persona_version`, `scenario_ref`, `scenario_seed_ref`, `run_ref`, `observation_content_digest` (post-redaction; raw never embedded), `claim_lexicon_scan_result` (object: `tokens_found` (array, MUST be empty in the customer-facing path), `scan_timestamp`, `scanner_version`), `event_class` (enum from [SPEC-FRD §12.2]), `attribution_advisory` (object: `confidence`, `caveats`), `harness_attestation_ref` (REQUIRED; the persona never writes its own state — the harness signs off).

**Validation.** `claim_lexicon_scan_result.tokens_found` non-empty AND `harness_attestation_ref` absent → ACEF-077.

### 5.2 `x-freddy/voice-rubric-emission` (F2)

**Cite:** [SPEC-FRD §10.7] Persona Voice Rubric.

**Fields.** `emission_id`, `rubric_id`, `rubric_version`, `redaction_attestation_ref` (REQUIRED and MUST temporally precede this record; voice is applied post-redaction per A10), `styled_prose_digest`, `claim_lexicon_scan_result` (same shape as F1), `rejection_state` (enum: `accepted`, `rejected_invalid_voice_rubric_emission`), `rejection_incident_ref` (REQUIRED when `rejection_state: "rejected_invalid_voice_rubric_emission"`).

**Validation.** `claim_lexicon_scan_result.tokens_found` non-empty AND `rejection_state: "accepted"` → ACEF-077 and the record is rejected (matches §10.7's strict requirement).

### 5.3 `x-freddy/roe-attestation` (F3)

**Cite:** [SPEC-FRD §6] Rules of Engagement Requirements.

**Fields.** `roe_attestation_id`, `scope_ref` (URN of the `authorized_test_scope` from §3.1), `roe_document_digest`, `roe_document_version`, `signed_by_actor_ref`, `signed_at`, `attestation_signature` (JWS), `signer_kid`.

**Note.** This is a `x-freddy` namespace because it adds Freddy-specific bookkeeping on top of the cross-vendor `authorized_test_scope`. The scope record itself is in ACEF Core (§3.1).

### 5.4 `x-freddy/freddy-internal-incident` (F4)

**Cite:** [SPEC-FRD §12.6] FreddyInternalIncident Object, [SPEC-FRD §12.7] IntegrationHealthEvent Object.

**Fields.** `incident_id`, `incident_class` (enum: `invalid_voice_rubric_emission`, `harness_failure`, `integration_health_event`, `cross_tenant_reference_detected`, `redaction_pipeline_failure`, `manifest_drift_detected`), `severity`, `detected_at`, `evidence_refs`, `escalation_state`.

**Note.** This is operator-only / internal; it MUST carry `confidentiality: "regulator-only"` or stricter, and `access_policy.roles` MUST exclude `subscriber` and any customer-facing roles.

---

## 6. Cross-Cutting Requirements

### 6.1 Test Criteria Battery

Every new record type MUST satisfy the following ten test criteria. Test IDs follow `TC<NN>` shape; the `FG` variant denotes fake-green tests.

| ID | Name | Description |
|---|---|---|
| TC1 | Positive schema validation | A golden bundle containing the record validates without error. |
| TC2 | Negative schema validation | A bundle with a missing required field, a wrong-type field, or an out-of-enum value MUST fail validation with the specific ACEF-NNN code expected. |
| TC3 | JCS round-trip | The record, when canonicalized per RFC 8785, parsed, and re-canonicalized, MUST be byte-equal. |
| TC4 | JWS sign-verify | The record (within its bundle) signed with RS256 and ES256, verified offline by the standalone verifier, MUST succeed. A tampered byte MUST cause verification failure. |
| TC5 | Merkle inclusion | The record's `record_id` MUST appear in the Merkle tree leaves and a verifiable inclusion proof MUST be derivable. |
| TC6 | Fake-green binding | For state-class records (`harness_attestation`, `finding_record`, `coverage_cell`, `regression_definition` (when active), `delivery_verdict` (when verified), `badge_state` (when green/provisional), or attestation-of-attestation): the record MUST fail validation when its required precursor evidence is absent. |
| TC7 | Determinism | A bundle produced by the ACEF Python SDK from a fixed input MUST be byte-equal on every run (deterministic ordering, JCS canonicalization, gzip with mtime=0/OS=0xFF). Cross-language parity is out of scope for this brief — see note below. |
| TC8 | Precursor construction blocker | (State-class records only) A direct attempt to construct the state without precursor evidence URNs MUST raise an SDK-level error before serialization, not just at validation time. |
| TC9 | Tampered precursor rejection | (State-class records only) A bundle whose `bound_evidence_refs` URN content has been altered post-signature MUST cause signature verification failure, not just hash-comparison failure. |
| TC10 | Read-back verification | (`delivery_verdict` only) A bundle claiming `verified_delivered` whose `read_back.read_back_digest` does not byte-equal `write_attempt.request_digest` MUST emit ACEF-072 and fail validation. |

**Note on cross-language parity.** The ACEF reference SDK is Python-only (per [SPEC-ACEF §1] and `pyproject.toml`'s `requires-python = ">=3.11"`). Cross-language byte-equality of ACEF bundles is an explicit non-goal of this brief — it is owned by downstream language SDK projects (Relay's `sdk-typescript` and `verifier-typescript`, and any future community-contributed ACEF TypeScript/Go/Java SDKs per the ACEF roadmap Phase 5). Relay's vendor-pin update workflow (see §8.3) re-runs the Python ↔ TypeScript parity tests inside Relay's own conformance suite after each pin bump. ACEF Core acceptance does not depend on TypeScript output existing.

### 6.2 X1 `redaction_policy_version` — Required Envelope Field

**Cite:** [SPEC-FRD §2.10] Product Telemetry Must Be Privacy-Safe, [SPEC-FRD §19] (privacy and telemetry section).

**Requirement.** Add to `acef-conventions/v1/record-envelope.schema.json` as a top-level property:

```json
"redaction_policy_version": {
  "type": "string",
  "description": "Semver-shaped version of the redaction policy that produced this record's content. Required when confidentiality is not 'public'. The policy contents must be retrievable from the bundle (in artifacts/) or via an external URN referenced in the manifest."
}
```

Conditional requirement (allOf in the envelope):

```json
{
  "if": {
    "properties": {"confidentiality": {"not": {"const": "public"}}}
  },
  "then": {"required": ["redaction_policy_version"]}
}
```

**Validation.** Missing `redaction_policy_version` on a non-public record → ACEF-074.

**Test criteria.** TC1, TC2 (negative: missing field on a `redacted` record).

### 6.3 X2 `redaction_attestation_ref` — Required Envelope Field

**Cite:** Same as X1.

**Requirement.** Add as top-level envelope property. URN reference. Required when `confidentiality != "public"`. References an attestation record proving the redaction policy was actually executed against the source content. Prevents "claimed redacted, actually raw" bundles.

**Test criteria.** TC1, TC2, TC6 (the referenced URN MUST exist in the bundle or be a fully-qualified external URN). TC-FRD-X2-FG: A bundle claiming `confidentiality: "redacted"` whose `redaction_attestation_ref` points to an absent URN MUST fail validation with ACEF-022.

### 6.4 X3 `tenant_label` — Required Envelope Field

**Cite:** [SPEC-FRD §2.19] Deduplication / cross-customer boundary, [SPEC-FRD §12.8] Cross-Customer Boundary Generalized Learning.

**Requirement.** Add as top-level envelope property, required on every record:

```json
"tenant_label": {
  "type": "string",
  "pattern": "^urn:acef:tenant:[a-z0-9-]{3,64}$",
  "description": "Stable tenant identifier. Two records in the same bundle MUST have the same tenant_label. Cross-tenant references MUST be rejected at the bundle level."
}
```

**Validation rule.** Two distinct `tenant_label` values within a single bundle → ACEF-075 (fatal). Reference integrity (existing ACEF-020) also enforces: a URN reference whose owning record has a different `tenant_label` is fatal.

**Test criteria.** TC1, TC2, TC7. TC-FRD-X3-N1: Mixed tenants in one bundle → ACEF-075. TC-FRD-X3-N2: A record's `entity_refs` URN that resolves to a record with a different `tenant_label` → ACEF-020.

### 6.5 X4 `causation_chain` — Optional Envelope Field, Strongly Recommended

**Cite:** [SPEC-FRD §10.6] Prove-It / Attestation Layer.

**Requirement.** Add as top-level envelope property:

```json
"causation_chain": {
  "type": "array",
  "items": {
    "type": "string",
    "description": "URN of an upstream record that caused this record. Order is most-recent-first."
  },
  "description": "Ordered upstream-record URNs that caused this record. Strongly recommended for state-class records; required for harness_attestation."
}
```

For `harness_attestation` (§3.6), this field is REQUIRED with at least one element.

**Validation.** Each URN in `causation_chain` MUST exist in the bundle or be a fully-qualified external URN. Missing → ACEF-073.

### 6.6 X5 `analysis_mode` — Required Manifest Field

**Cite:** [SPEC-FRD §4] Product Modes, [SPEC-FRD §4.1] Public Artifact Mode, [SPEC-FRD §4.2] Subscriber Mode, [SPEC-FRD §4.3] Internal Canary Mode.

**Requirement.** Add to `acef-conventions/v1/manifest.schema.json` as a top-level required property:

```json
"analysis_mode": {
  "enum": ["subscriber", "public_artifact", "canary", "unattributed_artifact"],
  "description": "Determines which evidence guarantees apply. Validators MUST apply mode-appropriate gates."
}
```

**Mode-dependent validation rules** (validators MUST enforce):

- `subscriber`: full guarantees. All record types valid. `authorized_test_scope`, `harness_attestation` required at the bundle level.
- `public_artifact`: no `delivery_verdict`, no `disposition_record`, no `accepted_risk_ref`. `attribution_advisory.confidence` MUST be `low` or `medium` on all `persona_observation` records.
- `canary`: no customer-facing records allowed (`badge_state` MUST be `unsupported`). Used for internal Freddy testing only.
- `unattributed_artifact`: stricter than `public_artifact`. No attribution. Used for the prospect-side teaser surface.

**Test criteria.** TC1, TC2 per mode. TC-FRD-X5-N1: a `public_artifact` bundle containing a `delivery_verdict` → rejected.

### 6.7 X6 `state_class` — Enumerated Taxonomy

**Cite:** [SPEC-FRD §10.6] Prove-It Doctrine, [SPEC-FRD §24.5] Fake-Green Test Requirement.

**Requirement.** Publish in ACEF Profiles a small JSON document at `acef-conventions/v1/state-class-taxonomy.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://acef.ai/schemas/v1/state-class-taxonomy.json",
  "title": "ACEF State Class Taxonomy",
  "type": "object",
  "required": ["state_classes"],
  "properties": {
    "state_classes": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["state_class_id", "description", "fake_green_test_required", "required_bound_evidence_types"],
        "properties": {
          "state_class_id": {"enum": ["step", "finding", "coverage_cell", "regression", "delivery", "badge", "attestation"]},
          "description": {"type": "string"},
          "fake_green_test_required": {"type": "boolean"},
          "required_bound_evidence_types": {
            "type": "array",
            "items": {"type": "string"}
          }
        }
      }
    }
  }
}
```

The seven enum values map exactly to [SPEC-FRD §24.5]'s state classes. Every `harness_attestation` MUST cite one of these values; values outside the enum → ACEF-076.

**Test criteria.** TC1, TC2. TC-FRD-X6-FG: a `harness_attestation` whose `state_class` is outside the enum → record rejected.

---

## 7. Conformance Suite Additions

ACEF currently has `test-vectors/` directories per regulation. Add `test-vectors/freddy/` mirroring the pattern.

### 7.1 Directory layout

```
test-vectors/freddy/
├── pass/
│   ├── subscriber-mode-full-loop.acef/
│   ├── public-artifact-mode.acef/
│   ├── canary-mode.acef/
│   ├── verified-delivery.acef/
│   ├── regression-active-with-fix-verification.acef/
│   ├── badge-green-with-fresh-coverage.acef/
│   ├── badge-provisional-with-reason.acef/
│   ├── accepted-risk-disposition.acef/
│   └── multi-finding-with-dedupe-collapse.acef/
├── fail/
│   ├── verified-delivery-without-readback/        # → ACEF-071
│   ├── verified-delivery-digest-mismatch/         # → ACEF-072
│   ├── harness-attestation-empty-evidence/        # → ACEF-070
│   ├── harness-attestation-persona-as-verifier/   # → record rejected at load
│   ├── badge-green-with-failed-integrity/         # → bundle rejected
│   ├── cross-tenant-references-in-one-bundle/     # → ACEF-075
│   ├── voice-rubric-with-claim-token/             # → ACEF-077
│   ├── scope-boundary-event-without-stop-attest/  # → schema allOf rejection
│   ├── external-disposition-overrides-internal/   # → record rejected at load
│   ├── public-artifact-with-delivery-verdict/     # → mode-violation rejection
│   └── non-public-record-without-redaction-pol/   # → ACEF-074
└── fake-green/
    ├── cannot-reach-step-without-evidence/
    ├── cannot-reach-finding-without-evidence/
    ├── cannot-reach-coverage-cell-without-evidence/
    ├── cannot-reach-active-regression-without-fix-verification/
    ├── cannot-reach-verified-delivery-without-readback/
    ├── cannot-reach-green-badge-without-fresh-coverage/
    └── cannot-reach-attestation-without-precursor-attestation/
```

### 7.2 Test vector content rules

Every `test-vectors/freddy/*/` bundle MUST:

- Carry a `README.md` at the root naming the requirement it exercises and the test criterion ID (TC1, TC-FRD-NNN, etc.).
- Pass JCS canonicalization round-trip (TC3).
- Pass determinism (TC7) — regenerated twice by the ACEF Python SDK from the same input, the bundle MUST be byte-equal across both runs.
- For `fail/` bundles: include in the README the exact ACEF-NNN code expected and the validator path to reach it.
- For `fake-green/` bundles: include in the README the precursor evidence that is intentionally absent, and the assertion that proves the state cannot be reached without it.

### 7.3 Conformance script additions

Extend `tests/conformance/` (Python — ACEF's only SDK surface) with:

- `test_freddy_pass_vectors.py` — iterates `pass/`, validates each, asserts no errors.
- `test_freddy_fail_vectors.py` — iterates `fail/`, validates each, asserts the specific ACEF-NNN code is emitted.
- `test_freddy_fake_green_vectors.py` — iterates `fake-green/`, validates each, asserts the bundle FAILS (the whole point — the state cannot be reached without evidence).
- `test_freddy_determinism.py` — for each `pass/` bundle, regenerates from the same input twice and asserts byte-equality across both runs. Determinism, not cross-language parity.

All four new test files MUST run inside ACEF's existing plumbing tier (≤60s budget; [SPEC-ACEF AM.6]) and contribute to `tests/baseline-counts.json`.

**Out of scope for ACEF Core acceptance:** TypeScript-side conformance. Relay maintains its own per-bundle Python ↔ TypeScript byte-equality tests inside `epochly-relay/relay/packages/sdk-typescript/test/` and `epochly-relay/relay/packages/verifier-typescript/test/`. Those tests re-run after Relay bumps the vendor pin to ACEF v0.4 (per §8.3) and are owned by the Relay team, not by ACEF.

### 7.4 Conformance documentation

Add `docs/CONFORMANCE.md` section: "Freddy Profile Conformance" — describes the analysis modes, the state-class taxonomy, and the test vector battery. Standards-friendly language; no Freddy-product marketing copy.

---

## 8. Backward Compatibility and Migration

### 8.1 Compatibility commitments

1. All existing ACEF v0.3 record types continue to validate without modification.
2. All existing `test-vectors/` (china-cac, eu-ai-act, eu-gpai-cop, nist-rmf) continue to pass.
3. All existing variant-registry entries continue to resolve.
4. The new cross-cutting envelope fields (X1–X4) are **conditional-required**, not absolute-required, on existing record types — they become required only when `confidentiality != "public"` (X1, X2), when a new state-class record is present (X4 for `harness_attestation`), or when the validator runs in `subscriber`/`public_artifact`/`canary` mode (X3, X5, X6 require the new manifest field).
5. The `acef-NNN` error taxonomy extension (ACEF-070..ACEF-077) is purely additive.
6. The `acef-conventions/v1/` path remains stable. New schemas land alongside existing ones, not in a v2 subdirectory.

### 8.2 Migration path for existing ACEF consumers

Existing ACEF consumers (ones that do not implement Freddy or another agent-reliability product) see:

- A new optional envelope property they can ignore.
- A new manifest property `analysis_mode` they need to set; default `subscriber` is safe for existing producers.
- New schemas for record types they will not emit; safely ignorable.
- New error codes they will not emit; safely ignorable.

### 8.3 Vendor pin update implications for Relay

Relay's `epochly-relay/relay/packages/acef/upstream/` is currently pinned at ACEF commit `57e1d14e063d3a2a88bfe5361fd81ca02bc6d540`. When ACEF v0.4 ships with these additions, Relay must:

1. Bump the pin via the documented workflow in `epochly-relay/relay/packages/acef/README.md`.
2. Recompute `vendor_tree_sha256` per the recipe.
3. Update `vendor_manifest.json` (`commit_sha`, `commit_date`, `maturity`).
4. Update the W11 vendor-drift guards in `tests/conformance/` to assert against the new pin.
5. Implement TypeScript parity for the new record types in `epochly-relay/relay/packages/sdk-typescript/` and `epochly-relay/relay/packages/verifier-typescript/`, and add per-record-type Python ↔ TypeScript byte-equality tests to Relay's own conformance suite. This is Relay's work, not ACEF's — TypeScript is not in ACEF's reference SDK scope.
6. Optionally collapse some of `relay_extensions/models/*.py` if their concepts have been promoted to ACEF Core (specifically `contract_gate_result` may be subsumed by `harness_attestation` with `verifier_class: "contract_gate"`).

---

## 9. Acceptance Criteria

Each requirement carries a stable assertion ID `FRD-ACEF-NNN`. ACEF maintainers MUST treat these as the bar for "done" on this requirements brief. CI MUST gate on all of them passing before tagging ACEF v0.4.

### 9.1 ACEF Core record type acceptance

| Assertion ID | Requirement | Acceptance criterion |
|---|---|---|
| FRD-ACEF-001 | `authorized_test_scope` schema exists | `acef-conventions/v1/authorized_test_scope.schema.json` validates against JSON Schema 2020-12. |
| FRD-ACEF-002 | `authorized_test_scope` enforces production-capable rule | TC-FRD-001-N1 passes (negative test). |
| FRD-ACEF-003 | `authorized_test_scope` enforces kill_switch_ref | TC-FRD-001-N2 passes. |
| FRD-ACEF-004 | `scope_boundary_event` schema exists | File present, validates. |
| FRD-ACEF-005 | `scope_boundary_event` enforces stop-attestation pairing | TC-FRD-002-N1 + TC-FRD-002-FG pass. |
| FRD-ACEF-006 | `finding_record` schema exists | File present, validates. |
| FRD-ACEF-007 | `finding_record` enforces evidence binding | TC-FRD-003-FG passes. |
| FRD-ACEF-008 | `finding_record` produces stable dedupe_key | TC-FRD-003-DEDUPE passes (Python ↔ TS parity). |
| FRD-ACEF-009 | `delivery_verdict` schema exists | File present, validates. |
| FRD-ACEF-010 | `delivery_verdict` enforces read-back | TC-FRD-004-N1 + TC-FRD-004-N2 + TC-FRD-004-FG pass. |
| FRD-ACEF-011 | `coverage_cell` schema exists | File present, validates. |
| FRD-ACEF-012 | `coverage_cell` enforces claim language vocabulary | Bundle with banned token in `claim_language` → ACEF-053. |
| FRD-ACEF-013 | `harness_attestation` schema exists | File present, validates. |
| FRD-ACEF-014 | `harness_attestation` rejects persona/llm as verifier | TC-FRD-006-N3 passes — record rejected AT LOAD, not just at validation. |
| FRD-ACEF-015 | `harness_attestation` enforces fake-green binding | TC-FRD-006-N2 + TC-FRD-006-FG pass. |

### 9.2 Variant acceptance

| Assertion ID | Requirement | Acceptance criterion |
|---|---|---|
| FRD-ACEF-020 | V1 `human_oversight_kill_switch` registered | Entry in `variant-registry.json`. Sample bundle validates. |
| FRD-ACEF-021 | V2 `regression_definition` registered | Same; promotion-state fake-green test passes. |
| FRD-ACEF-022 | V3 `disposition_record` rejects internal_state_unchanged=false | TC-FRD-V3-N1 passes. |
| FRD-ACEF-023 | V3 `disposition_record` enforces authority matrix | TC-FRD-V3-N2 passes. |
| FRD-ACEF-024 | V4 `badge_state` enforces page/integrity coherence | TC-FRD-V4-N1 passes. |
| FRD-ACEF-025 | V4 `badge_state` enforces provisional_reason | TC-FRD-V4-N2 passes. |
| FRD-ACEF-026 | V5 `evidence_freshness_window` enforces freshness/refresh consistency | Bundle with `current_state: "fresh"` and stale `next_required_refresh_at` rejected. |

### 9.3 Cross-cutting acceptance

| Assertion ID | Requirement | Acceptance criterion |
|---|---|---|
| FRD-ACEF-030 | X1 `redaction_policy_version` enforced on non-public records | ACEF-074 emitted on negative bundle. |
| FRD-ACEF-031 | X2 `redaction_attestation_ref` enforced | Missing referenced URN → ACEF-022. |
| FRD-ACEF-032 | X3 `tenant_label` enforced bundle-wide | Mixed-tenant bundle → ACEF-075. |
| FRD-ACEF-033 | X3 cross-tenant reference rejected | Cross-tenant URN reference → ACEF-020. |
| FRD-ACEF-034 | X4 `causation_chain` required on harness_attestation | Missing field on attestation → record rejected. |
| FRD-ACEF-035 | X5 `analysis_mode` required on manifest | Manifest without field → ACEF-002. |
| FRD-ACEF-036 | X5 mode-gated rules enforced | Cross-mode violation → bundle rejected. |
| FRD-ACEF-037 | X6 state-class taxonomy published | `state-class-taxonomy.json` exists; out-of-enum value → ACEF-076. |

### 9.4 Error taxonomy acceptance

| Assertion ID | Requirement | Acceptance criterion |
|---|---|---|
| FRD-ACEF-040 | ACEF-070 added | Code in `ERROR_REGISTRY`, severity FATAL, category INTEGRITY. |
| FRD-ACEF-041 | ACEF-071 added | Same as above. |
| FRD-ACEF-042 | ACEF-072 added | Same. |
| FRD-ACEF-043 | ACEF-073 added | Same; category REFERENCE. |
| FRD-ACEF-044 | ACEF-074 added | Severity ERROR, category SCHEMA. |
| FRD-ACEF-045 | ACEF-075 added | Severity FATAL, category REFERENCE. |
| FRD-ACEF-046 | ACEF-076 added | Severity ERROR, category SCHEMA. |
| FRD-ACEF-047 | ACEF-077 added | Severity FATAL, category INTEGRITY. |
| FRD-ACEF-048 | All eight new codes documented in ACEF spec | Spec §3.6 Error Taxonomy table updated. |

### 9.5 Conformance suite acceptance

| Assertion ID | Requirement | Acceptance criterion |
|---|---|---|
| FRD-ACEF-050 | `test-vectors/freddy/pass/` complete | All nine pass bundles present, README present, each validates clean. |
| FRD-ACEF-051 | `test-vectors/freddy/fail/` complete | All eleven fail bundles present, each emits the expected ACEF-NNN. |
| FRD-ACEF-052 | `test-vectors/freddy/fake-green/` complete | All seven state classes covered, each bundle fails validation. |
| FRD-ACEF-053 | Conformance scripts pass | `test_freddy_pass_vectors.py`, `test_freddy_fail_vectors.py`, `test_freddy_fake_green_vectors.py`, `test_freddy_determinism.py` all green. |
| FRD-ACEF-054 | Determinism verified for all new types | Each new record type has a determinism test asserting byte-equal output across repeated Python SDK runs of the same input. Cross-language parity is out of scope for ACEF acceptance — owned by Relay (§8.3). |
| FRD-ACEF-055 | Baseline counts updated | `tests/baseline-counts.json` increments reflect the new tests. |
| FRD-ACEF-056 | Plumbing-tier budget preserved | Total new test runtime ≤ 30 seconds in tier 1 (per [SPEC-ACEF AM.6] budget headroom). |

### 9.6 Compatibility acceptance

| Assertion ID | Requirement | Acceptance criterion |
|---|---|---|
| FRD-ACEF-060 | Existing test vectors continue passing | All v0.3 test-vectors validate clean against the v0.4 SDK. |
| FRD-ACEF-061 | Existing variant registry unchanged | Diff is purely additive. |
| FRD-ACEF-062 | Existing error codes unchanged | ACEF-001..ACEF-060 registry untouched. |
| FRD-ACEF-063 | Relay vendor-drift guards remain valid after pin bump | After Relay bumps the pin to v0.4, `tests/conformance/` in Relay re-runs green. |

### 9.7 Documentation acceptance

| Assertion ID | Requirement | Acceptance criterion |
|---|---|---|
| FRD-ACEF-070 | ACEF spec §3 updated with new record types | Spec contains schema diagrams, field semantics, and examples for `authorized_test_scope`, `scope_boundary_event`, `finding_record`, `delivery_verdict`, `coverage_cell`, `harness_attestation`. |
| FRD-ACEF-071 | ACEF spec §2 (regulation alignment) updated | New record types mapped to applicable EU AI Act / NIST RMF / GPAI CoP provisions in the cross-regulation alignment matrix. |
| FRD-ACEF-072 | `docs/CONFORMANCE.md` updated | New "Freddy Profile Conformance" section present. |
| FRD-ACEF-073 | `docs/USER_GUIDE.md` updated | At least one worked example per new record type. |
| FRD-ACEF-074 | Migration notes for v0.3 → v0.4 consumers | One-page migration doc at `docs/MIGRATION-v0.3-to-v0.4.md`. |

---

## 10. Design Decisions Pinned in This Brief

Every design choice that shaped this brief is recorded here with its rationale. The body of the brief implements these decisions — this section is the reader's index for why the spec looks the way it does. If an ACEF maintainer disagrees with any pinned decision, the disagreement is resolved by amending this section and the corresponding spec body before v0.4 freeze, not by leaving the decision unresolved.

### D1 — `harness_attestation` lives in ACEF Core, not Profiles

The Prove-It Doctrine (one signed attestation per state transition, bound to required evidence) is foundational to any agent-reliability or compliance-testing product, not regulation-specific. Splitting bundle-level signing (already in `src/acef/signing.py`) from transition-level attestation across two modules creates an artificial seam. Core. Implemented in §3.6.

### D2 — `authorized_test_scope` is a standalone Core record type, not a `governance_policy` variant

`governance_policy` describes organizational policy artifacts (training programs, role definitions, AI use case inventory entries). Test scope is operational, not governance. Forcing it into `governance_policy` produces misleading auditor semantics and crowds the variant registry with concepts that share no real schema. Standalone record type. Implemented in §3.1.

### D3 — `state_class` is a hard-coded enum in v0.4, not a community-extensible registry

The seven values from [SPEC-FRD §24.5] are the only state classes any consumer currently needs. Premature abstraction to a registry pattern, without a second consumer's state classes in hand, locks in design choices that may turn out wrong. The enum can be promoted to a registry in v0.5+ when (and only when) a second consumer arrives with materially different state classes; backward compatibility is straightforward because existing values remain valid. Implemented in §3.6 and §6.7.

### D4 — ACEF Core does not ship a Freddy-specific signer; consumers bring their own signing identity

`src/acef/signing.py` already provides JWS RS256/ES256 sign and verify helpers operating on JCS-canonicalized input. That primitive surface is sufficient for both `harness_attestation` and `delivery_verdict`. The signing *identity* (JWKS URL, key, `kid`) is operational and customer-specific and therefore belongs in the consumer's runtime, not the standard. No change to ACEF beyond confirming the existing signing API accepts the new record-type payloads.

### D5 — `dedupe_key` is fully normative — recipe and hash algorithm

The four-field canonical recipe (`class`, `subject_ref`, `expected_behavior`, `reproduction_steps_ref_content_hash`) under RFC 8785 (JCS), hashed with sha256, prefix `sha256:`. No hash agility in v0.4 — sha256 matches every other content-addressed identifier in ACEF v0.3 (every existing schema uses `^sha256:[0-9a-f]{64}$`), and cross-vendor dedupe determinism matters more than future hash flexibility. Hash migration, when cryptographic events demand it, will be a separate spec bump. Implemented in §3.3.

### D6 — Regulation mappings for `finding_record` ship in the per-regulation templates in this same release

`finding_record` is accepted as evidence for Article 9 (risk management) and Article 15 (accuracy / robustness / cybersecurity) — and MEASURE 2.x / MANAGE 4.x in NIST — via the §4 alignment matrix mappings and the v1.1 validation rules (`src/acef/validation/v1_1_rules.py`, conformance corpus `test-vectors/freddy/`), NOT by editing the general per-regulation templates (`src/acef/templates/eu-ai-act-2024.json`, `src/acef/templates/nist-ai-rmf-1.0.json`), which are unchanged. The binding ships in v0.4, not as a follow-on; otherwise `finding_record` exists in Core but the regulations cannot consume it.

### D7 — The subscriber-mode full-loop golden bundle is mandatory in the conformance suite

`test-vectors/freddy/pass/subscriber-mode-full-loop.acef/` is the canonical reference for "what a complete Freddy run looks like in ACEF" and is required, not optional. It is the bundle every new ACEF consumer reads first to understand how the new record types compose. Listed in §7.1 and required by FRD-ACEF-050.

---

## Appendix A — Already Satisfied by ACEF v0.3

For traceability. The following Freddy requirements are already met by the existing ACEF spec or reference SDK and require NO changes.

| Freddy spec citation | ACEF artifact that satisfies it |
|---|---|
| [SPEC-FRD §2.16] Evidence is permanent | ACEF bundle's content-addressed Merkle integrity model. |
| [SPEC-FRD §11.1] Evidence Levels (1/2/3) | ACEF record envelope's `confidentiality` and `access_policy` fields. |
| [SPEC-FRD §11.6] OpenTelemetry trace ingestion | ACEF `event_log` payload variant `logging_spec`. |
| [SPEC-FRD §2.10] Privacy-safe telemetry | ACEF redaction model (envelope `redaction_method`), strengthened by X1/X2 above. |
| [SPEC-FRD §9.4] Activation states | ACEF `transparency_disclosure` record type covers public surface state already. |
| [SPEC-FRD §12.2] Event class enum | Maps cleanly onto ACEF `event_log` variants; F1 `persona-observation` reuses the event_class taxonomy. |
| [SPEC-FRD §11.3] Two-stage evidence commit | ACEF bundle's execution-evidence vs delivery-evidence separation supported via two bundles linked by URN. |
| [SPEC-FRD signing] | ACEF's JWS (RS256/ES256) via `src/acef/signing.py`. |
| [SPEC-FRD canonicalization] | ACEF's JCS (RFC 8785) via `src/acef/integrity.py`. |
| [SPEC-FRD verifiability] | ACEF's offline verifier (Python; `src/acef/`). Downstream consumers that need additional language coverage own their own ports — Relay maintains a TypeScript verifier at `epochly-relay/relay/packages/verifier-typescript/`. |

---

## Appendix B — Glossary

| Term | Definition |
|---|---|
| **State class** | One of the seven harness state classes Freddy mandates fake-green coverage for: step, finding, coverage_cell, regression, delivery, badge, attestation. |
| **Fake-green test** | A test proving a state cannot be reached without its required precursor evidence. Required by [SPEC-FRD §24.5]. |
| **Three-anchor handoff** | The (scope_id, actor_identity_hash, manifest_commit_hash) tuple that every Freddy/Relay handoff carries. |
| **Prove-It Doctrine** | Every green state requires `claim → required evidence → verifier → attestation → signed state transition`. Per [SPEC-FRD §2.12]. |
| **Read-back verification** | Reading the delivered object from the destination and matching its content digest against the write digest. Per [SPEC-FRD §2.17]. |
| **Causation chain** | Ordered list of upstream record URNs that caused a given record. New envelope field per §6.5. |
| **Tenant label** | Stable per-customer identifier enforcing bundle-level isolation. New envelope field per §6.4. |
| **Analysis mode** | One of `subscriber`, `public_artifact`, `canary`, `unattributed_artifact`. New manifest field per §6.6. |
| **Voice rubric** | Per-persona prose-style instruction layer applied post-redaction. Per [SPEC-FRD §10.7]. |
| **Disposition** | Customer-asserted classification of a finding. Advisory; never overrides internal evidence state. Per [SPEC-FRD §14.2]. |

---

*End of requirements brief. Acceptance is by the ACEF maintainers; Freddy is one consumer among potentially many.*
