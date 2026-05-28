# subscriber-mode-full-loop

**Requirement:** Brief §7.1 (canonical reference) + VAL-CONFORMANCE-004
**Test criterion ID:** VAL-CONFORMANCE-001 (pass), VAL-CONFORMANCE-004 (inventory)
**Expected code:** none (pass bundle MUST validate clean)

This is the canonical reference bundle for ACEF v0.4 / Freddy Profile.
It exercises every new v1.1 record type:

- authorized_test_scope (1 record)
- scope_boundary_event (1 record, soft — no hard_stop)
- finding_record (1 record, dedupe_key auto-computed per brief §3.3)
- delivery_verdict (2 records — one dispatched, one verified_delivered with read-back triple)
- harness_attestation (1 record, RS256 signed_fields scope normative)

…AND every new variant discriminator (per F-M1-VARIANTS):

- human_oversight_action / kill_switch (V1)
- risk_treatment / regression_definition (V2)
- risk_treatment / external_disposition (V3)
- transparency_disclosure / verification_badge (V4)
- evidence_gap / freshness_window (V5)

A sibling Assessment Bundle carries the coverage_cell entry
(coverage_cell lives in the assessment bundle per VAL-SCHEMA-006).
