# harness-attestation-persona-as-verifier

**Requirement:** Brief §3.6 persona/llm verifier banned (VAL-LOAD-001)
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-070

The bundle's harness_attestation declares verifier_class='persona' —
banned per brief §3.6 because persona verifiers lack determinism.
Loader rejects this at load time (LoadRejection); validator's
enforce_harness_verifier_class mirrors the rejection with ACEF-070.
