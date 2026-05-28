# harness-attestation-empty-evidence

**Requirement:** Brief §3.6 empty bound_evidence_refs emits ACEF-070
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-070

The bundle's harness_attestation declares state_class='finding' but
carries an empty bound_evidence_refs array. A state-class attestation
without any binding is structurally unverifiable.
Validator's enforce_harness_evidence_binding emits ACEF-070.
