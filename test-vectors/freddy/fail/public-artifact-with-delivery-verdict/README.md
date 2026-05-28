# public-artifact-with-delivery-verdict

**Requirement:** Brief §6.6 — public_artifact forbids delivery_verdict
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-080

Bundle declares analysis_mode='public_artifact' but contains a
delivery_verdict record. Validator's enforce_mode_gated_forbidden_types
emits ACEF-080.
