# public-artifact-mode

**Requirement:** Brief §6.6 (analysis_mode=public_artifact) + VAL-CONFORMANCE-001
**Test criterion ID:** VAL-CONFORMANCE-001
**Expected code:** none

A v1.1 bundle declaring `analysis_mode: "public_artifact"`. Contains
authorized_test_scope, finding_record, harness_attestation. Per brief
§6.6 / plan WS3.9, public_artifact forbids delivery_verdict and any
disposition_record (external_disposition variant) — this bundle omits
both.
