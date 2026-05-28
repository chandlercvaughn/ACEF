# verified-delivery-without-readback

**Requirement:** Brief §3.4 verified_delivered requires read_back triple
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-071

The bundle declares delivery_state='verified_delivered' but omits both
read_back and harness_attestation_ref. The validator's
enforce_delivery_verdict_integrity emits ACEF-071. (Schema allOf may
ALSO emit ACEF-004 for the missing required fields; the conformance
driver asserts ACEF-071 is present.)
