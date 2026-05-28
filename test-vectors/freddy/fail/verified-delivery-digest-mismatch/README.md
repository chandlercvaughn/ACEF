# verified-delivery-digest-mismatch

**Requirement:** Brief §3.4 read_back digest must byte-equal write digest
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-072

The bundle's delivery_verdict has read_back.digest_match=true (so the
schema allOf is satisfied) BUT the read_back_digest does not byte-equal
write_attempt.request_digest. Validator's
enforce_delivery_verdict_integrity emits ACEF-072.
