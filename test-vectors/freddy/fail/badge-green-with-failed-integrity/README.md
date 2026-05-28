# badge-green-with-failed-integrity

**Requirement:** Brief §7.1 — bundle with failed integrity is rejected
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-014

Bundle's content-hashes.json declares zeros for the record files but
the actual file content hashes to non-zero. Validator's integrity
checker emits ACEF-014 (content hash mismatch).

Code choice: ACEF-014 is the documented integrity-hash-mismatch code
in the pre-v1.1 registry. Per dispatch prompt "ACEF-080 if mode
violation; otherwise a freshness/integrity error such as ACEF-014 —
document choice": this bundle has no mode violation, so ACEF-014.
