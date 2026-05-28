# non-public-record-without-redaction-pol

**Requirement:** Brief §X1 redaction_policy_version required for non-public records
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-074

Bundle has a record with confidentiality='redacted' but no
redaction_policy_version. Validator's enforce_redaction_policy_version
emits ACEF-074.
