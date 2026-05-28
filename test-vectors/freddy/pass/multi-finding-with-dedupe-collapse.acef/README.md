# multi-finding-with-dedupe-collapse

**Requirement:** Brief §3.3 dedupe_key normative recipe + VAL-SDK-003
**Test criterion ID:** VAL-CONFORMANCE-001
**Expected code:** none

Two finding_records with identical (class, subject_ref,
expected_behavior, reproduction_steps_ref_content_hash) produce
BYTE-EQUAL dedupe_key strings. The bundle still validates clean —
collapse is a downstream concern, the bundle just carries the shared
dedupe_key for the assessment phase to group on.
