# Non-public record OMITS the subject-bearing incident_dedupe_key

A confidential (regulator-only) source-backed incident_report that correctly OMITS `incident_dedupe_key` (§5.5 Q20 confidentiality MUST). Three of the four dedupe inputs are low-entropy, so a published unsalted key over a non-public subject would be offline-enumerable — the subject-bearing key MUST NOT appear on a non-public record. No ACEF-086.

**Expected code(s):** none (pass)
