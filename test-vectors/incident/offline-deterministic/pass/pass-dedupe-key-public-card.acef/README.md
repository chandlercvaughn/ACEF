# Public card carries a correct §5.5 incident_dedupe_key

A PUBLISHED public incident_card carrying a correct cross-database `incident_dedupe_key` = `sha256:` + hex(SHA-256(JCS({value_chain_role, subject_identity, harm_class, occurrence_date_utc}))) (§5.5). The subject_identity is the NFC-normalized + case-folded `provider|name|version` triple of the affected subject. Emitting the subject-bearing key on a PUBLIC record is conformant — no ACEF-086. The driver independently recomputes the recipe and asserts the emitted value byte-for-byte.

**Expected code(s):** none (pass)
