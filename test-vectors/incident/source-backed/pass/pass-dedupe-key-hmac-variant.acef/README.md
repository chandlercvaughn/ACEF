# Keyed incident_dedupe_key_hmac on a non-public record (redacted-subject dedupe)

A confidential (regulator-only) source-backed incident_report carrying ONLY the pepper-keyed `incident_dedupe_key_hmac` = `hmac-sha256:` + hex(HMAC-SHA-256(pepper, JCS(K))) over the SAME 4-key preimage K as the plaintext key (§5.5). The keyed variant is the redacted-subject dedupe path: because it is pepper-keyed (held by the §5.3 resolver) it is NOT enumerable, so the public-only omit rule does NOT apply and a non-public record MAY carry it. No ACEF-086. The driver independently recomputes the HMAC and asserts byte-equality.

**Expected code(s):** none (pass)
