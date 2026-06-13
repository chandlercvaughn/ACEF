# Malformed incident_dedupe_key_hmac shape on a report (ACEF-086)

A source-backed incident_report whose `incident_dedupe_key_hmac` is malformed (an under-length, non-64-hex digest). The v1.1 incident_report schema has additionalProperties:true and does NOT constrain this property, so the schema phase silently accepts the bad value; the validator RULE enforces the shape `hmac-sha256:` + 64 lowercase hex (mirrored from incident_card.schema.json) and raises ACEF-086 (the reserved §5.5/§5.11 code), NEVER ACEF-022. Recompute the value over the canonical preimage, or remove it.

**Expected code(s):** ACEF-086
