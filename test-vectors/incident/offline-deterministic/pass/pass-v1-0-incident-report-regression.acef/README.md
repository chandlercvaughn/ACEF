# v1.0 incident_report regression under core_version 1.0.0 (§5.10/§6)

A v1.0-shape incident_report (incident_type / severity / description, with the v1.0 notification_timeline) carrying NO v1.1-only card_source, in a bundle declaring core_version 1.0.0. The schema-version gate routes 1.0.0 to the frozen v1/ incident_report schema and the v1.1 incident rules do not apply, so the record validates CLEAN — no ACEF-081..088. This is the §5.10/§6 additive-superset backward-compatibility regression: a v1.0 report keeps validating under 1.0.0.

**Expected code(s):** none (pass)
