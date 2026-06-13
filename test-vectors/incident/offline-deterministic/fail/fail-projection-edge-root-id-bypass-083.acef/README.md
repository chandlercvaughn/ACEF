# public_projection_of report root-id masks divergent card_source id (ACEF-083)

A non-public incident_report (source) and a public incident_card (target) linked report→card by a typed `public_projection_of` edge. The report carries a ROOT `public_incident_id` that MATCHES the card, but its AUTHORITATIVE `card_source.public_incident_id` DIFFERS (both individually pattern-valid). The §5.7 shared-id check extracts the report's id from `card_source` BY RECORD TYPE, so the matching root id MUST NOT mask the divergent card_source id → ACEF-083. Both record-URN endpoints resolve, so no ACEF-020 is raised.

**Expected code(s):** ACEF-083
