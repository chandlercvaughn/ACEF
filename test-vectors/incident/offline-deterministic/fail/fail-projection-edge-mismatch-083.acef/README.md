# public_projection_of edge mismatched public_incident_id (ACEF-083)

A non-public incident_report (source) and a public incident_card (target) linked by a typed `public_projection_of` relationship running report→card, but the report's `card_source.public_incident_id` and the card's `public_incident_id` DIFFER (both individually pattern-valid). The §5.1/§5.8 projection-edge semantic check requires the report and card to share ONE public_incident_id → ACEF-083. Both record-URN endpoints resolve, so no ACEF-020 dangling-ref is raised.

**Expected code(s):** ACEF-083
