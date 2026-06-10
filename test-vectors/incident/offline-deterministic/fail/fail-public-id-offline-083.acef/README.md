# public_incident_id offline-surface failure (ACEF-083)

A public incident_card whose `public_incident_id` has a too-short suffix (< 26 Crockford-base32 chars, < 128 bits). The OFFLINE-deterministic class checks pattern only and raises ACEF-083 `class: offline-deterministic` — a pure-pattern failure computed from bundle bytes, NEVER an attribution claim.

**Expected code(s):** ACEF-083
