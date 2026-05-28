# scope-boundary-event-without-stop-attest

**Requirement:** Brief §3.2 allOf hard_stop_attestation_ref required when hard_stop_triggered=true
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-004

The bundle's scope_boundary_event has hard_stop_triggered=true but no
hard_stop_attestation_ref. The v1.1 schema's allOf conditional fires,
emitting ACEF-004 (schema validation failure).
