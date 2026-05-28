# external-disposition-overrides-internal

**Requirement:** Brief §V3 external_disposition advisory; MUST NOT mutate internal state
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-076

The bundle's risk_treatment (external_disposition variant) sets
internal_state_unchanged=false — external dispositions are advisory
per brief §V3. Validator's enforce_disposition_internal_state mirrors
the loader's LoadRejection with ACEF-076.
