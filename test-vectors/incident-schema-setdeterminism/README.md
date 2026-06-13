# incident-schema-setdeterminism vectors (F-M8-INCIDENT-SCHEMA)

Record-level `incident_card` payload vectors proving the set-determinism schema
fixes for **VAL-FIX-INCSCHEMA-002** (public `taxonomy_crosswalk.eu_ai_act.serious_incident_triggers`)
and **VAL-FIX-INCSCHEMA-003** (`harm_distribution_basis`). Each vector is a bare
`incident_card` payload validated directly against
`acef-conventions/v1.1/incident_card.schema.json` through the production
`acef.schemas.registry.build_schema_registry('v1.1')` resolver — the matching
granularity for a per-record-schema fix (a full `.acef` bundle would add Merkle /
manifest machinery irrelevant to a `uniqueItems` constraint).

These vectors are RED-first: the two `fail-*` cards VALIDATED before the
`uniqueItems` additions landed (the documented determinism hole) and are REJECTED
after; the two `pass-*` cards validate both before and after (no over-rejection).

| Vector | Disposition (post-fix) | Why |
|--------|------------------------|-----|
| `fail-dup-serious-incident-triggers.json` | reject (`uniqueItems`) | public `eu_ai_act.serious_incident_triggers` carries `["3.49.a","3.49.a"]` — a sorted-set-with-duplicate §5.7 reads for the ACEF-084 clock |
| `pass-unique-serious-incident-triggers.json` | accept | unique `["3.49.a","3.49.b"]` |
| `fail-dup-harm-distribution-basis.json` | reject (`uniqueItems`) | `harm_distribution_basis` carries `["race","race"]` — a sorted protected-attribute axis with a duplicate |
| `pass-unique-harm-distribution-basis.json` | accept | unique `["race","sex"]` |

Driver: `tests/conformance/test_incident_schema_setdeterminism_vectors.py`.
Deterministic: static literals only (no wall-clock, no random).
