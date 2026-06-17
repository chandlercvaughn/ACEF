# Published card with a hash-committed field (§5.11 commitment FORMAT)

A PUBLIC incident_card (coordinated_disclosure.status=public) carrying a `description_commitment` of valid `sha256:<64hex>` shape — the hash-committed projection of a non-public source field (§5.11). In the card-only offline-deterministic class the commitment is checked for FORMAT only (the preimage/linkage check is source-backed), so a well-formed commitment validates clean. The §6-enumerated 'published card with a hash-committed field'.

**Expected code(s):** none (pass)
