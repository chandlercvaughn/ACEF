# cross-tenant-references-in-one-bundle

**Requirement:** Brief §X3 tenant_label uniformity (VAL-VALIDATION-003)
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-075

Bundle has analysis_mode='subscriber' AND two records with distinct
tenant_label values ('tenant-alpha' and 'tenant-beta'). Validator's
enforce_tenant_uniformity emits ACEF-075.
