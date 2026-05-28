# cannot-reach-finding-without-evidence

**Requirement:** Brief §7.1 fake-green vector for state_class='finding'
**Test criterion ID:** VAL-CONFORMANCE-003
**Expected code(s):** ACEF-070 / ACEF-076

The bundle declares a harness_attestation with state_class='finding'
but binds it to a URN that does not resolve to any record in this
bundle. The state cannot be reached without the bound evidence — that
is the whole point of the fake-green test (brief §24.5 / Prove-It
Doctrine).

**Intentionally absent precursor:** The finding_record's reproduction.evidence_commit_ref target is deliberately not present in the bundle — there is no evidence the finding actually reproduces.

Validator MUST emit at least one ERROR/FATAL diagnostic
(typically ACEF-070).
