# cannot-reach-step-without-evidence

**Requirement:** Brief §7.1 fake-green vector for state_class='step'
**Test criterion ID:** VAL-CONFORMANCE-003
**Expected code(s):** ACEF-070 / ACEF-076

The bundle declares a harness_attestation with state_class='step'
but binds it to a URN that does not resolve to any record in this
bundle. The state cannot be reached without the bound evidence — that
is the whole point of the fake-green test (brief §24.5 / Prove-It
Doctrine).

**Intentionally absent precursor:** The event_log record(s) that would normally bind the step transition to concrete evidence are deliberately omitted from the bundle.

Validator MUST emit at least one ERROR/FATAL diagnostic
(typically ACEF-070).
