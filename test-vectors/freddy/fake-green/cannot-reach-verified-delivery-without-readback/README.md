# cannot-reach-verified-delivery-without-readback

**Requirement:** Brief §7.1 fake-green vector for state_class='delivery'
**Test criterion ID:** VAL-CONFORMANCE-003
**Expected code(s):** ACEF-070 / ACEF-076

The bundle declares a harness_attestation with state_class='delivery'
but binds it to a URN that does not resolve to any record in this
bundle. The state cannot be reached without the bound evidence — that
is the whole point of the fake-green test (brief §24.5 / Prove-It
Doctrine).

**Intentionally absent precursor:** No delivery_verdict record with a read_back block and matching digests is present.

Validator MUST emit at least one ERROR/FATAL diagnostic
(typically ACEF-070).
