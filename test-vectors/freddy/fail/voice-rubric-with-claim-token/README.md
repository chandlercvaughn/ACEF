# voice-rubric-with-claim-token

**Requirement:** Brief §F2 / VAL-VALIDATION-012 — x-freddy/voice-rubric-emission
banned claim-lexicon token without paired harness_attestation_ref
**Test criterion ID:** VAL-CONFORMANCE-002
**Expected code:** ACEF-077

The bundle declares manifest.namespaces['x-freddy'] (so the
bundled_freddy lint is active) and includes a
x-freddy/voice-rubric-emission record whose prose contains the banned
token 'compliant' AND lacks a paired harness_attestation_ref. The
namespace-lint hook emits ACEF-077.
