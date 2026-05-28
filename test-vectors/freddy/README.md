# Freddy Profile Conformance Vectors

This directory contains the ACEF v0.4 conformance test vectors for the
Freddy Profile. Per the brief
(`planning/freddy-on-acef-requirements-v0.1.md` §7.1) the inventory is
fixed at 9 pass + 11 fail + 7 fake-green bundles (27 total).

## Directory layout

```
test-vectors/freddy/
├── _builders/                          # Python builder modules
│   ├── __init__.py
│   └── _common.py                      # shared helpers + deterministic URN pool
├── build_all.py                        # orchestrator — regenerates every bundle
├── pass/                               # 9 bundles that MUST validate clean
│   ├── subscriber-mode-full-loop.acef/         # canonical reference
│   ├── public-artifact-mode.acef/
│   ├── canary-mode.acef/
│   ├── verified-delivery.acef/
│   ├── regression-active-with-fix-verification.acef/
│   ├── badge-green-with-fresh-coverage.acef/
│   ├── badge-provisional-with-reason.acef/
│   ├── accepted-risk-disposition.acef/
│   └── multi-finding-with-dedupe-collapse.acef/
├── fail/                               # 11 bundles, each declares expected ACEF-NNN
│   ├── verified-delivery-without-readback/        → ACEF-071
│   ├── verified-delivery-digest-mismatch/         → ACEF-072
│   ├── harness-attestation-empty-evidence/        → ACEF-070
│   ├── harness-attestation-persona-as-verifier/   → ACEF-070
│   ├── badge-green-with-failed-integrity/         → ACEF-014
│   ├── cross-tenant-references-in-one-bundle/     → ACEF-075
│   ├── voice-rubric-with-claim-token/             → ACEF-077
│   ├── scope-boundary-event-without-stop-attest/  → ACEF-004
│   ├── external-disposition-overrides-internal/   → ACEF-076
│   ├── public-artifact-with-delivery-verdict/     → ACEF-080
│   └── non-public-record-without-redaction-pol/   → ACEF-074
└── fake-green/                         # 7 bundles, one per state class
    ├── cannot-reach-step-without-evidence/
    ├── cannot-reach-finding-without-evidence/
    ├── cannot-reach-coverage-cell-without-evidence/
    ├── cannot-reach-active-regression-without-fix-verification/
    ├── cannot-reach-verified-delivery-without-readback/
    ├── cannot-reach-green-badge-without-fresh-coverage/
    └── cannot-reach-attestation-without-precursor-attestation/
```

Each bundle directory carries a `README.md` declaring:

- The requirement it exercises (brief section / contract ID).
- The test criterion ID (VAL-CONFORMANCE-NNN).
- For `fail/`: the expected `ACEF-NNN` code.
- For `fake-green/`: the intentionally-absent precursor evidence.

## Regenerating the bundles

```sh
source venv/bin/activate
python test-vectors/freddy/build_all.py
```

The build is byte-deterministic (per brief §7.2 / TC7): re-running
produces byte-equal bundle contents.

## Conformance drivers

The corresponding pytest drivers live under `tests/conformance/`:

| Driver | Assertion |
|---|---|
| `test_freddy_pass_vectors.py` | VAL-CONFORMANCE-001 |
| `test_freddy_fail_vectors.py` | VAL-CONFORMANCE-002 |
| `test_freddy_fake_green_vectors.py` | VAL-CONFORMANCE-003 |
| `test_freddy_full_loop_inventory.py` | VAL-CONFORMANCE-004 |
| `test_freddy_fake_green_ref_resolution.py` | VAL-CONFORMANCE-FAKE-GREEN-REF-001 / 002 |

Combined wall-clock of the five drivers is well under the 40-second
conformance sub-tier budget (VAL-CONFORMANCE-005).
