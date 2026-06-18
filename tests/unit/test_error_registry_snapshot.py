"""R0 snapshot protection + v1.1 new-code presence tests for ERROR_REGISTRY.

This test enforces:
  VAL-ERROR-001: ERROR_REGISTRY gains EXACTLY 11 new entries (ACEF-070..ACEF-080),
                 each value is (Severity, ErrorCategory, description_str).
  VAL-ERROR-002 / VAL-ERROR-003 (spec contract numbering): pre-existing codes
                 (ACEF-001..060) UNCHANGED byte-equal vs the R0 snapshot at
                 tests/conformance/fixtures/v1.0-errors.json (31 entries at
                 capture; the ACEF-001..060 range is sparse by design).

The R0 snapshot file is FROZEN per VAL-REGRESSION-001. This test treats it as
the authoritative baseline.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acef.errors import ERROR_REGISTRY, ErrorCategory, Severity

SNAPSHOT_PATH = Path(__file__).resolve().parents[1] / "conformance" / "fixtures" / "v1.0-errors.json"


# Expected v1.1 additions per plan WS2 + dispatch prompt.
# Each tuple: (code, severity_enum_value, category_enum_value, description).
EXPECTED_V1_1_ADDITIONS: list[tuple[str, str, str, str]] = [
    (
        "ACEF-070",
        "fatal",
        "integrity",
        "harness_attestation cites missing or unverifiable required evidence",
    ),
    (
        "ACEF-071",
        "fatal",
        "integrity",
        "delivery_verdict claims verified_delivered without read-back digest",
    ),
    (
        "ACEF-072",
        "fatal",
        "integrity",
        "delivery_verdict read-back digest does not match write-back digest",
    ),
    (
        "ACEF-073",
        "fatal",
        "reference",
        "causation_chain cites an unknown or unsigned URN",
    ),
    (
        "ACEF-074",
        "error",
        "schema",
        "Record missing redaction_policy_version when confidentiality != public",
    ),
    (
        "ACEF-075",
        "fatal",
        "reference",
        "tenant_label mismatch across records in a single bundle",
    ),
    (
        "ACEF-076",
        "error",
        "schema",
        "state_class record lacks fake-green test reference, or disposition_record sets internal_state_unchanged=false",
    ),
    (
        "ACEF-077",
        "fatal",
        "integrity",
        # Vendor-NEUTRAL Core description (PhD-review finding 35); the specific
        # x-freddy/voice-rubric-emission semantics live in bundled_freddy.py, not Core.
        "registered vendor-namespace lint reported a fatal integrity violation "
        "(the namespace's registered lint pattern supplies the specific record type and condition)",
    ),
    (
        "ACEF-078",
        "error",
        "reference",
        "redaction_attestation_ref points to unresolvable URN",
    ),
    (
        "ACEF-079",
        "error",
        "schema",
        "coverage_cell.claim_language contains banned token",
    ),
    (
        "ACEF-080",
        "error",
        "reference",
        "Bundle declares analysis_mode but lacks required envelope fields for that mode",
    ),
]


def _load_snapshot() -> dict[str, dict[str, str]]:
    with SNAPSHOT_PATH.open(encoding="utf-8") as fp:
        data = json.load(fp)
    assert isinstance(data, dict), "snapshot must be a top-level JSON object"
    return data


@pytest.mark.regression
class TestR0SnapshotIntegrity:
    """Pre-existing v1.0 codes must remain byte-equal to the R0 snapshot.

    Tagged with @pytest.mark.regression for VAL-REGRESSION-003 (R3 v1.0
    error codes byte-equal to snapshot). The same assertion is also tracked
    as a parametrized per-code test in
    ``tests/conformance/test_regression_r1_r4.py``.
    """

    def test_snapshot_file_exists(self):
        assert SNAPSHOT_PATH.exists(), f"R0 snapshot missing at {SNAPSHOT_PATH}"

    def test_snapshot_is_nonempty(self):
        snap = _load_snapshot()
        assert len(snap) == 31, f"R0 snapshot expected 31 v1.0 codes (sparse ACEF-001..060 range), got {len(snap)}"

    def test_every_v1_0_code_unchanged(self):
        """Every code in the snapshot must be present in ERROR_REGISTRY with
        the same severity, category, and description (byte-equal)."""
        snap = _load_snapshot()
        mismatches: list[tuple[str, str]] = []
        for code, expected in snap.items():
            got = ERROR_REGISTRY.get(code)
            if got is None:
                mismatches.append((code, "MISSING from ERROR_REGISTRY"))
                continue
            severity, category, description = got
            if severity.value != expected["severity"]:
                mismatches.append((code, f"severity {severity.value!r} != {expected['severity']!r}"))
            if category.value != expected["category"]:
                mismatches.append((code, f"category {category.value!r} != {expected['category']!r}"))
            if description != expected["description"]:
                mismatches.append(
                    (
                        code,
                        f"description {description!r} != {expected['description']!r}",
                    )
                )
        assert not mismatches, f"R0 snapshot mismatches: {mismatches}"

    def test_no_v1_0_code_deleted(self):
        snap_codes = set(_load_snapshot().keys())
        missing = sorted(snap_codes - set(ERROR_REGISTRY.keys()))
        assert not missing, f"v1.0 codes deleted from registry: {missing}"


class TestV11Additions:
    """The 11 new v1.1 codes must be present with the exact expected tuple."""

    def test_all_eleven_codes_present(self):
        missing = [code for (code, _, _, _) in EXPECTED_V1_1_ADDITIONS if code not in ERROR_REGISTRY]
        assert not missing, f"Missing v1.1 codes: {missing}"

    @pytest.mark.parametrize(
        "code,expected_severity,expected_category,expected_description",
        EXPECTED_V1_1_ADDITIONS,
        ids=[c for (c, _, _, _) in EXPECTED_V1_1_ADDITIONS],
    )
    def test_code_tuple_exact_match(
        self,
        code: str,
        expected_severity: str,
        expected_category: str,
        expected_description: str,
    ):
        entry = ERROR_REGISTRY[code]
        assert isinstance(entry, tuple) and len(entry) == 3, f"{code} entry must be a 3-tuple, got {entry!r}"
        severity, category, description = entry
        assert isinstance(severity, Severity), f"{code} severity must be Severity enum, got {type(severity)}"
        assert isinstance(category, ErrorCategory), f"{code} category must be ErrorCategory enum, got {type(category)}"
        assert isinstance(description, str), f"{code} description must be str, got {type(description)}"
        assert severity.value == expected_severity, f"{code} severity {severity.value!r} != {expected_severity!r}"
        assert category.value == expected_category, f"{code} category {category.value!r} != {expected_category!r}"
        assert description == expected_description, (
            f"{code} description mismatch:\n  got:      {description!r}\n  expected: {expected_description!r}"
        )

    def test_exactly_eleven_new_codes_added(self):
        """Sanity: post-v1.1 registry size must equal v1.0 size + 11."""
        snap = _load_snapshot()
        # v1.0 had 31 codes (sparse); v1.1 adds exactly 11.
        expected_size = len(snap) + len(EXPECTED_V1_1_ADDITIONS)
        assert len(ERROR_REGISTRY) == expected_size, (
            f"ERROR_REGISTRY size {len(ERROR_REGISTRY)} != "
            f"v1.0 ({len(snap)}) + v1.1 additions ({len(EXPECTED_V1_1_ADDITIONS)}) "
            f"= {expected_size}"
        )

    def test_new_codes_are_in_070_080_range(self):
        for code, _, _, _ in EXPECTED_V1_1_ADDITIONS:
            assert code.startswith("ACEF-0"), code
            num = int(code.split("-")[1])
            assert 70 <= num <= 80, f"v1.1 code {code} outside reserved 070-080 range"


class TestACEF076DualConditionDocumented:
    """F36: ACEF-076 is INTENTIONALLY shared by two state-mutation discipline
    failures (state_class fake-green AND disposition_record
    internal_state_unchanged=false, per ops plan WS3.4 + cross_record.py). The
    spec row + registry description previously documented only the first. Both
    surfaces must now name BOTH conditions so the taxonomy is honest."""

    _SPEC = Path(__file__).resolve().parents[2] / "planning" / "ACEF-Spec-Outline-v0.1.md"

    def test_registry_description_names_both_conditions(self) -> None:
        text = ERROR_REGISTRY["ACEF-076"][2].lower()
        assert "state_class" in text, text
        assert "internal_state_unchanged" in text, text

    def test_spec_row_names_both_conditions(self) -> None:
        spec = self._SPEC.read_text(encoding="utf-8")
        rows = [ln for ln in spec.splitlines() if "`ACEF-076`" in ln]
        assert rows, "spec lost its ACEF-076 row"
        row = rows[0].lower()
        assert "state_class" in row and "internal_state_unchanged" in row, row
