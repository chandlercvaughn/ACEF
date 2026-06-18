"""Per-code emission tests for the 11 new v1.1 error codes (ACEF-070..ACEF-080).

This file fulfills VAL-ERROR-003 of the acef-v0.4-freddy-adoption contract:
each of the 11 new codes must have at least one direct emission test —
either constructing an ACEFError (or subclass) with the code and asserting
the resulting object exposes the expected severity/category, OR exercising
the raise path for codes plumbed through specific subclasses.

Scope limit (per dispatch prompt): minimum bar is the constructor test.
Validator-emission tests for these codes belong in F-M1-VALIDATOR-* and are
NOT in this file.
"""

from __future__ import annotations

import pytest

from acef.errors import (
    ERROR_REGISTRY,
    ACEFError,
    ACEFIntegrityError,
    ACEFReferenceError,
    ACEFSchemaError,
    ErrorCategory,
    Severity,
    ValidationDiagnostic,
)

# Per-code emission spec: (code, expected_severity, expected_category, subclass)
# `subclass` is the most-specific ACEFError subclass whose `code` group
# matches this code's category (used to confirm category-routing via the
# subclass constructor). For categories without a dedicated subclass (e.g.
# SCHEMA in 070-080 range), we use the bare ACEFError.
EMISSION_CASES: list[tuple[str, Severity, ErrorCategory, type[ACEFError]]] = [
    ("ACEF-070", Severity.FATAL, ErrorCategory.INTEGRITY, ACEFIntegrityError),
    ("ACEF-071", Severity.FATAL, ErrorCategory.INTEGRITY, ACEFIntegrityError),
    ("ACEF-072", Severity.FATAL, ErrorCategory.INTEGRITY, ACEFIntegrityError),
    ("ACEF-073", Severity.FATAL, ErrorCategory.REFERENCE, ACEFReferenceError),
    ("ACEF-074", Severity.ERROR, ErrorCategory.SCHEMA, ACEFSchemaError),
    ("ACEF-075", Severity.FATAL, ErrorCategory.REFERENCE, ACEFReferenceError),
    ("ACEF-076", Severity.ERROR, ErrorCategory.SCHEMA, ACEFSchemaError),
    ("ACEF-077", Severity.FATAL, ErrorCategory.INTEGRITY, ACEFIntegrityError),
    ("ACEF-078", Severity.ERROR, ErrorCategory.REFERENCE, ACEFReferenceError),
    ("ACEF-079", Severity.ERROR, ErrorCategory.SCHEMA, ACEFSchemaError),
    ("ACEF-080", Severity.ERROR, ErrorCategory.REFERENCE, ACEFReferenceError),
]


# ---------------------------------------------------------------------------
# Construction tests — one parametrized test, one case per new code.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code,expected_severity,expected_category,_subclass",
    EMISSION_CASES,
    ids=[c for (c, _, _, _) in EMISSION_CASES],
)
def test_acef_error_construct_with_v1_1_code(
    code: str,
    expected_severity: Severity,
    expected_category: ErrorCategory,
    _subclass: type[ACEFError],
) -> None:
    """Constructing ACEFError with a v1.1 code wires up severity/category
    from ERROR_REGISTRY."""
    err = ACEFError(f"test emission for {code}", code=code)
    assert err.code == code
    assert err.severity == expected_severity
    assert err.category == expected_category
    assert str(err).startswith(f"[{code}] ")
    assert err.message == f"test emission for {code}"


@pytest.mark.parametrize(
    "code,expected_severity,expected_category,subclass",
    EMISSION_CASES,
    ids=[c for (c, _, _, _) in EMISSION_CASES],
)
def test_subclass_override_with_v1_1_code(
    code: str,
    expected_severity: Severity,
    expected_category: ErrorCategory,
    subclass: type[ACEFError],
) -> None:
    """Raising the category-appropriate subclass with code override picks
    up severity/category from ERROR_REGISTRY (matches existing pattern at
    src/acef/errors.py:79-89)."""
    with pytest.raises(subclass) as excinfo:
        raise subclass(f"raised via subclass for {code}", code=code)
    err = excinfo.value
    assert err.code == code
    assert err.severity == expected_severity
    assert err.category == expected_category


@pytest.mark.parametrize(
    "code,expected_severity,expected_category,_subclass",
    EMISSION_CASES,
    ids=[c for (c, _, _, _) in EMISSION_CASES],
)
def test_validation_diagnostic_with_v1_1_code(
    code: str,
    expected_severity: Severity,
    expected_category: ErrorCategory,
    _subclass: type[ACEFError],
) -> None:
    """ValidationDiagnostic carries the registry-derived severity/category
    when constructed with a v1.1 code (the path the validator uses to
    collect findings — see src/acef/errors.py:153-193)."""
    diag = ValidationDiagnostic(code, f"diagnostic for {code}")
    assert diag.code == code
    assert diag.severity == expected_severity
    assert diag.category == expected_category
    payload = diag.to_dict()
    assert payload["code"] == code
    assert payload["severity"] == expected_severity.value
    assert payload["category"] == expected_category.value


# ---------------------------------------------------------------------------
# Documented-condition tests — assertion of the registry description, so
# any drift between code semantics and the registry trips a failure.
# ---------------------------------------------------------------------------

EXPECTED_DESCRIPTIONS: dict[str, str] = {
    "ACEF-070": "harness_attestation cites missing or unverifiable required evidence",
    "ACEF-071": "delivery_verdict claims verified_delivered without read-back digest",
    "ACEF-072": "delivery_verdict read-back digest does not match write-back digest",
    "ACEF-073": "causation_chain cites an unknown or unsigned URN",
    "ACEF-074": "Record missing redaction_policy_version when confidentiality != public",
    "ACEF-075": "tenant_label mismatch across records in a single bundle",
    "ACEF-076": (
        "state_class record lacks fake-green test reference, or disposition_record sets internal_state_unchanged=false"
    ),
    "ACEF-077": "voice_rubric_emission contains claim-lexicon token without paired harness_attestation",
    "ACEF-078": "redaction_attestation_ref points to unresolvable URN",
    "ACEF-079": "coverage_cell.claim_language contains banned token",
    "ACEF-080": "Bundle declares analysis_mode but lacks required envelope fields for that mode",
}


@pytest.mark.parametrize(
    "code,expected_description",
    list(EXPECTED_DESCRIPTIONS.items()),
    ids=list(EXPECTED_DESCRIPTIONS.keys()),
)
def test_v1_1_code_description_matches_documented_condition(code: str, expected_description: str) -> None:
    _severity, _category, description = ERROR_REGISTRY[code]
    assert description == expected_description, (
        f"{code} description drift:\n  got:      {description!r}\n  expected: {expected_description!r}"
    )


# ---------------------------------------------------------------------------
# Per-code individual emission tests — one explicit function per new code,
# kept simple so VAL-ERROR-003 grep ("per-code emission test") is obvious.
# These are minimum-bar constructor tests; full validator-emission lives in
# later features (F-M1-VALIDATOR-*).
# ---------------------------------------------------------------------------


def test_acef_070_emission_harness_attestation_missing_evidence() -> None:
    err = ACEFIntegrityError("harness_attestation references URN not present in bundle", code="ACEF-070")
    assert err.code == "ACEF-070"
    assert err.severity == Severity.FATAL
    assert err.category == ErrorCategory.INTEGRITY


def test_acef_071_emission_delivery_verdict_no_readback() -> None:
    err = ACEFIntegrityError(
        "delivery_verdict.delivery_state=verified_delivered without read_back block",
        code="ACEF-071",
    )
    assert err.code == "ACEF-071"
    assert err.severity == Severity.FATAL
    assert err.category == ErrorCategory.INTEGRITY


def test_acef_072_emission_delivery_verdict_digest_mismatch() -> None:
    err = ACEFIntegrityError(
        "delivery_verdict.read_back.digest != write_attempt.request_digest",
        code="ACEF-072",
    )
    assert err.code == "ACEF-072"
    assert err.severity == Severity.FATAL
    assert err.category == ErrorCategory.INTEGRITY


def test_acef_073_emission_causation_chain_unsigned_urn() -> None:
    err = ACEFReferenceError(
        "causation_chain[0] URN resolves to record in unsigned bundle",
        code="ACEF-073",
    )
    assert err.code == "ACEF-073"
    assert err.severity == Severity.FATAL
    assert err.category == ErrorCategory.REFERENCE


def test_acef_074_emission_missing_redaction_policy_version() -> None:
    err = ACEFSchemaError(
        "record with confidentiality=redacted missing redaction_policy_version",
        code="ACEF-074",
    )
    assert err.code == "ACEF-074"
    assert err.severity == Severity.ERROR
    assert err.category == ErrorCategory.SCHEMA


def test_acef_075_emission_tenant_label_mismatch() -> None:
    err = ACEFReferenceError(
        "record A tenant_label=alpha conflicts with record B tenant_label=beta",
        code="ACEF-075",
    )
    assert err.code == "ACEF-075"
    assert err.severity == Severity.FATAL
    assert err.category == ErrorCategory.REFERENCE


def test_acef_076_emission_state_class_missing_fake_green_ref() -> None:
    err = ACEFSchemaError(
        "harness_attestation.state_class set without fake_green_test_ref",
        code="ACEF-076",
    )
    assert err.code == "ACEF-076"
    assert err.severity == Severity.ERROR
    assert err.category == ErrorCategory.SCHEMA


def test_acef_077_emission_voice_rubric_claim_lexicon() -> None:
    err = ACEFIntegrityError(
        "x-freddy/voice-rubric-emission contains 'verified' without harness_attestation_ref",
        code="ACEF-077",
    )
    assert err.code == "ACEF-077"
    assert err.severity == Severity.FATAL
    assert err.category == ErrorCategory.INTEGRITY


def test_acef_078_emission_redaction_attestation_ref_unresolvable() -> None:
    err = ACEFReferenceError(
        "redaction_attestation_ref urn:acef:rec:dead-beef not found in bundle",
        code="ACEF-078",
    )
    assert err.code == "ACEF-078"
    assert err.severity == Severity.ERROR
    assert err.category == ErrorCategory.REFERENCE


def test_acef_079_emission_coverage_cell_banned_claim_language() -> None:
    err = ACEFSchemaError(
        "coverage_cell.claim_language contains banned token 'compliant'",
        code="ACEF-079",
    )
    assert err.code == "ACEF-079"
    assert err.severity == Severity.ERROR
    assert err.category == ErrorCategory.SCHEMA


def test_acef_080_emission_analysis_mode_missing_required_fields() -> None:
    err = ACEFReferenceError(
        "analysis_mode=subscriber but bundle lacks required authorized_test_scope record",
        code="ACEF-080",
    )
    assert err.code == "ACEF-080"
    assert err.severity == Severity.ERROR
    assert err.category == ErrorCategory.REFERENCE


# ---------------------------------------------------------------------------
# Coverage gate: every code in the 070-080 reserved range MUST appear in the
# per-code emission set above. If a future maintainer adds a new code in the
# range without an emission test, this test fails.
# ---------------------------------------------------------------------------


def test_every_v1_1_code_has_at_least_one_emission_case() -> None:
    new_codes_in_registry = {code for code in ERROR_REGISTRY if 70 <= int(code.split("-")[1]) <= 80}
    covered = {code for (code, _, _, _) in EMISSION_CASES}
    uncovered = sorted(new_codes_in_registry - covered)
    assert not uncovered, f"v1.1 codes without emission test: {uncovered}"
