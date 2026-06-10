"""VAL-ERR-001 — incident error band ACEF-081..088 registration tests.

RFC-0002 §7 reserves the contiguous band **ACEF-081..088** (eight codes) for the
v1.1 incident-reporting profile. The 070-080 band is exhausted (ACEF-080 is the
ceiling), so these codes open a new reserved range. Unlike the v0.4 codes
(problem-text only, carried as a 3-tuple in ``ERROR_REGISTRY``), every incident
code MUST carry structured **problem + cause + fix-hint** text — the fix-hint is
the implementation-facing remediation sentence the RFC §7 fixes verbatim.

This test enforces:
  - All eight codes ACEF-081..088 are registered in the incident detail map.
  - Each carries a non-empty ``problem``, ``cause``, and ``fix`` string.
  - Severities match §7: ACEF-087 is INFO (near-miss marker, never a failure);
    the other seven are ERROR.
  - Categories are well-typed ``ErrorCategory`` members.
  - No incident code exists OUTSIDE the 081-088 band (band discipline).
  - ACEF-083 is a SINGLE code (the offline / online branches are a class tag in
    usage, not two codes).
  - The new codes do NOT mutate the frozen v0.4/v1.0 surface: ``ERROR_REGISTRY``
    keys are unchanged and the lookup accessor still resolves v0.4 codes.
"""

from __future__ import annotations

import re

import pytest

from acef.errors import (
    ERROR_REGISTRY,
    INCIDENT_ERROR_DETAILS,
    ACEFError,
    ErrorCategory,
    IncidentErrorDetail,
    Severity,
    ValidationDiagnostic,
    incident_error_detail,
    resolve_error_meta,
)

# The exact eight-code band from RFC-0002 §7.
INCIDENT_BAND: list[str] = [f"ACEF-{n:03d}" for n in range(81, 89)]

# Expected severity per §7: 087 (near_miss) is INFO, the rest ERROR.
EXPECTED_SEVERITY: dict[str, Severity] = {
    "ACEF-081": Severity.ERROR,
    "ACEF-082": Severity.ERROR,
    "ACEF-083": Severity.ERROR,
    "ACEF-084": Severity.ERROR,
    "ACEF-085": Severity.ERROR,
    "ACEF-086": Severity.ERROR,
    "ACEF-087": Severity.INFO,
    "ACEF-088": Severity.ERROR,
}

# Expected (severity, category) per §7, used to assert the EMITTED metadata when
# an incident code travels through the public APIs (ACEFError /
# ValidationDiagnostic). These mirror the IncidentErrorDetail values and are the
# load-bearing expectations of the roborev integration fix: the public emission
# path MUST surface info/profile for ACEF-087, evaluation for ACEF-084, etc.,
# NOT the old hardcoded (ERROR, SCHEMA) fallback.
EXPECTED_META: dict[str, tuple[Severity, ErrorCategory]] = {
    "ACEF-081": (Severity.ERROR, ErrorCategory.PROFILE),
    "ACEF-082": (Severity.ERROR, ErrorCategory.FORMAT),
    "ACEF-083": (Severity.ERROR, ErrorCategory.INTEGRITY),
    "ACEF-084": (Severity.ERROR, ErrorCategory.EVALUATION),
    "ACEF-085": (Severity.ERROR, ErrorCategory.EVALUATION),
    "ACEF-086": (Severity.ERROR, ErrorCategory.PROFILE),
    "ACEF-087": (Severity.INFO, ErrorCategory.PROFILE),
    "ACEF-088": (Severity.ERROR, ErrorCategory.EVALUATION),
}

_CODE_RE = re.compile(r"^ACEF-(\d{3})$")


class TestIncidentBandRegistration:
    """ACEF-081..088 are registered with structured problem/cause/fix."""

    def test_all_eight_codes_present(self) -> None:
        missing = [c for c in INCIDENT_BAND if c not in INCIDENT_ERROR_DETAILS]
        assert not missing, f"incident codes missing from registry: {missing}"

    def test_exactly_eight_codes(self) -> None:
        assert len(INCIDENT_ERROR_DETAILS) == 8, (
            f"incident registry must hold exactly 8 codes (the 081-088 band), "
            f"got {len(INCIDENT_ERROR_DETAILS)}: {sorted(INCIDENT_ERROR_DETAILS)}"
        )

    @pytest.mark.parametrize("code", INCIDENT_BAND)
    def test_detail_is_typed(self, code: str) -> None:
        detail = INCIDENT_ERROR_DETAILS[code]
        assert isinstance(detail, IncidentErrorDetail), f"{code} not an IncidentErrorDetail"
        assert isinstance(detail.severity, Severity), f"{code} severity not a Severity"
        assert isinstance(detail.category, ErrorCategory), f"{code} category not an ErrorCategory"

    @pytest.mark.parametrize("code", INCIDENT_BAND)
    def test_problem_cause_fix_nonempty(self, code: str) -> None:
        detail = INCIDENT_ERROR_DETAILS[code]
        assert detail.problem.strip(), f"{code} has empty problem"
        assert detail.cause.strip(), f"{code} has empty cause"
        assert detail.fix.strip(), f"{code} has empty fix-hint"

    @pytest.mark.parametrize("code", INCIDENT_BAND)
    def test_severity_matches_rfc(self, code: str) -> None:
        assert INCIDENT_ERROR_DETAILS[code].severity == EXPECTED_SEVERITY[code]

    def test_087_is_info(self) -> None:
        """ACEF-087 near_miss is an INFO marker, never a failure (§7)."""
        assert INCIDENT_ERROR_DETAILS["ACEF-087"].severity == Severity.INFO

    def test_only_087_is_info(self) -> None:
        info_codes = [c for c, d in INCIDENT_ERROR_DETAILS.items() if d.severity == Severity.INFO]
        assert info_codes == ["ACEF-087"], f"only ACEF-087 may be INFO, got {sorted(info_codes)}"


class TestBandDiscipline:
    """No incident code may fall outside the reserved 081-088 band."""

    def test_no_code_outside_band(self) -> None:
        out_of_band: list[str] = []
        for code in INCIDENT_ERROR_DETAILS:
            m = _CODE_RE.match(code)
            assert m is not None, f"{code} is not a well-formed ACEF-NNN code"
            num = int(m.group(1))
            if not (81 <= num <= 88):
                out_of_band.append(code)
        assert not out_of_band, f"incident codes outside the 081-088 band: {out_of_band}"

    def test_band_does_not_reuse_022_or_053(self) -> None:
        """The publishability/format codes must NOT reuse ACEF-022 / ACEF-053."""
        assert "ACEF-022" not in INCIDENT_ERROR_DETAILS
        assert "ACEF-053" not in INCIDENT_ERROR_DETAILS

    def test_083_is_a_single_code(self) -> None:
        """ACEF-083 carries BOTH the offline-deterministic and online-conformance
        branches as a class tag — it is one code, not two."""
        assert "ACEF-083" in INCIDENT_ERROR_DETAILS
        # No sibling like ACEF-083A / ACEF-089 split out the second branch.
        assert "ACEF-089" not in INCIDENT_ERROR_DETAILS
        detail = INCIDENT_ERROR_DETAILS["ACEF-083"]
        # The single code references both class branches in its text.
        text = (detail.problem + detail.cause + detail.fix).lower()
        assert "offline" in text and "online" in text, "ACEF-083 must name both class branches"


class TestAccessor:
    """incident_error_detail() resolves only the 081-088 band."""

    @pytest.mark.parametrize("code", INCIDENT_BAND)
    def test_accessor_returns_detail(self, code: str) -> None:
        detail = incident_error_detail(code)
        assert detail is not None
        assert detail is INCIDENT_ERROR_DETAILS[code]

    def test_accessor_returns_none_for_v04_code(self) -> None:
        """A v0.4 code is NOT an incident detail; the accessor returns None."""
        assert incident_error_detail("ACEF-080") is None
        assert incident_error_detail("ACEF-001") is None

    def test_accessor_returns_none_for_unknown(self) -> None:
        assert incident_error_detail("ACEF-999") is None


class TestFrozenSurfaceUnchanged:
    """Adding the incident band must not mutate the frozen v0.4/v1.0 surface."""

    def test_error_registry_keys_unchanged(self) -> None:
        """ERROR_REGISTRY still holds exactly the 42 v0.4/v1.0 codes — no
        incident code leaked into the frozen-snapshot-governed map."""
        assert len(ERROR_REGISTRY) == 42, (
            f"ERROR_REGISTRY size changed to {len(ERROR_REGISTRY)}; "
            f"incident codes must live in INCIDENT_ERROR_DETAILS, not ERROR_REGISTRY"
        )
        for code in INCIDENT_BAND:
            assert code not in ERROR_REGISTRY, f"{code} must NOT be added to ERROR_REGISTRY (frozen-snapshot governed)"

    def test_v04_codes_still_resolve(self) -> None:
        """The pre-existing 070-080 band is untouched."""
        assert ERROR_REGISTRY["ACEF-080"][0] == Severity.ERROR
        assert ERROR_REGISTRY["ACEF-070"][0] == Severity.FATAL


class TestSharedResolver:
    """resolve_error_meta() is the single code -> (Severity, Category) resolver
    used by BOTH public emission paths. It checks ERROR_REGISTRY first, then
    falls back to INCIDENT_ERROR_DETAILS for the 081-088 band, then to the
    legacy (ERROR, SCHEMA) default for unknown codes."""

    @pytest.mark.parametrize("code", INCIDENT_BAND)
    def test_resolver_returns_incident_meta(self, code: str) -> None:
        severity, category = resolve_error_meta(code)
        assert (severity, category) == EXPECTED_META[code], (
            f"{code} resolved to ({severity}, {category}); resolver must fall "
            f"back to INCIDENT_ERROR_DETAILS for the 081-088 band"
        )

    def test_resolver_prefers_error_registry(self) -> None:
        """A v0.4 code resolves from ERROR_REGISTRY (checked first)."""
        assert resolve_error_meta("ACEF-080") == (Severity.ERROR, ErrorCategory.REFERENCE)
        assert resolve_error_meta("ACEF-070") == (Severity.FATAL, ErrorCategory.INTEGRITY)
        assert resolve_error_meta("ACEF-032") == (Severity.INFO, ErrorCategory.PROFILE)

    def test_resolver_unknown_code_falls_back(self) -> None:
        """An unknown code keeps the legacy conservative default."""
        assert resolve_error_meta("ACEF-999") == (Severity.ERROR, ErrorCategory.SCHEMA)

    def test_resolver_matches_incident_detail(self) -> None:
        """The resolver's incident-band answer must equal the detail it derives
        from — no drift between the structured detail and the emitted meta."""
        for code in INCIDENT_BAND:
            detail = INCIDENT_ERROR_DETAILS[code]
            assert resolve_error_meta(code) == (detail.severity, detail.category)


class TestACEFErrorEmission:
    """Constructing an incident code through the PUBLIC ACEFError API must
    surface the CORRECT severity/category (roborev integration fix)."""

    @pytest.mark.parametrize("code", INCIDENT_BAND)
    def test_acef_error_meta(self, code: str) -> None:
        exc = ACEFError("incident condition", code=code)
        expected_sev, expected_cat = EXPECTED_META[code]
        assert exc.severity == expected_sev, (
            f"ACEFError({code}) emitted severity {exc.severity}; expected {expected_sev}"
        )
        assert exc.category == expected_cat, (
            f"ACEFError({code}) emitted category {exc.category}; expected {expected_cat}"
        )

    def test_acef_error_087_is_info_profile(self) -> None:
        """The load-bearing regression: ACEF-087 must NOT serialize as
        error/schema. It is an INFO/profile near-miss marker."""
        exc = ACEFError("realization is near_miss", code="ACEF-087")
        assert exc.severity == Severity.INFO
        assert exc.category == ErrorCategory.PROFILE
        assert exc.severity != Severity.ERROR

    def test_acef_error_084_is_evaluation(self) -> None:
        exc = ACEFError("clock mismatch", code="ACEF-084")
        assert exc.category == ErrorCategory.EVALUATION
        assert exc.category != ErrorCategory.SCHEMA

    def test_acef_error_v04_code_unchanged(self) -> None:
        """A v0.4 code's emission is unchanged by the resolver."""
        exc = ACEFError("missing evidence", code="ACEF-040")
        assert exc.severity == Severity.ERROR
        assert exc.category == ErrorCategory.EVALUATION

    def test_acef_error_unknown_code_keeps_default(self) -> None:
        exc = ACEFError("mystery", code="ACEF-999")
        assert exc.severity == Severity.ERROR
        assert exc.category == ErrorCategory.SCHEMA


class TestValidationDiagnosticEmission:
    """A ValidationDiagnostic carrying an incident code must serialize the
    CORRECT severity/category through to_dict() — this is the surface the
    validator (F-M3-VALIDATOR-RULES) and Assessment Bundle consume."""

    @pytest.mark.parametrize("code", INCIDENT_BAND)
    def test_diagnostic_meta(self, code: str) -> None:
        diag = ValidationDiagnostic(code, "incident condition")
        expected_sev, expected_cat = EXPECTED_META[code]
        assert diag.severity == expected_sev
        assert diag.category == expected_cat

    @pytest.mark.parametrize("code", INCIDENT_BAND)
    def test_diagnostic_to_dict_meta(self, code: str) -> None:
        diag = ValidationDiagnostic(code, "incident condition")
        d = diag.to_dict()
        expected_sev, expected_cat = EXPECTED_META[code]
        assert d["severity"] == expected_sev.value
        assert d["category"] == expected_cat.value

    def test_diagnostic_087_serializes_info_profile(self) -> None:
        """The exact roborev example: ACEF-087 must serialize as info/profile,
        NOT error/schema."""
        diag = ValidationDiagnostic("ACEF-087", "realization is near_miss")
        d = diag.to_dict()
        assert d["severity"] == "info"
        assert d["category"] == "profile"
        assert d["severity"] != "error"

    def test_diagnostic_084_serializes_evaluation(self) -> None:
        diag = ValidationDiagnostic("ACEF-084", "clock mismatch")
        d = diag.to_dict()
        assert d["category"] == "evaluation"
        assert d["category"] != "schema"

    def test_diagnostic_v04_code_unchanged(self) -> None:
        diag = ValidationDiagnostic("ACEF-041", "freshness")
        d = diag.to_dict()
        assert d["severity"] == "warning"
        assert d["category"] == "evaluation"


class TestFixHintRetrievableForEmittedCode:
    """A consumer that has an emitted incident code must be able to retrieve the
    fix-hint (the builder feature F-M5 surfaces it). The emission path and the
    fix-hint accessor must agree on the same code."""

    @pytest.mark.parametrize("code", INCIDENT_BAND)
    def test_fix_hint_retrievable_from_emitted_code(self, code: str) -> None:
        diag = ValidationDiagnostic(code, "incident condition")
        detail = incident_error_detail(diag.code)
        assert detail is not None, f"fix-hint not retrievable for emitted {code}"
        assert detail.fix.strip(), f"{code} fix-hint is empty"
        # The detail's severity/category must match what was emitted.
        assert (detail.severity, detail.category) == (diag.severity, diag.category)


class TestRfcFixHintContent:
    """Spot-check that the fix-hints carry the RFC §7 remediation wording so a
    filer sees what to fix (VAL-ERR-001 example + VAL-DX-003 downstream)."""

    def test_084_fix_mentions_shortest_clock(self) -> None:
        fix = INCIDENT_ERROR_DETAILS["ACEF-084"].fix.lower()
        assert "shortest applicable clock" in fix
        assert "regulatory_timeline" in fix

    def test_084_cause_names_fact_sources(self) -> None:
        cause = INCIDENT_ERROR_DETAILS["ACEF-084"].cause
        assert "card_source.eu_ai_act_facts" in cause
        assert "taxonomy_crosswalk.eu_ai_act" in cause

    def test_082_fix_mentions_grammar(self) -> None:
        fix = INCIDENT_ERROR_DETAILS["ACEF-082"].fix
        assert "ACEF-SEV:1.0" in fix

    def test_086_fix_mentions_publication_basis(self) -> None:
        fix = INCIDENT_ERROR_DETAILS["ACEF-086"].fix
        assert "declared_publication_basis" in fix
