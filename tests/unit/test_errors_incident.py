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
    ErrorCategory,
    IncidentErrorDetail,
    Severity,
    incident_error_detail,
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
