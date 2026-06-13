"""VAL-VALIDATION-008: banned claim_language in coverage_cell emits ACEF-079.

An Assessment Bundle (sibling file ``<bundle>.acef-assessment.json``) whose
``coverage_cells[].claim_language`` contains a banned token as a WHOLE WORD
(the closed normative ACEF-079 list: ``compliant``, ``certified``,
``AI Act-approved``, ``guaranteed``) MUST emit ACEF-079 AND MUST NOT emit
ACEF-053 (codex carved out ACEF-079 specifically to keep this outcome
independent of vendor-extension diagnostics).

The non-normative ``lawful`` token was removed (audit
cross-record-authority-1); see ``test_crossrec_auth_fixes.py`` for the
normative-list pin and the word-boundary matching tests.

The lint function is also exercised directly so the test pinpoints the
banned-language code path without coupling to other validator phases.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acef.errors import ValidationDiagnostic
from acef.validation.engine import validate_bundle
from acef.validation.v1_1_rules import (
    BANNED_CLAIM_LANGUAGE_TOKENS,
    lint_coverage_cell_claim_language,
)
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
    write_bundle,
)


def _coverage_cell(
    *,
    cell_id: str = "urn:acef:cell:00000000-0000-0000-0000-000000000001",
    claim_language: str = "Evidence covers this scenario class.",
) -> dict:
    """Build a minimal valid coverage_cell dict."""
    return {
        "cell_id": cell_id,
        "subject_ref": "urn:acef:sub:00000000-0000-0000-0000-000000000001",
        "dimensions": {
            "scenario_class": "tool_use",
            "surface_class": "chat",
            "time_window_start": "2026-01-01T00:00:00Z",
            "time_window_end": "2026-01-02T00:00:00Z",
        },
        "bound_evidence_refs": [
            "urn:acef:rec:00000000-0000-0000-0000-000000000099",
        ],
        "freshness_state": "fresh",
        "freshness_policy_ref": "urn:acef:pol:00000000-0000-0000-0000-000000000001",
        "claim_language": claim_language,
        "coverage_outcome": "covered",
    }


def _assessment_bundle_dict(claim_language: str) -> dict:
    """Build a minimal v1.1 Assessment Bundle with one coverage_cell."""
    return {
        "versioning": {"core_version": "1.1.0", "assessment_version": "1.1.0"},
        "assessment_id": "urn:acef:asx:00000000-0000-0000-0000-000000000001",
        "timestamp": "2026-01-02T00:00:00Z",
        "evaluation_instant": "2026-01-02T00:00:00Z",
        "assessor": {"name": "acef-validator", "version": "0.1.0"},
        "evidence_bundle_ref": {
            "content_hash": ("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
            "package_id": "urn:acef:pkg:11111111-1111-1111-1111-111111111111",
        },
        "profiles_evaluated": [],
        "template_digests": {},
        "results": [],
        "provision_summary": [],
        "structural_errors": [],
        "integrity": None,
        "coverage_cells": [_coverage_cell(claim_language=claim_language)],
    }


# ---------------------------------------------------------------------------
# Direct lint-function tests (no bundle-on-disk overhead)
# ---------------------------------------------------------------------------


def test_lint_clean_claim_language_no_diagnostics() -> None:
    """A neutral claim_language string produces no diagnostics."""
    bundle = _assessment_bundle_dict("Tool-use scenarios on chat surfaces are covered by bound evidence.")
    diags = lint_coverage_cell_claim_language(bundle)
    assert diags == []


def test_lint_no_coverage_cells_field_no_diagnostics() -> None:
    """Missing coverage_cells field — nothing to lint."""
    bundle = _assessment_bundle_dict("anything")
    bundle.pop("coverage_cells")
    diags = lint_coverage_cell_claim_language(bundle)
    assert diags == []


@pytest.mark.parametrize("token", list(BANNED_CLAIM_LANGUAGE_TOKENS))
def test_lint_each_banned_token_emits_acef_079(token: str) -> None:
    """Each token in the banned list, anywhere in claim_language, fires
    ACEF-079.
    """
    # Embed the token in a sentence so the substring-scan path is
    # exercised, not just exact-match.
    bundle = _assessment_bundle_dict(f"This system is {token} for the named scope.")
    diags = lint_coverage_cell_claim_language(bundle)
    found_codes = [d.code for d in diags]
    assert "ACEF-079" in found_codes, f"Token {token!r} should trigger ACEF-079; got: {found_codes!r}"
    # The diagnostic must name the offending token to aid debugging.
    assert any(token in d.message for d in diags), (
        f"Diagnostic should name the banned token; messages: {[d.message for d in diags]!r}"
    )


def test_lint_is_case_insensitive() -> None:
    """Banned tokens match regardless of case (e.g., 'COMPLIANT')."""
    bundle = _assessment_bundle_dict("System is COMPLIANT with policy.")
    diags = lint_coverage_cell_claim_language(bundle)
    assert any(d.code == "ACEF-079" for d in diags), (
        f"Uppercase 'COMPLIANT' should trigger ACEF-079; got: {[d.code for d in diags]!r}"
    )


def test_lint_multiple_banned_tokens_in_one_cell_emit_per_token() -> None:
    """Two banned tokens in the same cell emit one diagnostic each."""
    bundle = _assessment_bundle_dict("This system is compliant and certified.")
    diags = lint_coverage_cell_claim_language(bundle)
    codes_list = [d.code for d in diags]
    assert codes_list.count("ACEF-079") >= 2, f"Two banned tokens should emit two diagnostics; got: {codes_list!r}"


def test_lint_non_dict_input_no_crash() -> None:
    """Defensive: non-dict input returns empty list, no crash."""
    assert lint_coverage_cell_claim_language(None) == []  # type: ignore[arg-type]
    assert lint_coverage_cell_claim_language([]) == []  # type: ignore[arg-type]
    assert lint_coverage_cell_claim_language("not a dict") == []  # type: ignore[arg-type]


def test_lint_does_not_emit_acef_053() -> None:
    """ACEF-079 is the carved-out code; ACEF-053 MUST NOT fire from this
    lint (codex policy — separation of Core banned-copy from vendor-
    extension diagnostics).
    """
    bundle = _assessment_bundle_dict("This system is compliant.")
    diags = lint_coverage_cell_claim_language(bundle)
    found_codes = [d.code for d in diags]
    assert "ACEF-053" not in found_codes, (
        f"ACEF-053 must NOT be emitted by the banned-language lint; got: {found_codes!r}"
    )


# ---------------------------------------------------------------------------
# End-to-end engine test: sibling assessment file is picked up.
# ---------------------------------------------------------------------------


def _write_assessment_sibling(bundle_dir: Path, assessment: dict) -> None:
    """Write `<bundle_dir>.acef-assessment.json` sibling per golden-bundle convention."""
    sibling = bundle_dir.parent / f"{bundle_dir.name}.acef-assessment.json"
    sibling.write_text(json.dumps(assessment), encoding="utf-8")


def test_engine_picks_up_sibling_assessment_and_emits_acef_079(
    tmp_path: Path,
) -> None:
    """A v1.1 Evidence Bundle with a sibling .acef-assessment.json
    containing a banned-token coverage_cell triggers ACEF-079 via the
    end-to-end validate_bundle call.
    """
    bundle = tmp_path / "banned-claim"
    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:aa000000-0000-0000-0000-000000000001",
            ),
        ],
    )
    _write_assessment_sibling(
        bundle,
        _assessment_bundle_dict("This deployment is compliant with all rules."),
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-079" in found, f"Expected ACEF-079 from engine via sibling assessment; got: {found!r}"
    assert "ACEF-053" not in found, f"ACEF-053 must NOT be emitted alongside; got: {found!r}"


def test_engine_in_bundle_assessment_also_works(tmp_path: Path) -> None:
    """In-bundle ``acef-assessment.json`` is also discovered."""
    bundle = tmp_path / "banned-claim-in-bundle"
    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:bb000000-0000-0000-0000-000000000001",
            ),
        ],
    )
    (bundle / "acef-assessment.json").write_text(
        json.dumps(_assessment_bundle_dict("Output is certified for production.")),
        encoding="utf-8",
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-079" in found, found


def test_engine_clean_assessment_no_acef_079(tmp_path: Path) -> None:
    """A v1.1 bundle with a clean assessment file emits no ACEF-079."""
    bundle = tmp_path / "clean-claim"
    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:cc000000-0000-0000-0000-000000000001",
            ),
        ],
    )
    _write_assessment_sibling(
        bundle,
        _assessment_bundle_dict("Bound evidence covers the scenario."),
    )

    assessment = validate_bundle(bundle)
    assert "ACEF-079" not in codes(assessment.structural_errors)


def test_engine_v1_0_bundle_no_acef_079_even_with_banned_assessment(
    tmp_path: Path,
) -> None:
    """Regression: a v1.0-declared bundle does NOT trigger ACEF-079 from
    a sibling assessment (the v1.1 rule families are gated on
    schema_version == "v1.1" per VAL-REGRESSION-001).
    """
    bundle = tmp_path / "v1-0-banned-claim"
    write_bundle(
        bundle,
        manifest=base_manifest(core_version="1.0.0"),
        records=[
            base_record(
                record_id="urn:acef:rec:dd000000-0000-0000-0000-000000000001",
            ),
        ],
    )
    _write_assessment_sibling(
        bundle,
        _assessment_bundle_dict("System is compliant with everything."),
    )

    assessment = validate_bundle(bundle)
    assert "ACEF-079" not in codes(assessment.structural_errors)


def test_diagnostic_objects_are_validation_diagnostic_instances() -> None:
    """The lint returns ValidationDiagnostic instances (not raw tuples)."""
    bundle = _assessment_bundle_dict("System is compliant.")
    diags = lint_coverage_cell_claim_language(bundle)
    assert diags and all(isinstance(d, ValidationDiagnostic) for d in diags)
