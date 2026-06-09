"""Tests for scripts/rfc0002_integrity_sweep.py (F-M1-RFC-VERIFY).

These tests drive the reusable RFC-0002 verification sweep that backs
VAL-RFC-006 (no-overclaim) and VAL-RFC-007 (document integrity). They assert:

* the real RFC document passes every check and the sweep exits 0;
* each check fails for the specific defect it is meant to catch
  (malformed JSON, unbalanced fences, reordered headings, a normative-body
  overclaim, a section missing the id_grade / optional-online framing);
* an overclaim that appears ONLY in the historical Appendix E is excluded
  from the gating scope (VAL-RFC-006 excludes Appendix E by design).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "rfc0002_integrity_sweep.py"
_RFC = _REPO_ROOT / "planning" / "ACEF-RFC-0002-ai-incident-reporting-profile.md"


def _load_module():
    spec = importlib.util.spec_from_file_location("rfc0002_integrity_sweep", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sweep = _load_module()


# --- Whole-document sweep over the real RFC (the gating evidence) -----------


def test_real_rfc_passes_full_sweep() -> None:
    assert sweep.run(_RFC) == 0


def test_missing_rfc_returns_2(tmp_path: Path) -> None:
    assert sweep.run(tmp_path / "does-not-exist.md") == 2


# --- C1: json blocks parse ---------------------------------------------------


def test_c1_fails_on_valid_block_without_required_ids() -> None:
    # A single valid JSON block that is NOT an Appendix B excerpt must FAIL C1:
    # parsing-validity alone is insufficient; both canonical $id(s) are required.
    text = 'prefix\n```json\n{"a": 1}\n```\nsuffix\n'
    assert sweep.check_json_blocks(text) is False


def test_c1_fails_on_malformed_json_block() -> None:
    # Trailing comma is invalid JSON.
    text = 'prefix\n```json\n{"a": 1,}\n```\nsuffix\n'
    assert sweep.check_json_blocks(text) is False


def test_c1_fails_when_no_json_block_present() -> None:
    assert sweep.check_json_blocks("no fenced json here\n") is False


_INCIDENT_CARD_BLOCK = (
    "```json\n"
    "{\n"
    '  "$schema": "https://json-schema.org/draft/2020-12/schema",\n'
    '  "$id": "https://acef.ai/schemas/v1.1/incident_card.schema.json",\n'
    '  "title": "incident_card"\n'
    "}\n"
    "```\n"
)
_CARD_SOURCE_BLOCK = (
    "```json\n"
    "{\n"
    '  "$schema": "https://json-schema.org/draft/2020-12/schema",\n'
    '  "$id": "https://acef.ai/schemas/v1.1/incident_report.card_source.schema.json",\n'
    '  "title": "card_source"\n'
    "}\n"
    "```\n"
)


def test_c1_passes_when_both_appendix_b_ids_present() -> None:
    text = "prefix\n" + _INCIDENT_CARD_BLOCK + "between\n" + _CARD_SOURCE_BLOCK + "suffix\n"
    assert sweep.check_json_blocks(text) is True


def test_c1_fails_when_card_source_block_missing() -> None:
    # Valid JSON, but the card_source Appendix B excerpt is absent: C1 MUST fail.
    text = "prefix\n" + _INCIDENT_CARD_BLOCK + "suffix\n"
    assert sweep.check_json_blocks(text) is False


def test_c1_fails_when_incident_card_block_missing() -> None:
    # Valid JSON, but the incident_card Appendix B excerpt is absent: C1 MUST fail.
    text = "prefix\n" + _CARD_SOURCE_BLOCK + "suffix\n"
    assert sweep.check_json_blocks(text) is False


# --- C2: fences balanced -----------------------------------------------------


def test_c2_passes_on_even_fences() -> None:
    assert sweep.check_fences_balanced("```\nx\n```\n") is True


def test_c2_fails_on_odd_fences() -> None:
    assert sweep.check_fences_balanced("```\nx\n") is False


# --- C3: heading order -------------------------------------------------------


def test_c3_fails_on_reordered_headings() -> None:
    text = "## 1. A\n## 3. C\n## 2. B\n"
    assert sweep.check_heading_order(text) is False


def test_c3_passes_on_real_rfc() -> None:
    assert sweep.check_heading_order(_RFC.read_text(encoding="utf-8")) is True


def _ordered_top_headings() -> str:
    """The full, in-order §1..§11 + Appendix A..E heading skeleton."""
    lines = [f"## {n}. Section {n}\nbody\n" for n in range(1, 12)]
    lines += [f"## Appendix {letter}. Title\nbody\n" for letter in "ABCDE"]
    return "".join(lines)


def test_c3_passes_on_complete_ordered_skeleton() -> None:
    assert sweep.check_heading_order(_ordered_top_headings()) is True


def test_c3_fails_on_stray_unexpected_heading() -> None:
    # All expected headings present and in order, PLUS a stray `## References`
    # that matches neither `## <number>.` nor `## Appendix <letter>`.
    skeleton = _ordered_top_headings()
    text = skeleton + "## References\nsome refs\n"
    assert sweep.check_heading_order(text) is False


# --- C4: no-overclaim --------------------------------------------------------


def test_c4_fails_on_normative_body_overclaim() -> None:
    text = "## 5. Design\nThe id is forgery-resistant and institution-free.\n## Appendix E\nhistorical text\n"
    assert sweep.check_no_overclaim(text) is False


def test_c4_fails_on_offline_durable_overclaim() -> None:
    text = "## 5. Design\nThe handle is an offline, durable attributable credential.\n## Appendix E\nhistorical\n"
    assert sweep.check_no_overclaim(text) is False


def test_c4_excludes_appendix_e_overclaim() -> None:
    # An overclaim that appears ONLY after `## Appendix E` does NOT gate.
    text = "## 5. Design\nclean normative body\n## Appendix E\nold draft said forgery-resistant and institution-free.\n"
    assert sweep.check_no_overclaim(text) is True


def test_c4_fails_on_capitalized_overclaim_tokens() -> None:
    # Capitalized / mixed-case overclaim tokens must NOT evade the scan.
    text = "## 5. Design\nThe id is Forgery-Resistant and Institution-Free.\n## Appendix E\nhistorical\n"
    assert sweep.check_no_overclaim(text) is False


def test_c4_fails_on_capitalized_offline_durable_overclaim() -> None:
    text = "## 5. Design\nThe handle is an Offline, Durable attributable credential.\n## Appendix E\nhistorical\n"
    assert sweep.check_no_overclaim(text) is False


def test_c4_passes_on_real_rfc() -> None:
    assert sweep.check_no_overclaim(_RFC.read_text(encoding="utf-8")) is True


# --- C5: id_grade + optional-online framing ----------------------------------


def test_c5_passes_on_real_rfc() -> None:
    assert sweep.check_idgrade_and_online_framing(_RFC.read_text(encoding="utf-8")) is True


def test_c5_fails_when_section_lacks_idgrade() -> None:
    # A synthetic doc whose §5.3 lacks id_grade entirely.
    text = (
        "### 5.3 Public identifier\nno discriminator here, OPTIONAL online check\n"
        "### 5.7 Templates\nid_grade self-asserted at check time\n"
        "### 5.11 Publishability\nid_grade OPTIONAL online\n"
        "## 6. Conformance\nid_grade online-conformance\n"
    )
    assert sweep.check_idgrade_and_online_framing(text) is False


def test_c5_fails_when_section_has_idgrade_but_no_online_framing() -> None:
    # Every required section carries id_grade, but §5.7 lacks ANY optional-online
    # / check-time framing marker. C5 MUST fail (the gap finding #4).
    text = (
        "### 5.3 Public identifier\nid_grade self-asserted, OPTIONAL online check\n"
        "### 5.7 Templates\nid_grade self-asserted but no framing marker here\n"
        "### 5.11 Publishability\nid_grade at check time\n"
        "## 6. Conformance\nid_grade online-conformance class\n"
    )
    assert sweep.check_idgrade_and_online_framing(text) is False


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
