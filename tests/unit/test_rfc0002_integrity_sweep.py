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


def test_c3_ignores_hash_heading_inside_fenced_code_block() -> None:
    # An otherwise-valid §1..§11 + Appendix A..E skeleton that ALSO contains a
    # fenced code block whose body has a `## References` line (a shell comment).
    # That fenced `## ` line is NOT a Markdown heading and MUST be ignored: the
    # heading scan must be fence-aware and C3 MUST still PASS.
    skeleton = _ordered_top_headings()
    fenced = "```bash\n# usage\n## References\n## 99. not a heading\necho ok\n```\n"
    # Place the fenced block in the middle so the surrounding headings still
    # frame it as document body, not a trailing artifact.
    text = skeleton + fenced
    assert sweep.check_heading_order(text) is True


def test_c3_ignores_hash_heading_inside_text_fence() -> None:
    # Same defect, ```text fence variant, with the fence interleaved between
    # real headings. The fenced `## 99.` must not be collected as a heading.
    head = "".join(f"## {n}. Section {n}\nbody\n" for n in range(1, 6))
    fenced = "```text\n## 99. fenced pseudo-heading\n```\n"
    tail = "".join(f"## {n}. Section {n}\nbody\n" for n in range(6, 12))
    tail += "".join(f"## Appendix {letter}. Title\nbody\n" for letter in "ABCDE")
    text = head + fenced + tail
    assert sweep.check_heading_order(text) is True


def test_c3_ignores_hash_heading_inside_four_backtick_fence() -> None:
    # CommonMark: a fence opened with four backticks (````) spans until a CLOSING
    # fence of >=4 backticks of the SAME char. A nested THREE-backtick run inside
    # MUST NOT close it. The inner ``` and the `## References` line both live
    # inside the four-backtick block and are document body, not headings. With the
    # old toggle-on-any-triple-backtick logic the inner ``` flips fence state OFF
    # and the `## References` line leaks out as a stray heading -> C3 wrongly
    # FAILS (genuinely RED on the old code: an odd number of inner ``` runs).
    skeleton = _ordered_top_headings()
    fenced = '````markdown\nHere is a nested fenced example with one inner run:\n```\n{"a": 1}\n## References\n````\n'
    text = skeleton + fenced
    assert sweep.check_heading_order(text) is True


def test_c3_ignores_hash_heading_inside_tilde_fence() -> None:
    # CommonMark: `~~~` is a valid fence char. A `## 99.` line inside a tilde
    # fence is body, not a heading. The old logic only recognised ``` and so it
    # collected the fenced `## 99.` as a stray heading -> C3 wrongly FAILS.
    head = "".join(f"## {n}. Section {n}\nbody\n" for n in range(1, 6))
    fenced = "~~~\n## 99. tilde-fenced pseudo-heading\n~~~\n"
    tail = "".join(f"## {n}. Section {n}\nbody\n" for n in range(6, 12))
    tail += "".join(f"## Appendix {letter}. Title\nbody\n" for letter in "ABCDE")
    text = head + fenced + tail
    assert sweep.check_heading_order(text) is True


def test_c3_inner_triple_does_not_close_outer_quad_fence() -> None:
    # A `## 1.`-shaped heading sits AFTER the inner ``` but still INSIDE the outer
    # ```` block. If the inner ``` prematurely closed the outer fence, that line
    # would be (mis)collected as `## 1.` and corrupt the ordered heading list.
    # The whole four-backtick block (and everything in it) must be ignored.
    skeleton = _ordered_top_headings()
    fenced = "````text\n```\ninner code\n## 1. still inside the outer four-backtick fence\n````\n"
    text = skeleton + fenced
    assert sweep.check_heading_order(text) is True


def test_c2_passes_on_four_backtick_fence_with_nested_triple() -> None:
    # C2 (no dangling open fence) must treat the inner ``` as content of the outer
    # ```` block, not as an independent fence. A naive even-count of "```" markers
    # would see THREE occurrences (````, ```, ```, ````) and could miscount; the
    # CommonMark model sees exactly one balanced outer fence.
    text = "````\n```\ninner\n```\n````\n"
    assert sweep.check_fences_balanced(text) is True


def test_c2_passes_on_balanced_tilde_fence() -> None:
    assert sweep.check_fences_balanced("~~~\nx\n~~~\n") is True


def test_c2_fails_on_unclosed_four_backtick_fence() -> None:
    # An opening ```` with only a nested ``` ... ``` inside and no >=4 backtick
    # closer leaves the outer fence dangling at EOF -> C2 MUST fail.
    text = "````\n```\ninner\n```\n"
    assert sweep.check_fences_balanced(text) is False


def test_c2_fails_on_unclosed_tilde_fence() -> None:
    assert sweep.check_fences_balanced("~~~\nx\n") is False


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
