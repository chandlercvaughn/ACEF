"""PhD re-review REG-1/REG-2: the legal characterization of 'widespread
infringement' must be consistent and correctly cited across the repo.

Per primary law (Regulation (EU) 2024/1689): Art. 73(3) sets the 2-day clock for
"a widespread infringement OR a serious incident as defined in Article 3, point
(49)(b)" — two INDEPENDENT triggers. "Widespread infringement" is defined in
Art. 3, point (61) — a standalone term, NOT a sub-type or modifier of the Art.
3(49)(c) fundamental-rights trigger. RFC-0002 previously mischaracterized it as a
"cross-cutting modifier of (c), not a fifth letter," contradicting the (correct)
template framing; and Art. 3(61) was cited nowhere by point number.
"""

from __future__ import annotations

import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_RFC = _ROOT / "planning" / "ACEF-RFC-0002-ai-incident-reporting-profile.md"
_TEMPLATE = _ROOT / "src" / "acef" / "templates" / "eu-ai-act-art73-2026.json"


def test_rfc0002_does_not_call_widespread_a_modifier_of_c() -> None:
    """REG-1: the legally-wrong 'modifier of (c)' framing must be gone."""
    rfc = _RFC.read_text(encoding="utf-8")
    assert "cross-cutting modifier of (c)" not in rfc
    assert "modifier, not a 5th trigger" not in rfc
    assert "widespread is a cross-cutting modifier" not in rfc


def test_rfc0002_frames_widespread_as_independent_art73_trigger_citing_3_61() -> None:
    """REG-1/REG-2: the RFC frames widespread as an INDEPENDENT Art. 73(3) trigger
    and cites Art. 3, point (61)."""
    rfc = _RFC.read_text(encoding="utf-8")
    assert "3(61)" in rfc or "3, point (61)" in rfc, "RFC must cite Art. 3(61) for the widespread definition"
    assert "independent" in rfc.lower()


def test_no_assertive_widespread_modifier_wording_anywhere() -> None:
    """roborev on 586138c/eaacd4d: no line in the RFC or template may call
    'widespread' a 'modifier' AS AN ASSERTION. The only permitted co-occurrence of
    'widespread' and 'modifier' on one line is a negation that binds DIRECTLY to
    'modifier' — so a sneaky 'widespread is a modifier, not a separate trigger'
    (a 'not a' elsewhere on the line) is still caught. This guard makes the
    mischaracterization unable to recur."""
    # The negation must attach to the word 'modifier' itself. Strip markdown
    # emphasis markers first so '**not** a modifier' normalizes to 'not a modifier'.
    allowed_negations = ("not a modifier", "not a sub-type or modifier", "and not a modifier")
    for path in (_RFC, _TEMPLATE):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            low = line.lower()
            if "widespread" in low and "modifier" in low:
                norm = low.replace("*", "").replace("_", "")
                assert any(neg in norm for neg in allowed_negations), (
                    f"{path.name}:{lineno} asserts 'widespread' is a 'modifier' — it is an "
                    f"INDEPENDENT Art. 73(3) trigger (Art. 3(61)): {line.strip()[:140]!r}"
                )


def test_template_cites_art_3_61_for_widespread() -> None:
    """REG-2: the template's source_legislation and widespread paraphrase cite
    Art. 3(61) by point number (it pins every other sub-point precisely)."""
    tmpl = json.loads(_TEMPLATE.read_text(encoding="utf-8"))
    src = tmpl["source_legislation"]
    assert "3(61)" in src or "3, point (61)" in src, f"source_legislation must cite Art. 3(61); got {src!r}"
    blob = json.dumps(tmpl)
    assert "point (61)" in blob or "3(61)" in blob, "the widespread paraphrase must cite the Art. 3(61) point number"
