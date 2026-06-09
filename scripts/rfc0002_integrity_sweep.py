#!/usr/bin/env python3
"""Reusable verification sweep for ACEF RFC-0002 (VAL-RFC-006 + VAL-RFC-007).

Owned by F-M1-RFC-VERIFY. Verification-only: this script NEVER edits the RFC.

It runs two deterministic, byte-stable sweeps over the RFC Markdown document and
exits non-zero on any failure. There is no wall-clock or random input; two runs
over the same bytes produce identical output.

Checks
------
VAL-RFC-007 (document-integrity sweep):
  C1. Every fenced ``json`` block parses as valid JSON (notably the Appendix B
      ``incident_card`` schema and the ``card_source`` overlay).
  C2. Code fences are balanced: the count of ``` fence markers is even.
  C3. Top-level headings run ``## 1.`` .. ``## 11.`` then ``## Appendix A`` ..
      ``## Appendix E`` in that exact order, with no gaps or reordering.

VAL-RFC-006 (no-overclaim sweep):
  C4. The normative body (everything BEFORE ``## Appendix E``, i.e. sections
      1-11 plus Appendices A-D) contains NO surviving id-trust overclaim:
      no ``forgery-resistant`` / ``institution-free`` token, and no
      ``offline ... durable`` attribution overclaim. The check is also run over
      the whole document for evidence; the normative-body scope is the one that
      gates.
  C5. The ``id_grade`` discriminator AND the OPTIONAL-online domain-control
      framing are both present in each of sections 5.3, 5.7, 5.11, and 6, and
      are mutually consistent (every section carries both).

Exit codes
----------
* ``0`` — all checks PASS.
* ``1`` — one or more checks FAILED.
* ``2`` — the RFC document could not be located/read.

Usage
-----
``python scripts/rfc0002_integrity_sweep.py``
``python scripts/rfc0002_integrity_sweep.py --rfc <path>``
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DEFAULT_RFC = Path(__file__).resolve().parent.parent / "planning" / "ACEF-RFC-0002-ai-incident-reporting-profile.md"

# Overclaim tokens that MUST NOT survive in the normative body (VAL-RFC-006).
# Matched case-INSENSITIVELY so capitalised variants (e.g. "Forgery-Resistant",
# "Institution-Free") cannot evade the scan.
OVERCLAIM_TOKENS = ("forgery-resistant", "institution-free")
OVERCLAIM_TOKEN_RES = tuple(re.compile(re.escape(tok), re.IGNORECASE) for tok in OVERCLAIM_TOKENS)

# An "offline ... durable" attribution overclaim: the words "offline" and
# "durable" co-occurring within a short window (an attribution sentence). The
# RFC must never claim the handle is an offline/durable attributable credential.
OFFLINE_DURABLE_RE = re.compile(
    r"offline[^.\n]{0,80}durable|durable[^.\n]{0,80}offline",
    re.IGNORECASE,
)

# Required sections for the id_grade + optional-online consistency check.
REQUIRED_SECTIONS = ("5.3", "5.7", "5.11", "6")

# Both Appendix B schema excerpts MUST be present (by their canonical $id). C1
# fails if EITHER expected block is missing, even if the surviving blocks are
# valid JSON. This prevents a silent regression that drops one excerpt.
REQUIRED_SCHEMA_IDS = (
    "https://acef.ai/schemas/v1.1/incident_card.schema.json",
    "https://acef.ai/schemas/v1.1/incident_report.card_source.schema.json",
)

# Any level-2 heading line: "## <anything>". C3 collects EVERY such heading so
# a stray/unexpected heading (e.g. "## References") cannot slip past the scan.
ANY_TOP_HEADING_RE = re.compile(r"^## (.+?)\s*$")

# CommonMark fenced-code-block opener/closer. A fence line is, after at most
# three leading spaces of indentation, a run of >=3 IDENTICAL fence characters
# (backtick "`" OR tilde "~"). Group 1 is the leading indentation; group 2 is
# the fence-character run itself (its first char is the fence char, its length is
# the fence length). Per CommonMark a closing fence carries no info string, but
# matching char + length is sufficient for this sweep's purposes.
FENCE_LINE_RE = re.compile(r"^( {0,3})((`{3,})|(~{3,}))[ \t]*(.*)$")

# The canonical key of an EXPECTED top-level heading: "## 1. ...", "## 11. ...",
# or "## Appendix A. ...". Used to normalise an expected heading line to its key
# ("1".."11", "Appendix A".."Appendix E").
EXPECTED_HEADING_RE = re.compile(r"^## (\d+|Appendix [A-Z])\b")

# Optional-online domain-control framing markers. A section satisfies the
# framing requirement if it carries the "id_grade" discriminator AND at least
# one optional-online / check-time control phrase.
ONLINE_FRAMING_RE = re.compile(
    r"OPTIONAL online|optional online|at check time|check-time|online-conformance",
    re.IGNORECASE,
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _emit(ok: bool, check: str, detail: str) -> bool:
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {check}: {detail}")
    return ok


def check_json_blocks(text: str) -> bool:
    """C1: every ```json fenced block parses, and BOTH Appendix B excerpts exist.

    Parsing alone is insufficient: the sweep must guarantee the two normative
    Appendix B schema excerpts (``incident_card`` and ``card_source``) are both
    present. C1 fails if either canonical ``$id`` is absent, even when every
    surviving block is valid JSON.
    """
    blocks = re.findall(r"```json\n(.*?)```", text, re.S)
    if not blocks:
        return _emit(False, "C1 json-blocks", "no ```json blocks found (expected >=2)")
    failures: list[str] = []
    seen_ids: set[str] = set()
    for idx, block in enumerate(blocks, start=1):
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError as exc:
            failures.append(f"block #{idx}: {exc}")
            continue
        if isinstance(parsed, dict):
            block_id = parsed.get("$id")
            if isinstance(block_id, str):
                seen_ids.add(block_id)
    if failures:
        return _emit(False, "C1 json-blocks", "; ".join(failures))
    missing_ids = [sid for sid in REQUIRED_SCHEMA_IDS if sid not in seen_ids]
    if missing_ids:
        return _emit(
            False,
            "C1 json-blocks",
            f"all {len(blocks)} block(s) parse, but missing required Appendix B $id(s): {', '.join(missing_ids)}",
        )
    return _emit(
        True,
        "C1 json-blocks",
        f"all {len(blocks)} ```json block(s) parse as valid JSON; both Appendix B $id(s) present",
    )


def _fence_open_info(line: str) -> tuple[str, int] | None:
    """If ``line`` is a CommonMark code-fence OPENER, return ``(char, length)``.

    An opener is, after <=3 spaces of indentation, a run of >=3 identical fence
    characters (`` ` `` or ``~``). The info string (the run's trailing text) is
    irrelevant to opening. Returns ``None`` for non-fence lines.
    """
    m = FENCE_LINE_RE.match(line)
    if m is None:
        return None
    run = m.group(2)
    return run[0], len(run)


def _is_fence_close(line: str, open_char: str, open_len: int) -> bool:
    """True if ``line`` CLOSES a fence opened with ``open_char`` x ``open_len``.

    Per CommonMark a closing fence uses the SAME character as the opener, is at
    least as long as the opener, and carries NO info string (only trailing
    whitespace is permitted after the run).
    """
    m = FENCE_LINE_RE.match(line)
    if m is None:
        return False
    run = m.group(2)
    info = m.group(5)
    return run[0] == open_char and len(run) >= open_len and info.strip() == ""


def _has_dangling_fence(text: str) -> tuple[bool, int]:
    """Walk ``text`` under CommonMark fence rules; report any unclosed fence.

    Returns ``(dangling, n_blocks)`` where ``dangling`` is True iff a fence was
    opened and never closed before EOF, and ``n_blocks`` is the number of fenced
    code blocks that opened (closed or not). A nested fence run that is shorter
    than (or a different char from) the open fence is block CONTENT and does not
    open or close anything.
    """
    open_char: str | None = None
    open_len = 0
    n_blocks = 0
    for line in text.splitlines():
        if open_char is None:
            info = _fence_open_info(line)
            if info is not None:
                open_char, open_len = info
                n_blocks += 1
            continue
        # Inside a fence: only a matching-or-longer same-char run with no info
        # string closes it; everything else (including shorter/other-char fence
        # runs) is content.
        if _is_fence_close(line, open_char, open_len):
            open_char = None
            open_len = 0
    return open_char is not None, n_blocks


def check_fences_balanced(text: str) -> bool:
    """C2: under CommonMark fence rules, no code fence is left unclosed at EOF.

    This supersedes the old "even count of ``` markers" heuristic, which could
    not see ``~~~`` tilde fences and mis-counted longer (>=4 backtick) fences
    that contain nested shorter runs. A fence opens on a run of >=3 identical
    fence chars and closes only on a later >=-as-long run of the SAME char with
    no info string; nested shorter/other-char runs are content.
    """
    dangling, n_blocks = _has_dangling_fence(text)
    ok = not dangling
    if ok:
        detail = f"all {n_blocks} fenced block(s) closed (no dangling fence at EOF)"
    else:
        detail = f"DANGLING unclosed fence at EOF ({n_blocks} block(s) opened)"
    return _emit(ok, "C2 fences-balanced", detail)


def check_heading_order(text: str) -> bool:
    """C3: the COMPLETE set of ``## `` headings is exactly §1..§11, App A..E.

    Collects EVERY level-2 heading (not just the ones that match the expected
    pattern), then maps each to its canonical key. An expected heading maps to
    its number/appendix key; an unexpected heading (e.g. ``## References``) maps
    to a sentinel ``!<raw>`` so it can never coincide with an expected key. The
    full ordered list must equal the expected sequence — any stray, missing,
    duplicated, or reordered heading fails the check.

    The scan is fence-aware under CommonMark rules: a ``## `` line INSIDE a
    fenced code block (e.g. a shell comment ``## References`` in a ``bash``
    example, a nested ``` block inside a ```` block, or a ``~~~`` tilde block) is
    body content, NOT a Markdown heading, and is ignored. A fence opens on a run
    of >=3 identical fence chars and closes only on a later >=-as-long run of the
    SAME char with no info string; nested shorter/other-char runs are content.
    """
    expected = [str(n) for n in range(1, 12)] + [f"Appendix {letter}" for letter in "ABCDE"]
    found: list[str] = []
    open_char: str | None = None
    open_len = 0
    for line in text.splitlines():
        if open_char is None:
            info = _fence_open_info(line)
            if info is not None:
                # A fence opener line opens a fenced code block. The opener line
                # itself is never a heading; enter the block and move on.
                open_char, open_len = info
                continue
        else:
            # Inside a fenced code block: a matching close ends it; every other
            # line (including ``## `` comments and nested shorter runs) is body.
            if _is_fence_close(line, open_char, open_len):
                open_char = None
                open_len = 0
            continue
        raw = ANY_TOP_HEADING_RE.match(line)
        if raw is None:
            continue
        em = EXPECTED_HEADING_RE.match(line)
        if em:
            found.append(em.group(1))
        else:
            # Unexpected heading: record a sentinel that cannot match any key.
            found.append(f"!{raw.group(1)}")
    if found != expected:
        return _emit(
            False,
            "C3 heading-order",
            f"expected {expected} but found {found}",
        )
    return _emit(
        True,
        "C3 heading-order",
        "sections 1-11 then Appendix A-E present in order; no stray ## headings",
    )


def _normative_body(text: str) -> str:
    """The normative body: everything before the historical ``## Appendix E``.

    Appendix E holds the verbatim Revision-0 problem statements (the audit
    trail), which VAL-RFC-006 explicitly excludes from the overclaim scope.
    """
    marker = "\n## Appendix E"
    idx = text.find(marker)
    return text if idx == -1 else text[:idx]


def check_no_overclaim(text: str) -> bool:
    """C4: no surviving id-trust overclaim in the normative body."""
    body = _normative_body(text)
    findings: list[str] = []

    for token, token_re in zip(OVERCLAIM_TOKENS, OVERCLAIM_TOKEN_RES):
        n = len(token_re.findall(body))
        if n:
            findings.append(f'"{token}" x{n}')

    od = OFFLINE_DURABLE_RE.findall(body)
    if od:
        findings.append(f'"offline...durable" overclaim x{len(od)}')

    # Whole-document counts reported as independent evidence (non-gating).
    whole_overclaim = sum(len(r.findall(text)) for r in OVERCLAIM_TOKEN_RES)
    whole_od = len(OFFLINE_DURABLE_RE.findall(text))

    if findings:
        return _emit(
            False,
            "C4 no-overclaim",
            "normative-body overclaims: " + ", ".join(findings),
        )
    return _emit(
        True,
        "C4 no-overclaim",
        "no forgery-resistant/institution-free/offline-durable overclaim in "
        f"normative body (whole-doc evidence: overclaim-tokens={whole_overclaim}, "
        f"offline-durable={whole_od})",
    )


def _section_text(text: str, section: str) -> str:
    """Return the text of section ``5.3`` / ``5.7`` / ``5.11`` / top-level ``6``.

    A subsection (``### 5.x``) runs until the next ``### `` or ``## `` heading.
    A top-level section (``## N.``) runs until the next ``## `` heading.
    """
    if "." in section:
        start_re = re.compile(rf"^### {re.escape(section)}(?:[ .])", re.M)
        stop_re = re.compile(r"^#{2,3} ", re.M)
    else:
        start_re = re.compile(rf"^## {re.escape(section)}(?:[ .])", re.M)
        stop_re = re.compile(r"^## ", re.M)
    sm = start_re.search(text)
    if sm is None:
        return ""
    rest = text[sm.end() :]
    em = stop_re.search(rest)
    return rest if em is None else rest[: em.start()]


def check_idgrade_and_online_framing(text: str) -> bool:
    """C5: id_grade + optional-online framing present in 5.3/5.7/5.11/6."""
    missing: list[str] = []
    detail: list[str] = []
    for section in REQUIRED_SECTIONS:
        body = _section_text(text, section)
        if not body:
            missing.append(f"§{section} (section not found)")
            continue
        n_grade = len(re.findall(r"id_grade", body))
        has_online = bool(ONLINE_FRAMING_RE.search(body))
        detail.append(f"§{section}: id_grade={n_grade}, online-framing={'yes' if has_online else 'no'}")
        if n_grade == 0:
            missing.append(f"§{section} missing id_grade")
        if not has_online:
            missing.append(f"§{section} missing optional-online framing")
    if missing:
        return _emit(
            False,
            "C5 idgrade+online",
            "; ".join(missing) + " || " + "; ".join(detail),
        )
    return _emit(
        True,
        "C5 idgrade+online",
        "id_grade + optional-online framing present in all required sections [" + "; ".join(detail) + "]",
    )


def run(rfc_path: Path) -> int:
    if not rfc_path.is_file():
        print(f"[FATAL] RFC not found: {rfc_path}", file=sys.stderr)
        return 2
    text = _read(rfc_path)
    print(f"RFC-0002 integrity sweep over: {rfc_path}")

    results = [
        check_json_blocks(text),  # C1  (VAL-RFC-007)
        check_fences_balanced(text),  # C2  (VAL-RFC-007)
        check_heading_order(text),  # C3  (VAL-RFC-007)
        check_no_overclaim(text),  # C4  (VAL-RFC-006)
        check_idgrade_and_online_framing(text),  # C5  (VAL-RFC-006)
    ]

    passed = sum(1 for r in results if r)
    total = len(results)
    if all(results):
        print(f"SWEEP RESULT: PASS ({passed}/{total} checks green)")
        return 0
    print(f"SWEEP RESULT: FAIL ({passed}/{total} checks green)")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="ACEF RFC-0002 no-overclaim + document-integrity sweep.")
    parser.add_argument(
        "--rfc",
        type=Path,
        default=DEFAULT_RFC,
        help="Path to the RFC-0002 Markdown document.",
    )
    args = parser.parse_args()
    return run(args.rfc.resolve())


if __name__ == "__main__":
    sys.exit(main())
