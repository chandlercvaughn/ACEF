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
OVERCLAIM_TOKENS = ("forgery-resistant", "institution-free")

# An "offline ... durable" attribution overclaim: the words "offline" and
# "durable" co-occurring within a short window (an attribution sentence). The
# RFC must never claim the handle is an offline/durable attributable credential.
OFFLINE_DURABLE_RE = re.compile(
    r"offline[^.\n]{0,80}durable|durable[^.\n]{0,80}offline",
    re.IGNORECASE,
)

# Required sections for the id_grade + optional-online consistency check.
REQUIRED_SECTIONS = ("5.3", "5.7", "5.11", "6")

# A top-level section heading: "## 1. ...", "## 11. ...", "## Appendix A. ...".
TOP_HEADING_RE = re.compile(r"^## (\d+|Appendix [A-Z])\b")

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
    """C1: every ```json fenced block parses as valid JSON."""
    blocks = re.findall(r"```json\n(.*?)```", text, re.S)
    if not blocks:
        return _emit(False, "C1 json-blocks", "no ```json blocks found (expected >=2)")
    failures: list[str] = []
    for idx, block in enumerate(blocks, start=1):
        try:
            json.loads(block)
        except json.JSONDecodeError as exc:
            failures.append(f"block #{idx}: {exc}")
    if failures:
        return _emit(False, "C1 json-blocks", "; ".join(failures))
    return _emit(
        True,
        "C1 json-blocks",
        f"all {len(blocks)} ```json block(s) parse as valid JSON",
    )


def check_fences_balanced(text: str) -> bool:
    """C2: the count of ``` fence markers is even (every open is closed)."""
    count = text.count("```")
    ok = count % 2 == 0
    return _emit(
        ok,
        "C2 fences-balanced",
        f"fence-marker count = {count} ({'even' if ok else 'ODD/unbalanced'})",
    )


def check_heading_order(text: str) -> bool:
    """C3: sections 1..11 then Appendix A..E appear in exact order."""
    expected = [str(n) for n in range(1, 12)] + [f"Appendix {letter}" for letter in "ABCDE"]
    found: list[str] = []
    for line in text.splitlines():
        m = TOP_HEADING_RE.match(line)
        if m:
            found.append(m.group(1))
    if found != expected:
        return _emit(
            False,
            "C3 heading-order",
            f"expected {expected} but found {found}",
        )
    return _emit(
        True,
        "C3 heading-order",
        "sections 1-11 then Appendix A-E present in order",
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

    for token in OVERCLAIM_TOKENS:
        n = body.count(token)
        if n:
            findings.append(f'"{token}" x{n}')

    od = OFFLINE_DURABLE_RE.findall(body)
    if od:
        findings.append(f'"offline...durable" overclaim x{len(od)}')

    # Whole-document counts reported as independent evidence (non-gating).
    whole_overclaim = sum(text.count(t) for t in OVERCLAIM_TOKENS)
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
