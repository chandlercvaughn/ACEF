"""Unit tests — ``bundle_summary_markdown`` must escape manifest values that
would otherwise corrupt the Markdown table layout (roborev Low on 4d184a8).

``acef inspect --format markdown`` interpolates subject names + record-file
paths straight into GitHub-Flavored-Markdown table cells. A value containing a
literal ``|`` starts a new column; a value containing a newline terminates the
row. Both corrupt the rendered table — and a crafted value could inject
misleading Markdown into a compliance report. The renderer must escape ``|``
(and any value-internal backslash, so it cannot combine with the escape) and
collapse newlines, while leaving the structural delimiters intact.
"""

from __future__ import annotations

from acef.cli.formatters import bundle_summary_markdown


def _structural_pipes(row: str) -> int:
    """Count GFM STRUCTURAL ``|`` column delimiters in a table row.

    A ``|`` is a delimiter iff preceded by an EVEN number (0, 2, 4, …) of
    consecutive backslashes; an ODD run escapes it. A naive ``(?<!\\)\\|``
    regex only inspects ONE preceding backslash, so it MISSES an escape-ORDER
    regression that emits an even backslash run before a pipe (e.g. an
    implementation that escapes ``|`` BEFORE doubling backslashes turns
    ``a\\|b`` into ``a\\\\|b`` — four backslashes, which GFM parses as a literal
    backslash + a column break). This counter is order-correct (roborev Low on
    7c40c0f)."""
    count = 0
    for i, ch in enumerate(row):
        if ch != "|":
            continue
        backslashes = 0
        j = i - 1
        while j >= 0 and row[j] == "\\":
            backslashes += 1
            j -= 1
        if backslashes % 2 == 0:
            count += 1
    return count


def _base_manifest() -> dict[str, object]:
    return {
        "metadata": {"package_id": "urn:acef:pkg:x", "timestamp": "2026-01-01T00:00:00Z", "producer": {}},
        "versioning": {"core_version": "1.0.0"},
        "subjects": [],
        "entities": {},
        "record_files": [],
        "profiles": [],
    }


class TestSubjectsTableEscaping:
    def test_pipe_in_subject_name_does_not_inject_a_column(self) -> None:
        manifest = _base_manifest()
        manifest["subjects"] = [
            {
                "name": "evil | name",
                "subject_type": "ai_system",
                "risk_classification": "high-risk",
                "lifecycle_phase": "deployment",
            }
        ]
        md = bundle_summary_markdown(manifest)
        rows = [ln for ln in md.splitlines() if ln.startswith("| evil")]
        assert rows, f"subject data row missing:\n{md}"
        # A 4-column row has exactly 5 structural (unescaped) pipe delimiters; an
        # un-escaped injected '|' would push it to 6 and shift every cell.
        assert _structural_pipes(rows[0]) == 5, f"table corrupted by injected pipe: {rows[0]!r}"
        assert r"evil \| name" in rows[0]

    def test_newline_in_subject_field_does_not_split_the_row(self) -> None:
        manifest = _base_manifest()
        manifest["subjects"] = [
            {
                "name": "sys-a",
                "subject_type": "ai_system",
                "risk_classification": "high\nrisk",
                "lifecycle_phase": "deployment",
            }
        ]
        md = bundle_summary_markdown(manifest)
        rows = [ln for ln in md.splitlines() if ln.startswith("| sys-a")]
        assert rows, f"subject data row missing:\n{md}"
        # Newline collapsed to a space → value stays inside the one row.
        assert "high risk" in rows[0]
        # No orphan continuation line carrying the tail of the split value.
        assert not any(ln.strip() == "risk" or ln.startswith("risk |") for ln in md.splitlines())


class TestRecordFilesTableEscaping:
    def test_pipe_in_record_path_does_not_inject_a_column(self) -> None:
        manifest = _base_manifest()
        manifest["record_files"] = [{"record_type": "risk_register", "path": "records/a|b.jsonl", "count": 1}]
        md = bundle_summary_markdown(manifest)
        rows = [ln for ln in md.splitlines() if ln.startswith("| risk_register")]
        assert rows, f"record-file data row missing:\n{md}"
        # A 3-column row has exactly 4 structural pipe delimiters.
        assert _structural_pipes(rows[0]) == 4, f"table corrupted by injected pipe: {rows[0]!r}"
        assert r"records/a\|b.jsonl" in rows[0]


class TestBackslashAdjacentPipe:
    def test_trailing_backslash_then_pipe_cannot_reintroduce_a_break(self) -> None:
        """A value whose own backslash sits right before a '|' (``a\\|b``) must not
        let the value-internal backslash neutralize the escape and re-open a
        column. Backslash is escaped FIRST, so the cell still has the correct
        structural delimiter count."""
        manifest = _base_manifest()
        manifest["subjects"] = [
            {
                "name": "a\\|b",
                "subject_type": "ai_system",
                "risk_classification": "high-risk",
                "lifecycle_phase": "deployment",
            }
        ]
        md = bundle_summary_markdown(manifest)
        rows = [ln for ln in md.splitlines() if ln.startswith("| a")]
        assert rows, f"subject data row missing:\n{md}"
        # Order-correct structural count: 5 delimiters for the 4-column row.
        assert _structural_pipes(rows[0]) == 5, f"table corrupted: {rows[0]!r}"
        # Pin the exact backslash-FIRST escape source. Input chars a \ | b →
        # escape '\' first ('\'→'\\') then '|' ('|'→'\|') → a \\ \| b = ``a\\\|b``
        # (three backslashes, odd → the pipe is escaped). The WRONG order
        # (pipe-first) would emit ``a\\\\|b`` (four backslashes, even → a GFM
        # delimiter), which this exact-source assertion rejects.
        assert "| a\\\\\\|b |" in rows[0], f"escape order regressed: {rows[0]!r}"
