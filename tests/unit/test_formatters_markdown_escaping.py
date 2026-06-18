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

import re

from acef.cli.formatters import bundle_summary_markdown

# A pipe that is NOT preceded by a backslash — i.e. a STRUCTURAL table delimiter.
_UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")


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
        assert len(_UNESCAPED_PIPE.findall(rows[0])) == 5, f"table corrupted by injected pipe: {rows[0]!r}"
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
        assert len(_UNESCAPED_PIPE.findall(rows[0])) == 4, f"table corrupted by injected pipe: {rows[0]!r}"
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
        assert len(_UNESCAPED_PIPE.findall(rows[0])) == 5, f"table corrupted: {rows[0]!r}"
