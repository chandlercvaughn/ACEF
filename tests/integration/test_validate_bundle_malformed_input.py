"""Fuzzing regression for validate_bundle against malformed external input.

``validate_bundle`` (and everything it calls) consumes UNTRUSTED external
JSON/JSONL: the on-disk ``acef-manifest.json`` and the record ``*.jsonl``
files. It MUST ALWAYS return an ``AssessmentBundle`` carrying diagnostics —
it MUST NEVER raise, regardless of how malformed the input is. The schema and
envelope phases emit the correct typed diagnostics (ACEF-001/002/003/004/050
etc.) for wrong-typed fields; the downstream reference/count phases must
defensively SKIP malformed entries rather than crash.

roborev flagged a concrete crash class in the Phase-3 reference checker:
``manifest["record_files"]`` is iterated and ``rf.get(...)`` is called without
guarding ``rf`` being a non-dict, and the manifest value itself being a
non-list (``null`` / ``"x"``). This module fuzzes each external field shape
and asserts NO exception escapes ``validate_bundle`` while diagnostics are
still produced.

Every case wraps the real ``validate_bundle`` in ``try/except Exception`` so
that ANY raised exception FAILS the test (rather than erroring out opaquely),
making the "never raises" contract explicit.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acef.models.assessment import AssessmentBundle
from acef.validation.engine import validate_bundle


def _write_bundle(
    bundle_dir: Path,
    manifest: Any,
    *,
    record_files: dict[str, str] | None = None,
) -> None:
    """Write a raw bundle directory with an arbitrary (possibly malformed)
    manifest object and optional raw JSONL record files.

    ``manifest`` is dumped verbatim (it may be a non-dict to exercise the
    top-level guard). ``record_files`` maps a relative path (under the bundle
    root) to the raw text content of that JSONL file.
    """
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    for rel_path, content in (record_files or {}).items():
        target = bundle_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _run_never_raises(bundle_dir: Path) -> AssessmentBundle:
    """Invoke the REAL validate_bundle, FAILING the test if anything raises."""
    try:
        return validate_bundle(str(bundle_dir))
    except Exception as exc:  # noqa: BLE001 — the contract under test is "never raises"
        pytest.fail(
            f"validate_bundle raised {type(exc).__name__} on malformed input "
            f"(it must return diagnostics, never raise): {exc!r}"
        )


def _has_diagnostics(assessment: AssessmentBundle) -> bool:
    """A malformed bundle must surface at least one structured diagnostic."""
    return len(assessment.structural_errors) > 0


# --------------------------------------------------------------------------- #
# record_files: the roborev-flagged crash class.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "record_files_value",
    [
        None,  # null  -> non-list, iteration would crash
        "records/x.jsonl",  # string -> iterable of CHARACTERS, char.get crash
        42,  # int -> non-iterable
        {"path": "records/x.jsonl"},  # dict -> iterates KEYS (strings)
        ["not-a-dict"],  # list of string -> str.get crash (ACEF-022 loop)
        [123],  # list of int -> int.get crash
        [None],  # list of null
        [["nested"]],  # list of list
        [{"path": "records/r.jsonl", "record_type": "risk_register"}, 123],
        # ^ valid entry followed by a bare int (mixed list)
        [{}],  # dict missing path/record_type/count
        [{"path": 123}],  # path is a non-string
        [{"record_type": "risk_register"}],  # entry missing path
        [{"path": "records/r.jsonl"}],  # entry missing record_type
    ],
)
def test_malformed_record_files_never_crashes(tmp_path: Path, record_files_value: Any) -> None:
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": record_files_value,
    }
    bundle_dir = tmp_path / "rf.acef"
    _write_bundle(bundle_dir, manifest)

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    # Malformed manifest must still produce diagnostics (schema phase fires).
    assert _has_diagnostics(assessment)


def test_record_files_list_with_nondict_and_real_file(tmp_path: Path) -> None:
    """A record_files list that mixes a string entry with a real, existing
    record file must skip the string and still process the real file (the
    ACEF-022 file-existence loop AND the _check_record_counts loop both
    iterate this list)."""
    bundle_dir = tmp_path / "mixed.acef"
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": [
            "not-a-dict",
            {"path": "records/risk_register.jsonl", "record_type": "risk_register", "count": 1},
        ],
    }
    record_line = json.dumps(
        {
            "record_id": "urn:acef:rec:1",
            "record_type": "risk_register",
            "payload": {},
        }
    )
    _write_bundle(
        bundle_dir,
        manifest,
        record_files={"records/risk_register.jsonl": record_line + "\n"},
    )

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    # The real file exists, so NO ACEF-022 "record file not found" for it.
    codes = [e.get("code") for e in assessment.structural_errors]
    assert "ACEF-022" not in codes


def test_record_files_entry_pointing_at_missing_file(tmp_path: Path) -> None:
    """A well-formed record_files dict whose path does not exist must emit
    ACEF-022 (not crash)."""
    bundle_dir = tmp_path / "missing.acef"
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": [{"path": "records/does_not_exist.jsonl", "record_type": "risk_register", "count": 1}],
    }
    _write_bundle(bundle_dir, manifest)

    assessment = _run_never_raises(bundle_dir)
    codes = [e.get("code") for e in assessment.structural_errors]
    assert "ACEF-022" in codes


# --------------------------------------------------------------------------- #
# record_type: already covered by prior commits — keep as regression.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "record_type_value",
    [
        ["a", "b"],  # list — unhashable as a dict key
        {"k": "v"},  # dict — unhashable
        123,  # int
        True,  # bool (int subclass)
        None,  # null
    ],
)
def test_malformed_record_type_in_records_never_crashes(tmp_path: Path, record_type_value: Any) -> None:
    bundle_dir = tmp_path / "rt.acef"
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": [{"path": "records/r.jsonl", "record_type": "risk_register", "count": 1}],
    }
    record_line = json.dumps(
        {
            "record_id": "urn:acef:rec:1",
            "record_type": record_type_value,
            "payload": {},
        }
    )
    _write_bundle(bundle_dir, manifest, record_files={"records/r.jsonl": record_line + "\n"})

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    assert _has_diagnostics(assessment)


def test_malformed_record_type_in_record_files_never_crashes(tmp_path: Path) -> None:
    """A record_files entry whose declared record_type is a non-string must
    not crash the count roll-up (_check_record_counts)."""
    bundle_dir = tmp_path / "rfrt.acef"
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": [
            {"path": "records/r.jsonl", "record_type": ["bad"], "count": 1},
            {"path": "records/s.jsonl", "record_type": 42, "count": "lots"},
        ],
    }
    _write_bundle(bundle_dir, manifest)

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    assert _has_diagnostics(assessment)


# --------------------------------------------------------------------------- #
# Top-level manifest shape and other walked sections.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "manifest_value",
    [
        [],  # JSON array at top level
        "not-an-object",  # JSON string
        42,  # JSON number
        None,  # JSON null
        True,  # JSON bool
    ],
)
def test_manifest_not_an_object_never_crashes(tmp_path: Path, manifest_value: Any) -> None:
    bundle_dir = tmp_path / "topshape.acef"
    _write_bundle(bundle_dir, manifest_value)

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    assert _has_diagnostics(assessment)


@pytest.mark.parametrize(
    "section_overrides",
    [
        {"metadata": []},  # non-dict metadata (chained .get crash site)
        {"metadata": "x"},
        {"metadata": None},
        {"versioning": []},
        {"subjects": "x"},  # non-list subjects
        {"subjects": [123, "y"]},  # list of non-dict subjects
        {"entities": []},  # non-dict entities
        {"entities": {"components": "x"}},  # non-list components
        {"entities": {"components": [123]}},  # non-dict component
        {"entities": {"datasets": [None]}},
        {"entities": {"actors": ["bad"]}},
        {"entities": {"relationships": [123]}},
        {"profiles": "x"},  # non-list profiles
        {"profiles": [123]},  # non-dict profile decl
    ],
)
def test_malformed_manifest_sections_never_crash(tmp_path: Path, section_overrides: dict[str, Any]) -> None:
    bundle_dir = tmp_path / "sections.acef"
    manifest: dict[str, Any] = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
    }
    manifest.update(section_overrides)
    _write_bundle(bundle_dir, manifest)

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)


def test_metadata_non_dict_with_profiles_never_crashes(tmp_path: Path) -> None:
    """A manifest whose metadata is a non-dict, exercised through the
    profile-evaluation path (Phase 4), must not crash on the chained
    metadata.get accesses."""
    bundle_dir = tmp_path / "profmeta.acef"
    manifest: dict[str, Any] = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": [],  # non-dict metadata
        "subjects": "not-a-list",
        "profiles": [123, {"profile_id": "eu-ai-act-2024"}],
    }
    _write_bundle(bundle_dir, manifest)

    try:
        assessment = validate_bundle(str(bundle_dir), profiles=["eu-ai-act-2024"])
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"validate_bundle raised {type(exc).__name__} on malformed input with profiles: {exc!r}")
    assert isinstance(assessment, AssessmentBundle)


# --------------------------------------------------------------------------- #
# Records JSONL line shapes.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "jsonl_line",
    [
        "123",  # bare number
        '"a string"',  # bare string
        "null",  # null
        "[1, 2, 3]",  # array
        "true",  # bool
        "{not json}",  # malformed JSON
    ],
)
def test_records_jsonl_non_object_lines_never_crash(tmp_path: Path, jsonl_line: str) -> None:
    bundle_dir = tmp_path / "jsonl.acef"
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": [{"path": "records/r.jsonl", "record_type": "risk_register", "count": 1}],
    }
    _write_bundle(bundle_dir, manifest, record_files={"records/r.jsonl": jsonl_line + "\n"})

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    assert _has_diagnostics(assessment)


# --------------------------------------------------------------------------- #
# v1.1 dispatch path (Phase 3b: cross-record / v1_1 rules / namespace lints).
# core_version 1.1.0 routes through additional record/manifest walks that must
# likewise never crash on malformed input.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "section_overrides",
    [
        {"record_files": ["not-a-dict"]},
        {"record_files": None},
        {"record_files": "x"},
        {"subjects": "not-a-list"},
        {"entities": []},
        {"metadata": []},
        {"profiles": [123]},
        {"analysis_mode": ["bad"]},  # non-string analysis_mode (mode-gate walk)
        {"namespaces": "x"},  # non-dict namespaces (cross-record external-ns)
    ],
)
def test_v1_1_dispatch_path_never_crashes(tmp_path: Path, section_overrides: dict[str, Any]) -> None:
    """A core_version 1.1.0 manifest triggers the v1.1-only validation phases
    (cross-record, v1.1 rules, namespace lints). Each must skip malformed
    sections rather than crash."""
    bundle_dir = tmp_path / "v11.acef"
    manifest: dict[str, Any] = {
        "versioning": {"core_version": "1.1.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
    }
    manifest.update(section_overrides)
    _write_bundle(bundle_dir, manifest)

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)


def test_v1_1_dispatch_with_malformed_records_jsonl(tmp_path: Path) -> None:
    """v1.1 dispatch with a record file whose lines are non-objects and one
    whose payload is a non-dict must not crash the cross-record / v1.1 phases."""
    bundle_dir = tmp_path / "v11rec.acef"
    manifest = {
        "versioning": {"core_version": "1.1.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": [{"path": "records/r.jsonl", "record_type": "risk_register", "count": 2}],
    }
    lines = "\n".join(
        [
            "123",
            json.dumps({"record_id": "urn:acef:rec:1", "record_type": "risk_register", "payload": "not-a-dict"}),
            json.dumps({"record_id": "urn:acef:rec:2", "record_type": ["bad"], "payload": {}}),
        ]
    )
    _write_bundle(bundle_dir, manifest, record_files={"records/r.jsonl": lines + "\n"})

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    assert _has_diagnostics(assessment)


def test_records_jsonl_record_missing_record_type(tmp_path: Path) -> None:
    """A record object missing record_type entirely must be handled
    gracefully (envelope schema flags it; no crash)."""
    bundle_dir = tmp_path / "nort.acef"
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": [{"path": "records/r.jsonl", "record_type": "risk_register", "count": 1}],
    }
    record_line = json.dumps({"record_id": "urn:acef:rec:1", "payload": {}})
    _write_bundle(bundle_dir, manifest, record_files={"records/r.jsonl": record_line + "\n"})

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    assert _has_diagnostics(assessment)
