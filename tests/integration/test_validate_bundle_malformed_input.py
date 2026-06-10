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


# --------------------------------------------------------------------------- #
# metadata scalar fields: package_id / timestamp wrong-typed.
#
# roborev flagged that ``metadata.package_id`` flows verbatim into the Pydantic
# ``EvidenceBundleRef.package_id`` (str) field and ``metadata.timestamp`` flows
# into ``AssessmentBundle.evaluation_instant`` (str) AND the rule-engine
# ``package_timestamp`` parser. A non-string scalar there raised a raw Pydantic
# ``ValidationError`` (package_id) or a timestamp/str crash (timestamp) BEFORE
# Phase 1 schema diagnostics were collected. These must be guarded with
# ``isinstance(..., str)`` and coerced; the manifest schema (Phase 1) still
# emits the wrong-type diagnostic.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "bad_value",
    [
        ["a", "b"],  # list -> Pydantic str_type ValidationError
        {"k": "v"},  # dict
        42,  # int
        True,  # bool (int subclass)
        3.14,  # float
        None,  # null
    ],
)
def test_malformed_metadata_package_id_never_crashes(tmp_path: Path, bad_value: Any) -> None:
    """A non-string ``metadata.package_id`` must not reach the Pydantic
    EvidenceBundleRef str field and raise; it must be coerced and the manifest
    schema must still surface a diagnostic."""
    bundle_dir = tmp_path / "pkgid.acef"
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": bad_value,
            "timestamp": "2026-01-01T00:00:00Z",
        },
    }
    _write_bundle(bundle_dir, manifest)

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    # The coerced package_id must be a string (empty fallback), never the
    # malformed value, so downstream serialization stays well-typed.
    assert isinstance(assessment.evidence_bundle_ref.package_id, str)
    assert _has_diagnostics(assessment)


@pytest.mark.parametrize(
    "bad_value",
    [
        ["2026-01-01T00:00:00Z"],  # list
        {"ts": "2026-01-01T00:00:00Z"},  # dict
        1735689600,  # int (epoch seconds)
        True,  # bool
        2.5,  # float
        None,  # null
    ],
)
def test_malformed_metadata_timestamp_never_crashes(tmp_path: Path, bad_value: Any) -> None:
    """A non-string ``metadata.timestamp`` must not become the
    ``AssessmentBundle.evaluation_instant`` (Pydantic str) value or reach the
    rule-engine timestamp parser and raise. It is coerced to a fallback; the
    manifest schema still flags the wrong type."""
    bundle_dir = tmp_path / "ts.acef"
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": bad_value,
        },
    }
    _write_bundle(bundle_dir, manifest)

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    assert isinstance(assessment.evaluation_instant, str)
    assert _has_diagnostics(assessment)


@pytest.mark.parametrize(
    "bad_value",
    [
        ["2026-01-01T00:00:00Z"],  # list
        {"ts": "2026-01-01T00:00:00Z"},  # dict
        1735689600,  # int
        True,  # bool
        None,  # null
    ],
)
def test_malformed_metadata_timestamp_via_profiles_never_crashes(tmp_path: Path, bad_value: Any) -> None:
    """A non-string ``metadata.timestamp`` exercised through Phase-4 profile
    evaluation (where it is forwarded as ``package_timestamp`` into the rule
    engine's freshness/date comparisons) must not crash."""
    bundle_dir = tmp_path / "tsprof.acef"
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": bad_value,
        },
        "subjects": [{"subject_id": "urn:acef:subj:1", "risk_classification": "high_risk"}],
        "profiles": [{"profile_id": "eu-ai-act-2024"}],
    }
    _write_bundle(bundle_dir, manifest)

    try:
        assessment = validate_bundle(str(bundle_dir), profiles=["eu-ai-act-2024"])
    except Exception as exc:  # noqa: BLE001 — the contract under test is "never raises"
        pytest.fail(
            f"validate_bundle raised {type(exc).__name__} on a non-string "
            f"metadata.timestamp evaluated through profiles: {exc!r}"
        )
    assert isinstance(assessment, AssessmentBundle)
    assert isinstance(assessment.evaluation_instant, str)


def test_malformed_metadata_timestamp_on_signed_bundle_never_crashes(tmp_path: Path) -> None:
    """The integrity checker reads ``metadata.timestamp`` as ``manifest_ts`` to
    anchor x5c cert-validity checks. A non-string timestamp on a bundle that
    has a signatures/ directory must not reach the signing layer's
    ``.endswith('Z')`` string op and raise AttributeError."""
    bundle_dir = tmp_path / "signedts.acef"
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": [123],  # non-string anchor for cert validity
        },
        "record_files": [],
    }
    _write_bundle(bundle_dir, manifest)
    # Minimal integrity surface: a content-hashes.json + a signatures dir so the
    # signature-verification path (which consumes manifest_ts) is reached.
    #
    # The content-hashes.json MUST be a FLAT path->hash mapping (the shape
    # ``check_integrity`` expects). A nested ``{"algorithm": ..., "files": {}}``
    # has a non-string value (``files``), which trips the integrity type gate
    # (ACEF-014) and RETURNS EARLY — the signature path is never reached, so the
    # test would not exercise its target. An empty flat mapping ``{}`` passes the
    # type gate, so check_integrity proceeds into ``_check_signatures`` where the
    # non-string manifest timestamp is consumed (and handled gracefully).
    (bundle_dir / "hashes").mkdir(parents=True, exist_ok=True)
    (bundle_dir / "hashes" / "content-hashes.json").write_text(json.dumps({}), encoding="utf-8")
    sig_dir = bundle_dir / "signatures"
    sig_dir.mkdir(parents=True, exist_ok=True)
    (sig_dir / "broken.jws").write_text("not-a-real-jws", encoding="utf-8")

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    assert _has_diagnostics(assessment)
    # Prove the signature-verification path was ACTUALLY reached (not short-
    # circuited by the integrity type gate): the broken.jws is not a valid
    # 3-part JWS, so ``_check_signatures`` emits ACEF-012. Its presence is
    # evidence the guarded manifest-timestamp path ran without raising.
    codes = [e.get("code") for e in assessment.structural_errors]
    assert "ACEF-012" in codes, (
        f"signature-verification path was not reached: expected ACEF-012 from the broken .jws, got codes={codes}"
    )


# --------------------------------------------------------------------------- #
# Top-level exception backstop (untrusted-input boundary).
#
# The per-field guards above + the prior commits handle the KNOWN crash sites
# with precise diagnostics. The backstop is the LAST RESORT: if some
# not-yet-guarded path raises, the outermost phase orchestration catches it and
# converts it into a FATAL ACEF-001 diagnostic so the failure is SURFACED,
# never hidden, and ``validate_bundle`` still returns an AssessmentBundle.
# --------------------------------------------------------------------------- #


def test_pathological_input_triggers_backstop_no_raise(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Force a phase to raise an unexpected exception that slips past every
    per-field guard, and assert the top-level backstop catches it, emits a
    FATAL ACEF-001 diagnostic carrying the exception type + message, and
    returns (never raises)."""
    import acef.validation.engine as engine_mod

    sentinel = "pathological-phase-explosion-7f3a"

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError(sentinel)

    # check_references is called inside the phase orchestration, AFTER the
    # well-formed Phase-0/1 guards but well inside the try-boundary. Patching
    # it to raise simulates a not-yet-guarded deep crash site.
    monkeypatch.setattr(engine_mod, "check_references", _boom)

    bundle_dir = tmp_path / "pathological.acef"
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
    }
    _write_bundle(bundle_dir, manifest)

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    codes = [e.get("code") for e in assessment.structural_errors]
    assert "ACEF-001" in codes, f"backstop must emit fatal ACEF-001, got codes={codes}"
    # The surfaced diagnostic must carry the exception type + message so the
    # failure is visible, not silently swallowed.
    fatal = next(e for e in assessment.structural_errors if e.get("code") == "ACEF-001")
    assert fatal.get("severity") == "fatal"
    assert "RuntimeError" in fatal.get("message", "")
    assert sentinel in fatal.get("message", "")


def test_backstop_preserves_pre_failure_diagnostics_on_late_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a LATE phase raises, the backstop must return the diagnostics
    collected BEFORE the failure point IN ADDITION to the fatal ACEF-001 — it
    must NOT drop earlier findings.

    Construction: the bundle has no ``hashes/content-hashes.json``, so the
    Phase-2 integrity check emits a real ACEF-014 BEFORE the Phase-3 reference
    check runs. We then monkeypatch ``check_references`` to raise. The returned
    assessment MUST contain BOTH the earlier ACEF-014 (proving pre-failure
    diagnostics survive) AND the fatal ACEF-001 (proving the crash is
    surfaced). Before the incremental-flush fix, ACEF-014 was buffered in a
    local and dropped when the later phase raised — only ACEF-001 came back.
    """
    import acef.validation.engine as engine_mod

    sentinel = "late-phase-crash-after-early-diagnostics-9c2e"

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError(sentinel)

    # check_references runs in Phase 3, AFTER Phase 2 integrity has already
    # collected ACEF-014 for the missing content-hashes.json.
    monkeypatch.setattr(engine_mod, "check_references", _boom)

    bundle_dir = tmp_path / "earlydiag.acef"
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": [],
    }
    _write_bundle(bundle_dir, manifest)
    # Deliberately omit hashes/content-hashes.json so Phase-2 integrity emits a
    # known early diagnostic (ACEF-014) before the patched Phase-3 crash.

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    codes = [e.get("code") for e in assessment.structural_errors]
    # The fatal backstop diagnostic must be present...
    assert "ACEF-001" in codes, f"backstop must emit fatal ACEF-001, got codes={codes}"
    # ...AND the earlier integrity diagnostic collected before the crash must
    # NOT have been dropped.
    assert "ACEF-014" in codes, (
        "backstop dropped pre-failure diagnostics: expected the Phase-2 ACEF-014 "
        f"(missing content-hashes.json) to survive the late crash, got codes={codes}"
    )


def test_backstop_does_not_swallow_well_formed_input(tmp_path: Path) -> None:
    """The backstop must ONLY fire on unhandled exceptions. A well-formed (if
    minimal) bundle must NOT produce a spurious ACEF-001 backstop diagnostic —
    proving the boundary does not hide real behavior on the happy path."""
    bundle_dir = tmp_path / "wellformed.acef"
    manifest = {
        "versioning": {"core_version": "1.0.0"},
        "metadata": {
            "package_id": "urn:acef:pkg:fuzz",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        "record_files": [],
    }
    _write_bundle(bundle_dir, manifest)

    assessment = _run_never_raises(bundle_dir)
    assert isinstance(assessment, AssessmentBundle)
    # ACEF-001 here would mean the backstop spuriously fired on a non-crashing
    # path (or a real version-incompat, which this manifest does not have).
    codes = [e.get("code") for e in assessment.structural_errors]
    assert "ACEF-001" not in codes, (
        f"backstop must not fire on well-formed input (would hide real behavior); got codes={codes}"
    )
