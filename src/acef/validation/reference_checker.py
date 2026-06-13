"""ACEF reference checker — dangling refs, duplicates, file existence.

Phase 3 of the 4-phase validation pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from acef.errors import ValidationDiagnostic


def check_references(
    manifest_data: dict[str, Any],
    records: list[dict[str, Any]],
    bundle_dir: Path | None = None,
) -> list[ValidationDiagnostic]:
    """Check referential integrity of a bundle.

    Checks:
    - Dangling entity_refs (ACEF-020)
    - Duplicate URNs (ACEF-021)
    - Missing record files (ACEF-022)
    - Missing attachment files (ACEF-023)
    - Record count mismatches (ACEF-025)
    - Duplicate record IDs (ACEF-026)

    Returns:
        List of diagnostics.
    """
    diagnostics: list[ValidationDiagnostic] = []

    # Defensive type coercion: schema validation runs in Phase 1 but may
    # not block Phase 3 from running on a malformed manifest. If a section
    # arrives as a non-mapping/non-list, treat it as empty so we still
    # produce a clean diagnostic instead of crashing.
    def _dict_or_empty(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _list_or_empty(value: Any) -> list[Any]:
        return value if isinstance(value, list) else []

    # Collect all defined URNs
    defined_urns: set[str] = set()
    urn_sources: dict[str, str] = {}  # urn -> first source path

    # Package ID
    metadata_section = _dict_or_empty(manifest_data.get("metadata"))
    pkg_id = metadata_section.get("package_id", "")
    if pkg_id:
        _add_urn(defined_urns, urn_sources, pkg_id, "/metadata/package_id", diagnostics)

    # Subject URNs
    for i, sub in enumerate(_list_or_empty(manifest_data.get("subjects"))):
        if not isinstance(sub, dict):
            continue
        sub_id = sub.get("subject_id", "")
        if sub_id:
            _add_urn(defined_urns, urn_sources, sub_id, f"/subjects/{i}/subject_id", diagnostics)

    # Entity URNs
    entities = _dict_or_empty(manifest_data.get("entities"))
    for i, comp in enumerate(_list_or_empty(entities.get("components"))):
        if not isinstance(comp, dict):
            continue
        comp_id = comp.get("component_id", "")
        if comp_id:
            _add_urn(defined_urns, urn_sources, comp_id, f"/entities/components/{i}", diagnostics)

    for i, ds in enumerate(_list_or_empty(entities.get("datasets"))):
        if not isinstance(ds, dict):
            continue
        ds_id = ds.get("dataset_id", "")
        if ds_id:
            _add_urn(defined_urns, urn_sources, ds_id, f"/entities/datasets/{i}", diagnostics)

    for i, actor in enumerate(_list_or_empty(entities.get("actors"))):
        if not isinstance(actor, dict):
            continue
        act_id = actor.get("actor_id", "")
        if act_id:
            _add_urn(defined_urns, urn_sources, act_id, f"/entities/actors/{i}", diagnostics)

    # Record URNs are also valid relationship endpoints. The v1.1 incident graph
    # (RFC-0002 §5.8 / §8 #4) connects RECORDS — e.g. the public_projection_of
    # edge links an incident_report record URN to its incident_card record URN —
    # so the manifest schema broadens relationships[].source_ref/target_ref to
    # accept urn:acef:rec:<uuid>. A relationship endpoint therefore resolves
    # against either a defined entity URN OR an in-bundle record URN. Collect the
    # record URNs up front (the per-record loop below re-collects them for the
    # ACEF-026 duplicate check; this set is endpoint-resolution only).
    record_urns: set[str] = {
        rec.get("record_id", "") for rec in records if isinstance(rec, dict) and rec.get("record_id")
    }

    # Check relationship refs
    for i, rel in enumerate(_list_or_empty(entities.get("relationships"))):
        if not isinstance(rel, dict):
            continue
        for ref_field in ("source_ref", "target_ref"):
            ref = rel.get(ref_field, "")
            if ref and ref not in defined_urns and ref not in record_urns:
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-020",
                        f"Dangling {ref_field} in relationship {i}: {ref!r}",
                        path=f"/entities/relationships/{i}/{ref_field}",
                    )
                )

    # Pre-load content-hashes.json once for ACEF-027 advisory hash checks,
    # rather than re-reading from disk on every record iteration.
    content_hashes: dict[str, str] = {}
    if bundle_dir:
        # Defensively load content-hashes.json: if the file is missing,
        # malformed, or not a JSON object, we still need a dict so the
        # later membership checks (`att_path in content_hashes`) can
        # short-circuit cleanly. Phase 2 already emits structured
        # diagnostics for malformed integrity files; this is just a
        # crash guard for the reference-check path.
        ch_path = bundle_dir / "hashes" / "content-hashes.json"
        if ch_path.exists():
            try:
                _loaded = json.loads(ch_path.read_text(encoding="utf-8"))
            except Exception:
                _loaded = None
            # Guard against list/string/null at top level — only a dict is
            # subscriptable by path string at the later ACEF-027 check.
            if isinstance(_loaded, dict):
                # Filter out non-string values (e.g., {"a.txt": ["bad"]})
                # so verify_merkle_root / hash compare paths don't crash on
                # .encode() against a non-string value.
                content_hashes = {k: v for k, v in _loaded.items() if isinstance(v, str)}

    # Check record entity refs
    record_ids: set[str] = set()
    for i, rec in enumerate(records):
        rec_id = rec.get("record_id", "")
        if rec_id:
            if rec_id in record_ids:
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-026",
                        f"Duplicate record_id: {rec_id!r}",
                        path=f"/records/{i}/record_id",
                    )
                )
            record_ids.add(rec_id)

        entity_refs = _dict_or_empty(rec.get("entity_refs"))
        for ref_type in ("subject_refs", "component_refs", "dataset_refs", "actor_refs"):
            for ref in _list_or_empty(entity_refs.get(ref_type)):
                if ref and ref not in defined_urns:
                    diagnostics.append(
                        ValidationDiagnostic(
                            "ACEF-020",
                            f"Dangling {ref_type} in record {i}: {ref!r}",
                            path=f"/records/{i}/entity_refs/{ref_type}",
                        )
                    )

        # Check attachment paths and advisory hash (ACEF-027)
        if bundle_dir:
            from acef.errors import ACEFFormatError
            from acef.loader import _validate_path as _loader_validate_path

            for j, att in enumerate(_list_or_empty(rec.get("attachments"))):
                if not isinstance(att, dict):
                    # A non-object attachment entry can't carry a path or
                    # hash; skip rather than crash on .get(). Schema
                    # validation (Phase 1) will diagnose this.
                    continue
                att_path = att.get("path", "")
                if att_path:
                    # Reject paths that fail loader path validation (NUL bytes,
                    # NFC, '.', '..', backslash, absolute) BEFORE constructing
                    # a filesystem path. Then verify the resolved path stays
                    # inside the artifacts/ root so even a syntactically
                    # passing path cannot escape via symlinks or unusual
                    # filesystem behavior.
                    try:
                        _loader_validate_path(att_path)
                    except ACEFFormatError as exc:
                        diagnostics.append(
                            ValidationDiagnostic(
                                "ACEF-052",
                                f"Attachment path invalid: {att_path!r}: {exc}",
                                path=f"/records/{i}/attachments/{j}/path",
                            )
                        )
                        continue
                    full_path = bundle_dir / att_path
                    try:
                        resolved = full_path.resolve()
                        # Attachments live anywhere in the bundle (artifacts/
                        # is most common, but spec allows any relative path).
                        # Enforce containment to bundle_dir at minimum.
                        resolved.relative_to(bundle_dir.resolve())
                    except (ValueError, OSError):
                        diagnostics.append(
                            ValidationDiagnostic(
                                "ACEF-052",
                                f"Attachment path escapes bundle root: {att_path!r}",
                                path=f"/records/{i}/attachments/{j}/path",
                            )
                        )
                        continue
                    if not full_path.exists():
                        diagnostics.append(
                            ValidationDiagnostic(
                                "ACEF-023",
                                f"Attachment file not found: {att_path!r}",
                                path=f"/records/{i}/attachments/{j}/path",
                            )
                        )
                    # ACEF-027: Advisory hash mismatch check
                    att_hash = att.get("hash", "")
                    if att_hash and att_path in content_hashes:
                        if att_hash != content_hashes[att_path]:
                            diagnostics.append(
                                ValidationDiagnostic(
                                    "ACEF-027",
                                    f"Attachment hash field does not match content-hashes.json for {att_path!r}",
                                    path=f"/records/{i}/attachments/{j}/hash",
                                )
                            )

    # Check record_files entries. ``record_files`` is untrusted external JSON:
    # it may arrive as a non-list (null / string / number / object) or as a
    # list whose entries are non-dicts. Normalize to a list once and skip
    # non-dict entries so this ACEF-022 file-existence loop never crashes on
    # ``rf.get(...)``. The Phase-1 manifest-schema diagnostic already flags the
    # malformed shape (ACEF-002); here we only need a crash guard.
    if bundle_dir:
        record_files = manifest_data.get("record_files")
        if not isinstance(record_files, list):
            record_files = []
        for i, rf in enumerate(record_files):
            if not isinstance(rf, dict):
                continue
            rf_path = rf.get("path", "")
            if isinstance(rf_path, str) and rf_path:
                full_path = bundle_dir / rf_path
                if not full_path.exists():
                    diagnostics.append(
                        ValidationDiagnostic(
                            "ACEF-022",
                            f"Record file not found: {rf_path!r}",
                            path=f"/record_files/{i}/path",
                        )
                    )

    # Check record counts
    _check_record_counts(manifest_data, records, diagnostics)

    # Check subject_refs on components and datasets. ``entities`` and its
    # ``components``/``datasets`` arrays are untrusted external JSON; reuse the
    # _list_or_empty / isinstance guards so a non-list section or a non-dict
    # entry is skipped rather than crashing on ``.get(...)``. ``subject_refs``
    # itself may also be a non-list, so wrap it too.
    for i, comp in enumerate(_list_or_empty(entities.get("components"))):
        if not isinstance(comp, dict):
            continue
        for ref in _list_or_empty(comp.get("subject_refs")):
            if ref and ref not in defined_urns:
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-020",
                        f"Dangling subject_ref in component {i}: {ref!r}",
                        path=f"/entities/components/{i}/subject_refs",
                    )
                )

    for i, ds in enumerate(_list_or_empty(entities.get("datasets"))):
        if not isinstance(ds, dict):
            continue
        for ref in _list_or_empty(ds.get("subject_refs")):
            if ref and ref not in defined_urns:
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-020",
                        f"Dangling subject_ref in dataset {i}: {ref!r}",
                        path=f"/entities/datasets/{i}/subject_refs",
                    )
                )

    return diagnostics


def _add_urn(
    defined: set[str],
    sources: dict[str, str],
    urn: str,
    path: str,
    diagnostics: list[ValidationDiagnostic],
) -> None:
    """Add a URN to the defined set, checking for duplicates."""
    if urn in defined:
        diagnostics.append(
            ValidationDiagnostic(
                "ACEF-021",
                f"Duplicate URN: {urn!r} (first defined at {sources.get(urn, 'unknown')})",
                path=path,
            )
        )
    defined.add(urn)
    if urn not in sources:
        sources[urn] = path


def _check_record_counts(
    manifest_data: dict[str, Any],
    records: list[dict[str, Any]],
    diagnostics: list[ValidationDiagnostic],
) -> None:
    """Check that record_files counts match actual record counts."""
    # Count records by type. ``record_type`` is the dict KEY here, so a
    # non-string value (list/dict/int/bool/null) — which is well-formed JSON
    # but invalid per the record-envelope schema — would raise
    # ``TypeError: unhashable type`` (list/dict) and crash the validator. A
    # validator MUST NEVER raise on malformed input: it returns diagnostics.
    # The wrong-typed ``record_type`` is already flagged with ACEF-004 by the
    # Phase-1 envelope schema, so we simply SKIP non-string record_types in the
    # count (they cannot meaningfully match a manifest-declared string type).
    actual_counts: dict[str, int] = {}
    for rec in records:
        rt = rec.get("record_type", "")
        if not isinstance(rt, str):
            continue
        actual_counts[rt] = actual_counts.get(rt, 0) + 1

    # Sum expected counts from record_files. The manifest is schema-checked in
    # Phase 1 too, but a malformed manifest must likewise not crash this count
    # roll-up: skip any record_files entry whose declared ``record_type`` is a
    # non-string (relying on the Phase-1 manifest-schema diagnostic).
    expected_counts: dict[str, int] = {}
    rf_list = manifest_data.get("record_files")
    if not isinstance(rf_list, list):
        rf_list = []
    for rf in rf_list:
        if not isinstance(rf, dict):
            continue
        rt = rf.get("record_type", "")
        if not isinstance(rt, str):
            continue
        count = rf.get("count", 0)
        if not isinstance(count, int) or isinstance(count, bool):
            count = 0
        expected_counts[rt] = expected_counts.get(rt, 0) + count

    for rt, expected in expected_counts.items():
        actual = actual_counts.get(rt, 0)
        if actual != expected:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-025",
                    f"Record count mismatch for {rt}: manifest says {expected}, found {actual}",
                )
            )
