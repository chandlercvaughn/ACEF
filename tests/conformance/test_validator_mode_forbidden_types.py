"""VAL-VALIDATION-010: mode-gated forbidden record types emit ACEF-080.

Per plan WS3.9, each analysis_mode forbids specific record types:

- subscriber            : (none)
- public_artifact       : delivery_verdict, disposition_record (V3 variant)
- canary                : delivery_verdict; verification_badge with
                          page_state != "unsupported"; non-badge
                          transparency_disclosure with
                          confidentiality="public"
- unattributed_artifact : same as public_artifact PLUS any record with a
                          non-null attribution field

A violation MUST emit ACEF-080 with a diagnostic message naming the mode,
the record_id, and the rule. Note: ACEF-080 is also emitted by the
mode-gated *required*-record check in cross_record.py and by the
disposition_authority matrix check; this test file isolates the *forbidden*-
type side by reading the diagnostic messages.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acef.validation.engine import validate_bundle
from acef.validation.v1_1_rules import enforce_mode_gated_forbidden_types
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
)


def _write_minimal_v1_1_bundle(
    bundle_dir: Path,
    *,
    analysis_mode: str,
    records: list[dict],
    record_files: list[dict] | None = None,
) -> None:
    """Write a minimal v1.1 bundle with the given records.

    Caller provides records and (optionally) record_files. If record_files
    is None, all records go in a single records/all.jsonl with the first
    record's type — sufficient for direct-function tests but engine tests
    that mix types should pass an explicit record_files list.
    """
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "records").mkdir(parents=True, exist_ok=True)

    manifest = base_manifest(analysis_mode=analysis_mode)
    # Add subscriber-required records so the cross_record mode-gates check
    # does not fire ACEF-080 for missing required types (which would
    # confuse the assertions in this file).
    if analysis_mode == "subscriber" and record_files is None:
        manifest["record_files"] = [
            {
                "path": "records/all.jsonl",
                "record_type": records[0].get("record_type", "risk_register"),
                "count": len(records),
            }
        ]
    elif record_files is not None:
        manifest["record_files"] = record_files
    else:
        first_type = records[0].get("record_type", "risk_register") if records else "risk_register"
        manifest["record_files"] = [
            {
                "path": "records/all.jsonl",
                "record_type": first_type,
                "count": len(records),
            }
        ]

    # Write records, grouping by file path if record_files specifies
    # multiple paths (one file per type).
    if record_files:
        # group records by record_type → file path lookup
        path_by_type: dict[str, str] = {rf["record_type"]: rf["path"] for rf in record_files}
        by_path: dict[str, list[dict]] = {}
        for r in records:
            p = path_by_type.get(r.get("record_type", ""), "records/all.jsonl")
            by_path.setdefault(p, []).append(r)
        for path, recs in by_path.items():
            fpath = bundle_dir / path
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
    else:
        (bundle_dir / "records" / "all.jsonl").write_text(
            "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
        )

    (bundle_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def _mode_gate_messages(structural_errors: list[dict]) -> list[str]:
    """Filter structural_errors to ACEF-080 messages from the forbidden-
    type rule family (excluding the cross_record required-records and
    authority-matrix rules).

    The v1_1_rules module's diagnostics always mention either "forbidden"
    or "MUST have" — distinguishing them from cross_record's
    "missing required mode-gated" and disposition-authority messages.
    """
    out: list[str] = []
    for d in structural_errors:
        if d.get("code") != "ACEF-080":
            continue
        msg = d.get("message", "")
        if "forbidden" in msg or "page_state" in msg or "non-null attribution" in msg:
            out.append(msg)
    return out


# ---------------------------------------------------------------------------
# Function-level (direct call) tests
# ---------------------------------------------------------------------------


def test_subscriber_mode_no_forbidden_types() -> None:
    """subscriber mode forbids no record types — no ACEF-080 from this rule."""
    manifest = base_manifest(analysis_mode="subscriber")
    records = [
        base_record(
            record_id="urn:acef:rec:11110000-0000-0000-0000-000000000001",
            record_type="delivery_verdict",  # allowed in subscriber
        ),
    ]
    diags = enforce_mode_gated_forbidden_types(manifest, records)
    assert [d.code for d in diags] == []


def test_no_analysis_mode_no_check() -> None:
    """Without analysis_mode set, the forbidden-type check is a no-op."""
    manifest = base_manifest(analysis_mode=None)
    records = [
        base_record(
            record_id="urn:acef:rec:22220000-0000-0000-0000-000000000001",
            record_type="delivery_verdict",
        ),
    ]
    diags = enforce_mode_gated_forbidden_types(manifest, records)
    assert diags == []


@pytest.mark.parametrize(
    "mode",
    ["public_artifact", "canary", "unattributed_artifact"],
)
def test_delivery_verdict_forbidden_in_non_subscriber_modes(mode: str) -> None:
    """delivery_verdict is forbidden in public_artifact, canary, and
    unattributed_artifact (per plan WS3.9 table).
    """
    manifest = base_manifest(analysis_mode=mode)
    records = [
        base_record(
            record_id=f"urn:acef:rec:33330000-0000-0000-0000-{mode[:8]:>08}".replace(" ", "0"),
            record_type="delivery_verdict",
        ),
    ]
    diags = enforce_mode_gated_forbidden_types(manifest, records)
    found_codes = [d.code for d in diags]
    assert "ACEF-080" in found_codes, f"delivery_verdict in {mode!r} should emit ACEF-080; got: {found_codes!r}"
    # Mode must be named in the diagnostic.
    assert any(mode in d.message for d in diags), (
        f"Diagnostic should name the mode; messages: {[d.message for d in diags]!r}"
    )


def test_disposition_record_forbidden_in_public_artifact() -> None:
    """A risk_treatment with treatment_subtype=external_disposition (V3
    disposition_record variant) is forbidden in public_artifact mode.
    """
    manifest = base_manifest(analysis_mode="public_artifact")
    records = [
        base_record(
            record_id="urn:acef:rec:44440000-0000-0000-0000-000000000001",
            record_type="risk_treatment",
            payload={"treatment_subtype": "external_disposition"},
        ),
    ]
    diags = enforce_mode_gated_forbidden_types(manifest, records)
    assert any(d.code == "ACEF-080" for d in diags)
    # Diagnostic should explicitly mention disposition_record (the variant
    # name) so producers know what to remove.
    assert any("disposition_record" in d.message for d in diags), [d.message for d in diags]


def test_risk_treatment_non_disposition_subtype_ok_in_public_artifact() -> None:
    """A non-disposition risk_treatment (e.g., regression_definition) is
    allowed in public_artifact mode.
    """
    manifest = base_manifest(analysis_mode="public_artifact")
    records = [
        base_record(
            record_id="urn:acef:rec:55550000-0000-0000-0000-000000000001",
            record_type="risk_treatment",
            payload={"treatment_subtype": "regression_definition"},
        ),
    ]
    diags = enforce_mode_gated_forbidden_types(manifest, records)
    assert "ACEF-080" not in [d.code for d in diags]


def test_disposition_record_forbidden_in_unattributed_artifact() -> None:
    """unattributed_artifact mode inherits public_artifact restrictions."""
    manifest = base_manifest(analysis_mode="unattributed_artifact")
    records = [
        base_record(
            record_id="urn:acef:rec:66660000-0000-0000-0000-000000000001",
            record_type="risk_treatment",
            payload={"treatment_subtype": "external_disposition"},
        ),
    ]
    diags = enforce_mode_gated_forbidden_types(manifest, records)
    assert any(d.code == "ACEF-080" for d in diags)


def test_canary_badge_state_must_be_unsupported() -> None:
    """In canary mode, a verification_badge (transparency_disclosure V4)
    with page_state other than 'unsupported' violates the gate.
    """
    manifest = base_manifest(analysis_mode="canary")
    records = [
        base_record(
            record_id="urn:acef:rec:77770000-0000-0000-0000-000000000001",
            record_type="transparency_disclosure",
            payload={
                "variant": "verification_badge",
                "page_state": "green",
            },
        ),
    ]
    diags = enforce_mode_gated_forbidden_types(manifest, records)
    assert any(d.code == "ACEF-080" for d in diags)
    assert any("page_state" in d.message for d in diags), [d.message for d in diags]


def test_canary_badge_state_unsupported_ok() -> None:
    """In canary mode, a verification_badge with page_state='unsupported' OK."""
    manifest = base_manifest(analysis_mode="canary")
    records = [
        base_record(
            record_id="urn:acef:rec:88880000-0000-0000-0000-000000000001",
            record_type="transparency_disclosure",
            payload={
                "variant": "verification_badge",
                "page_state": "unsupported",
            },
        ),
    ]
    diags = enforce_mode_gated_forbidden_types(manifest, records)
    assert "ACEF-080" not in [d.code for d in diags]


def test_canary_public_transparency_disclosure_forbidden() -> None:
    """In canary mode, a non-badge transparency_disclosure with
    confidentiality='public' violates the gate.
    """
    manifest = base_manifest(analysis_mode="canary")
    rec = base_record(
        record_id="urn:acef:rec:99990000-0000-0000-0000-000000000001",
        record_type="transparency_disclosure",
        confidentiality="public",
        payload={"variant": "other"},
    )
    diags = enforce_mode_gated_forbidden_types(manifest, [rec])
    assert any(d.code == "ACEF-080" for d in diags), [d.message for d in diags]


def test_canary_private_transparency_disclosure_ok() -> None:
    """In canary mode, a private transparency_disclosure (non-badge) is OK."""
    manifest = base_manifest(analysis_mode="canary")
    rec = base_record(
        record_id="urn:acef:rec:aaaa0000-0000-0000-0000-000000000001",
        record_type="transparency_disclosure",
        confidentiality="redacted",
        payload={"variant": "other"},
    )
    diags = enforce_mode_gated_forbidden_types(manifest, [rec])
    assert "ACEF-080" not in [d.code for d in diags]


def test_unattributed_artifact_non_null_attribution_forbidden() -> None:
    """In unattributed_artifact mode, any record with non-null attribution
    info violates the gate.
    """
    manifest = base_manifest(analysis_mode="unattributed_artifact")
    rec = base_record(
        record_id="urn:acef:rec:bbbb0000-0000-0000-0000-000000000001",
        record_type="risk_register",
        payload={
            "attribution_advisory": {"confidence": "high", "source": "x"},
        },
    )
    diags = enforce_mode_gated_forbidden_types(manifest, [rec])
    assert any(d.code == "ACEF-080" for d in diags)
    assert any("non-null attribution" in d.message for d in diags), [d.message for d in diags]


def test_unattributed_artifact_payload_attribution_forbidden() -> None:
    """payload.attribution (non-empty) also triggers the gate."""
    manifest = base_manifest(analysis_mode="unattributed_artifact")
    rec = base_record(
        record_id="urn:acef:rec:cccc0000-0000-0000-0000-000000000001",
        record_type="risk_register",
        payload={"attribution": "vendor-x"},
    )
    diags = enforce_mode_gated_forbidden_types(manifest, [rec])
    assert any(d.code == "ACEF-080" for d in diags)


def test_unattributed_artifact_empty_attribution_ok() -> None:
    """payload.attribution='' (empty) is treated as 'not set' — no gate."""
    manifest = base_manifest(analysis_mode="unattributed_artifact")
    rec = base_record(
        record_id="urn:acef:rec:dddd0000-0000-0000-0000-000000000001",
        record_type="risk_register",
        payload={"attribution": ""},
    )
    diags = enforce_mode_gated_forbidden_types(manifest, [rec])
    assert "ACEF-080" not in [d.code for d in diags]


def test_unknown_mode_no_check() -> None:
    """A mode not in the table (e.g., a typo) is treated as no-check."""
    manifest = base_manifest()
    manifest["analysis_mode"] = "typo_mode"
    rec = base_record(
        record_id="urn:acef:rec:eeee0000-0000-0000-0000-000000000001",
        record_type="delivery_verdict",
    )
    diags = enforce_mode_gated_forbidden_types(manifest, [rec])
    # Unknown mode should not crash; gate-aware modes are the only ones
    # we enforce. (Schema validation catches the typo separately.)
    assert diags == []


# ---------------------------------------------------------------------------
# Engine-level tests
# ---------------------------------------------------------------------------


def test_engine_public_artifact_with_delivery_verdict_emits_acef_080(
    tmp_path: Path,
) -> None:
    """End-to-end: a public_artifact bundle with delivery_verdict emits
    ACEF-080.
    """
    bundle = tmp_path / "public-artifact-with-delivery"
    rec = base_record(
        record_id="urn:acef:rec:11ee0000-0000-0000-0000-000000000001",
        record_type="delivery_verdict",
    )
    _write_minimal_v1_1_bundle(bundle, analysis_mode="public_artifact", records=[rec])

    assessment = validate_bundle(bundle)
    msgs = _mode_gate_messages(assessment.structural_errors)
    assert msgs, f"Expected forbidden-type ACEF-080 from engine; all codes: {codes(assessment.structural_errors)!r}"
    assert any("public_artifact" in m for m in msgs)
    assert any("delivery_verdict" in m for m in msgs)


def test_engine_canary_badge_green_emits_acef_080(tmp_path: Path) -> None:
    """End-to-end: canary bundle with a green badge_state emits ACEF-080."""
    bundle = tmp_path / "canary-green-badge"
    rec = base_record(
        record_id="urn:acef:rec:22ee0000-0000-0000-0000-000000000001",
        record_type="transparency_disclosure",
        payload={"variant": "verification_badge", "page_state": "green"},
    )
    _write_minimal_v1_1_bundle(bundle, analysis_mode="canary", records=[rec])

    assessment = validate_bundle(bundle)
    msgs = _mode_gate_messages(assessment.structural_errors)
    assert msgs, f"Expected forbidden-type ACEF-080 from engine; all codes: {codes(assessment.structural_errors)!r}"


def test_engine_unattributed_artifact_with_attribution_emits_acef_080(
    tmp_path: Path,
) -> None:
    """End-to-end: unattributed_artifact + record with attribution → ACEF-080."""
    bundle = tmp_path / "unattributed-with-attr"
    rec = base_record(
        record_id="urn:acef:rec:33ee0000-0000-0000-0000-000000000001",
        record_type="risk_register",
        payload={"attribution_advisory": {"confidence": "low"}},
    )
    _write_minimal_v1_1_bundle(bundle, analysis_mode="unattributed_artifact", records=[rec])

    assessment = validate_bundle(bundle)
    msgs = _mode_gate_messages(assessment.structural_errors)
    assert msgs, (
        f"Expected ACEF-080 from engine for unattributed attribution; "
        f"all codes: {codes(assessment.structural_errors)!r}"
    )


def test_engine_v1_0_bundle_with_forbidden_record_no_acef_080(
    tmp_path: Path,
) -> None:
    """Regression: a v1.0-declared bundle with a forbidden record type
    does NOT trigger the v1.1 mode-gates rule (schema_version gate).

    (The bundle may emit other errors — e.g., ACEF-003 for unknown record
    types — but ACEF-080 from the v1.1 forbidden-type rule must not fire.)
    """
    bundle = tmp_path / "v1-0-forbidden"
    manifest = base_manifest(core_version="1.0.0")
    # v1.0 manifest doesn't support analysis_mode; the field is silently
    # accepted at the model level (additionalProperties:true on manifest)
    # but the v1.1 rule family is not invoked.
    manifest["analysis_mode"] = "public_artifact"
    manifest["record_files"] = [
        {
            "path": "records/all.jsonl",
            "record_type": "risk_register",
            "count": 1,
        }
    ]
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "records").mkdir(parents=True, exist_ok=True)
    rec = base_record(
        record_id="urn:acef:rec:44ee0000-0000-0000-0000-000000000001",
        record_type="risk_register",
    )
    (bundle / "records" / "all.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
    (bundle / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assessment = validate_bundle(bundle)
    msgs = _mode_gate_messages(assessment.structural_errors)
    assert not msgs, f"v1.0 bundle should not trigger v1.1 forbidden-type rule; got messages: {msgs!r}"
