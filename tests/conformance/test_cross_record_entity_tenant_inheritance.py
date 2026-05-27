"""VAL-VALIDATION-004: cross-tenant entity reference → ACEF-020.

Each entity inherits the tenant_label of its first declaring record. A
record from a different tenant referencing that entity violates §6.4 and
must emit ACEF-020 with a diagnostic naming the cross-tenant ref.
"""

from __future__ import annotations

from pathlib import Path

from acef.validation.engine import validate_bundle
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
    write_bundle,
)

_COMPONENT_URN = "urn:acef:cmp:99999999-9999-9999-9999-999999999999"


def test_cross_tenant_entity_reference_emits_acef_020(tmp_path: Path) -> None:
    """Record A (tenant alpha) declares entity E. Record B (tenant beta)
    references E. → ACEF-020.
    """
    bundle = tmp_path / "cross-tenant-ref"

    # Use a manifest WITHOUT analysis_mode so the tenant_uniformity check
    # doesn't fire ACEF-075 and obscure the assertion. The cross-tenant ref
    # check is independent of analysis_mode.
    write_bundle(
        bundle,
        manifest=base_manifest(analysis_mode=None),
        records=[
            base_record(
                record_id="urn:acef:rec:50000000-0000-0000-0000-000000000001",
                tenant_label="urn:acef:tenant:alpha",
                entity_refs={"component_refs": [_COMPONENT_URN]},
            ),
            base_record(
                record_id="urn:acef:rec:50000000-0000-0000-0000-000000000002",
                tenant_label="urn:acef:tenant:beta",
                entity_refs={"component_refs": [_COMPONENT_URN]},
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-020" in found, f"Expected ACEF-020 (cross-tenant entity reference), got: {found!r}"

    # Verify the diagnostic message names the cross-tenant ref.
    messages = [d["message"] for d in assessment.structural_errors if d.get("code") == "ACEF-020"]
    joined = " ".join(messages)
    assert "tenant" in joined.lower(), f"ACEF-020 diagnostic should mention tenant context; got: {messages!r}"


def test_same_tenant_referencing_shared_entity_clean(tmp_path: Path) -> None:
    """Two records sharing one tenant_label both referencing the same
    entity validates clean (no ACEF-020 for cross-tenant).
    """
    bundle = tmp_path / "same-tenant-shared-entity"
    write_bundle(
        bundle,
        manifest=base_manifest(analysis_mode=None),
        records=[
            base_record(
                record_id="urn:acef:rec:60000000-0000-0000-0000-000000000001",
                tenant_label="urn:acef:tenant:alpha",
                entity_refs={"component_refs": [_COMPONENT_URN]},
            ),
            base_record(
                record_id="urn:acef:rec:60000000-0000-0000-0000-000000000002",
                tenant_label="urn:acef:tenant:alpha",
                entity_refs={"component_refs": [_COMPONENT_URN]},
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    # ACEF-020 may still fire for other dangling-ref reasons (the
    # reference_checker phase may diagnose the component URN not declared
    # in manifest.entities.components). We assert that the cross-record
    # phase doesn't ADD a new ACEF-020 specifically about cross-tenant.
    messages = [
        d["message"]
        for d in assessment.structural_errors
        if d.get("code") == "ACEF-020" and "tenant" in d.get("message", "").lower()
    ]
    assert not messages, f"Same-tenant bundle should not emit any tenant-flavored ACEF-020; got: {messages!r}"


def test_first_declarer_wins_entity_inheritance(tmp_path: Path) -> None:
    """The first record to reference an entity owns its tenant_label.
    A later record from a different tenant referencing it emits ACEF-020,
    but a same-tenant follow-up does not.
    """
    bundle = tmp_path / "first-declarer"
    write_bundle(
        bundle,
        manifest=base_manifest(analysis_mode=None),
        records=[
            # First declarer: tenant alpha owns the component
            base_record(
                record_id="urn:acef:rec:70000000-0000-0000-0000-000000000001",
                tenant_label="urn:acef:tenant:alpha",
                entity_refs={"component_refs": [_COMPONENT_URN]},
            ),
            # Same-tenant referencer: should NOT trigger
            base_record(
                record_id="urn:acef:rec:70000000-0000-0000-0000-000000000002",
                tenant_label="urn:acef:tenant:alpha",
                entity_refs={"component_refs": [_COMPONENT_URN]},
            ),
            # Cross-tenant referencer: MUST trigger
            base_record(
                record_id="urn:acef:rec:70000000-0000-0000-0000-000000000003",
                tenant_label="urn:acef:tenant:beta",
                entity_refs={"component_refs": [_COMPONENT_URN]},
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    tenant_diags = [
        d
        for d in assessment.structural_errors
        if d.get("code") == "ACEF-020" and "tenant" in d.get("message", "").lower()
    ]
    # Exactly one tenant-flavored ACEF-020: the beta referencer
    assert len(tenant_diags) == 1, (
        f"Expected exactly one tenant-flavored ACEF-020 for the beta "
        f"referencer; got {len(tenant_diags)}: {tenant_diags!r}"
    )
    assert "beta" in tenant_diags[0]["message"]
