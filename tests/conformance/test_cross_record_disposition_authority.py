"""VAL-VALIDATION-LOAD-AUTHORITY-MATRIX-001: §14.5 disposition authority matrix.

20-cell integration test. For each cell (5 authority classes × 4 actor types)
this test:

- Builds a v1.1 bundle containing one `risk_treatment` record with
  `treatment_subtype: external_disposition` and an `authority_check` block
  carrying `authority_granted: true` for that pair.
- Runs the full validator.
- Asserts ACEF-080 fires when the matrix denies, and does NOT fire (for the
  authority-violation reason) when the matrix grants.

The unit-level matrix data is separately covered in
tests/unit/test_authority_matrix.py; this file proves the matrix is wired
through the validator end-to-end.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acef.validation.authority_matrix import all_cells
from acef.validation.engine import validate_bundle
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
    write_bundle,
)

_AUTHORITY_PHRASE = "authority matrix denies"


@pytest.mark.parametrize(
    "authority_class,actor_role,granted",
    all_cells(),
    ids=[f"{ac}-{ar}-{'granted' if g else 'denied'}" for ac, ar, g in all_cells()],
)
def test_matrix_cell_validation_path(
    tmp_path: Path,
    authority_class: str,
    actor_role: str,
    granted: bool,
) -> None:
    """End-to-end matrix test for one cell.

    Granted cells must NOT produce a matrix-denial ACEF-080.
    Denied cells MUST produce a matrix-denial ACEF-080.
    """
    bundle = tmp_path / f"{authority_class}-{actor_role}"

    actor_id = "urn:acef:act:abc12345-0000-0000-0000-000000000001"
    disposition_id = "urn:acef:rec:abc12345-0000-0000-0000-000000000002"

    manifest = base_manifest(
        entities_actors=[
            {
                "actor_id": actor_id,
                "role": actor_role,
                "name": "test-actor",
                "organization": "test-org",
            }
        ],
    )
    write_bundle(
        bundle,
        manifest=manifest,
        records=[
            base_record(
                record_id=disposition_id,
                record_type="risk_treatment",
                entity_refs={"actor_refs": [actor_id]},
                payload={
                    "treatment_subtype": "external_disposition",
                    "authority_check": {
                        "authority_class": authority_class,
                        "authority_granted": True,
                        "actor_ref": actor_id,
                    },
                },
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    diags = assessment.structural_errors

    matrix_denial_diags = [
        d for d in diags if d.get("code") == "ACEF-080" and _AUTHORITY_PHRASE in d.get("message", "")
    ]

    if granted:
        assert not matrix_denial_diags, (
            f"Cell ({authority_class!r}, {actor_role!r}) is granted but "
            f"validator emitted a matrix-denial diagnostic: "
            f"{matrix_denial_diags!r}"
        )
    else:
        assert matrix_denial_diags, (
            f"Cell ({authority_class!r}, {actor_role!r}) is denied but "
            f"validator did NOT emit a matrix-denial diagnostic. All codes: "
            f"{codes(diags)!r}"
        )


def test_disposition_record_with_authority_granted_false_clean(
    tmp_path: Path,
) -> None:
    """authority_granted: false does NOT violate the matrix (the matrix
    only restricts who may be granted; denying authority on anybody is
    always permitted).
    """
    bundle = tmp_path / "granted-false"

    actor_id = "urn:acef:act:abc12345-0000-0000-0000-000000000003"
    manifest = base_manifest(
        entities_actors=[
            {"actor_id": actor_id, "role": "provider", "name": "p", "organization": "o"},
        ],
    )
    write_bundle(
        bundle,
        manifest=manifest,
        records=[
            base_record(
                record_id="urn:acef:rec:abc12345-0000-0000-0000-000000000004",
                record_type="risk_treatment",
                entity_refs={"actor_refs": [actor_id]},
                payload={
                    "treatment_subtype": "external_disposition",
                    "authority_check": {
                        # Provider × accepted_risk_request would be DENIED
                        # if granted=true. Here granted is false, so no
                        # violation regardless of the matrix cell.
                        "authority_class": "accepted_risk_request",
                        "authority_granted": False,
                        "actor_ref": actor_id,
                    },
                },
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    matrix_denial_diags = [
        d
        for d in assessment.structural_errors
        if d.get("code") == "ACEF-080" and _AUTHORITY_PHRASE in d.get("message", "")
    ]
    assert not matrix_denial_diags, f"granted=false should not violate the matrix; got: {matrix_denial_diags!r}"


def test_disposition_record_without_authority_check_clean(tmp_path: Path) -> None:
    """A risk_treatment record without an authority_check block is not a
    disposition record per §14.5 semantics; the matrix check skips it.
    """
    bundle = tmp_path / "no-authority-check"
    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:abc12345-0000-0000-0000-000000000005",
                record_type="risk_treatment",
                payload={"treatment_subtype": "external_disposition"},
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    matrix_denial_diags = [
        d
        for d in assessment.structural_errors
        if d.get("code") == "ACEF-080" and _AUTHORITY_PHRASE in d.get("message", "")
    ]
    assert not matrix_denial_diags


def test_non_disposition_risk_treatment_skipped(tmp_path: Path) -> None:
    """risk_treatment records that aren't external_disposition variants
    skip the matrix check entirely.
    """
    bundle = tmp_path / "non-disposition"
    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:abc12345-0000-0000-0000-000000000006",
                record_type="risk_treatment",
                payload={
                    "treatment_subtype": "regression_definition",
                    "authority_check": {
                        # Even with a denied (authority, actor) pair, the
                        # check should not fire because this is not an
                        # external_disposition variant.
                        "authority_class": "evidence_dispute",
                        "authority_granted": True,
                    },
                },
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    matrix_denial_diags = [
        d
        for d in assessment.structural_errors
        if d.get("code") == "ACEF-080" and _AUTHORITY_PHRASE in d.get("message", "")
    ]
    assert not matrix_denial_diags
