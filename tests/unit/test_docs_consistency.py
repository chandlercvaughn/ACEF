"""Doc/spec consistency regressions for audit findings F11, F22, F25.

These guard against documentation drifting back out of sync with the
implementation + frozen schemas:

- F22: the spec conformance-checklist precedence string used a phantom
  ``provision_outcome`` value ``error`` that the normative algorithm, the frozen
  schema enum, and ``ProvisionOutcome`` all call ``not-assessed``.
- F11: API_REFERENCE documented ``acef.redact_record`` as returning a single
  ``RecordEnvelope``; it actually returns ``(redacted, attestation|None)``.
- F25: USER_GUIDE / MIGRATION claimed "six new record types" while the same docs
  (and the v1.1 schema set) establish ``coverage_cell`` is an Assessment-side
  field, leaving only five new Evidence record types.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import acef

_REPO_ROOT = Path(__file__).resolve().parents[2]


class TestF22ProvisionRollupPrecedenceString:
    def test_spec_checklist_row_matches_frozen_schema_precedence(self) -> None:
        spec = (_REPO_ROOT / "planning" / "ACEF-Spec-Outline-v0.1.md").read_text(encoding="utf-8")
        rows = [ln for ln in spec.splitlines() if "**Provision roll-up**" in ln]
        assert rows, "spec lost its Provision roll-up conformance-checklist row"
        row = rows[0]
        # The normative algorithm maps `outcome: error` to provision_outcome
        # `not-assessed`; `error` is NOT a provision_outcome value.
        assert "> error >" not in row, f"checklist cites the phantom 'error' provision_outcome: {row!r}"
        assert "not-assessed" in row, f"checklist must use 'not-assessed': {row!r}"

    def test_no_provisionoutcome_enum_value_named_error(self) -> None:
        from acef.models.enums import ProvisionOutcome

        assert "error" not in {o.value for o in ProvisionOutcome}


class TestF11RedactRecordReturnsTuple:
    def test_runtime_return_annotation_is_a_tuple(self) -> None:
        from acef.redaction import redact_record

        ann = inspect.signature(redact_record).return_annotation
        # With ``from __future__ import annotations`` the annotation is a string.
        assert "tuple[" in str(ann), f"redact_record return annotation is not a tuple: {ann!r}"

    def test_api_reference_documents_the_tuple_return(self) -> None:
        doc = (_REPO_ROOT / "docs" / "API_REFERENCE.md").read_text(encoding="utf-8")
        # Target the detailed section HEADER (``### `acef.redact_record(...)```),
        # not the earlier quick-reference one-liner.
        idx = doc.find("### `acef.redact_record(")
        assert idx != -1, "API_REFERENCE lost the redact_record section"
        section = doc[idx : idx + 1400]
        assert "tuple[RecordEnvelope" in section, "redact_record section must document the tuple return"
        assert "attestation" in section.lower(), "redact_record section must describe the attestation element"

    def test_redact_record_is_publicly_exported(self) -> None:
        assert hasattr(acef, "redact_record")


class TestF25SixVsFiveRecordTypes:
    def test_user_guide_does_not_claim_six_new_record_types(self) -> None:
        guide = (_REPO_ROOT / "docs" / "USER_GUIDE.md").read_text(encoding="utf-8").lower()
        assert "six new record types" not in guide, (
            "USER_GUIDE still claims 'six new record types' (coverage_cell is Assessment-side)"
        )

    def test_migration_does_not_claim_six_new_record_types(self) -> None:
        mig = (_REPO_ROOT / "docs" / "MIGRATION-v0.3-to-v0.4.md").read_text(encoding="utf-8").lower()
        for stale in ("six new record types", "6 new core record types"):
            assert stale not in mig, f"MIGRATION still claims {stale!r} (coverage_cell is Assessment-side)"

    def test_only_five_evidence_record_schemas_in_v1_1(self) -> None:
        """Ground truth for the "five" count: the v1.1 conventions ship exactly
        five new Evidence record-type schemas (no coverage_cell.schema.json — it
        is an inline Assessment-bundle field)."""
        v1_1 = _REPO_ROOT / "acef-conventions" / "v1.1"
        assert not (v1_1 / "coverage_cell.schema.json").exists(), (
            "coverage_cell must NOT have a standalone Evidence schema"
        )
        # The five RFC-0001 Evidence record types each have a schema.
        for name in (
            "harness_attestation",
            "authorized_test_scope",
            "scope_boundary_event",
            "finding_record",
            "delivery_verdict",
        ):
            assert (v1_1 / f"{name}.schema.json").exists(), f"missing v1.1 Evidence schema: {name}"


class TestF47RecordTypesInventory:
    def test_record_types_count_and_incident_card_registered(self) -> None:
        """F47: the RECORD_TYPES inventory comment ('16 v1.0 + 6 v1.1') omitted
        incident_card (the 7th v1.1 addition listed below it). Pin the true count
        (16 + 6 + 1 = 23) and incident_card's presence so the comment stays honest."""
        from acef.models.enums import RECORD_TYPES

        assert "incident_card" in RECORD_TYPES
        assert len(RECORD_TYPES) == 23, f"RECORD_TYPES count drifted: {len(RECORD_TYPES)}"


class TestF45PriorPackageRefDocstring:
    def test_init_docstring_describes_bundle_digest_not_urn(self) -> None:
        """F45: Package.__init__ called prior_package_ref a 'URN'; spec + schema +
        the from_prior_bundle helper mandate the bundle digest (sha256:)."""
        from acef.package import Package

        doc = (Package.__init__.__doc__ or "").lower()
        idx = doc.find("prior_package_ref:")
        assert idx != -1, "Package.__init__ lost its prior_package_ref doc entry"
        entry = doc[idx : idx + 400]
        assert "bundle digest" in entry or "sha256" in entry, "prior_package_ref doc must cite the bundle digest"
        assert "urn of a prior" not in entry, "prior_package_ref doc still calls it a URN"
