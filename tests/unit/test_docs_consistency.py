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
        header_end = doc.find("\n", idx)
        header = doc[idx:header_end]
        section = doc[idx : idx + 1400]
        assert "tuple[RecordEnvelope" in section, "redact_record section must document the tuple return"
        assert "attestation" in section.lower(), "redact_record section must describe the attestation element"
        # roborev Low on 4b387cd: the documented signature must show defaults so
        # policy/method/access_policy/urn_generator do not look required.
        assert "policy=None" in header, f"redact_record signature must show defaults: {header!r}"
        # roborev Low on 58c5678: the quick-reference line must mirror the
        # defaults too, not just the detailed header.
        qref = [ln for ln in doc.splitlines() if ln.strip().startswith("acef.redact_record(")]
        assert qref, "API_REFERENCE lost the redact_record quick-reference line"
        assert "policy=None" in qref[0], f"redact_record quick-ref must show defaults: {qref[0]!r}"


class TestCoverageCellDocsNoRemovedModel:
    """roborev Medium on 4b387cd: USER_GUIDE/MIGRATION referenced the removed
    CoverageCellPayload / CoverageDimensions models. coverage_cell is a raw dict
    in the Assessment Bundle's coverage_cells array (no typed model in v0.4)."""

    def test_removed_models_are_actually_absent_from_src(self) -> None:
        import acef.models.agent_reliability as ar

        assert not hasattr(ar, "CoverageCellPayload")
        assert not hasattr(ar, "CoverageDimensions")

    def test_docs_do_not_import_removed_coverage_cell_models(self) -> None:
        for rel in ("docs/USER_GUIDE.md", "docs/MIGRATION-v0.3-to-v0.4.md"):
            text = (_REPO_ROOT / rel).read_text(encoding="utf-8")
            for sym in ("import CoverageCellPayload", "CoverageDimensions("):
                assert sym not in text, f"{rel} still references removed coverage_cell model usage: {sym!r}"

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


class TestF30DeadSymbolsRemoved:
    """F30: three orphaned symbols (zero production callers) removed — no dead
    public surface that 'doesn't make sense' to a reader of the SDK."""

    def test_subject_modality_enum_removed(self) -> None:
        import acef.models.enums as enums_mod

        assert not hasattr(enums_mod, "SubjectModality"), "vestigial SubjectModality enum must be removed"

    def test_resolve_record_type_for_variant_removed(self) -> None:
        import acef.schemas.registry as reg_mod

        assert not hasattr(reg_mod, "resolve_record_type_for_variant"), "orphaned helper must be removed"

    def test_get_template_provisions_removed(self) -> None:
        import acef.templates.registry as treg_mod

        assert not hasattr(treg_mod, "get_template_provisions"), "test-only helper must be removed"


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
        # roborev Medium on 316173c: the doc must not point at a nonexistent
        # public helper (acef.from_prior_bundle); acef.chain is the real export.
        assert "from_prior_bundle" not in entry, "prior_package_ref doc references nonexistent acef.from_prior_bundle"
        assert "acef.chain" in entry, "prior_package_ref doc should point at the real acef.chain helper"
        assert hasattr(acef, "chain"), "acef.chain must be a real public export"
        assert not hasattr(acef, "from_prior_bundle"), "from_prior_bundle is not a public export — don't document it"
