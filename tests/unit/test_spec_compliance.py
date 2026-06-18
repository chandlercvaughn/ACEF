"""Tests for spec compliance fixes — assessment versioning, evaluation_scope,
gzip OS byte, modalities scope, ACEF-027, chain(), sign()/verify()."""

from __future__ import annotations

import json
from pathlib import Path

import acef
from acef.models.assessment import AssessmentBundle, AssessmentVersioning
from acef.package import Package


class TestAssessmentVersioning:
    """CG-1: Assessment Bundle must use assessment_version, not profiles_version."""

    def test_assessment_bundle_has_assessment_version(self) -> None:
        assessment = AssessmentBundle()
        data = assessment.to_dict()
        assert "assessment_version" in data["versioning"]
        assert "profiles_version" not in data["versioning"]

    def test_assessment_versioning_model(self) -> None:
        v = AssessmentVersioning()
        assert v.core_version == "1.0.0"
        assert v.assessment_version == "1.0.0"

    def test_validate_produces_assessment_version(self, minimal_package: Package) -> None:
        assessment = acef.validate(minimal_package)
        data = assessment.to_dict()
        assert "assessment_version" in data["versioning"]
        assert data["versioning"]["assessment_version"] == "1.0.0"


class TestEvaluationScopePackage:
    """CG-2: evaluation_scope='package' should evaluate provision once, not per-subject."""

    def test_package_scope_evaluated_once(self, tmp_dir: Path) -> None:
        """A package-scoped provision produces one summary entry, not one per subject."""
        from acef.templates.registry import _get_template_dir

        # Create a temporary template with a package-scoped provision
        template_data = {
            "template_id": "test-pkg-scope",
            "template_name": "Test Package Scope",
            "version": "1.0.0",
            "jurisdiction": "TEST",
            "instrument_type": "standard",
            "legal_force": "voluntary",
            "instrument_status": "final",
            "applicable_system_types": [],
            "provisions": [
                {
                    "provision_id": "pkg-gov",
                    "provision_name": "Package Governance",
                    "evaluation_scope": "package",
                    "required_evidence_types": ["governance_policy"],
                    "evaluation": [
                        {
                            "rule_id": "pkg-gov-exists",
                            "rule": "has_record_type",
                            "params": {"type": "governance_policy", "min_count": 1},
                            "severity": "fail",
                            "message": "Governance policy required",
                        }
                    ],
                }
            ],
        }

        # Write temp template
        template_dir = _get_template_dir()
        template_file = template_dir / "test-pkg-scope.json"
        template_file.write_text(json.dumps(template_data))

        try:
            # Create package with 2 subjects + governance_policy record
            pkg = Package(producer={"name": "test", "version": "1.0"})
            pkg.add_subject("ai_system", name="System A")
            pkg.add_subject("ai_model", name="Model B")
            pkg.add_profile("test-pkg-scope", provisions=["pkg-gov"])
            pkg.record("governance_policy", payload={"policy_type": "ai_governance"})

            assessment = acef.validate(pkg, profiles=["test-pkg-scope"])

            # Package-scoped provision should produce exactly 1 summary, not 2
            pkg_summaries = [ps for ps in assessment.provision_summary if ps.provision_id == "pkg-gov"]
            assert len(pkg_summaries) == 1
            # Should have empty subject_scope (package-level)
            assert pkg_summaries[0].subject_scope == []
        finally:
            template_file.unlink(missing_ok=True)
            # Clear template cache
            from acef.templates.registry import load_template

            load_template.cache_clear()


class TestGzipOSByte:
    """CG-4: gzip header OS byte must be 0xFF."""

    def test_archive_os_byte_is_0xff(self, minimal_package: Package, tmp_dir: Path) -> None:
        archive_path = tmp_dir / "test.acef.tar.gz"
        minimal_package.export(str(archive_path))

        with open(archive_path, "rb") as f:
            header = f.read(10)
            # Gzip header: bytes[0:2]=magic, [9]=OS
            assert header[0:2] == b"\x1f\x8b"  # gzip magic
            assert header[9] == 0xFF  # OS byte must be 0xFF per spec


class TestNoWallClockFallback:
    """MG-5: evidence_freshness must not use wall-clock time."""

    def test_no_evaluation_instant_returns_pass(self) -> None:
        from acef.models.records import RecordEnvelope
        from acef.validation.operators import op_evidence_freshness

        records = [RecordEnvelope(record_type="risk_register", payload={})]
        # No evaluation_instant provided — should NOT use wall-clock
        passed, _ = op_evidence_freshness(
            {"max_days": 365},
            records,
            evaluation_instant="",
            package_timestamp="",
        )
        # Returns True (pass) when no reference date available, rather than
        # falling back to wall-clock time
        assert passed


class TestModalitiesScopeFilter:
    """MG-4: modalities scope filter must be checked."""

    def test_modalities_filter_excludes_non_matching(self) -> None:
        from acef.models.records import RecordEnvelope
        from acef.validation.rule_engine import _matches_scope

        record = RecordEnvelope(record_type="risk_register", payload={})
        scope = {"modalities": ["image", "video"]}

        # Text-only subject should not match image/video scope
        assert not _matches_scope(record, scope, subject_modalities=["text"])

    def test_modalities_filter_includes_matching(self) -> None:
        from acef.models.records import RecordEnvelope
        from acef.validation.rule_engine import _matches_scope

        record = RecordEnvelope(record_type="risk_register", payload={})
        scope = {"modalities": ["text", "image"]}

        assert _matches_scope(record, scope, subject_modalities=["text"])

    def test_no_modalities_scope_matches_all(self) -> None:
        from acef.models.enums import ObligationRole
        from acef.models.records import RecordEnvelope
        from acef.validation.rule_engine import _matches_scope

        record = RecordEnvelope(
            record_type="risk_register",
            payload={},
            obligation_role=ObligationRole.PROVIDER,
        )
        scope = {"obligation_roles": ["provider"]}

        # No modalities in scope — should match regardless of subject modalities
        assert _matches_scope(record, scope, subject_modalities=["text"])


class TestChainFunction:
    """MG-14: acef.chain() convenience function."""

    def test_chain_creates_package_with_prior_ref(self, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_dir = tmp_dir / "prior.acef"
        minimal_package.export(str(bundle_dir))

        new_pkg = acef.chain(
            str(bundle_dir),
            producer={"name": "test", "version": "2.0"},
        )
        assert new_pkg.metadata.prior_package_ref is not None
        assert new_pkg.metadata.prior_package_ref.startswith("sha256:")


class TestTopLevelSignVerify:
    """MG-13: acef.sign and acef.verify exist."""

    def test_sign_is_callable(self) -> None:
        assert callable(acef.sign)

    def test_verify_is_callable(self) -> None:
        assert callable(acef.verify)

    def test_sign_is_sign_bundle(self) -> None:
        from acef.signing import sign_bundle

        assert acef.sign is sign_bundle

    def test_verify_is_verify_detached_jws(self) -> None:
        from acef.signing import verify_detached_jws

        assert acef.verify is verify_detached_jws


class TestACEF032Emission:
    """ACEF-032: Provision not yet effective produces info diagnostic."""

    def test_future_provision_emits_acef032(self, tmp_dir: Path) -> None:
        pkg = Package(producer={"name": "test", "version": "1.0"})
        pkg.add_subject("ai_system", name="Test", risk_classification="high-risk")
        pkg.add_profile("eu-ai-act-2024", provisions=["article-9"])

        # Evaluate with a date before the provision effective date
        assessment = acef.validate(
            pkg,
            profiles=["eu-ai-act-2024"],
            evaluation_instant="2024-01-01T00:00:00Z",
        )

        # Should have ACEF-032 info diagnostics
        acef032_errors = [e for e in assessment.structural_errors if e.get("code") == "ACEF-032"]
        assert len(acef032_errors) > 0


class TestSpecTemplateCitationsResolve:
    """F26: the spec + RFC-0001 + freddy-requirements cited a non-existent
    ``acef-conventions/v1/templates/`` directory and template IDs (``eu-ai-act-high-risk-v1``,
    ``nist-rmf-v1``) that do not exist, and falsely claimed those templates were extended to
    consume the v1.1 record types (which they do NOT contain). The docs now cite the real
    on-disk templates and describe the actual v1.1 validation-rule binding mechanism."""

    _REPO_ROOT = Path(__file__).resolve().parents[2]

    def test_no_planning_doc_cites_a_nonexistent_template_path_or_id(self) -> None:
        dead_refs = ["acef-conventions/v1/templates/", "eu-ai-act-high-risk-v1", "nist-rmf-v1"]
        for doc in sorted((self._REPO_ROOT / "planning").glob("*.md")):
            text = doc.read_text(encoding="utf-8")
            for token in dead_refs:
                assert token not in text, f"{doc.name} still cites the dead template ref {token!r}"

    def test_real_regulation_templates_exist_on_disk(self) -> None:
        templates_dir = self._REPO_ROOT / "src" / "acef" / "templates"
        for name in ("eu-ai-act-2024.json", "nist-ai-rmf-1.0.json"):
            assert (templates_dir / name).exists(), f"cited regulation template missing: {name}"

    def test_no_planning_doc_claims_per_regulation_templates_ship_the_v1_1_binding(self) -> None:
        """F26 follow-up (roborev Medium on 2b2dc31): the prior commit corrected
        the dead template paths but left stale claims in the RFC-0001 finding_record
        row + the freddy D6 heading that the per-regulation TEMPLATES ship/are the
        vehicle for the v1.1 record-type mappings — directly contradicting the
        corrected text that those templates are UNCHANGED. The binding ships as the
        §4 matrix + the v1.1 validation surface, never as template edits."""
        stale_phrases = [
            "per-regulation templates ship",
            "ship in the per-regulation templates",
            "templates ship in v0.4",
        ]
        for doc in sorted((self._REPO_ROOT / "planning").glob("*.md")):
            text = doc.read_text(encoding="utf-8").lower()
            for phrase in stale_phrases:
                assert phrase not in text, f"{doc.name} still claims {phrase!r} (templates are unchanged in v0.4)"

    def test_spec_v1_1_note_cites_actual_enforcement_surfaces(self) -> None:
        """F26 follow-up (roborev Medium on 2b2dc31): the spec v1.1-additions note
        attributed BOTH structural validity AND evidence-binding to
        ``v1_1_rules.py`` — but that module only enforces coverage-cell
        banned-language, state-class taxonomy, and analysis-mode gates. Structural
        validity is the v1.1 JSON Schemas; harness/delivery/causation evidence-binding
        is ``cross_record.py``. The note MUST cite the actual surfaces."""
        spec = (self._REPO_ROOT / "planning" / "ACEF-Spec-Outline-v0.1.md").read_text(encoding="utf-8")
        note_idx = spec.find("Note (v1.1 additions)")
        assert note_idx != -1, "spec lost its v1.1-additions note"
        note = spec[note_idx : note_idx + 1200]
        assert "acef-conventions/v1.1/" in note, "v1.1 note must cite the v1.1 schemas for structural validity"
        assert "cross_record.py" in note, "v1.1 note must cite cross_record.py for evidence-binding"

    def test_no_planning_doc_cites_v1_1_rules_as_the_sole_enforcement_surface(self) -> None:
        """F26 follow-up (roborev Medium on d2e84bf): wherever a planning doc cites
        ``v1_1_rules.py`` as a v1.1 enforcement surface, the SAME neighborhood MUST
        also cite the rest of the split surface — the v1.1 JSON Schemas
        (``acef-conventions/v1.1/``) for structural validity and ``cross_record.py``
        for harness/delivery/causation evidence-binding. ``v1_1_rules.py`` alone
        enforces only coverage-cell banned-language, state-class taxonomy, and
        analysis-mode gates, so a ``v1_1_rules.py``-only enforcement claim is the
        stale mischaracterization this class of fixes removes. Window-scoped so a
        localized claim cannot hide behind unrelated mentions elsewhere in the doc."""
        needle = "v1_1_rules.py"
        window = 800
        for doc in sorted((self._REPO_ROOT / "planning").glob("*.md")):
            text = doc.read_text(encoding="utf-8")
            start = 0
            while (idx := text.find(needle, start)) != -1:
                ctx = text[max(0, idx - window) : idx + window]
                assert "cross_record.py" in ctx, (
                    f"{doc.name}: {needle} at offset {idx} cited without cross_record.py nearby "
                    f"(v1_1_rules.py-only enforcement claim)"
                )
                assert "acef-conventions/v1.1/" in ctx, (
                    f"{doc.name}: {needle} at offset {idx} cited without the v1.1 schemas "
                    f"(acef-conventions/v1.1/) nearby"
                )
                start = idx + len(needle)


class TestF23OrphanArtifactNames:
    """F23: bias_assessment / acquisition_record appeared in the §2 mapping
    tables as if they were first-class record types, but neither is a RECORD_TYPES
    member nor a registered variant — they are payload concepts. Every line that
    names them must now resolve them to a real parent record type."""

    _SPEC = Path(__file__).resolve().parents[2] / "planning" / "ACEF-Spec-Outline-v0.1.md"

    def test_orphan_names_clarified_to_a_real_record_type(self) -> None:
        from acef.models.enums import RECORD_TYPES

        spec_lines = self._SPEC.read_text(encoding="utf-8").splitlines()
        for orphan in ("`bias_assessment`", "`acquisition_record"):
            hits = [ln for ln in spec_lines if orphan in ln]
            assert hits, f"spec lost the {orphan} mapping row"
            for ln in hits:
                names_real_parent = any(f"`{rt}`" in ln for rt in RECORD_TYPES)
                assert names_real_parent and "not a standalone record type" in ln.lower(), (
                    f"orphan {orphan} not resolved to a real record type: {ln!r}"
                )


class TestF28TransparencyMarkingVocabulary:
    """F28: the §3.4/§3.5/§5.1 examples used the obsolete marking_technique /
    metadata_format vocabulary that §3.1.5 replaced, so the spec's own example
    transparency_marking record would FAIL the shipped schema."""

    _REPO = Path(__file__).resolve().parents[2]
    _SPEC = _REPO / "planning" / "ACEF-Spec-Outline-v0.1.md"
    _REQUIRED = ("modality", "marking_scheme_id", "scheme_version", "metadata_container", "watermark_applied")

    def test_no_example_uses_the_obsolete_marking_technique_field(self) -> None:
        spec = self._SPEC.read_text(encoding="utf-8")
        assert "/payload/marking_technique" not in spec, "spec still uses the obsolete /payload/marking_technique"
        assert '"marking_technique": "secure_metadata"' not in spec, "spec §5.1 still uses the obsolete payload key"

    @staticmethod
    def _extract_balanced_dict(text: str, start: int) -> str:
        """Return the balanced ``{...}`` literal beginning at/after ``start``."""
        open_idx = text.index("{", start)
        depth = 0
        for i in range(open_idx, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return text[open_idx : i + 1]
        raise AssertionError("unbalanced braces in extracted payload")

    def test_section_5_1_example_payload_conforms_to_schema(self) -> None:
        """Extract the ACTUAL §5.1 transparency_marking payload from the spec
        Markdown (not a hardcoded copy — roborev on fda1a0e) and validate it
        against the shipped schema, so the documented example cannot drift out
        of conformance while this test still passes."""
        import ast

        from jsonschema import Draft202012Validator

        spec = self._SPEC.read_text(encoding="utf-8")
        # The §5.1 transparency_marking payload is the ``payload={...}`` block
        # that contains the marking_scheme_id key — locate it and parse the
        # balanced Python dict literal (inline comments + ``True`` are fine for
        # ast.literal_eval, which parses real Python source).
        anchor = spec.index('"marking_scheme_id": "c2pa-content-credentials"')
        payload_kw = spec.rindex("payload=", 0, anchor)
        payload_src = self._extract_balanced_dict(spec, payload_kw)
        documented_payload = ast.literal_eval(payload_src)

        for key in self._REQUIRED:
            assert key in documented_payload, f"§5.1 example missing required transparency_marking field {key!r}"
        schema = json.loads((self._REPO / "acef-conventions" / "v1" / "transparency_marking.schema.json").read_text())
        errors = list(Draft202012Validator(schema).iter_errors(documented_payload))
        assert not errors, f"documented §5.1 payload fails the schema: {[e.message for e in errors]}"


class TestF38ACEF040Realization:
    """F38: ACEF-040 ("Required evidence type missing") was advertised as
    never-emitted, but it is REALIZED — not as a standalone structural diagnostic
    (that would duplicate the verdict and wrongly escalate a voluntary provision's
    missing evidence to a blocking ERROR), but as a FAILED fail-severity
    required-evidence rule that rolls the provision up to NOT_SATISFIED. This test
    pins that realization: the failure surfaces via the rule outcome + roll-up,
    and NO standalone ACEF-040 structural diagnostic is emitted."""

    def test_missing_required_evidence_realizes_as_not_satisfied_not_a_diagnostic(self) -> None:
        from acef.models.enums import ProvisionOutcome, RuleOutcome, RuleSeverity
        from acef.templates.registry import _get_template_dir, load_template

        template_data = {
            "template_id": "test-req-evidence",
            "template_name": "Test Required Evidence",
            "version": "1.0.0",
            "jurisdiction": "TEST",
            "instrument_type": "standard",
            "legal_force": "binding",
            "instrument_status": "final",
            "default_effective_date": "2020-01-01",
            "applicable_system_types": [],
            "provisions": [
                {
                    "provision_id": "req-ev",
                    "provision_name": "Requires risk_register",
                    "effective_date": "2020-01-01",
                    "required_evidence_types": ["risk_register"],
                    "evaluation": [
                        {
                            "rule_id": "req-ev-governance-present",
                            "rule": "has_record_type",
                            "params": {"type": "governance_policy", "min_count": 1},
                            "severity": "info",
                            "message": "informational only",
                        }
                    ],
                }
            ],
        }
        template_dir = _get_template_dir()
        template_file = template_dir / "test-req-evidence.json"
        template_file.write_text(json.dumps(template_data))
        try:
            load_template.cache_clear()
            pkg = Package(producer={"name": "test", "version": "1.0"})
            pkg.add_subject("ai_system", name="Sys", risk_classification="high-risk")
            pkg.add_profile("test-req-evidence", provisions=["req-ev"])
            # A governance_policy record (satisfies the info rule) but NO
            # risk_register — so the auto-generated req-ev-risk_register-exists
            # fail-rule fails → ACEF-040.
            pkg.record("governance_policy", payload={"policy_type": "ai_governance"})

            assessment = acef.validate(
                pkg, profiles=["test-req-evidence"], evaluation_instant="2026-01-01T00:00:00Z"
            )
            # Realization 1: the auto-generated required-evidence rule FAILED at fail severity.
            exists_rule = next(
                (r for r in assessment.results if r.rule_id.endswith("-risk_register-exists")), None
            )
            assert exists_rule is not None, "the required-evidence existence rule was not evaluated"
            assert exists_rule.outcome == RuleOutcome.FAILED
            assert exists_rule.rule_severity == RuleSeverity.FAIL
            # Realization 2: the provision rolls up to NOT_SATISFIED (the gating verdict).
            summary = next(ps for ps in assessment.provision_summary if ps.provision_id == "req-ev")
            assert summary.provision_outcome == ProvisionOutcome.NOT_SATISFIED
            # And NO standalone ACEF-040 structural diagnostic is emitted (by design).
            codes = [e.get("code") for e in assessment.structural_errors]
            assert "ACEF-040" not in codes, f"ACEF-040 must NOT be a standalone structural diagnostic: {codes}"
        finally:
            template_file.unlink(missing_ok=True)
            load_template.cache_clear()


class TestF29ProvisionEffectiveReconciliation:
    """F29: provision-not-yet-effective has TWO mechanisms — the engine-level
    unconditional EXCLUSION (the live primary path) and the REDUNDANT
    if_provision_effective DSL condition (frozen-schema-supported + unit-tested).
    The spec must describe the engine-level exclusion as the mechanism, not
    present the DSL condition as the sole owner; and the DSL condition must remain
    defined (it is NOT removed — that would break the frozen schema + tests)."""

    _REPO = Path(__file__).resolve().parents[2]

    def test_spec_reconciles_engine_exclusion_with_redundant_dsl_condition(self) -> None:
        spec = (self._REPO / "planning" / "ACEF-Spec-Outline-v0.1.md").read_text(encoding="utf-8")
        idx = spec.find("Provision-not-yet-effective is handled by the **engine")
        assert idx != -1, "spec §3.7 must describe the engine-level not-yet-effective exclusion"
        para = spec[idx : idx + 800].lower()
        assert "excluded from evaluation" in para
        assert "acef-032" in para
        assert "redundant" in para and "if_provision_effective" in para

    def test_if_provision_effective_remains_in_the_frozen_schema(self) -> None:
        schema = json.loads(
            (self._REPO / "acef-conventions" / "v1" / "template.schema.json").read_text(encoding="utf-8")
        )
        text = json.dumps(schema)
        assert "if_provision_effective" in text, "the redundant condition is retained (frozen-schema contract)"
