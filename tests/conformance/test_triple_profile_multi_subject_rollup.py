"""Conformance vector: triple-profile x multi-subject union-with-attribution.

assessment-rollup-4 / RFC-0002 §5.7 self-identified gap: incident requiredness
routes through the existing per-profile + per-subject rollup. The engine
evaluates each profile in an independent loop, keying every ProvisionSummary to a
single ``profile_id``; multi-subject keys per ``subject_scope``. The RFC flagged
that no vector exercised the triple-profile x multi-subject case SIMULTANEOUSLY,
so the (profile_id, member_path, subject_scope) attribution triple under the
union semantics was unverified end-to-end.

This vector declares a SINGLE bundle with THREE incident-relevant profiles
(``eu-ai-act-art73-2026`` + ``oecd-ai-incidents-2025`` +
``eu-gpai-code-of-practice-2025`` — the GPAI Code of Practice carrying the Art.55
obligations) across TWO subjects with DIFFERENT risk classifications, because the
three profiles target different subject populations via per-provision
``applicable_to``:

* ``eu-ai-act-art73-2026`` provisions apply to ``high-risk`` subjects,
* ``eu-gpai-code-of-practice-2025`` safety/transparency provisions apply to
  ``gpai-systemic`` subjects,
* ``oecd-ai-incidents-2025`` provisions have empty ``applicable_to`` (every
  subject).

So the two subjects are a ``high-risk`` system and a ``gpai-systemic`` model. The
vector asserts:

* every ProvisionSummary keys to exactly one of the three declared profiles
  (per-profile attribution — never cross-contaminated),
* the union-with-attribution composes with per-subject evaluation AND with
  ``applicable_to`` subject filtering: an art73 provision is scoped ONLY to the
  high-risk subject, a GPAI provision ONLY to the gpai-systemic subject, and an
  OECD provision to BOTH subjects — each carrying the correct single-subject
  ``subject_scope`` (the (profile_id, provision, subject) triple).

Determinism: a fixed ``evaluation_instant`` after every provision's
``effective_date`` (so provisions are in force and evaluated per-subject, not
skipped); no wall-clock, no randomness.
"""

from __future__ import annotations

from pathlib import Path

from acef.package import Package
from acef.validation.engine import validate_bundle

# The three incident-relevant profiles evaluated simultaneously.
PROFILE_ART73 = "eu-ai-act-art73-2026"
PROFILE_OECD = "oecd-ai-incidents-2025"
PROFILE_GPAI = "eu-gpai-code-of-practice-2025"

# Applicable provisions declared per profile.
# art73 -> applicable_to ['high-risk']; oecd -> applicable_to [] (all subjects);
# gpai chosen provisions -> applicable_to includes 'gpai-systemic'.
ART73_PROVISIONS = ["article-3-49", "article-73"]
OECD_PROVISIONS = ["oecd-mandatory-core"]
GPAI_PROVISIONS = ["gpai-transparency-1", "gpai-safety-1"]

# After every provision's effective_date (art73 2026-08-02, gpai 2025-08-02) so
# the provisions are in force and evaluated PER SUBJECT (not skipped).
EVALUATION_INSTANT = "2027-01-01T00:00:00Z"

ALL_DECLARED_PROFILES = {PROFILE_ART73, PROFILE_OECD, PROFILE_GPAI}


def _build_triple_profile_multi_subject_bundle(bundle_dir: Path) -> tuple[str, str]:
    """Build a 2-subject bundle declaring all three incident profiles.

    Returns ``(high_risk_subject_id, gpai_systemic_subject_id)``.
    """
    pkg = Package(producer={"name": "triple-profile-multi-subject", "version": "1.0.0"})

    # art73 provisions target 'high-risk'.
    sys_high_risk = pkg.add_subject(
        "ai_system",
        name="High-Risk System",
        risk_classification="high-risk",
        modalities=["text"],
    )
    # GPAI safety/transparency provisions target 'gpai-systemic'.
    model_gpai = pkg.add_subject(
        "ai_model",
        name="Systemic GPAI Model",
        risk_classification="gpai-systemic",
        modalities=["text"],
    )

    pkg.add_profile(PROFILE_ART73, provisions=ART73_PROVISIONS)
    pkg.add_profile(PROFILE_OECD, provisions=OECD_PROVISIONS)
    pkg.add_profile(PROFILE_GPAI, provisions=GPAI_PROVISIONS)

    # Records bound to each subject so the bundle is non-empty and the per-subject
    # evaluation has evidence to roll up (the exact PASS/FAIL outcome is not what
    # this vector asserts — only the attribution keying is).
    for subj in (sys_high_risk, model_gpai):
        pkg.record(
            "risk_register",
            provisions=ART73_PROVISIONS + GPAI_PROVISIONS,
            payload={"description": "Risk", "likelihood": "low", "severity": "low"},
            obligation_role="provider",
            entity_refs={"subject_refs": [subj.id]},
        )
        pkg.record(
            "governance_policy",
            provisions=OECD_PROVISIONS + GPAI_PROVISIONS,
            payload={"policy_type": "quality_management", "description": "QMS"},
            obligation_role="provider",
            entity_refs={"subject_refs": [subj.id]},
        )

    pkg.export(str(bundle_dir))
    return sys_high_risk.id, model_gpai.id


class TestTripleProfileMultiSubjectRollup:
    def test_every_summary_keyed_to_one_declared_profile(self, tmp_dir: Path) -> None:
        """Per-profile attribution: each ProvisionSummary names exactly one of
        the three declared profile_ids — never blank, never cross-mixed."""
        bundle_dir = tmp_dir / "triple_profile_profile_key"
        _build_triple_profile_multi_subject_bundle(bundle_dir)

        assessment = validate_bundle(
            bundle_dir,
            profiles=sorted(ALL_DECLARED_PROFILES),
            evaluation_instant=EVALUATION_INSTANT,
        )

        assert assessment.provision_summary, "expected provision summaries for the triple-profile bundle"
        seen_profiles = {s.profile_id for s in assessment.provision_summary}
        assert seen_profiles == ALL_DECLARED_PROFILES, (
            f"every summary must key to one of the three declared profiles; "
            f"saw {seen_profiles}, expected {ALL_DECLARED_PROFILES}"
        )

    def test_union_with_attribution_composes_with_per_subject_and_applicable_to(self, tmp_dir: Path) -> None:
        """The (profile_id, provision_id, subject_scope) triple is correct for
        every declared provision, respecting per-subject ``applicable_to``:

        * art73 provisions scoped ONLY to the high-risk subject,
        * GPAI provisions scoped ONLY to the gpai-systemic subject,
        * OECD provisions scoped to BOTH subjects,

        each summary carrying exactly that subject's single-subject scope.
        """
        bundle_dir = tmp_dir / "triple_profile_cross_product"
        high_risk_id, gpai_id = _build_triple_profile_multi_subject_bundle(bundle_dir)

        assessment = validate_bundle(
            bundle_dir,
            profiles=sorted(ALL_DECLARED_PROFILES),
            evaluation_instant=EVALUATION_INSTANT,
        )

        # (profile_id, provision_id) -> set of subject_scopes seen.
        scopes_by_key: dict[tuple[str, str], set[tuple[str, ...]]] = {}
        for s in assessment.provision_summary:
            key = (s.profile_id, s.provision_id)
            scopes_by_key.setdefault(key, set()).add(tuple(s.subject_scope))

        # art73 provisions -> ONLY the high-risk subject.
        for prov in ART73_PROVISIONS:
            key = (PROFILE_ART73, prov)
            assert scopes_by_key.get(key) == {(high_risk_id,)}, (
                f"{PROFILE_ART73}::{prov} must be scoped ONLY to the high-risk subject; saw {scopes_by_key.get(key)}"
            )

        # GPAI provisions -> ONLY the gpai-systemic subject.
        for prov in GPAI_PROVISIONS:
            key = (PROFILE_GPAI, prov)
            assert scopes_by_key.get(key) == {(gpai_id,)}, (
                f"{PROFILE_GPAI}::{prov} must be scoped ONLY to the gpai-systemic subject; saw {scopes_by_key.get(key)}"
            )

        # OECD provision (empty applicable_to) -> BOTH subjects, each a distinct
        # single-subject scope.
        oecd_key = (PROFILE_OECD, "oecd-mandatory-core")
        assert scopes_by_key.get(oecd_key) == {(high_risk_id,), (gpai_id,)}, (
            f"{PROFILE_OECD}::oecd-mandatory-core must be scoped to BOTH subjects "
            f"(one summary each); saw {scopes_by_key.get(oecd_key)}"
        )

    def test_oecd_provision_yields_one_summary_per_subject(self, tmp_dir: Path) -> None:
        """The all-subjects OECD provision produces exactly two summaries (one per
        subject) — the per-subject cardinality for a no-filter provision."""
        bundle_dir = tmp_dir / "triple_profile_cardinality"
        high_risk_id, gpai_id = _build_triple_profile_multi_subject_bundle(bundle_dir)

        assessment = validate_bundle(
            bundle_dir,
            profiles=sorted(ALL_DECLARED_PROFILES),
            evaluation_instant=EVALUATION_INSTANT,
        )

        matching = [
            s
            for s in assessment.provision_summary
            if s.profile_id == PROFILE_OECD and s.provision_id == "oecd-mandatory-core"
        ]
        assert len(matching) == 2, (
            f"{PROFILE_OECD}::oecd-mandatory-core must produce one summary per subject (2), got {len(matching)}"
        )
        scopes = [tuple(s.subject_scope) for s in matching]
        assert all(len(sc) == 1 for sc in scopes), f"each per-subject summary scopes one subject: {scopes}"
        assert set(scopes) == {(high_risk_id,), (gpai_id,)}, (
            f"the two OECD per-subject summaries must scope the two distinct subjects: {scopes}"
        )
