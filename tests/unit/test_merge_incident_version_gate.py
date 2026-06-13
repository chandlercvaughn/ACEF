"""VAL-COVERAGE-MERGE-001 — roborev fixes on a32e21b7 (merge.py v1.1 awareness).

Two roborev (codex xhigh) findings against ``src/acef/merge.py``:

HIGH (merge.py:611) — the merged package was ALWAYS built with ``Versioning()``,
whose ``core_version`` defaults to ``1.0.0``. Merging packages that CARRY v1.1-only
incident content (``incident_card`` records, source-backed ``incident_report``
``card_source`` blocks, a §5.5 ``incident_dedupe_key``, or a v1.1 incident
relationship edge) therefore produced a merged manifest DECLARING ``core_version
1.0.0`` while CARRYING v1.1 content — a self-contradictory bundle that downstream
validation REJECTS (the v1.0 manifest's record-type allowlist does not admit
``incident_card`` → ``ACEF-003 Unknown record_type``; the same version-gate class
fixed throughout this operation). Fix: derive the merged ``core_version`` from the
inputs — the HIGHEST input ``core_version``, floored to ``1.1.0`` whenever the
resolved merged records/relationships require v1.1. A pure-v1.0 merge stays
``1.0.0`` (backward-compat).

MEDIUM (merge.py:104) — ``_compute_incident_links`` grouped EVERY record carrying a
payload field named ``incident_dedupe_key`` regardless of ``record_type``. Vendor
``x-*`` records skip payload validation, so a non-incident extension record bearing
a same-named field was FALSELY linked to real incident records. Fix: restrict
linkage candidates to the supported incident record types (the exact set + the
PUBLIC-plaintext-key constraint F-M8-DEDUPE emits on).

RED-first: each ``test_red_*`` reproduces the pre-fix defect (it FAILS on
``a32e21b7`` and passes after the fix).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from acef.merge import merge_packages
from acef.models.enums import Confidentiality
from acef.package import Package
from acef.redaction import RedactionPolicy
from acef.validation.engine import validate_bundle

_DEDUPE_KEY_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

_HARM_CORE = {
    "realization": "harm_event",
    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
    "harm_class": "physical_health",
}
_EU_FACTS = {
    "serious_incident_triggers": ["3.49.a"],
    "widespread": False,
    "death_involved": False,
}
_SEV_VECTOR = "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I"
# §5.3 public_incident_id pattern: ^AIIC-[A-Z0-9]{2,8}-[0-9]{4}-[0-9A-HJKMNP-TV-Z]{26,}$
# (Crockford-base32 suffix, >= 26 chars). These VALID ids let the end-to-end
# validate test pass the offline id-trust class for a self-asserted card.
_PID_A = "AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS"
_PID_B = "AIIC-ACME-2026-ZYXWVTSRQPNMKJHGFEDCBA9876543"

# The two pre-existing, feature-unrelated SDK quirks every vanilla SDK-built
# bundle exhibits (documented in tests/integration/test_report_incident_e2e.py):
# Package.__init__ appends an "Initial package creation" audit entry with an EMPTY
# actor_ref the manifest schema's URN pattern rejects, and a merge produces a
# merge-audit entry likewise without an actor_ref. Excluding them isolates the
# version-gate verdict (ACEF-003 Unknown record_type) this fix is responsible for.
_PRE_EXISTING_SDK_ERROR_PATHS: frozenset[str] = frozenset({"/audit_trail/0/actor_ref", "/audit_trail/1/actor_ref"})


def _incident_card_pkg(
    producer_name: str,
    *,
    public_incident_id: str,
    subject_identity: tuple[str, str, str],
    subject_name: str,
) -> tuple[Package, str]:
    """A package with ONE PUBLIC incident_card AND a subject (so the bundle is
    otherwise schema-valid and the only failure is the version gate).

    The typed ``incident_card`` builder calls ``_ensure_v1_1()``, so the INPUT
    package already declares ``core_version 1.1.0``; the merge must not regress it.
    """
    pkg = Package(
        producer={"name": producer_name, "version": "1.0"},
        redaction_policy=RedactionPolicy(version="1.0.0"),
    )
    pkg.add_subject("ai_system", name=subject_name, risk_classification="high-risk", modalities=["text"])
    env = pkg.incident_card(
        public_incident_id=public_incident_id,
        harm_core=dict(_HARM_CORE),
        severity_vector=_SEV_VECTOR,
        awareness_date="2026-08-01T00:00:00Z",
        eu_ai_act_facts=dict(_EU_FACTS),
        value_chain_role="foundation_model",
        subject_identity=subject_identity,
        occurrence_date="2026-07-15T09:30:00Z",
        confidentiality=Confidentiality.PUBLIC,
    )
    key = env.payload["incident_dedupe_key"]
    assert _DEDUPE_KEY_PATTERN.match(key), f"fixture must emit a §5.5 key, got {key!r}"
    return pkg, key


def _valid_risk_payload(risk_id: str) -> dict[str, Any]:
    """A schema-valid risk_register payload (risk_id/description/category required)."""
    return {"risk_id": risk_id, "description": "A documented risk.", "category": "safety"}


def _plain_pkg(producer_name: str, *, subject_name: str) -> Package:
    """A pure-v1.0 package (no incident content) — must merge to core_version 1.0.0."""
    pkg = Package(producer={"name": producer_name, "version": "1.0"})
    sub = pkg.add_subject("ai_system", name=subject_name, risk_classification="high-risk", modalities=["text"])
    pkg.record(
        "risk_register",
        payload=_valid_risk_payload(f"risk-{producer_name}"),
        entity_refs={"subject_refs": [sub.id]},
    )
    return pkg


def _incident_relevant_errors(assessment: Any) -> list[dict[str, Any]]:
    """ERROR/FATAL structural diagnostics minus the known pre-existing SDK quirks."""
    return [
        e
        for e in assessment.structural_errors
        if e.get("severity") in {"error", "fatal"} and e.get("path") not in _PRE_EXISTING_SDK_ERROR_PATHS
    ]


# ---------------------------------------------------------------------------
# HIGH — merged core_version derivation + end-to-end validity
# ---------------------------------------------------------------------------


class TestMergedCoreVersionDerivation:
    def test_red_merging_two_incident_cards_bumps_core_version_to_v1_1(self) -> None:
        """Two incident_card bundles -> merged core_version MUST be 1.1.0.

        Pre-fix (a32e21b7) the merged manifest declared ``core_version 1.0.0``
        (``Versioning()`` default) while carrying v1.1 incident_card records — a
        self-contradictory v1.0 manifest. RED: this asserts ``1.1.0``; pre-fix the
        merged value is ``1.0.0``.
        """
        pkg_a, _ = _incident_card_pkg(
            "Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"), subject_name="Sys A"
        )
        pkg_b, _ = _incident_card_pkg(
            "Org-B",
            public_incident_id=_PID_B,
            subject_identity=("Acme AI", "Vision-Pro", "2.1.0"),
            subject_name="Sys B",
        )
        assert pkg_a.versioning.core_version == "1.1.0", "precondition: incident_card input is v1.1"

        result = merge_packages([pkg_a, pkg_b])

        assert result.package.versioning.core_version == "1.1.0", (
            "merged bundle carrying v1.1 incident content MUST declare core_version 1.1.0, "
            "not the 1.0.0 Versioning() default"
        )

    def test_red_merged_incident_bundle_validates_end_to_end(self, tmp_path: Path) -> None:
        """The merged incident bundle EXPORTS + VALIDATES clean (no version-gate reject).

        Pre-fix the merged manifest declared ``core_version 1.0.0`` while carrying
        ``incident_card`` records, so ``validate_bundle`` emitted
        ``ACEF-003 Unknown record_type: 'incident_card'`` (the v1.0 record-type
        allowlist does not admit it). RED: this asserts ZERO incident-relevant
        ERROR/FATAL diagnostics AND that ACEF-003 is absent; pre-fix both fail.
        """
        pkg_a, _ = _incident_card_pkg(
            "Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"), subject_name="Sys A"
        )
        pkg_b, _ = _incident_card_pkg(
            "Org-B",
            public_incident_id=_PID_B,
            subject_identity=("Acme AI", "Vision-Pro", "2.1.0"),
            subject_name="Sys B",
        )
        result = merge_packages([pkg_a, pkg_b])

        bundle_dir = tmp_path / "merged-incident.acef"
        result.package.export(str(bundle_dir))

        assessment = validate_bundle(bundle_dir, profiles=["eu-ai-act-art73-2026"])
        codes = [e.get("code") for e in assessment.structural_errors]
        assert "ACEF-003" not in codes, (
            "v1.1 incident record_type must be admitted by the merged manifest's allowlist "
            f"(saw {[e for e in assessment.structural_errors if e.get('code') == 'ACEF-003']})"
        )
        errors = _incident_relevant_errors(assessment)
        assert errors == [], f"merged incident bundle must validate clean; unexpected: {errors}"

    def test_pure_v1_0_merge_stays_v1_0_and_validates(self, tmp_path: Path) -> None:
        """Backward-compat: merging two pure-v1.0 bundles MUST stay 1.0.0 and validate."""
        pkg_a = _plain_pkg("Org-A", subject_name="Sys A")
        pkg_b = _plain_pkg("Org-B", subject_name="Sys B")
        assert pkg_a.versioning.core_version == "1.0.0"
        assert pkg_b.versioning.core_version == "1.0.0"

        result = merge_packages([pkg_a, pkg_b])
        assert result.package.versioning.core_version == "1.0.0", (
            "a pure-v1.0 merge (no v1.1 content) MUST stay 1.0.0 — no spurious version bump"
        )

        bundle_dir = tmp_path / "merged-plain.acef"
        result.package.export(str(bundle_dir))
        assessment = validate_bundle(bundle_dir)
        errors = _incident_relevant_errors(assessment)
        assert errors == [], f"pure-v1.0 merge must validate clean; unexpected: {errors}"

    def test_mixed_v1_0_and_v1_1_inputs_merge_to_v1_1(self) -> None:
        """A v1.0 input merged WITH a v1.1 incident input -> merged 1.1.0.

        The HIGHEST input version wins, and the v1.1 incident content also floors
        it to 1.1.0; either path yields 1.1.0.
        """
        plain = _plain_pkg("Org-A", subject_name="Sys A")
        incident, _ = _incident_card_pkg(
            "Org-B", public_incident_id=_PID_B, subject_identity=("OpenAI", "GPT-X", "4.0"), subject_name="Sys B"
        )
        assert plain.versioning.core_version == "1.0.0"
        assert incident.versioning.core_version == "1.1.0"

        result = merge_packages([plain, incident])
        assert result.package.versioning.core_version == "1.1.0"

    def test_dedupe_key_alone_floors_to_v1_1_even_if_inputs_were_v1_0(self) -> None:
        """A resolved record carrying a §5.5 incident_dedupe_key floors core_version.

        Even if (hypothetically) the inputs declared 1.0.0, the presence of v1.1
        incident content in the MERGED record set requires 1.1.0 so the merged
        manifest is self-consistent. Drive it by forcing the input core_version
        back to 1.0.0 after the builder set it, leaving the v1.1 payload in place.
        """
        pkg_a, key = _incident_card_pkg(
            "Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"), subject_name="Sys A"
        )
        pkg_b, _ = _incident_card_pkg(
            "Org-B", public_incident_id=_PID_B, subject_identity=("OpenAI", "GPT-X", "4.0"), subject_name="Sys B"
        )
        # Force the declared versions back to 1.0.0 while KEEPING the v1.1
        # incident_card records + their incident_dedupe_key payloads.
        pkg_a.versioning.core_version = "1.0.0"
        pkg_b.versioning.core_version = "1.0.0"
        assert key  # the records still carry the v1.1 dedupe key

        result = merge_packages([pkg_a, pkg_b])
        assert result.package.versioning.core_version == "1.1.0", (
            "v1.1 incident content in the merged record set MUST floor core_version to 1.1.0 "
            "regardless of a (forged/stale) 1.0.0 input declaration"
        )


# ---------------------------------------------------------------------------
# MEDIUM — linkage restricted to supported incident record types
# ---------------------------------------------------------------------------


class TestLinkageRestrictedToIncidentRecordTypes:
    def test_red_vendor_x_record_with_same_key_is_not_linked(self) -> None:
        """A vendor x-* record carrying a same-named incident_dedupe_key is NOT linked.

        Vendor ``x-*`` records skip payload validation, so a non-incident extension
        record can carry a field literally named ``incident_dedupe_key``. Pre-fix
        ``_compute_incident_links`` grouped it WITH the real incident cards (it keyed
        purely on the payload field, ignoring record_type), falsely linking a
        non-incident record. RED: this asserts the x-* record is NOT in any link;
        pre-fix it IS falsely linked.
        """
        pkg_a, key = _incident_card_pkg(
            "Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"), subject_name="Sys A"
        )
        pkg_b, _ = _incident_card_pkg(
            "Org-B", public_incident_id=_PID_B, subject_identity=("OpenAI", "GPT-X", "4.0"), subject_name="Sys B"
        )

        pkg_x = Package(producer={"name": "Org-X", "version": "1.0"})
        sub_x = pkg_x.add_subject("ai_system", name="Sys X")
        x_env = pkg_x.record(
            "x-foo",
            payload={"incident_dedupe_key": key, "vendor_field": 1},
            entity_refs={"subject_refs": [sub_x.id]},
        )

        result = merge_packages([pkg_a, pkg_b, pkg_x])

        linked_ids: set[str] = set()
        for link in result.incident_links:
            linked_ids.update(link.record_ids)
        assert x_env.record_id not in linked_ids, (
            "a non-incident vendor x-* record carrying a same-named field MUST NOT be linked"
        )

        # The real incident_card↔incident_card linkage still works (regression guard).
        card_ids = {r.record_id for r in result.package.records if r.record_type == "incident_card"}
        assert len(result.incident_links) == 1, "the two real incident cards remain linked"
        assert set(result.incident_links[0].record_ids) == card_ids, (
            "the link must name exactly the two incident_card records — never the x-* record"
        )

    def test_non_incident_core_record_with_same_key_is_not_linked(self) -> None:
        """A core (non-incident) record carrying the same field name is NOT linked either."""
        pkg_a, key = _incident_card_pkg(
            "Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"), subject_name="Sys A"
        )
        pkg_b, _ = _incident_card_pkg(
            "Org-B", public_incident_id=_PID_B, subject_identity=("OpenAI", "GPT-X", "4.0"), subject_name="Sys B"
        )

        pkg_c = Package(producer={"name": "Org-C", "version": "1.0"})
        sub_c = pkg_c.add_subject("ai_system", name="Sys C")
        risk_env = pkg_c.record(
            "risk_register",
            payload={"incident_dedupe_key": key, "k": "c"},
            entity_refs={"subject_refs": [sub_c.id]},
        )

        result = merge_packages([pkg_a, pkg_b, pkg_c])

        linked_ids: set[str] = set()
        for link in result.incident_links:
            linked_ids.update(link.record_ids)
        assert risk_env.record_id not in linked_ids, (
            "a non-incident core record carrying a same-named field MUST NOT be linked"
        )
        assert len(result.incident_links) == 1


# ---------------------------------------------------------------------------
# MEDIUM (roborev on 7151416a) — the v1.1 VERSION trigger must share the
# linkage path's record-type guard: a NON-incident record (x-* or core)
# carrying a field literally named ``incident_dedupe_key`` MUST NOT drive an
# otherwise-v1.0 merge to 1.1.0. Pre-fix ``_merged_content_requires_v1_1``
# returned True for ANY record whose payload had that field name, regardless
# of ``record_type`` (merge.py:201) — the same false-positive the linkage path
# already avoids, reintroduced in the version path.
# ---------------------------------------------------------------------------


class TestVersionTriggerRestrictedToIncidentRecordTypes:
    def test_red_vendor_x_record_with_dedupe_field_does_not_bump_to_v1_1(self) -> None:
        """A pure-v1.0 merge with a NON-incident x-* record carrying a field named
        ``incident_dedupe_key`` MUST stay core_version 1.0.0.

        Pre-fix (7151416a) ``_merged_content_requires_v1_1`` hit the unconditional
        ``if _INCIDENT_DEDUPE_PAYLOAD_KEY in payload: return True`` (merge.py:201),
        which ignored ``record_type`` — so a vendor ``x-foo`` record (payload
        validation skipped) carrying a same-named field wrongly floored the merged
        manifest to 1.1.0, forcing v1.1-only validation on an otherwise-v1.0 merge.
        RED: this asserts the merged core_version stays 1.0.0; pre-fix it is 1.1.0.
        """
        plain_a = _plain_pkg("Org-A", subject_name="Sys A")

        pkg_x = Package(producer={"name": "Org-X", "version": "1.0"})
        sub_x = pkg_x.add_subject("ai_system", name="Sys X")
        pkg_x.record(
            "x-foo",
            payload={"incident_dedupe_key": "sha256:" + "a" * 64, "vendor_field": 1},
            entity_refs={"subject_refs": [sub_x.id]},
        )
        # The x-* record never bumps its own package off v1.0 (Package.record's
        # incident_dedupe_key trigger is scoped to incident_report).
        assert plain_a.versioning.core_version == "1.0.0"
        assert pkg_x.versioning.core_version == "1.0.0"

        result = merge_packages([plain_a, pkg_x])

        assert result.package.versioning.core_version == "1.0.0", (
            "a non-incident vendor x-* record carrying a same-named incident_dedupe_key field "
            "MUST NOT drive an otherwise-v1.0 merge to 1.1.0 — the version trigger must share "
            "the linkage path's record-type guard"
        )

    def test_red_non_incident_core_record_with_dedupe_field_does_not_bump(self) -> None:
        """A non-incident CORE record carrying the same field name also stays 1.0.0."""
        plain_a = _plain_pkg("Org-A", subject_name="Sys A")

        pkg_c = Package(producer={"name": "Org-C", "version": "1.0"})
        sub_c = pkg_c.add_subject("ai_system", name="Sys C")
        pkg_c.record(
            "risk_register",
            payload={
                "risk_id": "risk-c",
                "description": "A documented risk.",
                "category": "safety",
                "incident_dedupe_key": "sha256:" + "b" * 64,
            },
            entity_refs={"subject_refs": [sub_c.id]},
        )
        assert plain_a.versioning.core_version == "1.0.0"
        assert pkg_c.versioning.core_version == "1.0.0"

        result = merge_packages([plain_a, pkg_c])

        assert result.package.versioning.core_version == "1.0.0", (
            "a non-incident core record carrying a same-named incident_dedupe_key field "
            "MUST NOT drive an otherwise-v1.0 merge to 1.1.0"
        )

    def test_real_incident_card_still_drives_v1_1(self) -> None:
        """Regression: a REAL incident_card still floors the merge to 1.1.0.

        Restricting the version trigger to incident record types must NOT regress
        the legitimate v1.1 content path — an incident_card is a v1.1-only record
        type and always gates, exactly as Package.record() does.
        """
        plain = _plain_pkg("Org-A", subject_name="Sys A")
        incident, _ = _incident_card_pkg(
            "Org-B", public_incident_id=_PID_B, subject_identity=("OpenAI", "GPT-X", "4.0"), subject_name="Sys B"
        )
        result = merge_packages([plain, incident])
        assert result.package.versioning.core_version == "1.1.0"

    def test_incident_report_with_dedupe_key_still_drives_v1_1(self) -> None:
        """Regression: a dedupe_key on a REAL incident_report record still gates.

        ``incident_dedupe_key`` is a v1.1-only ``incident_report`` field
        (_v1_1_only_incident_report_fields includes _RESERVED_DEDUPE_FIELDS), so a
        record-typed incident_report carrying it floors the merge to 1.1.0 — the
        dedupe-key-on-an-incident-record case the dispatch requires.
        """
        plain = _plain_pkg("Org-A", subject_name="Sys A")

        pkg_ir = Package(producer={"name": "Org-IR", "version": "1.0"})
        sub_ir = pkg_ir.add_subject("ai_system", name="Sys IR")
        pkg_ir.record(
            "incident_report",
            payload={
                "report_id": "ir-1",
                "incident_dedupe_key": "sha256:" + "c" * 64,
            },
            entity_refs={"subject_refs": [sub_ir.id]},
        )
        # The incident_report+dedupe_key payload bumped its own package to v1.1.
        assert pkg_ir.versioning.core_version == "1.1.0"

        result = merge_packages([plain, pkg_ir])
        assert result.package.versioning.core_version == "1.1.0", (
            "a §5.5 incident_dedupe_key on a REAL incident_report record MUST still floor "
            "the merged core_version to 1.1.0"
        )


# ---------------------------------------------------------------------------
# LOW (roborev on 7151416a) — the merged core_version max must compare the
# FULL semver tuple INCLUDING patch. Pre-fix ``_core_version_sort_key``
# returned only ``(major, minor)`` (merge.py:156), so ``1.1.0`` and ``1.1.7``
# compared EQUAL and ``max()`` returned whichever input appeared first —
# order-dependent and capable of DOWNGRADING the merged manifest below an
# input core_version.
# ---------------------------------------------------------------------------


class TestMergedCoreVersionPatchAware:
    def test_red_patch_segment_wins_regardless_of_input_order(self) -> None:
        """Merging 1.1.0 and 1.1.7 yields 1.1.7 in BOTH input orders.

        Pre-fix ``_core_version_sort_key`` ignored the patch segment, so 1.1.0 and
        1.1.7 sorted EQUAL and ``max()`` returned the FIRST-appearing input — the
        result was order-dependent and dropped the higher patch (a downgrade below
        an input core_version). RED: this asserts 1.1.7 regardless of order; pre-fix
        the ``[1.1.0, 1.1.7]`` order returns 1.1.0.
        """
        low, _ = _incident_card_pkg(
            "Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"), subject_name="Sys A"
        )
        high, _ = _incident_card_pkg(
            "Org-B",
            public_incident_id=_PID_B,
            subject_identity=("Acme AI", "Vision-Pro", "2.1.0"),
            subject_name="Sys B",
        )
        low.versioning.core_version = "1.1.0"
        high.versioning.core_version = "1.1.7"

        forward = merge_packages([low, high])
        reverse = merge_packages([high, low])

        assert forward.package.versioning.core_version == "1.1.7", (
            "merged core_version MUST take the higher PATCH (1.1.7), not the first-appearing "
            "input — the version max must compare the full semver tuple including patch"
        )
        assert reverse.package.versioning.core_version == "1.1.7", (
            "merged core_version must be order-INDEPENDENT — reversing the inputs must not change the result from 1.1.7"
        )

    def test_higher_patch_input_is_never_downgraded(self) -> None:
        """The merged result is never below the highest input patch (no downgrade)."""
        a, _ = _incident_card_pkg(
            "Org-A", public_incident_id=_PID_A, subject_identity=("OpenAI", "GPT-X", "4.0"), subject_name="Sys A"
        )
        b, _ = _incident_card_pkg(
            "Org-B",
            public_incident_id=_PID_B,
            subject_identity=("Acme AI", "Vision-Pro", "2.1.0"),
            subject_name="Sys B",
        )
        a.versioning.core_version = "1.1.3"
        b.versioning.core_version = "1.1.12"

        # 12 > 3 numerically; a lexicographic or minor-only compare would mishandle this.
        result = merge_packages([a, b])
        assert result.package.versioning.core_version == "1.1.12"
