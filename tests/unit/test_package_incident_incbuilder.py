"""Unit tests for the F-M8-INCIDENT-BUILDER package-builder fixes.

Covers the three incident-builder assertions of F-M8-INCIDENT-BUILDER:

- **VAL-FIX-INCBUILD-001 (commitment field-name grammar).** ``incident_card``'s
  ``commitments=`` loop emits ``payload[f"{field}_commitment"]`` directly from the
  caller-supplied keys. The incident_card schema sets ``additionalProperties:false``
  + the key pattern ``^[a-z0-9_]+_commitment$``, so a non-``[a-z0-9_]`` field name
  (``rootCause`` -> ``rootCause_commitment``, ``"Root Cause"`` -> ``"Root
  Cause_commitment"``) emitted a record that fails payload validation with ACEF-004 —
  breaking the VAL-DX-001 "one call -> valid signable bundle" contract. The fix
  validates each commitment field name against ``^[a-z0-9_]+$`` at builder time and
  raises a clear ``ValueError`` (mirroring ``mint_incident_id``'s input-validation
  style) naming the offending key + the required grammar — it does NOT silently
  normalize (that would change the committed field identity).

- **VAL-FIX-INCBUILD-002 (self-contained regulator-only one-call path).**
  ``report_incident`` defaults to ``confidentiality=REGULATOR_ONLY``; on a v1.1
  package ``record()`` requires X1 (``redaction_policy_version``) for any non-public
  record, so a first-time ``Package(...).report_incident(...)`` WITHOUT a
  pre-attached RedactionPolicy raised ValueError instead of producing a bundle. The
  fix makes the regulator-only one-call path self-contained: ``report_incident``
  surfaces a ``redaction_policy`` / ``redaction_policy_version`` kwarg AND attaches a
  sensible default RedactionPolicy when the package has none and the record is
  non-public, so the bare no-policy call now emits a valid signable bundle. The X1
  enforcement that other ``record()`` callers rely on is unchanged.

- **VAL-FIX-INCBUILD-003 (sub-second truncation is documented + pinned).**
  ``_format_iso_instant`` re-emits awareness_date / deadline via
  ``strftime('%Y-%m-%dT%H:%M:%SZ')``, dropping any sub-second component. This is
  conformance-neutral (the validator reparses the truncated value and recomputes the
  same deadline — no ACEF-084). The truncation is now documented on
  ``report_incident`` / ``incident_card`` and the invariant is pinned here so the
  intentional behavior is locked.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from acef.integrity import canonicalize, sha256_hex
from acef.models.records import RecordEnvelope
from acef.models.urns import URNType
from acef.package import Package
from acef.redaction import RedactionPolicy
from acef.schemas.registry import validate_against_schema
from acef.validation.engine import validate_bundle

_HARM_CORE = {
    "realization": "harm_event",
    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
    "harm_class": "physical_health",
}
_SEVERITY_VECTOR = "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I"
_PUBLIC_ID = "AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS"
_AWARENESS = "2026-08-01T00:00:00Z"
_FACTS = {"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": False}


def _pkg_with_policy() -> Package:
    return Package(
        producer={"name": "test", "version": "1.0"},
        redaction_policy=RedactionPolicy(version="1.0.0"),
    )


def _pkg_no_policy() -> Package:
    """A bare package with NO attached RedactionPolicy — the first-time-caller path."""
    return Package(producer={"name": "test", "version": "1.0"})


# ===========================================================================
# VAL-FIX-INCBUILD-001 — commitment field-name grammar (^[a-z0-9_]+$).
# ===========================================================================


class TestCommitmentFieldNameValidation:
    @pytest.mark.parametrize(
        "bad_field",
        [
            "rootCause",  # uppercase letters
            "Root Cause",  # space + uppercase
            "root-cause",  # hyphen
            "root.cause",  # dot
            "",  # empty
            "rootCause_commitment",  # already-suffixed (double-suffix trap)
            "description\n",  # trailing-newline bypass: $ matched before \n (roborev ae5f0e2)
            "root_cause\n",  # trailing newline after an otherwise-grammar-valid name
        ],
    )
    def test_non_grammar_commitment_field_name_raises_valueerror(self, bad_field: str) -> None:
        """A commitment field name outside ``^[a-z0-9_]+(?![\\s\\S])`` is rejected at the
        call site with a clear ValueError naming the offending key + the grammar, instead
        of producing an opaque ACEF-004 at export/validation. A trailing newline is
        rejected: the preflight uses ``fullmatch`` so ``"description\\n"`` cannot emit a
        schema-invalid ``"description\\n_commitment"`` key (the ``$``-before-``\\n``
        bypass)."""
        pkg = _pkg_with_policy()
        with pytest.raises(ValueError) as exc:
            pkg.incident_card(
                public_incident_id=_PUBLIC_ID,
                harm_core=dict(_HARM_CORE),
                severity_vector=_SEVERITY_VECTOR,
                awareness_date=_AWARENESS,
                eu_ai_act_facts=dict(_FACTS),
                commitments={bad_field: "the secret value"},
            )
        msg = str(exc.value)
        # The offending key is named...
        assert repr(bad_field) in msg or bad_field in msg
        # ...and the required grammar is surfaced as a fix hint.
        assert "[a-z0-9_]+" in msg

    def test_valid_commitment_field_name_emits_commitment_and_validates_clean(self) -> None:
        """A valid ``[a-z0-9_]+`` field name still works end-to-end: the
        ``<name>_commitment`` key is emitted with the JCS+SHA-256 whole-value
        commitment, and the resulting incident_card payload validates clean (no
        ACEF-004 on the commitment key)."""
        pkg = _pkg_with_policy()
        env = pkg.incident_card(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEVERITY_VECTOR,
            awareness_date=_AWARENESS,
            eu_ai_act_facts=dict(_FACTS),
            commitments={"root_cause": "the secret value"},
        )
        # The commitment key is emitted with the documented sha256:<hex> shape.
        assert "root_cause_commitment" in env.payload
        expected = "sha256:" + sha256_hex(canonicalize("the secret value"))
        assert env.payload["root_cause_commitment"] == expected
        # And the payload validates clean against the incident_card schema — no
        # ACEF-004 caused by a malformed commitment key.
        errors = validate_against_schema(env.payload, "incident_card", "v1.1")
        commitment_errors = [e for e in errors if "_commitment" in str(e.message)]
        assert commitment_errors == [], f"commitment key rejected by schema: {commitment_errors}"

    def test_multiple_valid_commitments_all_emitted(self) -> None:
        """Several valid field names each yield their own ``<name>_commitment``."""
        pkg = _pkg_with_policy()
        env = pkg.incident_card(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEVERITY_VECTOR,
            awareness_date=_AWARENESS,
            eu_ai_act_facts=dict(_FACTS),
            commitments={"root_cause": "a", "internal_ref2": {"k": "v"}},
        )
        assert env.payload["root_cause_commitment"] == "sha256:" + sha256_hex(canonicalize("a"))
        assert env.payload["internal_ref2_commitment"] == "sha256:" + sha256_hex(canonicalize({"k": "v"}))


# ===========================================================================
# VAL-FIX-INCBUILD-002 — regulator-only one-call path is self-contained.
# ===========================================================================


class TestRegulatorOnlyOneCallIsSelfContained:
    def test_bare_no_policy_report_incident_emits_a_record(self) -> None:
        """A first-time ``Package(...).report_incident(...)`` with the default
        regulator-only confidentiality and NO pre-attached RedactionPolicy now
        produces a record (the documented X1/X2 fields auto-populate from a
        builder-supplied default policy) instead of raising ValueError."""
        pkg = _pkg_no_policy()
        env = pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="Confidential Art.73 serious-incident report.",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
        )
        assert env.record_type == "incident_report"
        # X1 was auto-populated from the self-supplied default policy.
        assert isinstance(env.redaction_policy_version, str) and env.redaction_policy_version
        # X2 (the event_log attestation) was minted too.
        assert isinstance(env.redaction_attestation_ref, str) and env.redaction_attestation_ref
        # The card_source is retained on the regulator-only (access-class) record.
        assert env.payload["card_source"]["public_incident_id"] == _PUBLIC_ID

    def test_bare_no_policy_report_incident_validates_clean_end_to_end(self, tmp_path: Path) -> None:
        """The bare no-policy regulator-only one-call path produces a bundle that
        validates clean (no ACEF-074 for a missing redaction policy version)."""
        key_path, _ = _write_ec_key(tmp_path)
        pkg = _pkg_no_policy_deterministic()
        pkg.add_subject("ai_system", name="Sys", risk_classification="high-risk", modalities=["text"])
        pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="Confidential Art.73 serious-incident report.",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
        )
        pkg.sign(key_path)
        bundle_dir = tmp_path / "report.acef"
        pkg.export(str(bundle_dir))

        assessment = validate_bundle(bundle_dir, profiles=["eu-ai-act-art73-2026"])
        codes = [e.get("code") for e in assessment.structural_errors]
        # No ACEF-074 (missing redaction policy version) and no Art.73 clock error.
        assert "ACEF-074" not in codes
        assert "ACEF-084" not in codes

    def test_explicit_redaction_policy_version_kwarg_is_honored(self) -> None:
        """The caller can supply ``redaction_policy_version`` explicitly on the
        regulator-only path; the supplied value is written to X1 verbatim while X2 is
        still auto-minted. On the bare no-policy path the builder DERIVES the
        self-supplied default policy's version from the explicit value, so X2's
        ``policy_version`` equals X1 (roborev Medium 1 consistency)."""
        pkg = _pkg_no_policy()
        env = pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="x",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
            redaction_policy_version="9.9.9",
        )
        assert env.redaction_policy_version == "9.9.9"
        # X2 was minted even though the caller only supplied X1 explicitly,
        # and it carries the SAME version as X1.
        assert isinstance(env.redaction_attestation_ref, str) and env.redaction_attestation_ref
        assert _attestation_policy_version(pkg, env) == "9.9.9"

    def test_explicit_redaction_policy_kwarg_is_honored(self) -> None:
        """A caller-supplied ``redaction_policy`` is used for X1/X2 auto-population
        on the regulator-only path (the package had none attached)."""
        pkg = _pkg_no_policy()
        env = pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="x",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
            redaction_policy=RedactionPolicy(version="2.3.4"),
        )
        assert env.redaction_policy_version == "2.3.4"

    def test_attached_package_policy_still_wins_when_no_kwarg(self) -> None:
        """When the package already has an attached RedactionPolicy and the caller
        supplies no override, that policy's version is used (the pre-existing
        contract is preserved — the builder default does NOT clobber it)."""
        pkg = _pkg_with_policy()  # version 1.0.0
        env = pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="x",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
        )
        assert env.redaction_policy_version == "1.0.0"

    def test_public_report_incident_needs_no_policy(self) -> None:
        """An explicitly PUBLIC report_incident is not a non-public record, so it
        needs no redaction policy at all (the self-supply only triggers for the
        non-public default)."""
        from acef.models.enums import Confidentiality

        pkg = _pkg_no_policy()
        env = pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="x",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
            confidentiality=Confidentiality.PUBLIC,
        )
        assert env.record_type == "incident_report"


def _attestation_policy_version(pkg: Package, env: RecordEnvelope) -> str:
    """Return the ``policy_version`` recorded on the minted X2 event_log
    attestation whose ``record_id`` is X2 on ``env``."""
    ref = env.redaction_attestation_ref
    assert isinstance(ref, str) and ref, "expected an X2 attestation ref on the record"
    attestations = [r for r in pkg.records if r.record_id == ref]
    assert len(attestations) == 1, f"expected exactly one X2 attestation for {ref}, got {len(attestations)}"
    policy_version = attestations[0].payload["policy_version"]
    assert isinstance(policy_version, str)
    return policy_version


# ===========================================================================
# roborev Medium 1 — X1 (record) and X2 (attestation) policy versions MUST agree
# when an explicit ``redaction_policy_version`` is supplied.
# ===========================================================================


class TestExplicitVersionX1X2Consistency:
    def test_explicit_version_with_no_policy_derives_consistent_attestation(self) -> None:
        """On the bare no-policy path an explicit ``redaction_policy_version`` is
        threaded into BOTH X1 (record) and X2 (the auto-minted attestation): the
        default policy the builder self-supplies is derived FROM the explicit
        version, so the record-claimed version and the attestation policy version
        agree. (Before the fix X1=='9.9.9' while the attestation defaulted to
        '1.0.0' — a silent divergence.)"""
        pkg = _pkg_no_policy()
        env = pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="x",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
            redaction_policy_version="9.9.9",
        )
        assert env.redaction_policy_version == "9.9.9"
        # X2 (attestation) policy version MUST equal X1 (record) — no divergence.
        assert _attestation_policy_version(pkg, env) == "9.9.9"

    def test_explicit_version_matching_attached_policy_is_consistent(self) -> None:
        """When the explicit ``redaction_policy_version`` equals the attached
        policy's version both X1 and X2 carry that version (no rejection — they
        agree)."""
        pkg = _pkg_with_policy()  # version 1.0.0
        env = pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="x",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
            redaction_policy_version="1.0.0",
        )
        assert env.redaction_policy_version == "1.0.0"
        assert _attestation_policy_version(pkg, env) == "1.0.0"

    def test_explicit_version_diverging_from_attached_policy_is_rejected(self) -> None:
        """When the package already has an effective policy (attached version
        1.0.0) and the caller supplies a DIFFERENT explicit
        ``redaction_policy_version``, the builder fails closed with a clear
        ValueError naming BOTH versions — rather than silently shipping a bundle
        whose record X1 and attestation X2 disagree."""
        pkg = _pkg_with_policy()  # version 1.0.0
        with pytest.raises(ValueError) as exc:
            pkg.report_incident(
                public_incident_id=_PUBLIC_ID,
                harm_core=dict(_HARM_CORE),
                incident_type="operational_failure",
                description="x",
                awareness_date=_AWARENESS,
                eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
                redaction_policy_version="9.9.9",
            )
        msg = str(exc.value)
        assert "9.9.9" in msg
        assert "1.0.0" in msg

    def test_explicit_version_diverging_from_explicit_policy_is_rejected(self) -> None:
        """Same fail-closed guard when BOTH an explicit ``redaction_policy`` and a
        diverging explicit ``redaction_policy_version`` are supplied in one call."""
        pkg = _pkg_no_policy()
        with pytest.raises(ValueError) as exc:
            pkg.report_incident(
                public_incident_id=_PUBLIC_ID,
                harm_core=dict(_HARM_CORE),
                incident_type="operational_failure",
                description="x",
                awareness_date=_AWARENESS,
                eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
                redaction_policy=RedactionPolicy(version="2.3.4"),
                redaction_policy_version="9.9.9",
            )
        msg = str(exc.value)
        assert "9.9.9" in msg
        assert "2.3.4" in msg


# ===========================================================================
# roborev Medium 2 — a per-call ``redaction_policy`` override is CALL-LOCAL and
# MUST NOT leak into package state for later record()/report_incident() calls.
# ===========================================================================


class TestPerCallRedactionPolicyIsCallLocal:
    def test_per_call_policy_does_not_leak_into_later_records(self) -> None:
        """On a package WITH an attached policy P (1.0.0), a per-call
        ``redaction_policy=Q`` (5.6.7) applies to THAT call only; a later
        report_incident WITHOUT an override uses P again, not Q. Before the fix Q
        permanently overwrote ``self._redaction_policy`` and leaked into the
        second record."""
        pkg = _pkg_with_policy()  # attached P, version 1.0.0
        env1 = pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="first (override Q)",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
            redaction_policy=RedactionPolicy(version="5.6.7"),
        )
        # The override DID apply to the first call.
        assert env1.redaction_policy_version == "5.6.7"
        assert _attestation_policy_version(pkg, env1) == "5.6.7"

        # A second record WITHOUT an override must see the ORIGINAL attached P.
        env2 = pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="second (no override -> P)",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
        )
        assert env2.redaction_policy_version == "1.0.0", "Q leaked into the second record (package state mutated)"
        assert _attestation_policy_version(pkg, env2) == "1.0.0"

    def test_attached_policy_object_is_unchanged_after_per_call_override(self) -> None:
        """The package's attached RedactionPolicy object identity/version is the
        same before and after a per-call override (no in-place mutation)."""
        pkg = _pkg_with_policy()
        before = pkg._redaction_policy
        pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="x",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
            redaction_policy=RedactionPolicy(version="5.6.7"),
        )
        after = pkg._redaction_policy
        assert after is before
        assert after is not None and after.version == "1.0.0"

    def test_per_call_policy_restored_even_on_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """If ``record()`` raises mid-call — AFTER the call-local policy swap has
        already happened — the per-call override is still restored: the package
        keeps its ORIGINAL attached policy (the ``try/finally`` in
        ``report_incident``).

        This exercises the ``finally`` restore directly, NOT the pre-swap mismatch
        guard (which would raise before the swap and prove nothing about
        restoration). We monkeypatch ``Package.record`` with a wrapper that (a)
        asserts the per-call override Q is installed at ``self._redaction_policy``
        at the moment ``record()`` runs — proving the swap occurred — then (b)
        raises. After ``report_incident`` propagates that error we assert the
        package's policy is back to the ORIGINAL attached P. If the ``finally``
        restore were deleted, ``self._redaction_policy`` would still be Q here and
        this test would FAIL — so it is non-vacuous."""
        pkg = _pkg_with_policy()  # attached P, 1.0.0
        original = pkg._redaction_policy
        assert original is not None and original.version == "1.0.0"
        per_call = RedactionPolicy(version="5.6.7")  # the override Q
        boom = RuntimeError("record() exploded after the call-local policy swap")

        observed_at_record_time: list[Any] = []

        def _exploding_record(self: Package, *args: Any, **kwargs: Any) -> RecordEnvelope:
            # The swap MUST already have installed the per-call override by the time
            # report_incident delegates to record(). Capturing it proves the swap
            # happened before the failure (i.e. we are past the pre-swap guard).
            observed_at_record_time.append(self._redaction_policy)
            raise boom

        monkeypatch.setattr(Package, "record", _exploding_record)

        with pytest.raises(RuntimeError) as exc:
            pkg.report_incident(
                public_incident_id=_PUBLIC_ID,
                harm_core=dict(_HARM_CORE),
                incident_type="operational_failure",
                description="x",
                awareness_date=_AWARENESS,
                eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
                redaction_policy=per_call,  # Q — no diverging explicit version, so the pre-swap guard does NOT fire
            )
        assert exc.value is boom

        # The swap DID install Q before record() ran (we failed AFTER the swap).
        assert observed_at_record_time == [per_call]
        # ...and the finally restored the ORIGINAL attached P (identity + version).
        assert pkg._redaction_policy is original
        assert pkg._redaction_policy is not None and pkg._redaction_policy.version == "1.0.0"

    def test_per_call_policy_on_bare_package_does_not_persist(self) -> None:
        """On a package with NO attached policy, a per-call ``redaction_policy``
        applies only to that call and does NOT persist: a later non-public record
        with no override (and no auto-default available) goes back to the
        no-policy state. We assert the package's policy is None after the override
        call returns."""
        pkg = _pkg_no_policy()
        pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="x",
            awareness_date=_AWARENESS,
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
            redaction_policy=RedactionPolicy(version="2.3.4"),
        )
        # The per-call override did not stick on the bare package.
        assert pkg._redaction_policy is None


# ===========================================================================
# VAL-FIX-INCBUILD-003 — sub-second truncation is intentional + pinned.
# ===========================================================================


class TestAwarenessSubSecondTruncation:
    def test_awareness_date_is_stored_at_second_precision(self) -> None:
        """A caller-supplied awareness_date with sub-second precision is stored on
        the Art.73 timeline entry at SECOND precision (no millis), and the deadline
        is consistent with the same truncated instant — the documented, intentional
        invariant (no ACEF-084 because the validator reparses the same value)."""
        pkg = _pkg_with_policy()
        env = pkg.report_incident(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="x",
            # Sub-second precision + a non-UTC offset.
            awareness_date="2026-08-01T12:30:45.999+02:00",
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
        )
        timeline = env.payload["card_source"]["coordinated_disclosure"]["regulatory_timeline"]
        art73 = next(e for e in timeline if e["framework"] == "eu-ai-act-art73")
        # Truncated to second precision in UTC (12:30:45.999+02:00 -> 10:30:45Z).
        assert art73["awareness_date"] == "2026-08-01T10:30:45Z"
        # death_involved=true => 10-day clock; deadline truncated consistently.
        assert art73["deadline"] == "2026-08-11T10:30:45Z"
        assert "." not in art73["awareness_date"]
        assert "." not in art73["deadline"]

    def test_incident_card_awareness_date_is_stored_at_second_precision(self) -> None:
        """Same truncation invariant on the public incident_card path."""
        pkg = _pkg_with_policy()
        env = pkg.incident_card(
            public_incident_id=_PUBLIC_ID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEVERITY_VECTOR,
            awareness_date="2026-08-01T12:30:45.123456Z",
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": False},
        )
        timeline = env.payload["coordinated_disclosure"]["regulatory_timeline"]
        art73 = next(e for e in timeline if e["framework"] == "eu-ai-act-art73")
        assert art73["awareness_date"] == "2026-08-01T12:30:45Z"
        assert "." not in art73["awareness_date"]
        assert "." not in art73["deadline"]


# ---------------------------------------------------------------------------
# Deterministic-bundle helpers (for the end-to-end validation test).
# ---------------------------------------------------------------------------


def _deterministic_urn_generator() -> Any:
    counter = {"n": 0}

    def _gen(urn_type: URNType) -> str:
        counter["n"] += 1
        return f"urn:acef:{urn_type.value}:00000000-0000-0000-0000-{counter['n']:012x}"

    return _gen


def _fixed_clock() -> Any:
    from datetime import UTC, datetime

    return datetime(2026, 8, 10, 0, 0, 0, tzinfo=UTC)


def _pkg_no_policy_deterministic() -> Package:
    return Package(
        producer={"name": "acef-incbuilder-e2e", "version": "1.1.0"},
        clock=_fixed_clock,
        urn_generator=_deterministic_urn_generator(),
    )


def _write_ec_key(tmp_path: Path) -> tuple[str, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "signing-key.pem"
    key_path.write_bytes(pem)
    return str(key_path), key


class TestIncidentBuilderAtomicity:
    """F37: a failed report_incident() / incident_card() must leave the package
    UNMUTATED. Previously _ensure_v1_1() (bump core_version → 1.1.0) and
    _declare_art73_profile() ran BEFORE the awareness_date parse, so an
    unparseable date raised AFTER the package was half-mutated — contradicting
    the documented "a failed call leaves the package unmutated" contract."""

    def test_report_incident_bad_awareness_date_leaves_package_unmutated(self) -> None:
        from acef.package import _ART73_PROFILE_ID

        pkg = _pkg_no_policy()
        assert pkg._versioning.core_version == "1.0.0"
        assert not any(p.profile_id == _ART73_PROFILE_ID for p in pkg._profiles)
        with pytest.raises(ValueError):
            pkg.report_incident(
                public_incident_id=_PUBLIC_ID,
                harm_core=dict(_HARM_CORE),
                incident_type="operational_failure",
                description="unparseable awareness_date",
                awareness_date="not-an-iso-date",
                eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
            )
        assert pkg._versioning.core_version == "1.0.0", "core_version mutated despite a failed report_incident"
        assert not any(p.profile_id == _ART73_PROFILE_ID for p in pkg._profiles), "Art.73 profile declared on failure"

    def test_incident_card_bad_awareness_date_leaves_package_unmutated(self) -> None:
        from acef.package import _ART73_PROFILE_ID

        pkg = _pkg_no_policy()
        assert pkg._versioning.core_version == "1.0.0"
        assert not any(p.profile_id == _ART73_PROFILE_ID for p in pkg._profiles)
        with pytest.raises(ValueError):
            pkg.incident_card(
                public_incident_id=_PUBLIC_ID,
                harm_core=dict(_HARM_CORE),
                severity_vector="ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",
                awareness_date="not-an-iso-date",
                eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": False},
            )
        assert pkg._versioning.core_version == "1.0.0", "core_version mutated despite a failed incident_card"
        assert not any(p.profile_id == _ART73_PROFILE_ID for p in pkg._profiles), "Art.73 profile declared on failure"
