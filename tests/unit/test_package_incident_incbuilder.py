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
        ],
    )
    def test_non_grammar_commitment_field_name_raises_valueerror(self, bad_field: str) -> None:
        """A commitment field name outside ``^[a-z0-9_]+$`` is rejected at the call
        site with a clear ValueError naming the offending key + the grammar, instead
        of producing an opaque ACEF-004 at export/validation."""
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
        key_path, key = _write_ec_key(tmp_path)
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
        still auto-minted (the builder self-supplies a policy for the attestation)."""
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
        # X2 was minted even though the caller only supplied X1 explicitly.
        assert isinstance(env.redaction_attestation_ref, str) and env.redaction_attestation_ref

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
