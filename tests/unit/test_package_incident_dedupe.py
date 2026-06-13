"""VAL-BUILD-DEDUPE-001 — RFC-0002 §5.5 ``incident_dedupe_key`` emission.

The cross-database dedupe spine is ACEF's own ``incident_dedupe_key`` (§5.5),
built like RFC-0001's ``finding_record.dedupe_key`` — an RFC 8785 (JCS)
canonicalization of a 4-key OBJECT, SHA-256, ``"sha256:"`` prefix::

    incident_dedupe_key = "sha256:" + hex(SHA-256(JCS({
        value_chain_role,     # the card enum
        subject_identity,     # NFC-normalized, case-folded "provider|name|version"
        harm_class,           # harm_core.harm_class
        occurrence_date_utc,  # occurrence (else detection) as a UTC YYYY-MM-DD date
    })))

These tests are a SPEC ORACLE: they recompute the expected key INDEPENDENTLY of
the builder (their own JCS+SHA-256 over the 4-key object) and assert byte
equality, so a builder that silently changed the preimage shape (a delimiter
string, a different key order, a non-folded identity) FAILS.

Confidentiality (§5.5, resolves Q20): the subject-bearing key is emitted ONLY on
a PUBLISHED/public card; on ANY non-public record it MUST be OMITTED (three of
four inputs are low-entropy / enumerable). The keyed
``incident_dedupe_key_hmac`` variant (HMAC-SHA-256 under a resolver pepper) is
the redacted-subject dedupe path; absent a pepper it degrades to link-only
(emit nothing).

Determinism: same inputs -> byte-identical key (JCS + SHA-256, no wall-clock /
random). The subject_identity NFC + case-fold makes the key cross-DB stable
regardless of the per-bundle subject UUID or unicode spelling.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import unicodedata

from acef.integrity import canonicalize
from acef.models.enums import Confidentiality
from acef.package import Package
from acef.redaction import RedactionPolicy

_DEDUPE_KEY_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_DEDUPE_HMAC_PATTERN = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")

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
_PID = "AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS"


def _new_pkg() -> Package:
    return Package(
        producer={"name": "test", "version": "1.0"},
        redaction_policy=RedactionPolicy(version="1.0.0"),
    )


# --- the independent §5.5 oracle (NOT the builder's code path) -------------


def _expected_subject_identity(provider: str, name: str, version: str) -> str:
    """NFC-normalize then case-fold the ``provider|name|version`` triple (§5.5)."""
    triple = f"{provider}|{name}|{version}"
    return unicodedata.normalize("NFC", triple).casefold()


def _expected_dedupe_key(
    *, value_chain_role: str, provider: str, name: str, version: str, harm_class: str, occurrence_date_utc: str
) -> str:
    """Recompute the §5.5 key INDEPENDENTLY (object -> JCS -> SHA-256)."""
    preimage = {
        "value_chain_role": value_chain_role,
        "subject_identity": _expected_subject_identity(provider, name, version),
        "harm_class": harm_class,
        "occurrence_date_utc": occurrence_date_utc,
    }
    digest = hashlib.sha256(canonicalize(preimage)).hexdigest()
    return "sha256:" + digest


def _expected_dedupe_hmac(
    *,
    pepper: bytes,
    value_chain_role: str,
    provider: str,
    name: str,
    version: str,
    harm_class: str,
    occurrence_date_utc: str,
) -> str:
    preimage = {
        "value_chain_role": value_chain_role,
        "subject_identity": _expected_subject_identity(provider, name, version),
        "harm_class": harm_class,
        "occurrence_date_utc": occurrence_date_utc,
    }
    mac = hmac.new(pepper, canonicalize(preimage), hashlib.sha256).hexdigest()
    return "hmac-sha256:" + mac


# ---------------------------------------------------------------------------
# Public card EMITS a correct §5.5 incident_dedupe_key.
# ---------------------------------------------------------------------------


class TestPublicCardEmitsDedupeKey:
    def test_public_card_emits_pattern_valid_dedupe_key(self) -> None:
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            occurrence_date="2026-07-15T09:30:00Z",
            confidentiality=Confidentiality.PUBLIC,
        )
        key = env.payload.get("incident_dedupe_key")
        assert key is not None, "a PUBLIC card MUST emit incident_dedupe_key (§5.5)"
        assert _DEDUPE_KEY_PATTERN.match(key), f"{key!r} is not sha256:<64-hex>"

    def test_emitted_key_equals_the_independent_5_5_recipe(self) -> None:
        # The SPEC ORACLE: the builder's key must byte-equal a key recomputed
        # independently from the 4-key OBJECT (JCS + SHA-256), proving the preimage
        # shape, key order, and subject_identity NFC+case-fold are exactly §5.5.
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="integrated_application",
            subject_identity=("Acme AI", "Vision-Pro", "2.1.0"),
            occurrence_date="2026-07-15T09:30:00Z",
            confidentiality=Confidentiality.PUBLIC,
        )
        expected = _expected_dedupe_key(
            value_chain_role="integrated_application",
            provider="Acme AI",
            name="Vision-Pro",
            version="2.1.0",
            harm_class="physical_health",
            occurrence_date_utc="2026-07-15",
        )
        assert env.payload["incident_dedupe_key"] == expected

    def test_occurrence_date_normalized_to_utc_calendar_date(self) -> None:
        # A late-UTC-offset occurrence instant rolls to the correct UTC calendar
        # date (YYYY-MM-DD), so the key keys on the UTC day, not the local day.
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            occurrence_date="2026-07-15T23:30:00-05:00",  # = 2026-07-16T04:30Z
            confidentiality=Confidentiality.PUBLIC,
        )
        expected = _expected_dedupe_key(
            value_chain_role="foundation_model",
            provider="OpenAI",
            name="GPT-X",
            version="4.0",
            harm_class="physical_health",
            occurrence_date_utc="2026-07-16",
        )
        assert env.payload["incident_dedupe_key"] == expected

    def test_detection_date_used_when_occurrence_absent(self) -> None:
        # occurrence_date (else detection_date) — when occurrence is omitted the
        # detection date drives occurrence_date_utc (§5.5).
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            detection_date="2026-07-20T00:00:00Z",
            confidentiality=Confidentiality.PUBLIC,
        )
        expected = _expected_dedupe_key(
            value_chain_role="foundation_model",
            provider="OpenAI",
            name="GPT-X",
            version="4.0",
            harm_class="physical_health",
            occurrence_date_utc="2026-07-20",
        )
        assert env.payload["incident_dedupe_key"] == expected

    def test_value_chain_role_also_stored_on_payload(self) -> None:
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="third_party_component",
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            occurrence_date="2026-07-15T00:00:00Z",
            confidentiality=Confidentiality.PUBLIC,
        )
        assert env.payload["value_chain_role"] == "third_party_component"

    def test_subject_identity_is_nfc_normalized_and_case_folded(self) -> None:
        # Two unicode spellings of the SAME provider (composed café vs decomposed
        # cafe + combining acute, different case) MUST yield the SAME key — the
        # cross-DB interop property the NFC + case-fold guarantees.
        composed = "Café AI"  # "Café AI"
        decomposed_upper = "CAFÉ AI"  # "CAFÉ AI" decomposed
        pkg_a = _new_pkg()
        env_a = pkg_a.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            subject_identity=(composed, "Model", "1.0"),
            occurrence_date="2026-07-15T00:00:00Z",
            confidentiality=Confidentiality.PUBLIC,
        )
        pkg_b = _new_pkg()
        env_b = pkg_b.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            subject_identity=(decomposed_upper, "Model", "1.0"),
            occurrence_date="2026-07-15T00:00:00Z",
            confidentiality=Confidentiality.PUBLIC,
        )
        assert env_a.payload["incident_dedupe_key"] == env_b.payload["incident_dedupe_key"]

    def test_dedupe_key_is_deterministic_across_two_builds(self) -> None:
        def _build() -> str:
            pkg = _new_pkg()
            env = pkg.incident_card(
                public_incident_id=_PID,
                harm_core=dict(_HARM_CORE),
                severity_vector=_SEV_VECTOR,
                awareness_date="2026-08-01T00:00:00Z",
                eu_ai_act_facts=dict(_EU_FACTS),
                value_chain_role="foundation_model",
                subject_identity=("OpenAI", "GPT-X", "4.0"),
                occurrence_date="2026-07-15T00:00:00Z",
                confidentiality=Confidentiality.PUBLIC,
            )
            return str(env.payload["incident_dedupe_key"])

        assert _build() == _build()

    def test_subject_identity_accepts_provider_name_version_dict(self) -> None:
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            subject_identity={"provider": "OpenAI", "name": "GPT-X", "version": "4.0"},
            occurrence_date="2026-07-15T00:00:00Z",
            confidentiality=Confidentiality.PUBLIC,
        )
        expected = _expected_dedupe_key(
            value_chain_role="foundation_model",
            provider="OpenAI",
            name="GPT-X",
            version="4.0",
            harm_class="physical_health",
            occurrence_date_utc="2026-07-15",
        )
        assert env.payload["incident_dedupe_key"] == expected


# ---------------------------------------------------------------------------
# Non-public records OMIT the subject-bearing key (§5.5 / Q20).
# ---------------------------------------------------------------------------


class TestNonPublicOmitsDedupeKey:
    def test_regulator_only_card_omits_dedupe_key(self) -> None:
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            occurrence_date="2026-07-15T00:00:00Z",
            confidentiality=Confidentiality.REGULATOR_ONLY,
        )
        assert "incident_dedupe_key" not in env.payload, (
            "the subject-bearing key MUST be OMITTED on a non-public record (§5.5 Q20)"
        )

    def test_report_incident_omits_dedupe_key(self) -> None:
        # report_incident is the confidential Art.73 path (regulator-only default);
        # it MUST NOT carry the subject-bearing plaintext dedupe key.
        pkg = _new_pkg()
        env = pkg.report_incident(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            incident_type="operational_failure",
            description="x",
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts={"serious_incident_triggers": ["3.49.a"], "widespread": False, "death_involved": True},
            value_chain_role="foundation_model",
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            occurrence_date="2026-07-15T00:00:00Z",
        )
        assert "incident_dedupe_key" not in env.payload
        assert "incident_dedupe_key" not in env.payload.get("card_source", {})


# ---------------------------------------------------------------------------
# HMAC variant (redacted-subject dedupe) — emitted only with a pepper.
# ---------------------------------------------------------------------------


class TestHmacVariant:
    def test_public_card_with_pepper_emits_hmac_variant(self) -> None:
        pepper = b"resolver-secret-pepper-32bytes!!"
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            occurrence_date="2026-07-15T00:00:00Z",
            confidentiality=Confidentiality.PUBLIC,
            pepper=pepper,
        )
        hmac_key = env.payload.get("incident_dedupe_key_hmac")
        assert hmac_key is not None, "a pepper MUST yield incident_dedupe_key_hmac (§5.5)"
        assert _DEDUPE_HMAC_PATTERN.match(hmac_key)
        expected = _expected_dedupe_hmac(
            pepper=pepper,
            value_chain_role="foundation_model",
            provider="OpenAI",
            name="GPT-X",
            version="4.0",
            harm_class="physical_health",
            occurrence_date_utc="2026-07-15",
        )
        assert hmac_key == expected

    def test_no_pepper_emits_no_hmac_variant(self) -> None:
        # Absent a pepper the keyed variant degrades to link-only — emit nothing.
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            occurrence_date="2026-07-15T00:00:00Z",
            confidentiality=Confidentiality.PUBLIC,
        )
        assert "incident_dedupe_key_hmac" not in env.payload

    def test_str_pepper_is_utf8_encoded(self) -> None:
        # A str pepper is accepted (UTF-8 encoded) and matches the bytes form.
        pkg_s = _new_pkg()
        env_s = pkg_s.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            occurrence_date="2026-07-15T00:00:00Z",
            confidentiality=Confidentiality.PUBLIC,
            pepper="my-secret",
        )
        expected = _expected_dedupe_hmac(
            pepper=b"my-secret",
            value_chain_role="foundation_model",
            provider="OpenAI",
            name="GPT-X",
            version="4.0",
            harm_class="physical_health",
            occurrence_date_utc="2026-07-15",
        )
        assert env_s.payload["incident_dedupe_key_hmac"] == expected


# ---------------------------------------------------------------------------
# Incomplete inputs -> no key (cannot compute the 4-key recipe).
# ---------------------------------------------------------------------------


class TestIncompleteInputsOmitKey:
    def test_no_value_chain_role_omits_key(self) -> None:
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            occurrence_date="2026-07-15T00:00:00Z",
            confidentiality=Confidentiality.PUBLIC,
        )
        assert "incident_dedupe_key" not in env.payload

    def test_no_subject_identity_omits_key(self) -> None:
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            occurrence_date="2026-07-15T00:00:00Z",
            confidentiality=Confidentiality.PUBLIC,
        )
        assert "incident_dedupe_key" not in env.payload

    def test_no_date_omits_key(self) -> None:
        pkg = _new_pkg()
        env = pkg.incident_card(
            public_incident_id=_PID,
            harm_core=dict(_HARM_CORE),
            severity_vector=_SEV_VECTOR,
            awareness_date="2026-08-01T00:00:00Z",
            eu_ai_act_facts=dict(_EU_FACTS),
            value_chain_role="foundation_model",
            subject_identity=("OpenAI", "GPT-X", "4.0"),
            confidentiality=Confidentiality.PUBLIC,
        )
        assert "incident_dedupe_key" not in env.payload
