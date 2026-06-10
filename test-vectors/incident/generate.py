#!/usr/bin/env python3
"""Deterministic regenerator for the RFC-0002 §6 incident conformance vectors.

This script materializes the v1.1-REQUIRED incident conformance vectors under
``test-vectors/incident/`` — the **offline-deterministic** (card-only) and
**source-backed** classes of RFC-0002 §6, plus the single forged-assigner
``online-conformance`` reject vector (VAL-VEC-002). The ``online-registry`` and
``public-registry-admission`` classes are v1.2 (§11) and are NOT generated.

Every artifact is BYTE-STABLE across runs: all timestamps, ids, and suffixes are
fixed literals; no ``datetime.now`` / ``random`` is read; all JSON is written
with ``sort_keys=True`` and compact separators. Re-running this script over a
clean tree reproduces byte-identical bundles (proven by the conformance driver's
``test_vector_validation_is_byte_stable`` + a CI ``git diff`` check).

Usage (from repo root, venv active)::

    python test-vectors/incident/generate.py

It rewrites the vector directories + ``vectors.json`` + the per-vector
``.acef-assessment.json`` expected outputs, then the driver
``tests/conformance/test_incident_vectors.py`` validates them.

Mechanics: each bundle is built entirely through the SDK ``Package`` builder under
an INJECTED fixed clock + deterministic URN generator, with ``core_version: 1.1.0``
set on the package versioning so Phase-1 schema validation routes to the v1.1
incident schema set. The incident record is added via ``pkg.record(...)`` (yielding a
fully-valid record envelope) and the whole bundle is exported in one shot — manifest,
records JSONL, content-hashes.json, and merkle-tree.json are all production-valid and
mutually consistent, so a PASS vector validates CLEAN. The vectors carry NO
``manifest.profiles[]`` block; the §6 conformance class is supplied to the driver via
``vectors.json`` ``profiles`` (passed to ``validate_bundle(profiles=...)``), keeping
the bundle minimal and free of template-DSL evaluation noise.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from acef.models.metadata import Versioning
from acef.models.urns import URNType
from acef.package import Package
from acef.redaction import RedactionPolicy
from acef.validation.engine import validate_bundle

# ---------------------------------------------------------------------------
# Fixed determinism anchors (no wall-clock / random anywhere).
# ---------------------------------------------------------------------------

_INCIDENT_DIR = Path(__file__).resolve().parent

# A >=26-char Crockford-base32 suffix (>=128 bits — the §5.3 pattern minimum).
_SUFFIX = "0123456789ABCDEFGHJKMNPQRS"
_VALID_ID = f"AIIC-OPENAI-2026-{_SUFFIX}"
_FORGED_ASSIGNER = "OPENAI"

_FIXED_CLOCK = datetime(2026, 8, 1, 0, 0, 0, tzinfo=UTC)
_RECORD_TS = "2026-08-10T00:00:00Z"
_AWARENESS = "2026-08-01T00:00:00Z"

# Confidentiality of a source-backed / confidential incident_report carrying the
# private card_source block (Finding 2). RFC-0002 §5.1: incident_report defaults to
# regulator-only, "never the public artifact".
_CONFIDENTIAL = "regulator-only"
# Fixed semver for the X1 redaction_policy_version on non-public records.
_REDACTION_POLICY_VERSION = "1.0.0"

_VALID_HARM_CORE: dict[str, Any] = {
    "realization": "harm_event",
    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
    "harm_class": "physical_health",
}

# A grammar-valid ACEF-SEV:1.0 vector whose band() projection is "major"
# (HG:H, BR not P, RV not I → major). Used to author a severity↔band match (pass)
# and a deliberate disagreement (ACEF-088 fail).
_SEV_VECTOR_MAJOR = "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I"

_ART73_PROFILE = "eu-ai-act-art73-2026"
_OECD_PROFILE = "oecd-ai-incidents-2025"
_OECD_MANDATORY = [1, 2, 3, 4, 7, 10, 11]


def _deterministic_urn_generator() -> Any:
    """A counter-based URN generator so the SDK export is byte-stable."""
    counters: dict[URNType, int] = {}

    def _gen(urn_type: URNType) -> str:
        n = counters.get(urn_type, 0)
        counters[urn_type] = n + 1
        # A zero-padded deterministic UUID-shaped tail keyed on the type+counter.
        tail = f"{n:032x}"
        uuid_form = f"{tail[0:8]}-{tail[8:12]}-{tail[12:16]}-{tail[16:20]}-{tail[20:32]}"
        return f"urn:acef:{urn_type.value}:{uuid_form}"

    return _gen


# ---------------------------------------------------------------------------
# Bundle writer.
# ---------------------------------------------------------------------------


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")


def _build_bundle(
    bundle_dir: Path,
    *,
    record_type: str,
    payload: dict[str, Any],
    confidentiality: str = "public",
) -> None:
    """Materialize a v1.1 incident bundle directory carrying ONE incident record.

    The ENTIRE bundle (manifest, records JSONL, content-hashes.json, merkle-tree.json)
    is built through the SDK ``Package`` builder under an INJECTED fixed clock + a
    deterministic URN generator, then exported with ``core_version: 1.1.0`` set on the
    package versioning. Building the incident record through ``pkg.record(...)`` (rather
    than hand-stamping a partial dict) yields a fully-valid record envelope — the
    schema-required ``urn:acef:rec:<uuid>`` id, ``entity_refs``, ``obligation_role``,
    ``trust_level``, ``lifecycle_phase``, ``collector``, ``provisions_addressed`` — and a
    consistent content-hashes + Merkle root, so a PASS vector validates CLEAN (no
    spurious ACEF-002/004/011). Byte-stable: the export is deterministic under the
    injected clock/URN generator (VAL-SDK-007), and all post-export JSON is written
    sorted/compact.

    No ``manifest.profiles[]`` block is declared; the §6 conformance class is supplied
    to the driver via ``vectors.json`` (passed to ``validate_bundle(profiles=...)``),
    keeping the bundle minimal and free of template-DSL evaluation noise.

    Confidentiality (Finding 2): a source-backed / confidential ``incident_report``
    carries the private ``card_source`` block (and ``root_cause_analysis``) and therefore
    MUST be emitted NON-public (``regulator-only``) — never ``public`` — so the private
    block is not published (RFC-0002 §5.1/§5.11: ``incident_report`` defaults to
    ``confidentiality: regulator-only``, "never the public artifact"). When
    ``confidentiality`` is non-public, a ``RedactionPolicy`` is attached so the SDK
    auto-populates the v1.1 X1 (``redaction_policy_version``) + X2
    (``redaction_attestation_ref``) envelope fields and mints the in-bundle Core
    ``event_log`` attestation record, so the non-public record validates cleanly (no
    ACEF-074/078). Both X1/X2 and the attestation record are minted under the SAME
    injected fixed clock + deterministic URN generator, so the bundle stays byte-stable.
    The public ``incident_card`` vectors keep ``confidentiality: public``.
    """
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.parent.mkdir(parents=True, exist_ok=True)

    is_non_public = confidentiality != "public"
    redaction_policy = (
        RedactionPolicy(
            version=_REDACTION_POLICY_VERSION,
            method="sha256-hash-commitment",
            description="Confidential Art.73 source-backed redaction policy (regulator-only card_source).",
        )
        if is_non_public
        else None
    )

    pkg = Package(
        producer={"name": "acef-incident-vectors", "version": "1.1.0"},
        clock=lambda: _FIXED_CLOCK,
        urn_generator=_deterministic_urn_generator(),
        redaction_policy=redaction_policy,
    )
    # v1.1 gating: route Phase-1 schema validation to the v1.1 incident schema set.
    pkg._versioning = Versioning(core_version="1.1.0", profiles_version="1.0.0")
    pkg.add_subject(
        "ai_system",
        name="Vector Subject",
        version="1.0.0",
        provider="ACEF Conformance",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )
    pkg.record(
        record_type,
        payload=payload,
        confidentiality=confidentiality,
        timestamp=_RECORD_TS,
    )
    # The SDK constructor seeds an audit_trail entry with no actor_ref, which fails
    # the manifest schema's actor_ref URN pattern. An empty audit_trail is schema-valid
    # (the v1.0 golden + freddy bundles ship with `"audit_trail": []`), so clear it for
    # a clean PASS-vector validation. This does not affect the incident records or hashes.
    pkg._audit_trail = []
    pkg.export(str(bundle_dir))


def _write_readme(bundle_dir: Path, *, title: str, body: str, expected: str) -> None:
    text = f"# {title}\n\n{body.rstrip()}\n\n**Expected code(s):** {expected}\n"
    (bundle_dir / "README.md").write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Payload builders.
# ---------------------------------------------------------------------------


def _card_source_report_payload(
    *,
    triggers: list[str],
    widespread: bool,
    death: bool,
    deadline: str,
    id_state: str = "RESERVED",
    severity_vector: str | None = None,
    publishability_map: dict[str, str] | None = None,
    disclosure_status: str = "coordinated",
) -> dict[str, Any]:
    """A source-backed incident_report carrying a confidential card_source block."""
    card_source: dict[str, Any] = {
        "public_incident_id": _VALID_ID,
        "id_grade": "self-asserted",
        "id_state": id_state,
        "harm_core": dict(_VALID_HARM_CORE),
        "publishability_map": publishability_map
        if publishability_map is not None
        else {"/root_cause_analysis": "regulator-only"},
        "eu_ai_act_facts": {
            "edition": "reg-2024-1689",
            "serious_incident_triggers": triggers,
            "widespread": widespread,
            "death_involved": death,
        },
        "coordinated_disclosure": {
            "status": disclosure_status,
            "regulatory_timeline": [
                {
                    "framework": "eu-ai-act-art73",
                    "clock_model": "awareness_days",
                    "awareness_date": _AWARENESS,
                    "deadline": deadline,
                }
            ],
        },
    }
    if severity_vector is not None:
        card_source["severity_vector"] = severity_vector
    return {
        "incident_type": "operational_failure",
        "severity": "major",
        "description": "Confidential Art.73 serious-incident report.",
        "root_cause_analysis": "Privileged analysis withheld from the public projection.",
        "card_source": card_source,
    }


# ---------------------------------------------------------------------------
# Vector specifications.
# ---------------------------------------------------------------------------


def _vector_specs() -> list[dict[str, Any]]:
    """Return the declarative spec for every vector (single source of truth)."""
    specs: list[dict[str, Any]] = []

    # === PASS — offline-deterministic (card-only) ===

    # P1: a multi-profile card (union requiredness) — declares BOTH the EU eu_ai_act
    # and OECD members so neither binding ACEF-081 fires; severity matches band().
    specs.append(
        {
            "name": "pass-multi-profile-card",
            "conformance_class": "offline-deterministic",
            "disposition": "pass",
            "profiles": [_ART73_PROFILE, _OECD_PROFILE],
            "record_type": "incident_card",
            "title": "Multi-profile public Art.73 + OECD card (union requiredness)",
            "body": (
                "A complete PUBLIC incident_card declaring BOTH the EU Art.73 (`eu_ai_act`) "
                "and OECD (`oecd`) crosswalk members, validated under both profiles. The "
                "union-requiredness rule is satisfied (each profile's mandatory member "
                "present), so no binding ACEF-081 fires. The `eu_ai_act` member carries the "
                "FULL Art.73 fact set (a trigger + boolean widespread + boolean "
                "death_involved) and a matching `coordinated_disclosure.regulatory_timeline` "
                "eu-ai-act-art73 entry whose deadline equals the 15-day general clock, so the "
                "public-card Art.73 path passes with no ACEF-084. severity matches band()."
            ),
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "severity": "major",
                "severity_vector": _SEV_VECTOR_MAJOR,
                "harm_core": dict(_VALID_HARM_CORE),
                "taxonomy_crosswalk": {
                    "eu_ai_act": {
                        "edition": "reg-2024-1689",
                        "serious_incident_triggers": ["3.49.a"],
                        "widespread": False,
                        "death_involved": False,
                    },
                    "oecd": {
                        "edition": "oecd-crf-2025",
                        "criteria": [{"id": f"oecd-crf-2025/{n}", "value": f"v-{n}"} for n in _OECD_MANDATORY],
                    },
                },
                "coordinated_disclosure": {
                    "status": "coordinated",
                    "regulatory_timeline": [
                        {
                            "framework": "eu-ai-act-art73",
                            "clock_model": "awareness_days",
                            "awareness_date": _AWARENESS,
                            "deadline": "2026-08-16T00:00:00Z",
                        }
                    ],
                },
            },
            "forbid_codes": ["ACEF-082", "ACEF-083", "ACEF-084", "ACEF-085", "ACEF-088"],
        }
    )

    # P2: OECD voluntary advisory — a card with NO oecd member, validated under the
    # voluntary OECD profile. Any ACEF-081 is ADVISORY (warning), never a blocking
    # error. Pass = no ERROR/FATAL.
    specs.append(
        {
            "name": "pass-oecd-voluntary-advisory",
            "conformance_class": "offline-deterministic",
            "disposition": "pass",
            "profiles": [_OECD_PROFILE],
            "record_type": "incident_card",
            "title": "OECD voluntary profile — advisory, non-binding",
            "body": (
                "A public incident_card lacking the `oecd` crosswalk member, validated "
                "under the VOLUNTARY OECD profile (`legal_force: voluntary`). The missing "
                "member surfaces an ADVISORY (warning) ACEF-081, never a binding error — "
                "voluntary frameworks do not block conformance (RFC §5.7 / Finding 1)."
            ),
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
            "forbid_codes": ["ACEF-082", "ACEF-083", "ACEF-085", "ACEF-088"],
        }
    )

    # P3: near_miss INFO marker — a PASS-with-info vector (ACEF-087 INFO).
    near_miss_core = dict(_VALID_HARM_CORE)
    near_miss_core["realization"] = "near_miss"
    specs.append(
        {
            "name": "pass-near-miss-info",
            "conformance_class": "offline-deterministic",
            "disposition": "pass",
            "profiles": [],
            "record_type": "incident_card",
            "title": "near_miss informational marker (ACEF-087 INFO)",
            "body": (
                "A public incident_card whose `harm_core.realization` is `near_miss`. "
                "ACEF-087 is an INFORMATIONAL marker (§5.5) — surfaced at INFO severity, "
                "NEVER a failure. The bundle is a PASS that carries an info diagnostic."
            ),
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": near_miss_core,
            },
            "info_codes": ["ACEF-087"],
            "forbid_codes": ["ACEF-082", "ACEF-083", "ACEF-085", "ACEF-088"],
        }
    )

    # === PASS — source-backed ===

    # P4: Art.73 single-trigger — source-backed report, 15-day general clock, correct
    # deadline (awareness + 15d = 2026-08-16). No ACEF-084.
    specs.append(
        {
            "name": "pass-art73-single-trigger",
            "conformance_class": "source-backed",
            "disposition": "pass",
            "confidentiality": _CONFIDENTIAL,
            "profiles": [_ART73_PROFILE],
            "record_type": "incident_report",
            "title": "Art.73 single-trigger — 15-day general clock",
            "body": (
                "A source-backed incident_report with a single Art.3(49)(a) trigger, no "
                "widespread/death, and a stated regulatory_timeline deadline equal to the "
                "shortest applicable clock (15 days from awareness). No ACEF-084."
            ),
            "payload": _card_source_report_payload(
                triggers=["3.49.a"], widespread=False, death=False, deadline="2026-08-16T00:00:00Z"
            ),
            "forbid_codes": ["ACEF-084", "ACEF-082", "ACEF-083", "ACEF-085", "ACEF-088"],
        }
    )

    # P5: Art.73 compound multi-trigger (death + critical-infra) → 2-day shortest clock,
    # correct deadline (awareness + 2d = 2026-08-03). No ACEF-084 (the compound exercises
    # the shortest-applicable rule that 2d beats 10d).
    specs.append(
        {
            "name": "pass-art73-compound-2day",
            "conformance_class": "source-backed",
            "disposition": "pass",
            "confidentiality": _CONFIDENTIAL,
            "profiles": [_ART73_PROFILE],
            "record_type": "incident_report",
            "title": "Art.73 compound (death + critical-infra) — 2-day shortest clock",
            "body": (
                "A source-backed incident_report with compound triggers `3.49.a` + `3.49.b` "
                "and `death_involved: true`. The shortest applicable clock is 2 days "
                "(critical-infrastructure beats the 10-day death clock), and the stated "
                "deadline equals awareness + 2d. No ACEF-084 — the compound shortest-clock "
                "rule is satisfied."
            ),
            "payload": _card_source_report_payload(
                triggers=["3.49.a", "3.49.b"], widespread=False, death=True, deadline="2026-08-03T00:00:00Z"
            ),
            "forbid_codes": ["ACEF-084", "ACEF-082", "ACEF-083", "ACEF-085", "ACEF-088"],
        }
    )

    # === FAIL — offline-deterministic (card-only) ===

    # F1: ACEF-082 — severity_vector present but not parseable.
    specs.append(
        {
            "name": "fail-severity-vector-parse-082",
            "conformance_class": "offline-deterministic",
            "disposition": "fail",
            "profiles": [],
            "record_type": "incident_card",
            "title": "severity_vector parse failure (ACEF-082)",
            "body": (
                "A public incident_card whose `severity_vector` does not parse against the "
                "ACEF-SEV:1.0 grammar (a truncated vector). The validator raises ACEF-082."
            ),
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
                "severity_vector": "ACEF-SEV:1.0/HG:H",
            },
            "expect_codes": ["ACEF-082"],
        }
    )

    # F2: ACEF-083 (offline) — public_incident_id pattern failure (short suffix).
    specs.append(
        {
            "name": "fail-public-id-offline-083",
            "conformance_class": "offline-deterministic",
            "disposition": "fail",
            "profiles": [],
            "record_type": "incident_card",
            "title": "public_incident_id offline-surface failure (ACEF-083)",
            "body": (
                "A public incident_card whose `public_incident_id` has a too-short suffix "
                "(< 26 Crockford-base32 chars, < 128 bits). The OFFLINE-deterministic class "
                "checks pattern only and raises ACEF-083 `class: offline-deterministic` — a "
                "pure-pattern failure computed from bundle bytes, NEVER an attribution claim."
            ),
            "payload": {
                "public_incident_id": "AIIC-OPENAI-2026-TOOSHORT",
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
            "expect_codes": ["ACEF-083"],
        }
    )

    # F3: ACEF-085 — harm_core ↔ crosswalk contradiction. harm_class=physical_health
    # derives a 3.49.* trigger; the eu_ai_act member asserts a DIFFERENT trigger and
    # OMITS the derived one.
    specs.append(
        {
            "name": "fail-harm-core-crosswalk-085",
            "conformance_class": "offline-deterministic",
            "disposition": "fail",
            "profiles": [],
            "record_type": "incident_card",
            "title": "harm_core ↔ crosswalk contradiction (ACEF-085)",
            "body": (
                "A public incident_card whose `taxonomy_crosswalk.eu_ai_act` asserts "
                "serious_incident_triggers that OMIT the trigger derived from "
                "`harm_core.harm_class` (the card claims a harm_class but lists only an "
                "unrelated trigger). The derivation-consistency check raises ACEF-085."
            ),
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
                "taxonomy_crosswalk": {
                    "eu_ai_act": {
                        "edition": "reg-2024-1689",
                        "serious_incident_triggers": ["3.49.d"],
                    }
                },
            },
            "expect_codes": ["ACEF-085"],
        }
    )

    # F4: ACEF-088 — severity disagrees with band(severity_vector). Vector bands to
    # "major"; severity declared "minor".
    specs.append(
        {
            "name": "fail-severity-band-088",
            "conformance_class": "offline-deterministic",
            "disposition": "fail",
            "profiles": [],
            "record_type": "incident_card",
            "title": "severity ↔ band() disagreement (ACEF-088)",
            "body": (
                "A public incident_card carrying BOTH `severity` and `severity_vector` "
                "where the coarse `severity` (`minor`) disagrees with "
                "`band(severity_vector)` (`major`). The consistency check raises ACEF-088."
            ),
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "severity": "minor",
                "severity_vector": _SEV_VECTOR_MAJOR,
                "harm_core": dict(_VALID_HARM_CORE),
            },
            "expect_codes": ["ACEF-088"],
        }
    )

    # F5: ACEF-086 — public disclosure of a special-category field without a satisfying
    # declared_publication_basis. coordinated_disclosure.status=public engages the gate.
    # forbid ACEF-022 (the gate must use the reserved 08x code, never the redaction code).
    specs.append(
        {
            "name": "fail-publishability-086",
            "conformance_class": "offline-deterministic",
            "disposition": "fail",
            "profiles": [],
            "record_type": "incident_card",
            "title": "public disclosure without declared_publication_basis (ACEF-086)",
            "body": (
                "A public incident_card (`coordinated_disclosure.status: public`) that "
                "projects the special-category field `harm_distribution_basis` public "
                "WITHOUT a satisfying `declared_publication_basis` (no Art.6 basis + Art.9 "
                "condition, no anonymization method). The §5.11 publishability gate raises "
                "ACEF-086 — NOT ACEF-022."
            ),
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
                "harm_distribution_basis": ["race", "sex"],
                "coordinated_disclosure": {"status": "public", "reporter_role": "internal"},
            },
            "expect_codes": ["ACEF-086"],
            "forbid_codes": ["ACEF-022"],
        }
    )

    # === FAIL — source-backed ===

    # F6: ACEF-084 — Art.73 compound (death + critical-infra) with a WRONG deadline.
    # Shortest clock is 2 days (awareness + 2d = 2026-08-03); the vector states a 10-day
    # deadline (2026-08-11), so the deadline is inconsistent → ACEF-084.
    specs.append(
        {
            "name": "fail-art73-compound-wrong-clock-084",
            "conformance_class": "source-backed",
            "disposition": "fail",
            "confidentiality": _CONFIDENTIAL,
            "profiles": [_ART73_PROFILE],
            "record_type": "incident_report",
            "title": "Art.73 compound multi-trigger wrong clock (ACEF-084)",
            "body": (
                "A source-backed incident_report with compound triggers `3.49.a` + `3.49.b` "
                "and `death_involved: true` — the shortest applicable clock is 2 days "
                "(critical-infrastructure). The stated regulatory_timeline deadline is the "
                "10-day death clock (awareness + 10d), which is INCONSISTENT with the "
                "shortest applicable 2-day clock → ACEF-084."
            ),
            "payload": _card_source_report_payload(
                triggers=["3.49.a", "3.49.b"], widespread=False, death=True, deadline="2026-08-11T00:00:00Z"
            ),
            "expect_codes": ["ACEF-084"],
        }
    )

    # === VAL-VEC-003 — RESERVED-id death-clock vectors (source-backed, no public card) ===

    # V3a: death_involved → 10-day clock, correct deadline (awareness + 10d = 2026-08-11).
    specs.append(
        {
            "name": "reserved-id-death-10day",
            "conformance_class": "source-backed",
            "disposition": "pass",
            "confidentiality": _CONFIDENTIAL,
            "profiles": [_ART73_PROFILE],
            "record_type": "incident_report",
            "title": "RESERVED-id death clock (10 days), no public card",
            "body": (
                "A confidential, source-backed incident_report with a RESERVED "
                "public_incident_id and NO public incident_card. `death_involved: true` "
                "(no critical-infra, no widespread) → the Art.73 clock is 10 days, computed "
                "from `card_source.eu_ai_act_facts` before any public card exists. The "
                "stated deadline equals awareness + 10d → no ACEF-084. Exercises the §5.7 "
                "confidential critical path."
            ),
            "payload": _card_source_report_payload(
                triggers=["3.49.a"], widespread=False, death=True, deadline="2026-08-11T00:00:00Z"
            ),
            "clock_days": 10,
            "no_public_card": True,
            "forbid_codes": ["ACEF-084"],
        }
    )

    # V3b: compound death + 3.49.b → 2-day shortest clock, correct deadline (awareness + 2d).
    specs.append(
        {
            "name": "reserved-id-death-compound-2day",
            "conformance_class": "source-backed",
            "disposition": "pass",
            "confidentiality": _CONFIDENTIAL,
            "profiles": [_ART73_PROFILE],
            "record_type": "incident_report",
            "title": "RESERVED-id compound death + critical-infra (2 days), no public card",
            "body": (
                "A confidential, source-backed incident_report with a RESERVED "
                "public_incident_id and NO public incident_card. Compound "
                "`death_involved: true` + `3.49.b` (critical-infrastructure) → the SHORTEST "
                "applicable clock is 2 days (the 2-day critical-infra clock beats the 10-day "
                "death clock), computed from `card_source.eu_ai_act_facts`. The stated "
                "deadline equals awareness + 2d → no ACEF-084."
            ),
            "payload": _card_source_report_payload(
                triggers=["3.49.a", "3.49.b"], widespread=False, death=True, deadline="2026-08-03T00:00:00Z"
            ),
            "clock_days": 2,
            "no_public_card": True,
            "forbid_codes": ["ACEF-084"],
        }
    )

    # === VAL-VEC-002 — forged-assigner online-class REJECT (offline PASSES) ===
    # Finding 1: the vector's PRIMARY disposition is the ONLINE outcome — `reject` —
    # so a generic consumer reading `disposition` classifies the required online-reject
    # case correctly (it previously sat under `online-conformance/pass` with
    # disposition=pass, which mislabeled the required reject as a pass). The bundle ITSELF
    # still passes the OFFLINE class (valid pattern AIIC-OPENAI-…); that fact is carried on
    # the SEPARATE `offline_class: pass` field documenting the VAL-DOMAIN-001 cross-check.
    # The online-class reject (ACEF-083) is exercised by the driver via
    # verify_domain_control with an injected attacker proof; the offline-pass premise is
    # exercised by validate_bundle (no ACEF-083). The committed `.acef-assessment.json`
    # records the OFFLINE emitted-code set (the bundle's deterministic offline output).
    specs.append(
        {
            "name": "forged-assigner-online-reject-083",
            "conformance_class": "online-conformance",
            # PRIMARY disposition = the ONLINE verdict (Finding 1). The bundle lands under
            # `online-conformance/reject/`, not under a `pass` tree.
            "disposition": "reject",
            # The OFFLINE-pass fact is a SEPARATE field (not the disposition).
            "offline_class": "pass",
            "online_disposition": "reject",
            "public_incident_id": _VALID_ID,
            "assigner": _FORGED_ASSIGNER,
            "profiles": [],
            "record_type": "incident_card",
            "title": "Forged assigner — online REJECT (ACEF-083), offline class PASS",
            "body": (
                "A public incident_card bearing a valid-pattern `AIIC-OPENAI-2026-…` id that "
                "was forged by an attacker (signed with an attacker key, not OpenAI's). "
                "OFFLINE-deterministic validation checks pattern + JWS self-consistency ONLY "
                "and NEVER attributes the id to openai.com — so this card PASSES the offline "
                "class BY DESIGN (no ACEF-083 offline). Attribution is the OPTIONAL ONLINE "
                "domain-control verifier's job: presented with an attacker proof bound to the "
                "WRONG key (a presented-but-invalid proof), the online class returns `reject` "
                "→ ACEF-083 `class: online-conformance`. A network timeout instead returns "
                "`unverified` (an explicit non-result), never a silent pass and never a "
                "forgery verdict. The online check runs against INJECTED stubs — no real "
                "network. See `tests/conformance/test_incident_vectors.py` "
                "(test_forged_assigner_*)."
            ),
            "payload": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "harm_core": dict(_VALID_HARM_CORE),
            },
            "forbid_codes": ["ACEF-083"],  # offline class must NOT raise ACEF-083 for this card.
        }
    )

    return specs


# ---------------------------------------------------------------------------
# Generation driver.
# ---------------------------------------------------------------------------


def _prune_stale_vector_dirs(live_bundle_dirs: set[Path], live_assessment_files: set[Path]) -> list[str]:
    """Remove generated vector artifacts NOT produced by the current spec set.

    Finding 3: the on-disk corpus must NOT silently drift from the manifest. A
    ``*.acef`` directory (identified by its ``acef-manifest.json``) or a
    ``*.acef.acef-assessment.json`` file under ``test-vectors/incident/`` that the
    current ``_vector_specs()`` did NOT just emit is stale (a removed/renamed
    vector) and is deleted, so re-running ``generate.py`` after dropping a vector
    leaves no orphan on disk. Returns the list of pruned relative paths (for the
    run log)."""
    pruned: list[str] = []
    for manifest_path in sorted(_INCIDENT_DIR.rglob("acef-manifest.json")):
        bundle = manifest_path.parent
        if bundle not in live_bundle_dirs:
            shutil.rmtree(bundle)
            pruned.append(bundle.relative_to(_INCIDENT_DIR).as_posix())
    for assessment_path in sorted(_INCIDENT_DIR.rglob("*.acef.acef-assessment.json")):
        if assessment_path not in live_assessment_files:
            assessment_path.unlink()
            pruned.append(assessment_path.relative_to(_INCIDENT_DIR).as_posix())
    # Drop now-empty class/disposition directories left behind by pruning.
    for child in sorted(_INCIDENT_DIR.rglob("*"), reverse=True):
        if child.is_dir() and not any(child.iterdir()):
            child.rmdir()
    return pruned


def generate() -> None:
    specs = _vector_specs()
    vectors_index: list[dict[str, Any]] = []
    live_bundle_dirs: set[Path] = set()
    live_assessment_files: set[Path] = set()

    for spec in specs:
        name = spec["name"]
        conformance_class = spec["conformance_class"]
        disposition = spec["disposition"]
        confidentiality = spec.get("confidentiality", "public")
        rel_dir = Path(conformance_class) / disposition / f"{name}.acef"
        bundle_dir = _INCIDENT_DIR / rel_dir
        live_bundle_dirs.add(bundle_dir)

        _build_bundle(
            bundle_dir,
            record_type=spec["record_type"],
            payload=spec["payload"],
            confidentiality=confidentiality,
        )

        if spec.get("expect_codes"):
            expected_label = ", ".join(spec["expect_codes"])
        elif disposition == "reject":
            # Finding 1: an online-conformance reject vector emits NO offline code
            # (offline never attributes); the reject is the ONLINE verdict (ACEF-083).
            expected_label = "ACEF-083 (online-conformance reject); offline class: pass (none)"
        else:
            expected_label = "none (pass)"
        _write_readme(bundle_dir, title=spec["title"], body=spec["body"], expected=expected_label)

        # Validate now to capture the live emitted-code set into the committed
        # expected assessment (the driver re-checks this is not stale).
        profiles = spec.get("profiles") or None
        assessment = validate_bundle(bundle_dir, profiles=profiles)
        emitted_codes = sorted({str(e.get("code")) for e in assessment.structural_errors})

        assessment_rel = Path(conformance_class) / disposition / f"{name}.acef.acef-assessment.json"
        assessment_path = _INCIDENT_DIR / assessment_rel
        live_assessment_files.add(assessment_path)
        _write_json(
            assessment_path,
            {
                "vector": name,
                "class": conformance_class,
                "disposition": disposition,
                "emitted_codes": emitted_codes,
            },
        )

        entry: dict[str, Any] = {
            "name": name,
            "class": conformance_class,
            "disposition": disposition,
            "path": str(rel_dir),
            "assessment_path": str(assessment_rel),
            "record_type": spec["record_type"],
            "profiles": spec.get("profiles", []),
            "confidentiality": confidentiality,
        }
        for optional in (
            "expect_codes",
            "forbid_codes",
            "info_codes",
            "clock_days",
            "no_public_card",
            "offline_class",
            "offline_disposition",
            "online_disposition",
            "public_incident_id",
            "assigner",
        ):
            if optional in spec:
                entry[optional] = spec[optional]
        vectors_index.append(entry)

    # Finding 3: prune any on-disk vector artifact not in the current spec set, so
    # the corpus cannot silently drift from the manifest we are about to write.
    pruned = _prune_stale_vector_dirs(live_bundle_dirs, live_assessment_files)

    vectors_index.sort(key=lambda e: str(e["name"]))
    _write_json(
        _INCIDENT_DIR / "vectors.json",
        {
            "schema": "acef-incident-conformance-vectors/1.1.0",
            "description": (
                "RFC-0002 §6 v1.1-REQUIRED incident conformance vectors "
                "(offline-deterministic + source-backed) plus one online-conformance "
                "forged-assigner reject vector. online-registry / public-registry-admission "
                "are v1.2 and excluded."
            ),
            "vectors": vectors_index,
        },
    )

    # Finding 3: hard consistency guard — the on-disk *.acef dirs MUST equal the
    # manifest exactly after pruning. Fail loudly rather than emit a drifted corpus.
    manifest_dirs = {str(e["path"]) for e in vectors_index}
    on_disk_dirs = {m.parent.relative_to(_INCIDENT_DIR).as_posix() for m in _INCIDENT_DIR.rglob("acef-manifest.json")}
    if on_disk_dirs != manifest_dirs:
        raise SystemExit(
            "generate.py: on-disk vector dirs disagree with vectors.json after pruning: "
            f"stale-on-disk={sorted(on_disk_dirs - manifest_dirs)!r} "
            f"missing-on-disk={sorted(manifest_dirs - on_disk_dirs)!r}"
        )

    if pruned:
        print(f"pruned {len(pruned)} stale vector artifact(s): {sorted(pruned)!r}")
    print(f"generated {len(vectors_index)} incident conformance vectors under {_INCIDENT_DIR}")


if __name__ == "__main__":
    generate()
