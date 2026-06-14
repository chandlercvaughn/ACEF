"""Integration: the offline incident rules through the PRODUCTION validator.

These tests drive ``acef.validation.engine.validate_bundle`` against on-disk
bundle directories whose ``acef-manifest.json`` declares ``core_version: 1.1.0``
(routing Phase 1 to the v1.1 schema set) and whose records JSONL carries an
incident_card / incident_report. They prove the engine-level wiring and the
load-bearing version-gating:

- VAL-VLD-001 — incident rules FIRE on a 1.1.0 bundle, do NOT fire on a 1.0.0
  bundle, and a v1.0 golden bundle's result is byte-identical before/after this
  operation.
- VAL-CLOCK-001 — the Art.73 clock + ACEF-084 (mismatch, existential, framework
  match) reach structural_errors through the engine.
- VAL-PUB-001 — the §5.11 publishability gate (ACEF-086) reaches
  structural_errors through the engine.

The bundles are constructed by building a real v1.0 bundle via the SDK Package
builder (so content-hashes / Merkle / manifest shape are production-valid), then
rewriting versioning.core_version -> 1.1.0 and substituting an incident records
file. This mirrors exactly what the validator reads (parsed manifest + JSONL),
without depending on the not-yet-built F-M5 report_incident builder.

Determinism: every fixture is a static literal; no wall-clock / random values.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acef.integrity import compute_content_hashes
from acef.package import Package
from acef.validation.engine import validate_bundle

_SUFFIX = "0123456789ABCDEFGHJKMNPQRS"
_VALID_ID = f"AIIC-OPENAI-2026-{_SUFFIX}"

_VALID_HARM_CORE: dict[str, Any] = {
    "realization": "harm_event",
    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
    "harm_class": "physical_health",
}


def _codes(assessment: Any) -> list[str]:
    return [e.get("code") for e in assessment.structural_errors]


def _errors_for(assessment: Any, code: str) -> list[dict[str, Any]]:
    return [e for e in assessment.structural_errors if e.get("code") == code]


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")


def _build_incident_bundle(
    tmp_path: Path,
    *,
    core_version: str,
    record_type: str,
    payload: dict[str, Any],
    profiles: list[str] | None = None,
    name: str = "inc.acef",
    sign_record: bool = False,
    sign_with_x5c: bool = False,
    tamper_after_sign: bool = False,
    omit_timestamp: bool = False,
) -> Path:
    """Build an on-disk bundle directory carrying ONE incident record.

    Exports a real v1.0 bundle via the SDK (production manifest / hashes), then
    rewrites versioning.core_version, substitutes the incident records file,
    recomputes content-hashes.json, and (optionally) declares profiles.

    When ``sign_record`` is True, a self-consistent record-envelope ``attestation``
    JWS over ``/payload`` is attached (ES256, key embedded in the JWS header). When
    ``tamper_after_sign`` is also True, the payload is mutated AFTER signing so the
    JWS no longer self-verifies (the §5.3(ii) self-inconsistency).

    When ``sign_with_x5c`` is True the attestation JWS carries an ``x5c`` chain
    (a self-signed leaf cert) instead of an embedded JWK — this is the ONLY path
    whose §5.3(ii) self-consistency sub-check anchors certificate validity to the
    manifest timestamp (``verify_x5c_chain``). A JWK-only JWS never reaches the
    cert-validity branch, so the empty-timestamp coercion bug is observable only
    via x5c.

    When ``omit_timestamp`` is True the manifest is rewritten WITHOUT
    ``metadata.timestamp`` (the missing-scalar case that ``_resolve_package_scalars``
    coerces to the empty string ``""``).
    """
    import base64
    from datetime import UTC, datetime

    import jsonpointer
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from acef.integrity import canonicalize
    from acef.signing import create_detached_jws

    pkg = Package(producer={"name": "test", "version": "1.0"})
    pkg.add_subject("ai_system", name="Sys", risk_classification="high-risk")
    pkg.record("risk_register", payload={"description": "seed"})
    bundle_dir = tmp_path / name
    pkg.export(str(bundle_dir))

    # Replace the seed record file with an incident records file.
    records_dir = bundle_dir / "records"
    for existing in records_dir.glob("*.jsonl"):
        existing.unlink()

    rec: dict[str, Any] = {
        "record_id": f"urn:acef:record:{record_type}-1",
        "record_type": record_type,
        "timestamp": "2026-08-10T00:00:00Z",
        "confidentiality": "public",
        "payload": payload,
    }
    if sign_record:
        key = ec.generate_private_key(ec.SECP256R1())
        subset = {"/payload": jsonpointer.resolve_pointer(rec, "/payload")}
        x5c_chain: list[str] | None = None
        if sign_with_x5c:
            # Self-signed leaf cert -> x5c chain. The §5.3(ii) sub-check anchors
            # this cert's validity to the manifest timestamp via verify_x5c_chain;
            # a JWK-only JWS never reaches that branch.
            cert_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "acef-test-card")])
            cert = (
                x509.CertificateBuilder()
                .subject_name(cert_name)
                .issuer_name(cert_name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
                .not_valid_after(datetime(2035, 1, 1, tzinfo=UTC))
                .sign(key, hashes.SHA256())
            )
            x5c_chain = [base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")]
        rec["attestation"] = {
            "method": "jws",
            "signer": "provider",
            "signed_fields": ["/payload"],
            "signature": create_detached_jws(canonicalize(subset), key, kid="card-key", x5c=x5c_chain),
        }
        if tamper_after_sign:
            # Mutate the payload AFTER signing -> the JWS no longer self-verifies.
            rec["payload"]["id_grade"] = "tampered-after-signing"
    rec_path = records_dir / f"{record_type}.jsonl"
    _write_jsonl(rec_path, [rec])

    # Rewrite the manifest: bump core_version, point record_files at the new
    # file, and declare profiles.
    manifest_path = bundle_dir / "acef-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["versioning"]["core_version"] = core_version
    manifest["record_files"] = [{"path": f"records/{record_type}.jsonl", "record_type": record_type, "record_count": 1}]
    if profiles is not None:
        manifest["profiles"] = [{"profile_id": pid, "applicable_provisions": []} for pid in profiles]
    if omit_timestamp:
        # Drop metadata.timestamp entirely -> _resolve_package_scalars coerces the
        # missing scalar to "" (the case the incident-rule path must map to None).
        _metadata = manifest.get("metadata")
        if isinstance(_metadata, dict):
            _metadata.pop("timestamp", None)
    manifest_path.write_text(json.dumps(manifest, separators=(",", ":"), sort_keys=True), encoding="utf-8")

    # Recompute content-hashes.json so Phase-2 integrity does not flood the
    # diagnostics (we assert on incident codes, not integrity).
    hashes = compute_content_hashes(bundle_dir)
    (bundle_dir / "hashes" / "content-hashes.json").write_text(
        json.dumps(hashes, separators=(",", ":"), sort_keys=True), encoding="utf-8"
    )
    return bundle_dir


# ---------------------------------------------------------------------------
# VAL-VLD-001: version-gating
# ---------------------------------------------------------------------------


class TestVersionGating:
    def test_incident_rules_fire_on_1_1_0_bundle(self, tmp_path: Path) -> None:
        # A forged-pattern public_incident_id on a 1.1.0 bundle -> ACEF-083 fires.
        payload = {
            "public_incident_id": "AIIC-OPENAI-2026-tooshort",
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
        }
        bundle = _build_incident_bundle(tmp_path, core_version="1.1.0", record_type="incident_card", payload=payload)
        assessment = validate_bundle(bundle)
        assert "ACEF-083" in _codes(assessment)

    def test_incident_rules_do_not_fire_on_1_0_0_bundle(self, tmp_path: Path) -> None:
        # The SAME malformed id on a 1.0.0 bundle -> NO incident code fires (the
        # v1.1 dispatch block is never entered).
        payload = {
            "public_incident_id": "AIIC-OPENAI-2026-tooshort",
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
        }
        bundle = _build_incident_bundle(tmp_path, core_version="1.0.0", record_type="incident_card", payload=payload)
        assessment = validate_bundle(bundle)
        codes = _codes(assessment)
        for incident_code in (f"ACEF-08{n}" for n in range(1, 9)):
            assert incident_code not in codes, f"{incident_code} must not fire on a v1.0 bundle"

    def test_v1_0_golden_bundle_result_unchanged(self) -> None:
        # A pre-existing v1.0 golden bundle validates with ZERO incident codes —
        # the incident rules are absent for v1.0 (byte-equivalent to pre-op).
        golden_root = Path("tests/conformance/golden-bundles")
        if not golden_root.is_dir():
            pytest.skip("golden-bundles directory not present")
        candidates = sorted(p for p in golden_root.iterdir() if p.is_dir() and (p / "acef-manifest.json").is_file())
        if not candidates:
            pytest.skip("no golden bundle directories found")
        checked = 0
        for bundle in candidates:
            manifest = json.loads((bundle / "acef-manifest.json").read_text(encoding="utf-8"))
            core_v = manifest.get("versioning", {}).get("core_version", "1.0.0")
            if not str(core_v).startswith("1.0"):
                continue
            assessment = validate_bundle(bundle)
            codes = _codes(assessment)
            for incident_code in (f"ACEF-08{n}" for n in range(1, 9)):
                assert incident_code not in codes, (
                    f"{incident_code} fired on v1.0 golden bundle {bundle.name} — regression"
                )
            checked += 1
        if checked == 0:
            pytest.skip("no v1.0 golden bundles found")


# ---------------------------------------------------------------------------
# VAL-CLOCK-001: Art.73 clock + ACEF-084 through the engine
# ---------------------------------------------------------------------------


def _card_source_payload(
    *,
    triggers: list[str],
    widespread: bool,
    death: bool,
    deadline: str | None,
    awareness: str = "2026-08-01T00:00:00Z",
) -> dict[str, Any]:
    timeline: list[dict[str, Any]] = []
    if deadline is not None:
        timeline = [
            {
                "framework": "eu-ai-act-art73",
                "clock_model": "awareness_days",
                "awareness_date": awareness,
                "deadline": deadline,
            }
        ]
    return {
        "incident_type": "malfunction",
        "severity": "major",
        "description": "x",
        "card_source": {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "id_state": "RESERVED",
            "harm_core": dict(_VALID_HARM_CORE),
            "publishability_map": {"/root_cause_analysis": "regulator-only"},
            "eu_ai_act_facts": {
                "edition": "reg-2024-1689",
                "serious_incident_triggers": triggers,
                "widespread": widespread,
                "death_involved": death,
            },
            "coordinated_disclosure": {"status": "coordinated", "regulatory_timeline": timeline},
        },
    }


class TestArt73ClockEngine:
    def test_death_ten_day_clock_passes_no_084(self, tmp_path: Path) -> None:
        payload = _card_source_payload(
            triggers=["3.49.a"], widespread=False, death=True, deadline="2026-08-11T00:00:00Z"
        )
        bundle = _build_incident_bundle(
            tmp_path,
            core_version="1.1.0",
            record_type="incident_report",
            payload=payload,
            profiles=["eu-ai-act-art73-2026"],
        )
        assessment = validate_bundle(bundle)
        assert "ACEF-084" not in _codes(assessment)

    def test_death_wrong_deadline_raises_084(self, tmp_path: Path) -> None:
        payload = _card_source_payload(
            triggers=["3.49.a"], widespread=False, death=True, deadline="2026-08-16T00:00:00Z"
        )
        bundle = _build_incident_bundle(
            tmp_path,
            core_version="1.1.0",
            record_type="incident_report",
            payload=payload,
            profiles=["eu-ai-act-art73-2026"],
        )
        assessment = validate_bundle(bundle)
        assert "ACEF-084" in _codes(assessment)

    def test_compound_death_plus_critical_infra_two_day_clock(self, tmp_path: Path) -> None:
        payload = _card_source_payload(
            triggers=["3.49.a", "3.49.b"], widespread=False, death=True, deadline="2026-08-03T00:00:00Z"
        )
        bundle = _build_incident_bundle(
            tmp_path,
            core_version="1.1.0",
            record_type="incident_report",
            payload=payload,
            profiles=["eu-ai-act-art73-2026"],
        )
        assessment = validate_bundle(bundle)
        assert "ACEF-084" not in _codes(assessment)

    def test_empty_evidence_art73_bundle_fails(self, tmp_path: Path) -> None:
        # incident_card with NO trigger facts, art73 profile declared -> ACEF-084
        # existential failure.
        payload = {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
            "taxonomy_crosswalk": {
                "eu_ai_act": {"edition": "reg-2024-1689"}  # no serious_incident_triggers
            },
            "coordinated_disclosure": {"status": "coordinated", "regulatory_timeline": []},
        }
        bundle = _build_incident_bundle(
            tmp_path,
            core_version="1.1.0",
            record_type="incident_card",
            payload=payload,
            profiles=["eu-ai-act-art73-2026"],
        )
        assessment = validate_bundle(bundle)
        assert "ACEF-084" in _codes(assessment)

    def test_non_eu_only_timeline_fails(self, tmp_path: Path) -> None:
        payload = _card_source_payload(triggers=["3.49.a"], widespread=False, death=True, deadline=None)
        payload["card_source"]["coordinated_disclosure"] = {
            "status": "coordinated",
            "regulatory_timeline": [
                {
                    "framework": "us-circia",
                    "clock_model": "awareness_days",
                    "awareness_date": "2026-08-01T00:00:00Z",
                    "deadline": "2026-08-31T00:00:00Z",
                }
            ],
        }
        bundle = _build_incident_bundle(
            tmp_path,
            core_version="1.1.0",
            record_type="incident_report",
            payload=payload,
            profiles=["eu-ai-act-art73-2026"],
        )
        assessment = validate_bundle(bundle)
        assert "ACEF-084" in _codes(assessment)

    def test_profiles_arg_without_manifest_declaration_runs_art73_checks(self, tmp_path: Path) -> None:
        # FINDING 2: a bundle that does NOT declare the Art.73 profile in its manifest,
        # but for which the caller (validate_bundle / CLI --profile) requests
        # ["eu-ai-act-art73-2026"], MUST still get the delegated ACEF-084 checks. A
        # wrong-clock bundle (death -> 10 days required; 15-day deadline stated) ->
        # ACEF-084.
        payload = _card_source_payload(
            triggers=["3.49.a"], widespread=False, death=True, deadline="2026-08-16T00:00:00Z"
        )
        # profiles=None -> the manifest does NOT declare eu-ai-act-art73-2026.
        bundle = _build_incident_bundle(
            tmp_path,
            core_version="1.1.0",
            record_type="incident_report",
            payload=payload,
            profiles=None,
        )
        # Requested only through the validate_bundle profiles argument.
        assessment = validate_bundle(bundle, profiles=["eu-ai-act-art73-2026"])
        assert "ACEF-084" in _codes(assessment)


# ---------------------------------------------------------------------------
# VAL-PUB-001: §5.11 publishability gate (ACEF-086) through the engine
# ---------------------------------------------------------------------------


class TestPublishabilityEngine:
    def test_special_category_without_basis_raises_086(self, tmp_path: Path) -> None:
        payload = {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
            "harm_distribution_basis": ["race", "sex"],
            "coordinated_disclosure": {"status": "public", "reporter_role": "internal"},
        }
        bundle = _build_incident_bundle(tmp_path, core_version="1.1.0", record_type="incident_card", payload=payload)
        assessment = validate_bundle(bundle)
        codes = _codes(assessment)
        assert "ACEF-086" in codes
        assert "ACEF-022" not in codes

    def test_special_category_with_full_basis_passes(self, tmp_path: Path) -> None:
        payload = {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
            "harm_distribution_basis": ["race"],
            "declared_publication_basis": {
                "art6_basis": "legitimate_interests",
                "art9_condition": "substantial_public_interest",
            },
            "coordinated_disclosure": {"status": "public", "reporter_role": "internal"},
        }
        bundle = _build_incident_bundle(tmp_path, core_version="1.1.0", record_type="incident_card", payload=payload)
        assessment = validate_bundle(bundle)
        assert "ACEF-086" not in _codes(assessment)

    def test_unresolvable_pointer_source_backed_raises_086(self, tmp_path: Path) -> None:
        payload = {
            "incident_type": "malfunction",
            "severity": "major",
            "description": "x",
            "card_source": {
                "public_incident_id": _VALID_ID,
                "id_grade": "self-asserted",
                "id_state": "PUBLISHED",
                "harm_core": dict(_VALID_HARM_CORE),
                "publishability_map": {"/nonexistent_field": "regulator-only"},
                "eu_ai_act_facts": {
                    "edition": "reg-2024-1689",
                    "serious_incident_triggers": ["3.49.a"],
                    "widespread": False,
                    "death_involved": False,
                },
                "coordinated_disclosure": {"status": "coordinated"},
            },
        }
        bundle = _build_incident_bundle(tmp_path, core_version="1.1.0", record_type="incident_report", payload=payload)
        assessment = validate_bundle(bundle)
        assert "ACEF-086" in _codes(assessment)


# ---------------------------------------------------------------------------
# Offline ACEF-083 honesty: a forged but self-consistent card PASSES offline.
# ---------------------------------------------------------------------------


class TestOfflineId083Engine:
    def test_forged_assigner_valid_pattern_passes_offline(self, tmp_path: Path) -> None:
        # AIIC-OPENAI-... forged by an attacker; valid pattern, no snapshot ->
        # offline class passes (no ACEF-083). Attribution is the OPTIONAL online
        # verifier's job, never the offline class.
        payload = {
            "public_incident_id": _VALID_ID,  # AIIC-OPENAI-2026-...
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
        }
        bundle = _build_incident_bundle(tmp_path, core_version="1.1.0", record_type="incident_card", payload=payload)
        assessment = validate_bundle(bundle)
        assert "ACEF-083" not in _codes(assessment)

    def test_signed_card_self_consistent_jws_passes(self, tmp_path: Path) -> None:
        # A signed incident_card whose JWS self-verifies -> no ACEF-083 through the
        # production engine (the §5.3(ii) sub-check is satisfied).
        payload = {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
        }
        bundle = _build_incident_bundle(
            tmp_path, core_version="1.1.0", record_type="incident_card", payload=payload, sign_record=True
        )
        assessment = validate_bundle(bundle)
        assert "ACEF-083" not in _codes(assessment)

    def test_signed_card_tampered_jws_raises_083(self, tmp_path: Path) -> None:
        # Tamper the payload AFTER signing -> JWS self-inconsistency -> ACEF-083
        # (class:offline-deterministic) reaches structural_errors through the engine.
        payload = {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
        }
        bundle = _build_incident_bundle(
            tmp_path,
            core_version="1.1.0",
            record_type="incident_card",
            payload=payload,
            sign_record=True,
            tamper_after_sign=True,
        )
        assessment = validate_bundle(bundle)
        errors = _errors_for(assessment, "ACEF-083")
        assert errors, "tampered signed card must raise ACEF-083 via the engine"
        assert any("offline-deterministic" in e.get("message", "") for e in errors)


# ---------------------------------------------------------------------------
# Structural-review P3: the incident-rule JWS path must coerce an empty
# package_timestamp ("" from a MISSING metadata.timestamp) to None — matching
# the rule_engine sibling (rule_engine.py:270) and the signing layer's
# skip-if-not-provided contract. Otherwise verify_x5c_chain("") raises ACEF-012,
# is swallowed by the broad except, and a self-CONSISTENT x5c-backed card emits a
# SPURIOUS ACEF-083 in addition to the legitimate missing-timestamp diagnostic.
# ---------------------------------------------------------------------------


class TestIncidentTimestampCoercionP3:
    def test_omitted_timestamp_x5c_signed_card_no_spurious_083(self, tmp_path: Path) -> None:
        # RED (pre-fix): a v1.1 bundle that OMITS metadata.timestamp and carries a
        # self-consistent x5c-backed JWS attestation emits a SPURIOUS ACEF-083 —
        # package_timestamp="" reaches verify_x5c_chain, raises ACEF-012, is
        # swallowed, and _attestation_self_inconsistent returns True. The JWS is
        # actually fine. GREEN (post-fix): no ACEF-083; the x5c cert-validity anchor
        # is correctly SKIPPED ("" -> None) while the legitimate missing-timestamp
        # rejection remains.
        payload = {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
        }
        bundle = _build_incident_bundle(
            tmp_path,
            core_version="1.1.0",
            record_type="incident_card",
            payload=payload,
            sign_record=True,
            sign_with_x5c=True,
            omit_timestamp=True,
        )
        assessment = validate_bundle(bundle)
        assert "ACEF-083" not in _codes(assessment), (
            "spurious ACEF-083 on a missing-timestamp bundle whose x5c JWS is "
            "self-consistent — the empty package_timestamp must coerce to None "
            "(rule_engine sibling idiom)"
        )

    def test_present_timestamp_x5c_self_consistent_no_083(self, tmp_path: Path) -> None:
        # CONTROL (unchanged): WITH a valid metadata.timestamp + a self-consistent
        # x5c-backed JWS -> no ACEF-083 (the cert validity covers the timestamp).
        payload = {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
        }
        bundle = _build_incident_bundle(
            tmp_path,
            core_version="1.1.0",
            record_type="incident_card",
            payload=payload,
            sign_record=True,
            sign_with_x5c=True,
            omit_timestamp=False,
        )
        assessment = validate_bundle(bundle)
        assert "ACEF-083" not in _codes(assessment)

    def test_present_timestamp_x5c_tampered_still_raises_083(self, tmp_path: Path) -> None:
        # CONTROL (must NOT be suppressed by the fix): WITH a valid timestamp + a
        # GENUINELY self-INconsistent x5c-backed JWS (payload tampered after
        # signing) -> ACEF-083 STILL fires. The fix must not blunt real detection.
        payload = {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
        }
        bundle = _build_incident_bundle(
            tmp_path,
            core_version="1.1.0",
            record_type="incident_card",
            payload=payload,
            sign_record=True,
            sign_with_x5c=True,
            tamper_after_sign=True,
            omit_timestamp=False,
        )
        assessment = validate_bundle(bundle)
        errors = _errors_for(assessment, "ACEF-083")
        assert errors, "tampered x5c-signed card must STILL raise ACEF-083"
        assert any("offline-deterministic" in e.get("message", "") for e in errors)


# ---------------------------------------------------------------------------
# OECD voluntary profile: legal_force-aware ACEF-081 + advisory completeness
# (roborev Findings 1 & 2 — surfaced by the OECD profile, fixed in incident_rules)
# ---------------------------------------------------------------------------


def _oecd_crit_id(n: int) -> str:
    return f"oecd-crf-2025/{n}"


_OECD_MANDATORY = [1, 2, 3, 4, 7, 10, 11]


class TestOECDVoluntaryProfileEngine:
    def test_voluntary_oecd_missing_crosswalk_is_not_binding_error(self, tmp_path: Path) -> None:
        # Finding 1: an incident_card lacking taxonomy_crosswalk.oecd, validated
        # against the VOLUNTARY oecd profile, must NOT emit a binding ACEF-081
        # error (legal_force=voluntary). Any ACEF-081 emitted is advisory.
        payload = {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
        }
        bundle = _build_incident_bundle(tmp_path, core_version="1.1.0", record_type="incident_card", payload=payload)
        assessment = validate_bundle(bundle, profiles=["oecd-ai-incidents-2025"])
        binding_081 = [e for e in _errors_for(assessment, "ACEF-081") if e.get("severity") == "error"]
        assert not binding_081, "voluntary OECD profile produced a binding ACEF-081 error"

    def test_binding_art73_missing_crosswalk_still_errors(self, tmp_path: Path) -> None:
        # Regression: the SAME structural gap on the BINDING Art.73 profile still
        # raises ACEF-081 at ERROR severity.
        payload = {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
            "taxonomy_crosswalk": {"nist_ai_600_1": {"edition": "2024-07-final", "categories": []}},
        }
        bundle = _build_incident_bundle(tmp_path, core_version="1.1.0", record_type="incident_card", payload=payload)
        assessment = validate_bundle(bundle, profiles=["eu-ai-act-art73-2026"])
        error_081 = [e for e in _errors_for(assessment, "ACEF-081") if e.get("severity") == "error"]
        assert error_081, "binding Art.73 profile must still raise ACEF-081 at error severity"

    def test_oecd_member_missing_mandatory_criteria_surfaces_advisory(self, tmp_path: Path) -> None:
        # Finding 2: an OECD member present with edition but only criterion #1 ->
        # an advisory completeness diagnostic listing the missing mandatory ids,
        # never a binding error.
        payload = {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
            "taxonomy_crosswalk": {
                "oecd": {"edition": "oecd-crf-2025", "criteria": [{"id": _oecd_crit_id(1), "value": "x"}]}
            },
        }
        bundle = _build_incident_bundle(tmp_path, core_version="1.1.0", record_type="incident_card", payload=payload)
        assessment = validate_bundle(bundle, profiles=["oecd-ai-incidents-2025"])
        # Some advisory (warning/info) diagnostic listing the missing mandatory ids.
        advisory = [
            e
            for e in assessment.structural_errors
            if e.get("severity") in {"warning", "info"} and "oecd-crf-2025/10" in str(e.get("message", ""))
        ]
        assert advisory, "missing OECD mandatory criteria must surface an advisory completeness diagnostic"
        # And NO binding error code was raised for the voluntary completeness gap.
        assert all(e.get("severity") != "error" for e in advisory)

    def test_oecd_member_with_all_mandatory_no_advisory(self, tmp_path: Path) -> None:
        payload = {
            "public_incident_id": _VALID_ID,
            "id_grade": "self-asserted",
            "harm_core": dict(_VALID_HARM_CORE),
            "taxonomy_crosswalk": {
                "oecd": {
                    "edition": "oecd-crf-2025",
                    "criteria": [{"id": _oecd_crit_id(n), "value": f"v-{n}"} for n in _OECD_MANDATORY],
                }
            },
        }
        bundle = _build_incident_bundle(tmp_path, core_version="1.1.0", record_type="incident_card", payload=payload)
        assessment = validate_bundle(bundle, profiles=["oecd-ai-incidents-2025"])
        completeness = [
            e for e in assessment.structural_errors if e.get("details", {}).get("missing_mandatory_criteria")
        ]
        assert completeness == [], "a complete OECD member must not surface a completeness advisory"
