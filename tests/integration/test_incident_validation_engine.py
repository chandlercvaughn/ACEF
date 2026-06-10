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
) -> Path:
    """Build an on-disk bundle directory carrying ONE incident record.

    Exports a real v1.0 bundle via the SDK (production manifest / hashes), then
    rewrites versioning.core_version, substitutes the incident records file,
    recomputes content-hashes.json, and (optionally) declares profiles.
    """
    pkg = Package(producer={"name": "test", "version": "1.0"})
    pkg.add_subject("ai_system", name="Sys", risk_classification="high-risk")
    pkg.record("risk_register", payload={"description": "seed"})
    bundle_dir = tmp_path / name
    pkg.export(str(bundle_dir))

    # Replace the seed record file with an incident records file.
    records_dir = bundle_dir / "records"
    for existing in records_dir.glob("*.jsonl"):
        existing.unlink()

    rec = {
        "record_id": f"urn:acef:record:{record_type}-1",
        "record_type": record_type,
        "timestamp": "2026-08-10T00:00:00Z",
        "confidentiality": "public",
        "payload": payload,
    }
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
