"""VAL-VEC-001/002/003 — RFC-0002 §6 incident conformance vectors.

This driver discovers and runs the v1.1-REQUIRED incident conformance vectors
under ``test-vectors/incident/`` through the PRODUCTION validator
(:func:`acef.validation.engine.validate_bundle`) and the OPTIONAL online
domain-control verifier (:func:`acef.domain_control.verify_domain_control`). It
covers exactly the two v1.1-REQUIRED conformance classes of RFC-0002 §6 —
**offline-deterministic** (card-only) and **source-backed** — plus the
``online-conformance`` ``reject`` outcome for the single forged-assigner vector
(VAL-VEC-002). The ``online-registry`` and ``public-registry-admission`` classes
are v1.2 (§11) and are NOT exercised here.

Vector layout (mirrors ``test-vectors/freddy/``):

    test-vectors/incident/
      vectors.json                 # the per-vector manifest (source of truth)
      generate.py                  # deterministic regenerator (no wall-clock/random)
      <class>/<disposition>/<name>.acef/
        acef-manifest.json
        records/<record_type>.jsonl
        hashes/content-hashes.json
        README.md                  # human-readable + the expected-code declaration
      <name>.acef.acef-assessment.json   # the expected assessment (codes only)

The ``vectors.json`` manifest declares, per vector: its conformance ``class``,
``disposition`` (pass | fail), the validation ``profiles`` the §6 class runs it
under (passed to ``validate_bundle(profiles=...)`` — NOT declared in the bundle
manifest, so the bundle stays minimal and no template-DSL diagnostics fire), the
``expect_codes`` membership set (fail vectors), the ``forbid_codes`` set (pass
vectors that must stay clean), and — for the two RESERVED-id death-clock vectors
(VAL-VEC-003) — the asserted ``clock_days`` (10 / 2) and ``no_public_card`` flag.

Determinism: every vector is a static on-disk byte-stable artifact (fixed
timestamps, fixed ids, sorted JSON). The driver re-validates them twice and
asserts the emitted code set is byte-stable across the two runs (VAL-VEC-001).
The online verifier runs against INJECTED in-memory DNS/HTTP stubs and a fixed
clock — never the real network.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from acef.domain_control import (
    DomainControlVerdict,
    challenge_token_for,
    verify_domain_control,
)
from acef.signing import _derive_jwk, create_detached_jws, verify_detached_jws
from acef.validation.engine import validate_bundle

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_INCIDENT_DIR = _REPO_ROOT / "test-vectors" / "incident"
_VECTORS_MANIFEST = _INCIDENT_DIR / "vectors.json"

# A fixed check-time instant for the OPTIONAL online verifier (no wall-clock).
_FIXED_NOW = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Vector-manifest loading.
# ---------------------------------------------------------------------------


def _load_vectors_manifest() -> list[dict[str, Any]]:
    if not _VECTORS_MANIFEST.is_file():
        return []
    data = json.loads(_VECTORS_MANIFEST.read_text(encoding="utf-8"))
    vectors = data.get("vectors")
    return vectors if isinstance(vectors, list) else []


_VECTORS = _load_vectors_manifest()


# The online-conformance class is NOT validated through the generic offline
# ``validate_bundle`` pass/fail path — its disposition (``reject``) is the ONLINE
# verifier's verdict, which the offline engine (which NEVER attributes the id)
# cannot and must not produce. Online-conformance vectors are exercised ONLY
# through ``verify_domain_control`` (see ``test_forged_assigner_*``), with the
# bundle separately asserted to PASS the offline class.
_OFFLINE_VALIDATABLE_CLASSES = {"offline-deterministic", "source-backed"}


def _vectors_for(disposition: str, *, conformance_class: str | None = None) -> list[dict[str, Any]]:
    out = []
    for v in _VECTORS:
        if v.get("disposition") != disposition:
            continue
        # Generic offline pass/fail parametrization runs vectors THROUGH the
        # offline ``validate_bundle``; the online-conformance class is routed
        # through the online verifier instead (Finding 1 — VAL-VEC-002).
        if str(v.get("class")) not in _OFFLINE_VALIDATABLE_CLASSES:
            continue
        if conformance_class is not None and v.get("class") != conformance_class:
            continue
        out.append(v)
    return sorted(out, key=lambda v: str(v.get("name")))


def _bundle_dir(vector: dict[str, Any]) -> Path:
    return _INCIDENT_DIR / str(vector.get("path"))


def _emitted_codes(assessment: Any) -> list[str]:
    return [str(e.get("code")) for e in assessment.structural_errors]


def _blocking_diags(assessment: Any) -> list[dict[str, Any]]:
    return [e for e in assessment.structural_errors if str(e.get("severity", "")).lower() in ("error", "fatal")]


def _validate(vector: dict[str, Any]) -> Any:
    profiles = vector.get("profiles")
    profiles = profiles if isinstance(profiles, list) and profiles else None
    return validate_bundle(_bundle_dir(vector), profiles=profiles)


def _validate_any(vector: dict[str, Any]) -> Any:
    """Run the OFFLINE ``validate_bundle`` on ANY vector regardless of its §6 class.

    ``_validate`` is reached only for the offline-validatable classes (the
    parametrization filters online-conformance off the generic path); the
    online-conformance vector still PASSES the offline class by design
    (VAL-DOMAIN-001), and this helper validates it directly so the committed
    offline-pass cross-check can be asserted."""
    return _validate(vector)


# ---------------------------------------------------------------------------
# Sanity: the manifest + at least the required vector families are present.
# ---------------------------------------------------------------------------


def test_vectors_manifest_present_and_nonempty() -> None:
    assert _VECTORS_MANIFEST.is_file(), (
        f"missing vectors manifest {_VECTORS_MANIFEST} — run "
        f"`python test-vectors/incident/generate.py` to materialize the vectors."
    )
    assert _VECTORS, "vectors.json declares no vectors"


def test_required_conformance_classes_only() -> None:
    """RFC-0002 §6: the v1.1-REQUIRED classes are offline-deterministic +
    source-backed; the only other class exercised here is the single
    online-conformance reject vector (VAL-VEC-002). online-registry /
    public-registry-admission (v1.2) MUST NOT appear."""
    allowed = {"offline-deterministic", "source-backed", "online-conformance"}
    seen = {str(v.get("class")) for v in _VECTORS}
    forbidden = seen - allowed
    assert not forbidden, f"v1.2 conformance classes leaked into v1.1 vectors: {sorted(forbidden)!r}"


def test_required_fail_codes_each_have_a_vector() -> None:
    """Every reserved incident error in the v1.1-required §8 set has at least one
    fail vector that triggers it: ACEF-081/082/083/084/085/086/088. ACEF-081's binding
    per-profile-attributed ERROR is exercised by fail-multi-profile-missing-member-081
    (the §6-enumerated multi-profile FAIL bundle); the OECD voluntary ACEF-081 stays an
    ADVISORY warning on its pass vector. ACEF-087 (near_miss INFO) is a PASS-with-info
    vector."""
    fail_codes: set[str] = set()
    for v in _vectors_for("fail"):
        fail_codes.update(str(c) for c in v.get("expect_codes", []))
    for required in ("ACEF-081", "ACEF-082", "ACEF-084", "ACEF-085", "ACEF-086", "ACEF-088"):
        assert required in fail_codes, f"no fail vector triggers {required}"
    # ACEF-083 is exercised by BOTH (a) the offline-class pattern-failure fail
    # vector (offline-deterministic) AND (b) the online-conformance forged-assigner
    # reject vector (verifier path). Either source satisfies the requirement; the
    # offline source is asserted directly here so the offline fail surface stays
    # covered even after the online vector moved off the generic fail path.
    assert "ACEF-083" in fail_codes, "no offline fail vector triggers ACEF-083 (pattern surface)"


# ---------------------------------------------------------------------------
# Finding 3 — EXACT inventory protection. The required vector NAMES, grouped by
# (class, disposition), MUST match an explicit expected set. Renaming or deleting
# a required vector — or silently adding one — FAILS this test. The on-disk vector
# directories MUST also match the manifest exactly (no silent drift).
# ---------------------------------------------------------------------------

# The exact required corpus, keyed (class, disposition) -> frozenset of names.
# This is the single authoritative inventory the driver enforces; it is kept in
# lockstep with ``generate.py`` ``_vector_specs()``.
_EXPECTED_INVENTORY: dict[tuple[str, str], frozenset[str]] = {
    ("offline-deterministic", "pass"): frozenset(
        {
            "pass-multi-profile-card",
            "pass-oecd-voluntary-advisory",
            "pass-near-miss-info",
            "pass-dedupe-key-public-card",
            "pass-hash-committed-card",
            "pass-v1-0-incident-report-regression",
        }
    ),
    ("offline-deterministic", "fail"): frozenset(
        {
            "fail-severity-vector-parse-082",
            "fail-public-id-offline-083",
            "fail-projection-edge-mismatch-083",
            "fail-projection-edge-root-id-bypass-083",
            "fail-harm-core-crosswalk-085",
            "fail-severity-band-088",
            "fail-publishability-086",
            "fail-multi-profile-missing-member-081",
        }
    ),
    ("source-backed", "pass"): frozenset(
        {
            "pass-art73-single-trigger",
            "pass-art73-compound-2day",
            "reserved-id-death-10day",
            "reserved-id-death-compound-2day",
            "pass-dedupe-key-omitted-non-public",
            "pass-dedupe-key-hmac-variant",
        }
    ),
    ("source-backed", "fail"): frozenset(
        {
            "fail-art73-compound-wrong-clock-084",
            "fail-dedupe-key-emit-non-public-086",
            "fail-dedupe-hmac-malformed-shape-086",
        }
    ),
    ("online-conformance", "reject"): frozenset(
        {
            "forged-assigner-online-reject-083",
        }
    ),
}


def test_exact_inventory_matches_manifest() -> None:
    """The (class, disposition) -> {names} grouping of ``vectors.json`` MUST equal
    the explicit expected inventory EXACTLY. Removing, renaming, or adding a
    required vector fails this test (Finding 3 — no silent corpus drift)."""
    actual: dict[tuple[str, str], set[str]] = {}
    for v in _VECTORS:
        key = (str(v.get("class")), str(v.get("disposition")))
        actual.setdefault(key, set()).add(str(v.get("name")))

    expected = {k: set(names) for k, names in _EXPECTED_INVENTORY.items()}
    assert actual.keys() == expected.keys(), (
        f"vector (class, disposition) groups changed: "
        f"unexpected={sorted(actual.keys() - expected.keys())!r} "
        f"missing={sorted(expected.keys() - actual.keys())!r}"
    )
    for key in expected:
        assert actual[key] == expected[key], (
            f"vector inventory for {key!r} drifted: "
            f"unexpected={sorted(actual[key] - expected[key])!r} "
            f"missing={sorted(expected[key] - actual[key])!r}"
        )


def test_on_disk_vector_dirs_match_manifest_exactly() -> None:
    """The set of ``*.acef`` vector directories ON DISK MUST equal exactly the set
    declared in ``vectors.json`` (Finding 3). A generated dir not in the manifest
    (stale drift) OR a manifest entry with no dir (dangling) fails this test."""
    manifest_dirs = {str(v.get("path")) for v in _VECTORS}
    on_disk: set[str] = set()
    for manifest_path in _INCIDENT_DIR.rglob("acef-manifest.json"):
        bundle = manifest_path.parent
        rel = bundle.relative_to(_INCIDENT_DIR).as_posix()
        on_disk.add(rel)

    assert on_disk == manifest_dirs, (
        f"on-disk vector dirs disagree with vectors.json: "
        f"stale-on-disk={sorted(on_disk - manifest_dirs)!r} "
        f"missing-on-disk={sorted(manifest_dirs - on_disk)!r} — "
        f"run `python test-vectors/incident/generate.py` to resync."
    )


def test_source_backed_incident_reports_are_non_public() -> None:
    """Finding 2: every SOURCE-BACKED ``incident_report`` vector (it carries the
    private ``card_source`` block + ``root_cause_analysis``) MUST be emitted
    NON-public on disk (e.g. ``regulator-only``), so the confidential block is not
    published. The public ``incident_card`` vectors stay ``public``."""
    source_backed = [v for v in _VECTORS if str(v.get("class")) == "source-backed"]
    assert source_backed, "no source-backed vectors present"
    for vector in source_backed:
        bundle_dir = _bundle_dir(vector)
        report_path = bundle_dir / "records" / "incident_report.jsonl"
        assert report_path.is_file(), f"{vector.get('name')!r} has no incident_report record"
        record = json.loads(report_path.read_text(encoding="utf-8").splitlines()[0])
        conf = record.get("confidentiality")
        assert conf is not None and conf != "public", (
            f"source-backed {vector.get('name')!r} published its confidential card_source as "
            f"confidentiality={conf!r}; it MUST be non-public (e.g. regulator-only)"
        )
        # The private block must still be carried on the (non-public) record so the
        # regulator-only consumer can read the Art.73 facts.
        assert "card_source" in record.get("payload", {}), (
            f"{vector.get('name')!r} lost its card_source block during regeneration"
        )


# ---------------------------------------------------------------------------
# VAL-VEC-001 — pass vectors validate clean (modulo INFO/advisory).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.conformance
@pytest.mark.parametrize(
    "vector",
    _vectors_for("pass"),
    ids=lambda v: str(v.get("name")),
)
def test_pass_vector_validates_clean(vector: dict[str, Any]) -> None:
    """A pass vector emits ZERO ERROR/FATAL diagnostics. INFO-severity diagnostics
    (e.g. ACEF-087 near_miss) and advisory (WARNING) diagnostics are permitted —
    they are explicitly non-binding (§5.5 / legal_force=voluntary)."""
    assessment = _validate(vector)
    blocking = _blocking_diags(assessment)
    assert not blocking, (
        f"pass vector {vector.get('name')!r} emitted ERROR/FATAL diagnostics (expected none):\n"
        + "\n".join(
            f"  {d.get('severity', '?')} {d.get('code', '?')}: {str(d.get('message', ''))[:200]}" for d in blocking
        )
    )
    # Pass vectors must NOT emit any code on their forbid list.
    emitted = set(_emitted_codes(assessment))
    forbidden = {str(c) for c in vector.get("forbid_codes", [])}
    leaked = emitted & forbidden
    assert not leaked, f"pass vector {vector.get('name')!r} emitted forbidden codes {sorted(leaked)!r}"


@pytest.mark.plumbing
@pytest.mark.conformance
def test_near_miss_pass_vector_surfaces_acef087_info() -> None:
    """The near_miss vector is a PASS (no ERROR/FATAL) but MUST surface ACEF-087 at
    INFO severity (§5.5 — informational marker, never a failure)."""
    near_miss = [v for v in _vectors_for("pass") if "ACEF-087" in {str(c) for c in v.get("info_codes", [])}]
    assert near_miss, "no near_miss pass vector declaring ACEF-087 as an info marker"
    for vector in near_miss:
        assessment = _validate(vector)
        info_087 = [
            e
            for e in assessment.structural_errors
            if str(e.get("code")) == "ACEF-087" and str(e.get("severity", "")).lower() == "info"
        ]
        assert info_087, f"{vector.get('name')!r} expected an ACEF-087 INFO marker"
        assert not _blocking_diags(assessment), f"{vector.get('name')!r} near_miss must not block"


# ---------------------------------------------------------------------------
# VAL-VEC-001 — fail vectors emit the expected ACEF code(s).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.conformance
@pytest.mark.parametrize(
    "vector",
    _vectors_for("fail"),
    ids=lambda v: str(v.get("name")),
)
def test_fail_vector_emits_expected_codes(vector: dict[str, Any]) -> None:
    """A fail vector emits every code in its ``expect_codes`` set (membership, not
    exclusivity — additional diagnostics are allowed) and none in ``forbid_codes``
    (e.g. ACEF-022 must NEVER substitute for a reserved ACEF-08x publishability
    code)."""
    expected = [str(c) for c in vector.get("expect_codes", [])]
    assert expected, f"fail vector {vector.get('name')!r} declares no expect_codes"
    assessment = _validate(vector)
    emitted = _emitted_codes(assessment)
    for code in expected:
        assert code in emitted, (
            f"fail vector {vector.get('name')!r} expected {code} but it was not emitted. "
            f"Emitted: {sorted(set(emitted))!r}\n"
            + "\n".join(
                f"  {d.get('severity', '?')} {d.get('code', '?')}: {str(d.get('message', ''))[:160]}"
                for d in assessment.structural_errors
            )
        )
    forbidden = {str(c) for c in vector.get("forbid_codes", [])}
    leaked = set(emitted) & forbidden
    assert not leaked, f"fail vector {vector.get('name')!r} emitted forbidden codes {sorted(leaked)!r}"


# ---------------------------------------------------------------------------
# VAL-VEC-001 — byte-stability across two runs.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.conformance
@pytest.mark.parametrize(
    "vector",
    sorted(_VECTORS, key=lambda v: str(v.get("name"))),
    ids=lambda v: str(v.get("name")),
)
def test_vector_validation_is_byte_stable(vector: dict[str, Any]) -> None:
    """Validating the SAME on-disk vector twice produces a byte-identical sorted
    diagnostic projection (code + severity + message). The vectors carry no
    wall-clock / random content, and validate_bundle derives its evaluation
    instant from the manifest timestamp, so the result is reproducible."""

    def _projection(assessment: Any) -> str:
        rows = sorted(
            (str(e.get("code")), str(e.get("severity")), str(e.get("message"))) for e in assessment.structural_errors
        )
        return json.dumps(rows, sort_keys=True, ensure_ascii=False)

    first = _projection(_validate(vector))
    second = _projection(_validate(vector))
    assert first == second, f"vector {vector.get('name')!r} validation is not byte-stable across two runs"


def test_committed_assessment_matches_emitted_codes() -> None:
    """Each vector's committed ``.acef-assessment.json`` records the SAME emitted
    code set the production validator emits now — proving the committed expected
    assessment is not stale.

    For the offline-validatable classes the committed ``emitted_codes`` is the
    offline ``validate_bundle`` output. The online-conformance forged-assigner
    vector is NOT routed through the offline pass/fail path (offline never
    attributes), so its committed ``emitted_codes`` records the OFFLINE-pass cross
    set (empty) and the ONLINE reject is carried separately on
    ``online_emitted_codes`` (asserted in
    :func:`test_online_conformance_committed_artifact_records_online_acef083`)."""
    for vector in sorted(_VECTORS, key=lambda v: str(v.get("name"))):
        expected_path = _INCIDENT_DIR / str(vector.get("assessment_path"))
        assert expected_path.is_file(), f"missing committed assessment for {vector.get('name')!r}: {expected_path}"
        committed = json.loads(expected_path.read_text(encoding="utf-8"))
        committed_codes = sorted(str(c) for c in committed.get("emitted_codes", []))
        if str(vector.get("class")) not in _OFFLINE_VALIDATABLE_CLASSES:
            # The online-conformance vector's committed ``emitted_codes`` is the
            # OFFLINE-pass cross set (empty). It is NOT routed through the offline
            # pass/fail driver path, but the bundle DOES pass offline by design
            # (VAL-DOMAIN-001), so cross-check it directly here.
            assert committed_codes == [], (
                f"online-conformance vector {vector.get('name')!r}: committed offline "
                f"emitted_codes must be [] (offline pass), got {committed_codes!r}"
            )
            live_codes = sorted(set(_emitted_codes(_validate_any(vector))))
            assert live_codes == [], (
                f"online-conformance vector {vector.get('name')!r}: offline validation must "
                f"emit no codes (offline pass by design), got {live_codes!r}"
            )
            continue
        live_codes = sorted(set(_emitted_codes(_validate(vector))))
        assert committed_codes == live_codes, (
            f"vector {vector.get('name')!r}: committed assessment codes {committed_codes!r} "
            f"!= live emitted codes {live_codes!r} — regenerate the vectors."
        )


def test_online_conformance_committed_artifact_records_online_acef083() -> None:
    """roborev fix: the forged-assigner ``online-conformance`` vector's COMMITTED
    assessment artifact (``assessment_path``) MUST be self-describing — a consumer
    reading ONLY the committed artifact (without re-running the optional online
    verifier) MUST see the expected ONLINE reject. Concretely the committed
    artifact records:

    * ``online_emitted_codes`` containing ``ACEF-083`` (the ONLINE verifier reject),
    * ``offline_emitted_codes`` == ``[]`` (the OFFLINE-pass cross-check),
    * an ``online_diagnostic`` carrying the byte-stable ACEF-083
      ``class: online-conformance`` reject the driver asserts, and
    * the legacy ``emitted_codes`` == ``[]`` (the offline-pass output, kept for the
      existing matcher).

    Previously the committed artifact recorded ``emitted_codes: []`` only (the
    offline output), so a consumer never saw the online ACEF-083 reject in the
    artifact — only in the README/driver. This test pins the artifact as the
    authoritative source for BOTH the offline pass and the online reject."""
    vector = _forged_vector()
    expected_path = _INCIDENT_DIR / str(vector.get("assessment_path"))
    assert expected_path.is_file(), f"missing committed assessment for {vector.get('name')!r}: {expected_path}"
    committed = json.loads(expected_path.read_text(encoding="utf-8"))

    online_codes = sorted(str(c) for c in committed.get("online_emitted_codes", []))
    assert "ACEF-083" in online_codes, (
        f"online-conformance committed artifact must record the ONLINE ACEF-083 reject in "
        f"online_emitted_codes; got {online_codes!r}"
    )

    offline_codes = committed.get("offline_emitted_codes")
    assert offline_codes == [], (
        f"online-conformance committed artifact must record an EMPTY offline_emitted_codes "
        f"(the offline-pass cross-check), got {offline_codes!r}"
    )
    # The legacy ``emitted_codes`` (consumed by the existing matcher) stays the
    # offline-pass output (empty).
    assert committed.get("emitted_codes") == [], (
        "online-conformance committed artifact's legacy emitted_codes must stay [] (offline pass)"
    )

    # The committed online diagnostic must be the ACEF-083 class:online-conformance reject.
    diag = committed.get("online_diagnostic")
    assert isinstance(diag, dict), f"committed artifact must carry an online_diagnostic object, got {diag!r}"
    assert diag.get("code") == "ACEF-083", f"online_diagnostic.code must be ACEF-083, got {diag.get('code')!r}"
    assert (diag.get("details") or {}).get("class") == "online-conformance", (
        f"online_diagnostic must be tagged class:online-conformance, got {(diag.get('details') or {}).get('class')!r}"
    )
    # The committed online_class fact stays consistent with the artifact.
    assert committed.get("offline_class") == "pass", (
        "online-conformance committed artifact must record offline_class=pass (the cross-check)"
    )


def test_online_conformance_committed_diagnostic_matches_live_verifier() -> None:
    """The committed ``online_diagnostic`` MUST equal the diagnostic the OPTIONAL
    online verifier produces NOW for the forged-assigner vector, under the same
    fixed clock + injected attacker proof the generator used — proving the
    committed online artifact is not stale and is reproduced deterministically by
    ``generate.py`` (byte-stable). The keys are FIXED deterministic EC keys (not
    randomly generated) so the diagnostic is byte-identical across runs."""
    vector = _forged_vector()
    expected_path = _INCIDENT_DIR / str(vector.get("assessment_path"))
    committed = json.loads(expected_path.read_text(encoding="utf-8"))
    committed_diag = committed.get("online_diagnostic")

    live = _online_reject_diagnostic_dict(vector)
    assert committed_diag == live, (
        f"committed online_diagnostic is stale: committed={committed_diag!r} != live={live!r} — "
        f"regenerate the vectors (`python test-vectors/incident/generate.py`)."
    )


# ---------------------------------------------------------------------------
# VAL-VEC-002 — forged-assigner: ONLINE class rejects (ACEF-083), OFFLINE passes.
# ---------------------------------------------------------------------------


def _gen_ec_key() -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1())


def _forged_vector() -> dict[str, Any]:
    forged = [v for v in _VECTORS if v.get("class") == "online-conformance"]
    assert forged, "no online-conformance forged-assigner vector declared"
    return forged[0]


def _load_generator() -> Any:
    """Import the vector generator module by file path (it lives under
    ``test-vectors/`` which is not an importable package). The generator owns the
    SINGLE deterministic computation of the forged-assigner online ACEF-083 reject
    diagnostic, so the committed-artifact cross-check uses the same code path the
    generator persisted from — no drift between the two."""
    import importlib.util

    gen_path = _INCIDENT_DIR / "generate.py"
    spec = importlib.util.spec_from_file_location("incident_generate", gen_path)
    assert spec is not None and spec.loader is not None, f"cannot load generator from {gen_path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _online_reject_diagnostic_dict(_vector: dict[str, Any]) -> dict[str, Any]:
    """The byte-stable ACEF-083 ``class: online-conformance`` reject diagnostic the
    OPTIONAL online verifier produces NOW for the forged-assigner card — computed
    through the generator's single source of truth (fixed keys + fixed clock +
    injected attacker proof)."""
    return _load_generator().online_reject_diagnostic_dict()  # type: ignore[no-any-return]


@pytest.mark.conformance
def test_forged_assigner_vector_is_labeled_online_reject() -> None:
    """Finding 1: the forged-assigner vector's PRIMARY ``disposition`` is the ONLINE
    outcome — ``reject`` — and it lives under the ``online-conformance/reject``
    tree, NOT under a ``pass`` tree. The OFFLINE-pass fact is carried on a SEPARATE
    ``offline_class: pass`` field (documenting the VAL-DOMAIN-001 cross-check), so a
    generic consumer reading the disposition classifies it as the required
    online-reject case, never as a pass."""
    vector = _forged_vector()
    assert vector.get("disposition") == "reject", (
        f"forged-assigner vector disposition must be the online outcome 'reject', got {vector.get('disposition')!r}"
    )
    assert str(vector.get("path", "")).startswith("online-conformance/reject/"), (
        f"forged-assigner vector must live under online-conformance/reject/, got {vector.get('path')!r}"
    )
    # The offline-pass fact is a SEPARATE field — not the disposition.
    assert vector.get("offline_class") == "pass", (
        "forged-assigner vector must record offline_class=pass (the offline cross-check)"
    )


@pytest.mark.conformance
def test_forged_assigner_passes_offline_class() -> None:
    """VAL-VEC-002 / cross-check VAL-DOMAIN-001: the forged ``AIIC-OPENAI-…`` card —
    a valid pattern signed by an attacker key, internally self-consistent — PASSES
    the OFFLINE-deterministic class (no ACEF-083), because the offline class NEVER
    attributes the id to the assigner domain. The vector's README documents this.

    The SAME bundle that the online verifier REJECTS is asserted here to PASS the
    offline class — proving the forged card's offline-pass / online-reject split."""
    vector = _forged_vector()
    assessment = _validate(vector)
    assert "ACEF-083" not in _emitted_codes(assessment), (
        "the offline class must NOT attribute the forged AIIC-OPENAI id to openai.com — "
        "a self-consistent forged card passes offline by design (§5.3)"
    )
    # Offline class emits ZERO ERROR/FATAL diagnostics for this bundle.
    assert not _blocking_diags(assessment), (
        "forged-assigner bundle must PASS the offline class with no ERROR/FATAL; got "
        + "; ".join(f"{d.get('code')}:{d.get('severity')}" for d in _blocking_diags(assessment))
    )
    # The vector declares its offline class fact as pass (separate from the
    # primary online ``reject`` disposition).
    assert vector.get("offline_class") == "pass"


@pytest.mark.conformance
def test_forged_assigner_rejected_online_class_acef083() -> None:
    """VAL-VEC-002: under the ONLINE class the forged card is REJECTED with ACEF-083
    ``class: online-conformance``. The attacker publishes a challenge-shaped DNS TXT
    proof bound to THEIR OWN key, not the card's registrant key — a presented-but-
    invalid proof → reject. The verifier runs against INJECTED in-memory stubs and a
    fixed clock; NO real network is touched."""
    vector = _forged_vector()
    public_incident_id = str(vector.get("public_incident_id"))
    assigner = str(vector.get("assigner"))

    # The card's legitimate registrant key (the key the card's JWS is signed with).
    card_key = _gen_ec_key()
    card_jwk = _derive_jwk(card_key)

    # Sanity: the card's own JWS is internally consistent (the offline-pass premise).
    payload_bytes = json.dumps({"public_incident_id": public_incident_id}, sort_keys=True).encode("utf-8")
    jws = create_detached_jws(payload_bytes, card_key, kid="card-kid")
    verify_detached_jws(jws, payload_bytes)

    # The attacker controls a DIFFERENT key and publishes a proof bound to it. This is
    # a presented-but-invalid proof for the CARD's key → reject (online-conformance).
    attacker_jwk = _derive_jwk(_gen_ec_key())
    attacker_proof = challenge_token_for(assigner, attacker_jwk)

    def dns_resolver(name: str) -> list[str]:
        return [attacker_proof]

    def no_http(url: str) -> Any:
        from acef.domain_control import HttpResponse

        return HttpResponse(status=404, content_type="", body="")

    result = verify_domain_control(
        public_incident_id,
        card_jwk,
        dns_resolver=dns_resolver,
        http_fetcher=no_http,
        now=_FIXED_NOW,
    )
    assert result.verdict is DomainControlVerdict.REJECT, (
        f"forged-assigner online check expected REJECT, got {result.verdict.value!r}"
    )
    assert result.diagnostic is not None
    assert result.diagnostic.code == "ACEF-083"
    assert result.diagnostic.details.get("class") == "online-conformance"


@pytest.mark.conformance
def test_forged_assigner_absent_proof_is_unverified_not_reject() -> None:
    """The online class returns ``unverified`` (NOT reject, NEVER a silent pass) when
    NO proof is presented and the lookups cannot complete — the explicit-non-result
    invariant the forged-assigner vector's README documents (§5.3)."""
    vector = _forged_vector()
    card_jwk = _derive_jwk(_gen_ec_key())

    def dns_timeout(name: str) -> list[str]:
        raise TimeoutError("DNS timed out")

    def http_timeout(url: str) -> Any:
        raise TimeoutError("HTTP timed out")

    result = verify_domain_control(
        str(vector.get("public_incident_id")),
        card_jwk,
        dns_resolver=dns_timeout,
        http_fetcher=http_timeout,
        now=_FIXED_NOW,
    )
    assert result.verdict is DomainControlVerdict.UNVERIFIED
    assert result.diagnostic is None


# ---------------------------------------------------------------------------
# VAL-VEC-003 — two RESERVED-id death-clock source-backed vectors (10d / 2d).
# ---------------------------------------------------------------------------


def _death_clock_vectors() -> list[dict[str, Any]]:
    return sorted(
        (v for v in _VECTORS if v.get("clock_days") in (10, 2) and v.get("no_public_card")),
        key=lambda v: int(v.get("clock_days")),
    )


def test_two_reserved_id_death_clock_vectors_exist() -> None:
    vectors = _death_clock_vectors()
    clocks = sorted(int(v.get("clock_days")) for v in vectors)
    assert clocks == [2, 10], f"expected RESERVED-id death-clock vectors for 2 and 10 days; got {clocks!r}"


@pytest.mark.conformance
@pytest.mark.parametrize(
    "vector",
    _death_clock_vectors(),
    ids=lambda v: f"{v.get('name')}-{v.get('clock_days')}d",
)
def test_reserved_id_death_clock_vector(vector: dict[str, Any]) -> None:
    """VAL-VEC-003: each RESERVED-id source-backed vector validates its Art.73 clock
    from ``card_source.eu_ai_act_facts`` (NO public incident_card present):

    - (a) ``death_involved: true`` → 10-day clock, deadline = awareness + 10d → no ACEF-084;
    - (b) compound ``death_involved: true`` + ``3.49.b`` → 2-day shortest clock → no ACEF-084.

    The clock-days assertion is proven directly via
    :func:`acef.validation.incident_rules.shortest_art73_clock_days` over the
    vector's own ``card_source.eu_ai_act_facts``, and end-to-end through
    ``validate_bundle`` (no ACEF-084, no public card)."""
    from acef.validation.incident_rules import shortest_art73_clock_days

    clock_days = int(vector.get("clock_days"))
    bundle_dir = _bundle_dir(vector)

    # No public incident_card record exists in this bundle (RESERVED id, confidential).
    record_types = sorted(p.stem for p in (bundle_dir / "records").glob("*.jsonl"))
    assert "incident_card" not in record_types, (
        f"{vector.get('name')!r} must be a RESERVED-id report with NO public incident_card; "
        f"found record files {record_types!r}"
    )

    # Read the source-backed facts straight from the on-disk record and assert the
    # shortest applicable clock the validator computes from them.
    report_path = bundle_dir / "records" / "incident_report.jsonl"
    record = json.loads(report_path.read_text(encoding="utf-8").splitlines()[0])
    facts = record["payload"]["card_source"]["eu_ai_act_facts"]
    assert shortest_art73_clock_days(facts) == clock_days, (
        f"{vector.get('name')!r}: expected {clock_days}-day shortest clock from eu_ai_act_facts {facts!r}"
    )

    # End-to-end: the bundle validates with NO ACEF-084 (the stated deadline equals
    # the shortest applicable clock).
    assessment = _validate(vector)
    assert "ACEF-084" not in _emitted_codes(assessment), (
        f"{vector.get('name')!r}: a correct {clock_days}-day clock must not raise ACEF-084:\n"
        + "\n".join(
            f"  {d.get('severity', '?')} {d.get('code', '?')}: {str(d.get('message', ''))[:200]}"
            for d in assessment.structural_errors
            if str(d.get("code")) == "ACEF-084"
        )
    )


# ---------------------------------------------------------------------------
# VAL-BUILD-DEDUPE-001 — §5.5 incident_dedupe_key emit/omit + recipe oracle.
#
# The four dedupe vectors prove: (a) a published card carries a CORRECT
# incident_dedupe_key whose value byte-equals the §5.5 recipe recomputed
# INDEPENDENTLY here; (b) a non-public record OMITS it (valid); (c) a forged
# non-public record that EMITS it FAILS with ACEF-086; (d) the keyed HMAC variant
# is byte-stable and valid on a non-public record. The recipe is recomputed from
# the vector's own declared inputs (carried on vectors.json), so a builder/
# validator drift that changed the preimage shape is caught at the conformance
# layer, not just in the unit oracle.
# ---------------------------------------------------------------------------


def _vector_by_name(name: str) -> dict[str, Any]:
    for v in _VECTORS:
        if v.get("name") == name:
            return v
    raise AssertionError(f"required dedupe vector {name!r} not declared in vectors.json")


def _payload_of_only_incident_record(vector: dict[str, Any]) -> dict[str, Any]:
    """Read the single incident record's payload from the vector's on-disk bundle."""
    bundle_dir = _bundle_dir(vector)
    record_type = str(vector.get("record_type"))
    record_path = bundle_dir / "records" / f"{record_type}.jsonl"
    assert record_path.is_file(), f"{vector.get('name')!r} missing {record_type}.jsonl"
    record = json.loads(record_path.read_text(encoding="utf-8").splitlines()[0])
    payload = record.get("payload")
    assert isinstance(payload, dict), f"{vector.get('name')!r} record has no payload object"
    return payload


def _independent_dedupe_key(recipe: dict[str, Any]) -> str:
    """Recompute the §5.5 key INDEPENDENTLY (object -> JCS -> SHA-256) from the
    vector's declared recipe inputs — NOT via the production helper."""
    import hashlib
    import unicodedata

    from acef.integrity import canonicalize

    provider, name, version = recipe["subject_identity"]
    triple = f"{provider}|{name}|{version}"
    preimage = {
        "value_chain_role": recipe["value_chain_role"],
        "subject_identity": unicodedata.normalize("NFC", triple).casefold(),
        "harm_class": recipe["harm_class"],
        "occurrence_date_utc": str(recipe["occurrence_date"])[:10],
    }
    return "sha256:" + hashlib.sha256(canonicalize(preimage)).hexdigest()


def _independent_dedupe_hmac(recipe: dict[str, Any]) -> str:
    import hashlib
    import hmac
    import unicodedata

    from acef.integrity import canonicalize

    provider, name, version = recipe["subject_identity"]
    triple = f"{provider}|{name}|{version}"
    preimage = {
        "value_chain_role": recipe["value_chain_role"],
        "subject_identity": unicodedata.normalize("NFC", triple).casefold(),
        "harm_class": recipe["harm_class"],
        "occurrence_date_utc": str(recipe["occurrence_date"])[:10],
    }
    pepper = bytes.fromhex(recipe["pepper_hex"])
    return "hmac-sha256:" + hmac.new(pepper, canonicalize(preimage), hashlib.sha256).hexdigest()


@pytest.mark.conformance
def test_public_card_dedupe_key_equals_independent_5_5_recipe() -> None:
    """(a) The PUBLISHED card's on-disk incident_dedupe_key byte-equals the §5.5
    recipe recomputed independently from the vector's declared inputs, and the card
    validates CLEAN (no ACEF-086)."""
    vector = _vector_by_name("pass-dedupe-key-public-card")
    payload = _payload_of_only_incident_record(vector)
    emitted = payload.get("incident_dedupe_key")
    assert emitted is not None, "the published dedupe vector must carry incident_dedupe_key"
    recipe = vector.get("dedupe_recipe")
    assert isinstance(recipe, dict), "the public dedupe vector must declare its dedupe_recipe"
    assert emitted == _independent_dedupe_key(recipe), (
        "the on-disk incident_dedupe_key does not equal the §5.5 recipe recomputed independently"
    )
    assert "ACEF-086" not in _emitted_codes(_validate(vector))


@pytest.mark.conformance
def test_non_public_record_omits_dedupe_key_and_passes() -> None:
    """(b) The non-public record OMITS the subject-bearing key and validates with no
    ACEF-086."""
    vector = _vector_by_name("pass-dedupe-key-omitted-non-public")
    payload = _payload_of_only_incident_record(vector)
    assert "incident_dedupe_key" not in payload, (
        "the non-public dedupe vector MUST OMIT the subject-bearing incident_dedupe_key (§5.5 Q20)"
    )
    assert "ACEF-086" not in _emitted_codes(_validate(vector))


@pytest.mark.conformance
def test_forged_emit_on_non_public_fails_086() -> None:
    """(c) The forged non-public record that EMITS incident_dedupe_key FAILS with
    ACEF-086 (the reserved §5.11 code, never ACEF-022)."""
    vector = _vector_by_name("fail-dedupe-key-emit-non-public-086")
    payload = _payload_of_only_incident_record(vector)
    # The forged record DOES carry the subject-bearing key on a non-public record.
    assert payload.get("incident_dedupe_key") is not None, (
        "the forged vector must EMIT incident_dedupe_key on its non-public record"
    )
    record_path = _bundle_dir(vector) / "records" / f"{vector.get('record_type')}.jsonl"
    record = json.loads(record_path.read_text(encoding="utf-8").splitlines()[0])
    assert record.get("confidentiality") not in (None, "public"), "the forged vector record must be non-public"
    codes = _emitted_codes(_validate(vector))
    assert "ACEF-086" in codes, f"a forged emit-on-non-public must raise ACEF-086; got {sorted(set(codes))!r}"
    assert "ACEF-022" not in codes, "the dedupe confidentiality gate must use ACEF-086, never ACEF-022"


@pytest.mark.conformance
def test_hmac_variant_equals_independent_recipe_and_passes() -> None:
    """(d) The keyed HMAC variant on a non-public record byte-equals the §5.5 HMAC
    recipe recomputed independently and validates CLEAN (no ACEF-086 — the keyed
    variant is exempt from the public-only omit rule)."""
    vector = _vector_by_name("pass-dedupe-key-hmac-variant")
    payload = _payload_of_only_incident_record(vector)
    emitted = payload.get("incident_dedupe_key_hmac")
    assert emitted is not None, "the HMAC dedupe vector must carry incident_dedupe_key_hmac"
    assert "incident_dedupe_key" not in payload, (
        "the HMAC vector must carry ONLY the keyed variant on its non-public record"
    )
    recipe = vector.get("dedupe_hmac_recipe")
    assert isinstance(recipe, dict), "the HMAC dedupe vector must declare its dedupe_hmac_recipe"
    assert emitted == _independent_dedupe_hmac(recipe), (
        "the on-disk incident_dedupe_key_hmac does not equal the §5.5 HMAC recipe recomputed independently"
    )
    assert "ACEF-086" not in _emitted_codes(_validate(vector))


@pytest.mark.conformance
def test_v1_0_regression_version_gate_is_load_bearing(tmp_path: Path) -> None:
    """The §6 v1.0 incident_report regression proves a REAL version gate, not an
    innocuous payload that both versions accept (roborev Low on 8db5635).

    The discriminator: the SAME bundle bytes — a public incident_report carrying a
    MALFORMED ``incident_dedupe_key`` (``sha256:short``, which the v1.1 §5.5 dedupe-shape
    rule rejects with ACEF-086) — differ ONLY in the declared manifest ``core_version``.
    The malformed key is force-injected AFTER ``pkg.record()`` so the SDK's ``_ensure_v1_1``
    auto-upgrade (which would otherwise drag any dedupe-bearing payload up to 1.1.0 and
    defeat the test) never fires; the manifest keeps the requested core_version.

    The engine routes the incident rules ONLY on the v1.1 schema path
    (``acef.validation.engine`` gates ``run_incident_rules`` on ``schema_version ==
    'v1.1'``):

      * core_version 1.0.0 -> schema_version v1 -> incident rules SKIPPED -> the malformed
        key is never shape-checked -> NO ACEF-086 (the v1.0 backward-compat path).
      * core_version 1.1.0 -> schema_version v1.1 -> rules RUN -> ACEF-086.

    Identical content, opposite outcomes keyed solely on the declared core_version: the
    version gate is load-bearing, so the committed clean v1.0 regression vector is clean
    BECAUSE it is routed to v1, not merely because its payload is innocuous."""
    gen = _load_generator()
    # The §6 v1.0 regression vector's own payload shape (v1.0 incident_report, no
    # v1.1-only card_source), kept in lockstep with the generator spec.
    base_payload = {
        "incident_type": "operational_failure",
        "severity": "major",
        "description": "A v1.0-shape incident report with no v1.1 card_source.",
        "notification_timeline": [
            {"recipient": "AI Office", "notification_date": gen._AWARENESS, "method": "portal_submission"}
        ],
    }
    outcomes: dict[str, tuple[str, set[str]]] = {}
    for core_version in ("1.0.0", "1.1.0"):
        bundle_dir = tmp_path / f"version-gate-{core_version}.acef"
        gen._build_bundle(
            bundle_dir,
            record_type="incident_report",
            payload=dict(base_payload),
            confidentiality="public",
            core_version=core_version,
            force_payload_fields={"incident_dedupe_key": "sha256:short"},
        )
        manifest = json.loads((bundle_dir / "acef-manifest.json").read_text(encoding="utf-8"))
        emitted = {str(e.get("code")) for e in validate_bundle(str(bundle_dir), profiles=[]).structural_errors}
        outcomes[core_version] = (str(manifest["versioning"]["core_version"]), emitted)

    # The injected key did NOT trigger the SDK auto-upgrade — each manifest kept its
    # requested core_version, so the two bundles differ ONLY by the declared version.
    assert outcomes["1.0.0"][0] == "1.0.0", "force-injected dedupe key must not auto-upgrade the v1.0 manifest"
    assert outcomes["1.1.0"][0] == "1.1.0"
    # v1.0 path: incident rules gated OFF -> the malformed dedupe key is NOT shape-checked.
    assert "ACEF-086" not in outcomes["1.0.0"][1], (
        "a malformed incident_dedupe_key under core_version 1.0.0 must NOT raise ACEF-086 — "
        "the v1.1 incident rules are gated off on the v1 schema path; the regression is "
        f"clean BECAUSE of the version gate. Got {sorted(outcomes['1.0.0'][1])!r}"
    )
    # v1.1 path: the SAME malformed key is shape-checked -> ACEF-086. Proves the gate matters.
    assert "ACEF-086" in outcomes["1.1.0"][1], (
        "the SAME malformed incident_dedupe_key under core_version 1.1.0 MUST raise ACEF-086 — "
        f"otherwise the version gate would be inert. Got {sorted(outcomes['1.1.0'][1])!r}"
    )
