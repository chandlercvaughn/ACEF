"""Integration tests — trust-anchor threading through the bundle-validation
pipeline (VAL-FIX-LOADER-005, audit finding loader-roundtrip-5).

Spec §3.1.3 "Signature trust model (normative)": "If x5c is present,
verifiers MUST validate the full certificate chain against a locally
configured set of trust anchors."

Before this fix, ``validate_bundle`` / ``check_integrity`` accepted no
trust-anchor configuration and called ``verify_detached_jws`` without
``trust_anchors`` — anchor termination was structurally unreachable from the
standard validation pipeline, so a self-issued internally-consistent x5c
chain passed the integrity phase with no anchor enforcement (RED proof:
``validate_bundle(..., trust_anchors=[...])`` raised TypeError before the
threading existed).

After the fix:
- ``validate_bundle(bundle, trust_anchors=[root])`` on a bundle signed with
  an x5c chain terminating at ``root`` -> clean (no signature diagnostics).
- The same call against a self-issued chain NOT terminating at any
  configured anchor -> ACEF-012 signature diagnostic.
- Default (``trust_anchors`` omitted) preserves today's behavior EXACTLY:
  self-attested trust, no anchor enforcement (backward compatibility — the
  frozen golden bundles carry no x5c, so default-None is behavior-neutral).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acef.integrity import canonicalize, canonicalize_json_str, compute_content_hashes
from acef.models.enums import RuleOutcome
from acef.package import Package
from acef.signing import create_detached_jws
from acef.templates import registry as templates_registry
from acef.validation.engine import validate_bundle
from acef.validation.integrity_checker import check_integrity, get_signature_info

_SIGNATURE_CODES = ("ACEF-012", "ACEF-013")


def _make_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _make_cert(
    subject_cn: str,
    *,
    public_key: ec.EllipticCurvePublicKey,
    signing_key: ec.EllipticCurvePrivateKey,
    issuer_cn: str | None = None,
    ca: bool = False,
) -> x509.Certificate:
    """Build a cert whose validity window covers the bundle's (wall-clock)
    manifest timestamp — exported bundles stamp metadata.timestamp at export
    time, and verify_x5c_chain checks cert validity against that value.

    ``ca=True`` adds BasicConstraints ca=True + KeyUsage keyCertSign —
    required for any cert in the ISSUER role now that verify_x5c_chain
    enforces RFC 5280 path constraints on issuers.
    """
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or subject_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=365))
        .not_valid_after(now + timedelta(days=3650))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    return builder.sign(signing_key, hashes.SHA256())


def _b64(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")


def _export_bundle(tmp_path: Path) -> Path:
    """Export a minimal valid bundle (unsigned)."""
    pkg = Package(producer={"name": "x5c-anchor-test", "version": "1.0.0"})
    system = pkg.add_subject(
        "ai_system",
        name="Anchor Test System",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )
    pkg.record(
        "risk_register",
        provisions=["article-9"],
        payload={"description": "Test risk", "likelihood": "medium", "severity": "high"},
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    bundle_dir = tmp_path / "bundle.acef"
    pkg.export(str(bundle_dir))
    return bundle_dir


def _sign_bundle_with_x5c(
    bundle_dir: Path,
    leaf_key: ec.EllipticCurvePrivateKey,
    x5c: list[str],
) -> None:
    """Write an x5c detached JWS over the bundle's canonicalized
    content-hashes.json into signatures/ (mirrors signing.sign_bundle, which
    only supports jwk headers). signatures/ is OUTSIDE the hash domain, so
    adding it post-export does not perturb content hashes."""
    content_hashes_path = bundle_dir / "hashes" / "content-hashes.json"
    payload = canonicalize_json_str(content_hashes_path.read_text(encoding="utf-8"))
    jws = create_detached_jws(payload, leaf_key, kid="x5c-anchor-key", x5c=x5c)
    sig_dir = bundle_dir / "signatures"
    sig_dir.mkdir(exist_ok=True)
    (sig_dir / "x5c-anchor-key.jws").write_text(jws, encoding="utf-8")


def _build_anchored_chain() -> tuple[ec.EllipticCurvePrivateKey, list[str], x509.Certificate]:
    """leaf <- intermediate <- root, with intermediate/root as PROPER CA
    certs (verify_x5c_chain enforces RFC 5280 issuer path constraints).
    Returns (leaf_key, x5c, root_cert)."""
    root_key = _make_key()
    inter_key = _make_key()
    leaf_key = _make_key()
    root = _make_cert("pipeline-root", public_key=root_key.public_key(), signing_key=root_key, ca=True)
    inter = _make_cert(
        "pipeline-intermediate",
        public_key=inter_key.public_key(),
        signing_key=root_key,
        issuer_cn="pipeline-root",
        ca=True,
    )
    leaf = _make_cert(
        "pipeline-leaf",
        public_key=leaf_key.public_key(),
        signing_key=inter_key,
        issuer_cn="pipeline-intermediate",
    )
    return leaf_key, [_b64(leaf), _b64(inter), _b64(root)], root


def _build_self_issued_chain() -> tuple[ec.EllipticCurvePrivateKey, list[str]]:
    """A self-signed single-cert chain — internally consistent, anyone can
    mint one. Returns (leaf_key, x5c)."""
    key = _make_key()
    cert = _make_cert("self-issued-signer", public_key=key.public_key(), signing_key=key)
    return key, [_b64(cert)]


def _signature_diags(assessment_errors: list[dict[str, object]]) -> list[dict[str, object]]:
    return [e for e in assessment_errors if e.get("code") in _SIGNATURE_CODES]


class TestValidateBundleTrustAnchors:
    def test_anchored_x5c_bundle_validates_clean(self, tmp_path: Path) -> None:
        """End-to-end plumbing: a bundle signed with an x5c chain terminating
        at the configured anchor produces NO signature diagnostics."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = validate_bundle(str(bundle_dir), trust_anchors=[root])
        assert _signature_diags(assessment.structural_errors) == []

    def test_self_issued_x5c_rejected_when_anchors_configured(self, tmp_path: Path) -> None:
        """THE pipeline fix (RED-first): a self-issued, internally-consistent
        x5c chain MUST be rejected when trust anchors are configured and the
        chain does not terminate at any of them. Before the threading existed
        this call raised TypeError (no ``trust_anchors`` parameter) — anchor
        enforcement was structurally unreachable from validate_bundle."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        # An unrelated root is configured — the self-issued chain must NOT
        # anchor to it.
        _, _, unrelated_root = _build_anchored_chain()
        assessment = validate_bundle(str(bundle_dir), trust_anchors=[unrelated_root])

        diags = _signature_diags(assessment.structural_errors)
        assert len(diags) == 1, f"expected exactly one signature diagnostic, got: {diags!r}"
        assert diags[0]["code"] == "ACEF-012"
        assert "trust anchor" in str(diags[0]["message"])
        assert "x5c-anchor-key.jws" in str(diags[0]["message"])

    def test_default_no_anchors_preserves_self_attested_behavior(self, tmp_path: Path) -> None:
        """Backward compatibility: WITHOUT trust_anchors the same self-issued
        bundle still passes the integrity phase (self-attested trust per the
        spec trust model — absent locally configured anchors, the signature
        proves data integrity, not organizational identity)."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = validate_bundle(str(bundle_dir))
        assert _signature_diags(assessment.structural_errors) == []

    def test_anchored_and_default_produce_identical_diagnostics(self, tmp_path: Path) -> None:
        """For a properly anchored bundle, validating WITH anchors yields the
        same diagnostic set as validating WITHOUT (the anchor check adds no
        false positives)."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        with_anchors = validate_bundle(str(bundle_dir), trust_anchors=[root])
        without_anchors = validate_bundle(str(bundle_dir))
        assert with_anchors.structural_errors == without_anchors.structural_errors


class TestCheckIntegrityTrustAnchors:
    def test_check_integrity_rejects_unanchored_chain(self, tmp_path: Path) -> None:
        """Phase-2 entry point: check_integrity itself enforces anchor
        termination when anchors are supplied."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        _, _, unrelated_root = _build_anchored_chain()
        diagnostics = check_integrity(bundle_dir, trust_anchors=[unrelated_root])
        sig_diags = [d for d in diagnostics if d.code == "ACEF-012"]
        assert len(sig_diags) == 1
        assert "trust anchor" in sig_diags[0].message

    def test_check_integrity_default_unchanged(self, tmp_path: Path) -> None:
        """Default call (no anchors) — no signature diagnostics for the same
        self-issued bundle, preserving today's behavior exactly."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        diagnostics = check_integrity(bundle_dir)
        assert [d for d in diagnostics if d.code in _SIGNATURE_CODES] == []

    def test_check_integrity_accepts_anchored_chain(self, tmp_path: Path) -> None:
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        diagnostics = check_integrity(bundle_dir, trust_anchors=[root])
        assert [d for d in diagnostics if d.code in _SIGNATURE_CODES] == []


# --------------------------------------------------------------------------
# Cross-phase consistency (roborev Medium finding on d80198be):
# trust_anchors previously reached check_integrity (Phase 2) ONLY, while
# get_signature_info — which feeds bundle_signed rules (Phase 4) and the
# v1.1 causation-chain check (Phase 3b) — ignored anchors. An unanchored
# x5c signature therefore emitted ACEF-012 in Phase 2 yet still COUNTED
# as verified for bundle_signed and causation-chain purposes.
# --------------------------------------------------------------------------


class TestGetSignatureInfoTrustAnchors:
    def test_unanchored_sig_not_counted_when_anchors_configured(self, tmp_path: Path) -> None:
        """get_signature_info MUST apply the same trust configuration as the
        integrity phase: with anchors configured, an x5c signature whose
        chain does not terminate at any anchor is NOT counted."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        _, _, unrelated_root = _build_anchored_chain()
        count, algs = get_signature_info(bundle_dir, trust_anchors=[unrelated_root])
        assert (count, algs) == (0, [])

    def test_anchored_sig_counted_with_matching_anchor(self, tmp_path: Path) -> None:
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        count, algs = get_signature_info(bundle_dir, trust_anchors=[root])
        assert (count, algs) == (1, ["ES256"])

    def test_default_counts_self_attested_sig(self, tmp_path: Path) -> None:
        """Regression: default (no anchors) preserves today's behavior — the
        self-issued x5c signature still counts as verified."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        count, algs = get_signature_info(bundle_dir)
        assert (count, algs) == (1, ["ES256"])


# --------------------------------------------------------------------------
# Phase-4 consistency: a bundle_signed rule must agree with the
# integrity phase about whether the bundle is signed.
# --------------------------------------------------------------------------

_PROBE_TEMPLATE_ID = "x5c-anchor-bundle-signed-probe"
_PROBE_RULE_ID = "probe-bundle-signed"

_PROBE_TEMPLATE: dict[str, object] = {
    "template_id": _PROBE_TEMPLATE_ID,
    "template_name": "x5c anchor probe — bundle_signed cross-phase consistency",
    "version": "1.0.0",
    "jurisdiction": "TEST",
    "source_legislation": "test fixture (not a regulation)",
    "instrument_type": "guidance",
    "legal_force": "binding",
    "instrument_status": "final",
    "default_effective_date": "2020-01-01",
    "applicable_system_types": ["high-risk"],
    "provisions": [
        {
            "provision_id": "probe-signature",
            "provision_name": "Bundle signature",
            "description": "The bundle must carry at least one verified signature",
            "effective_date": "2020-01-01",
            "evaluation_scope": "package",
            "evaluation": [
                {
                    "rule_id": _PROBE_RULE_ID,
                    "rule": "bundle_signed",
                    "params": {"min_signatures": 1},
                    "severity": "fail",
                    "message": "Bundle must carry at least one verified signature",
                }
            ],
        }
    ],
}


@pytest.fixture
def bundle_signed_template(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Register a throwaway template carrying a single bundle_signed rule.

    No SHIPPED template uses the bundle_signed operator, so the Phase-4
    threading can only be exercised through a fixture template. The
    registry's template directory is redirected for the duration of the
    test and the lru_cache is cleared on both sides so no cached entry
    leaks across tests (clear_template_cache exists precisely for this —
    see acef.templates.registry).
    """
    template_dir = tmp_path / "probe-templates"
    template_dir.mkdir()
    (template_dir / f"{_PROBE_TEMPLATE_ID}.json").write_text(json.dumps(_PROBE_TEMPLATE), encoding="utf-8")
    monkeypatch.setattr(templates_registry, "_get_template_dir", lambda: template_dir)
    templates_registry.clear_template_cache()
    yield _PROBE_TEMPLATE_ID
    templates_registry.clear_template_cache()


def _probe_rule_outcome(assessment: object) -> RuleOutcome:
    results = [r for r in assessment.results if r.rule_id == _PROBE_RULE_ID]  # type: ignore[attr-defined]
    assert len(results) == 1, f"expected exactly one {_PROBE_RULE_ID} result, got {results!r}"
    return results[0].outcome  # type: ignore[no-any-return]


class TestBundleSignedRuleTrustAnchors:
    def test_unanchored_sig_fails_bundle_signed_when_anchors_configured(
        self, tmp_path: Path, bundle_signed_template: str
    ) -> None:
        """THE cross-phase fix (RED-first): with anchors configured, an
        unanchored x5c signature emits ACEF-012 in Phase 2 — so it must NOT
        count for a bundle_signed rule in Phase 4. Before the fix the rule
        PASSED while the integrity phase rejected the very same signature."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        _, _, unrelated_root = _build_anchored_chain()
        assessment = validate_bundle(
            str(bundle_dir),
            profiles=[bundle_signed_template],
            trust_anchors=[unrelated_root],
        )
        # Phase 2 rejected the signature...
        assert len(_signature_diags(assessment.structural_errors)) == 1
        # ...and Phase 4 now agrees: the bundle does not count as signed.
        assert _probe_rule_outcome(assessment) == RuleOutcome.FAILED

    def test_unanchored_sig_passes_bundle_signed_without_anchors(
        self, tmp_path: Path, bundle_signed_template: str
    ) -> None:
        """Regression: default (no anchors) — the same self-issued signature
        still satisfies bundle_signed (self-attested trust)."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = validate_bundle(str(bundle_dir), profiles=[bundle_signed_template])
        assert _signature_diags(assessment.structural_errors) == []
        assert _probe_rule_outcome(assessment) == RuleOutcome.PASSED

    def test_anchored_sig_passes_bundle_signed_with_anchors(self, tmp_path: Path, bundle_signed_template: str) -> None:
        """A properly anchored signature satisfies bundle_signed when the
        matching anchor is configured (no false negatives)."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = validate_bundle(
            str(bundle_dir),
            profiles=[bundle_signed_template],
            trust_anchors=[root],
        )
        assert _signature_diags(assessment.structural_errors) == []
        assert _probe_rule_outcome(assessment) == RuleOutcome.PASSED


# --------------------------------------------------------------------------
# Phase-3b consistency: the v1.1 causation-chain check reads the verified-
# signature count — it must see the SAME count as the integrity phase.
# --------------------------------------------------------------------------

_UPSTREAM_URN = "urn:acef:rec:aaaa0000-0000-0000-0000-000000000001"
_DOWNSTREAM_URN = "urn:acef:rec:aaaa0000-0000-0000-0000-000000000002"


def _export_v1_1_causation_bundle(tmp_path: Path) -> Path:
    """Hand-write a v1.1 bundle whose downstream record's causation_chain
    references the in-bundle upstream record.

    Records are JCS-canonical JSONL; content-hashes.json is computed with
    the SAME acef.integrity routine the validator uses, so the integrity
    phase verifies clean and the only variable under test is whether the
    signature counts as verified.
    """
    bundle_dir = tmp_path / "bundle-v11.acef"
    (bundle_dir / "records").mkdir(parents=True)

    def _record(record_id: str, causation_chain: list[str] | None = None) -> dict[str, object]:
        rec: dict[str, object] = {
            "record_id": record_id,
            "record_type": "risk_register",
            "provisions_addressed": [],
            "timestamp": "2026-01-01T00:00:00Z",
            "lifecycle_phase": "development",
            "collector": {"name": "x5c-anchor-test", "version": "1.0.0"},
            "obligation_role": "provider",
            "confidentiality": "public",
            "trust_level": "self-attested",
            "entity_refs": {
                "subject_refs": [],
                "component_refs": [],
                "dataset_refs": [],
                "actor_refs": [],
            },
            "payload": {
                "risk_id": "risk-001",
                "category": "safety",
                "description": "Test risk",
                "likelihood": "possible",
                "severity": "major",
            },
            "attachments": [],
        }
        if causation_chain is not None:
            rec["causation_chain"] = causation_chain
        return rec

    records = [_record(_UPSTREAM_URN), _record(_DOWNSTREAM_URN, causation_chain=[_UPSTREAM_URN])]
    lines = b"".join(canonicalize(r) + b"\n" for r in records)
    (bundle_dir / "records" / "risk_register.jsonl").write_bytes(lines)

    manifest = {
        "metadata": {
            "package_id": "urn:acef:pkg:aaaa0000-0000-0000-0000-00000000000f",
            "created_at": "2026-01-01T00:00:00Z",
            "timestamp": "2026-01-01T00:00:00Z",
            "producer": {"name": "x5c-anchor-test", "version": "1.0.0"},
        },
        "versioning": {"core_version": "1.1.0", "profiles_version": "1.0.0"},
        "subjects": [
            {
                "subject_id": "urn:acef:sub:aaaa0000-0000-0000-0000-0000000000ab",
                "subject_type": "ai_system",
                "name": "Causation Test System",
                "version": "1.0.0",
                "provider": "x5c-anchor-test",
                "risk_classification": "high-risk",
                "modalities": ["text"],
                "lifecycle_phase": "deployment",
                "lifecycle_timeline": [],
            }
        ],
        "entities": {"components": [], "datasets": [], "actors": [], "relationships": []},
        "profiles": [],
        "record_files": [{"path": "records/risk_register.jsonl", "record_type": "risk_register", "count": 2}],
        "audit_trail": [],
    }
    (bundle_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    hashes_dir = bundle_dir / "hashes"
    hashes_dir.mkdir()
    (hashes_dir / "content-hashes.json").write_text(json.dumps(compute_content_hashes(bundle_dir)), encoding="utf-8")
    return bundle_dir


def _codes(assessment: object) -> list[str]:
    return [d.get("code") for d in assessment.structural_errors]  # type: ignore[attr-defined]


class TestCausationChainSignatureCountTrustAnchors:
    def test_unanchored_sig_with_anchors_emits_acef_073(self, tmp_path: Path) -> None:
        """RED-first: with anchors configured, the unanchored signature does
        not count — the in-bundle causation chain is on an effectively
        UNSIGNED bundle, so ACEF-073 MUST fire (it previously did not,
        because the Phase-3b count ignored anchors while Phase 2 rejected
        the signature with ACEF-012)."""
        bundle_dir = _export_v1_1_causation_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        _, _, unrelated_root = _build_anchored_chain()
        assessment = validate_bundle(str(bundle_dir), trust_anchors=[unrelated_root])
        codes = _codes(assessment)
        assert "ACEF-012" in codes, f"expected Phase-2 ACEF-012, got: {codes!r}"
        assert "ACEF-073" in codes, f"expected ACEF-073 (count agrees with Phase 2), got: {codes!r}"

    def test_unanchored_sig_without_anchors_no_acef_073(self, tmp_path: Path) -> None:
        """Regression: default (no anchors) — the self-attested signature
        counts, the causation chain resolves, no ACEF-073 and no ACEF-012."""
        bundle_dir = _export_v1_1_causation_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = validate_bundle(str(bundle_dir))
        codes = _codes(assessment)
        assert "ACEF-012" not in codes
        assert "ACEF-073" not in codes

    def test_anchored_sig_with_anchors_no_acef_073(self, tmp_path: Path) -> None:
        bundle_dir = _export_v1_1_causation_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = validate_bundle(str(bundle_dir), trust_anchors=[root])
        codes = _codes(assessment)
        assert "ACEF-012" not in codes
        assert "ACEF-073" not in codes


# --------------------------------------------------------------------------
# Expected-producer binding (PhD-review finding 2 / spec Appendix D.3):
# an ANCHORED signature whose leaf subject does not match a configured
# expected producer is the "valid signature, wrong signer" case and MUST
# emit ACEF-012 during normal validate_bundle() — closing the gap where a
# valid anchored cert from any party was accepted as the producer's.
# --------------------------------------------------------------------------


class TestExpectedProducerBinding:
    def test_anchored_subject_matches_expected_producer_clean(self, tmp_path: Path) -> None:
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()  # leaf CN == "pipeline-leaf"
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = validate_bundle(str(bundle_dir), trust_anchors=[root], expected_producer="CN=pipeline-leaf")
        assert _signature_diags(assessment.structural_errors) == []

    def test_anchored_wrong_subject_emits_acef_012(self, tmp_path: Path) -> None:
        """RED-first: anchored, but the configured expected producer is NOT the
        leaf subject — validate_bundle MUST flag it (was silent before)."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = validate_bundle(str(bundle_dir), trust_anchors=[root], expected_producer="evil-corp")
        diags = _signature_diags(assessment.structural_errors)
        assert len(diags) == 1, f"expected one wrong-signer diagnostic, got {diags!r}"
        assert diags[0]["code"] == "ACEF-012"
        assert "wrong signer" in str(diags[0]["message"])

    def test_match_is_exact_not_substring(self, tmp_path: Path) -> None:
        """'pipeline' is a substring of the 'pipeline-leaf' subject CN but is NOT
        an exact match — a substring matcher would wrongly accept it. The exact-CN
        matcher rejects it, so an ACEF-012 wrong-signer diagnostic fires."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = validate_bundle(str(bundle_dir), trust_anchors=[root], expected_producer="pipeline")
        diags = _signature_diags(assessment.structural_errors)
        assert len(diags) == 1 and diags[0]["code"] == "ACEF-012"

    def test_no_expected_producer_is_integrity_only(self, tmp_path: Path) -> None:
        """Backward compatibility: without expected_producer the anchored bundle
        validates clean (the binding is reported, not enforced)."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        assessment = validate_bundle(str(bundle_dir), trust_anchors=[root])
        assert _signature_diags(assessment.structural_errors) == []

    def test_self_attested_not_flagged_even_with_expected_producer(self, tmp_path: Path) -> None:
        """A self-attested (unanchored) signature is integrity-only by definition;
        the expected-producer check applies only to ANCHORED signatures, so no
        wrong-signer diagnostic fires (the absence of anchoring is the story, and
        without trust anchors there is no anchored signature to bind)."""
        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c = _build_self_issued_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        # No trust anchors -> the signature is self-attested; expected_producer
        # has nothing anchored to check, so no wrong-signer ACEF-012.
        assessment = validate_bundle(str(bundle_dir), expected_producer="anyone")
        assert _signature_diags(assessment.structural_errors) == []

    def test_public_validate_api_threads_expected_producer(self, tmp_path: Path) -> None:
        """roborev on 04efe61 (High): the binding must be enforceable through the
        PUBLIC acef.validate() wrapper, not only validate_bundle(). A wrong expected
        producer through the public API must surface ACEF-012."""
        import acef

        bundle_dir = _export_bundle(tmp_path)
        leaf_key, x5c, root = _build_anchored_chain()
        _sign_bundle_with_x5c(bundle_dir, leaf_key, x5c)

        wrong = acef.validate(str(bundle_dir), trust_anchors=[root], expected_producer="evil-corp")
        diags = _signature_diags(wrong.structural_errors)
        assert len(diags) == 1 and diags[0]["code"] == "ACEF-012"
        right = acef.validate(str(bundle_dir), trust_anchors=[root], expected_producer="CN=pipeline-leaf")
        assert _signature_diags(right.structural_errors) == []
