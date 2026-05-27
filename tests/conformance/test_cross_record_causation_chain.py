"""causation_chain URN resolution → ACEF-073.

Covers:
- VAL-VALIDATION-005: in-bundle URN in causation_chain but bundle unsigned → ACEF-073
- VAL-VALIDATION-EXTERNAL-URN-001: external URN declared in
  manifest.namespaces['x-external'].bundleReferences → resolves clean (no ACEF-073)
- VAL-VALIDATION-EXTERNAL-URN-002: external URN NOT declared → ACEF-073

Signature counting comes from `acef.validation.integrity_checker.get_signature_info`,
which counts only cryptographically-verified JWS files in `signatures/`. Since
our test bundles have no signatures/ directory, `signature_count == 0` —
which is the unsigned condition.
"""

from __future__ import annotations

from pathlib import Path

from acef.validation.engine import validate_bundle
from tests.conformance._v1_1_bundle_helpers import (
    base_manifest,
    base_record,
    codes,
    write_bundle,
)

# VAL-VALIDATION-005


def test_in_bundle_urn_in_causation_chain_but_unsigned_emits_acef_073(
    tmp_path: Path,
) -> None:
    """A causation_chain URN that points at an in-bundle record but the
    bundle is unsigned → ACEF-073 (cannot trust the chain on an
    unsigned bundle).
    """
    bundle = tmp_path / "unsigned-in-bundle-chain"
    upstream_id = "urn:acef:rec:80000000-0000-0000-0000-000000000001"
    downstream_id = "urn:acef:rec:80000000-0000-0000-0000-000000000002"
    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(record_id=upstream_id),
            base_record(record_id=downstream_id, causation_chain=[upstream_id]),
        ],
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-073" in found, f"Expected ACEF-073 for unsigned in-bundle causation chain, got: {found!r}"

    # Diagnostic should mention the URN and "unsigned".
    messages = [d["message"] for d in assessment.structural_errors if d.get("code") == "ACEF-073"]
    assert any(upstream_id in m for m in messages), f"Expected diagnostic mentioning {upstream_id!r}; got: {messages!r}"
    assert any("unsigned" in m for m in messages), f"Expected diagnostic mentioning 'unsigned'; got: {messages!r}"


def test_causation_chain_absent_no_acef_073(tmp_path: Path) -> None:
    """Records without causation_chain do not trigger ACEF-073."""
    bundle = tmp_path / "no-causation-chain"
    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:90000000-0000-0000-0000-000000000001",
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    assert "ACEF-073" not in codes(assessment.structural_errors)


# VAL-VALIDATION-EXTERNAL-URN-001


def test_external_urn_declared_in_bundle_references_resolves_clean(
    tmp_path: Path,
) -> None:
    """A causation_chain URN that points at a record in an externally-
    referenced bundle (declared in `manifest.namespaces['x-external']
    .bundleReferences`) MUST validate clean — no ACEF-073.
    """
    bundle = tmp_path / "external-declared"
    external_urn = "urn:acef:rec:cafe1111-1111-1111-1111-111111111111"

    manifest = base_manifest(
        namespaces={
            "x-external": {
                "bundleReferences": [
                    {
                        "urn": external_urn,
                        "bundle_id": "urn:acef:pkg:other-bundle-0001",
                    }
                ]
            }
        },
    )

    write_bundle(
        bundle,
        manifest=manifest,
        records=[
            base_record(
                record_id="urn:acef:rec:a0000000-0000-0000-0000-000000000001",
                causation_chain=[external_urn],
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    diags_073 = [d for d in assessment.structural_errors if d.get("code") == "ACEF-073"]
    assert not diags_073, f"Expected no ACEF-073 for declared external URN, got: {diags_073!r}"


def test_external_urn_declared_as_plain_string_also_resolves(tmp_path: Path) -> None:
    """The bundleReferences shorthand: a plain-string URN entry also
    counts as declared.
    """
    bundle = tmp_path / "external-string-shorthand"
    external_urn = "urn:acef:rec:cafe2222-2222-2222-2222-222222222222"

    manifest = base_manifest(
        namespaces={"x-external": {"bundleReferences": [external_urn]}},
    )

    write_bundle(
        bundle,
        manifest=manifest,
        records=[
            base_record(
                record_id="urn:acef:rec:b0000000-0000-0000-0000-000000000001",
                causation_chain=[external_urn],
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    diags_073 = [d for d in assessment.structural_errors if d.get("code") == "ACEF-073"]
    assert not diags_073, f"Plain-string bundleReferences shorthand should resolve, got: {diags_073!r}"


# VAL-VALIDATION-EXTERNAL-URN-002


def test_external_urn_not_declared_emits_acef_073(tmp_path: Path) -> None:
    """A causation_chain URN that is neither in-bundle nor declared in
    external references → ACEF-073.
    """
    bundle = tmp_path / "external-undeclared"
    unknown_urn = "urn:acef:rec:dead0000-0000-0000-0000-000000000001"

    write_bundle(
        bundle,
        manifest=base_manifest(),
        records=[
            base_record(
                record_id="urn:acef:rec:c0000000-0000-0000-0000-000000000001",
                causation_chain=[unknown_urn],
            ),
        ],
    )

    assessment = validate_bundle(bundle)
    found = codes(assessment.structural_errors)
    assert "ACEF-073" in found, f"Expected ACEF-073 for undeclared external URN, got: {found!r}"

    messages = [d["message"] for d in assessment.structural_errors if d.get("code") == "ACEF-073"]
    assert any(unknown_urn in m for m in messages), f"Expected diagnostic naming {unknown_urn!r}; got: {messages!r}"
