"""PhD re-review W2: the §3.7 'Canonical evaluation instant' must DOCUMENT the
omitted-caller default and its producer-control caveat.

When the calling API does not pin an explicit ``evaluation_instant``, the engine
derives it deterministically from the Evidence Bundle's ``metadata.timestamp``
(NOT wall-clock, per §3.7 reproducibility). That timestamp is producer-controlled,
so the spec must say so and direct a consumer who needs producer-independent
freshness/effective-date gating to pass an explicit ``evaluation_instant`` — the
same limitation Appendix D.4 discloses as a non-goal.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from acef.package import Package
from acef.validation.engine import validate_bundle


def test_omitted_evaluation_instant_defaults_to_metadata_timestamp(tmp_path: Path) -> None:
    """With no caller-supplied evaluation_instant, the engine pins it to the
    bundle's metadata.timestamp (reproducible, NOT wall-clock)."""
    pkg = Package(producer={"name": "ts-default", "version": "1.0.0"})
    pkg.add_subject("ai_system", name="S", risk_classification="high-risk", modalities=["text"])
    bundle_dir = tmp_path / "b.acef"
    pkg.export(str(bundle_dir))

    manifest = json.loads((bundle_dir / "acef-manifest.json").read_text(encoding="utf-8"))
    pkg_ts = manifest["metadata"]["timestamp"]
    assert isinstance(pkg_ts, str) and pkg_ts

    assessment = validate_bundle(bundle_dir)  # no evaluation_instant supplied
    assert assessment.evaluation_instant == pkg_ts, (
        "omitted evaluation_instant must derive from metadata.timestamp (§3.7 default), not wall-clock"
    )


def test_explicit_evaluation_instant_overrides_metadata_timestamp(tmp_path: Path) -> None:
    """A caller-supplied evaluation_instant is used verbatim (the producer-
    independent path a regulator assessing at filing time must use)."""
    pkg = Package(producer={"name": "ts-override", "version": "1.0.0"})
    pkg.add_subject("ai_system", name="S", risk_classification="high-risk", modalities=["text"])
    bundle_dir = tmp_path / "b.acef"
    pkg.export(str(bundle_dir))

    explicit = "2099-01-01T00:00:00Z"
    assessment = validate_bundle(bundle_dir, evaluation_instant=explicit)
    assert assessment.evaluation_instant == explicit


def test_spec_documents_evaluation_instant_producer_control_caveat() -> None:
    """§3.7 must document the omitted-caller default + producer-control caveat +
    the D.4 cross-reference."""
    spec = (Path(__file__).resolve().parents[2] / "planning" / "ACEF-Spec-Outline-v0.1.md").read_text(encoding="utf-8")
    idx = spec.find("Default when the caller omits `evaluation_instant`")
    assert idx != -1, "spec must document the omitted-caller evaluation_instant default"
    section = spec[idx : idx + 3400]
    assert "producer-controlled" in section, "must flag metadata.timestamp as producer-controlled"
    assert "pass an explicit `evaluation_instant`" in section, "must direct consumers to pass an explicit instant"
    assert "D.4" in section, "must cross-reference the Appendix D.4 freshness non-goal"
    # The reproducibility guarantee binds the ACCEPTED/evaluated path. A bundle with
    # no usable metadata.timestamp is structurally invalid (FATAL/rejected); any
    # date-sensitive diagnostics computed against a wall-clock fallback on such a
    # bundle are NON-AUTHORITATIVE (the assessment is already rejected). This must
    # match the engine, which does NOT short-circuit profile evaluation on a
    # schema-invalid timestamp — so the spec must not claim "runs no date-sensitive
    # rules".
    assert "NON-AUTHORITATIVE" in section, "spec must mark fallback-instant diagnostics as non-authoritative"
    assert "no accepted (non-fatal) assessment ever depends on a wall-clock" in section, (
        "spec must scope the no-wall-clock guarantee to the accepted/evaluated path"
    )
    # The spec must distinguish the two fallback shapes precisely (roborev on
    # ee40372/d037f5c): absent/non-string -> wall-clock; non-ISO string -> verbatim.
    # Pin the two fallback shapes as ONE span each (not just the words appearing
    # somewhere in the slice): absent/non-string -> falls back -> wall-clock; and
    # non-ISO string -> recorded verbatim. Normalize markdown emphasis/backticks
    # first so '**absent or non-string**' etc. match.
    norm_section = section.replace("*", "").replace("`", "")
    assert re.search(r"absent or non-string.{0,80}falls back.{0,40}wall-clock", norm_section, re.DOTALL), (
        "spec must state, in one span, that an absent/non-string metadata.timestamp falls back to wall-clock"
    )
    assert re.search(r"present-but-non-ISO string.{0,40}recorded verbatim", norm_section, re.DOTALL), (
        "spec must state, in one span, that a present-but-non-ISO metadata.timestamp is recorded verbatim"
    )


def test_non_iso_metadata_timestamp_is_fatal_and_rejected(tmp_path: Path) -> None:
    """The carve-out's load-bearing fact: a bundle whose metadata.timestamp is not
    ISO-8601 is structurally invalid (FATAL) and rejected, so any date-sensitive
    diagnostics computed against the (verbatim, non-deterministic) instant are
    non-authoritative (they appear only inside an already-rejected assessment).

    Asserts the SPECIFIC timestamp schema diagnostic (ACEF-002 at
    /metadata/timestamp) rather than merely 'some fatal' — the manifest mutation
    also breaks integrity (an ACEF-010 fatal), which must NOT be what makes this
    pass (else a timestamp-validation regression would slip through)."""
    import json

    pkg = Package(producer={"name": "ts-bad", "version": "1.0.0"})
    pkg.add_subject("ai_system", name="S", risk_classification="high-risk", modalities=["text"])
    bundle_dir = tmp_path / "b.acef"
    pkg.export(str(bundle_dir))

    manifest_path = bundle_dir / "acef-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["metadata"]["timestamp"] = "not-a-real-date"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assessment = validate_bundle(bundle_dir)  # no evaluation_instant supplied
    ts_fatal = [
        e
        for e in assessment.structural_errors
        if e.get("severity") == "fatal"
        and e.get("code") == "ACEF-002"
        and "/metadata/timestamp" in str(e.get("path", ""))
    ]
    assert ts_fatal, (
        "a non-ISO metadata.timestamp must produce a FATAL ACEF-002 at /metadata/timestamp "
        f"(not merely some integrity fatal); structural_errors="
        f"{[(e.get('code'), e.get('path')) for e in assessment.structural_errors]}"
    )
    # And the spec's "recorded verbatim" claim is load-bearing: a present-but-non-ISO
    # string is used as evaluation_instant verbatim (NOT a wall-clock value) — which
    # is exactly why such diagnostics are non-deterministic and non-authoritative.
    assert assessment.evaluation_instant == "not-a-real-date", (
        "a present-but-non-ISO metadata.timestamp must be recorded verbatim as evaluation_instant, "
        f"got {assessment.evaluation_instant!r}"
    )
