"""Deterministic generator for the F-M8-STIX §5.8 emit-only conformance vectors.

Materializes two byte-stable on-disk incident_card bundles under
``test-vectors/incident-stix/`` plus a ``vectors.json`` manifest:

- ``with-stix`` — a public ``incident_card`` built with supplied STIX object_refs;
  the emitted ``taxonomy_crosswalk.stix`` carries ``edition: "2.1"`` and the
  §5.10-sorted, de-duplicated, pattern-valid ``object_refs[]``.
- ``without-stix`` — the SAME card with NO STIX input; the optional ``stix``
  member is OMITTED entirely.

These vectors live OUTSIDE ``test-vectors/incident/`` so the existing
exact-inventory driver (``tests/conformance/test_incident_vectors.py``) — which
rglobs ``acef-manifest.json`` under ``test-vectors/incident/`` and pins an EXACT
vector corpus — is not perturbed. The dedicated driver
``tests/conformance/test_incident_stix_vectors.py`` validates these bundles
through the production validator and recomputes the §5.10 sort independently.

Determinism: a FIXED clock + a deterministic (counter-based) URN generator make
every byte of the records / content-hashes / manifest reproducible — no
wall-clock, no random nonce, no uuid4. The vectors are NOT signed: signatures
live OUTSIDE the hash domain (spec §3.1.1) and a randomized ECDSA nonce / freshly
generated key would make the archive non-reproducible, so omitting the signature
keeps the committed bundle byte-stable across regenerations. The STIX emit-only
surface under test (``taxonomy_crosswalk.stix.object_refs``) is fully in the hash
domain and is byte-stable by construction.

Run: ``python test-vectors/incident-stix/generate.py``
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from acef.models.urns import URNType
from acef.package import Package
from acef.redaction import RedactionPolicy

_THIS_DIR = Path(__file__).resolve().parent

# A public_incident_id matching the v1.1 grammar (AIIC-{assigner}-{year}-{suffix}).
_PUBLIC_INCIDENT_ID = "AIIC-OPENAI-2026-0123456789ABCDEFGHJKMNPQRS"

_HARM_CORE: dict[str, Any] = {
    "realization": "harm_event",
    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
    "harm_class": "physical_health",
}

_EU_FACTS: dict[str, Any] = {
    "serious_incident_triggers": ["3.49.a"],
    "widespread": False,
    "death_involved": False,
}

# Producer-asserted STIX 2.1 SDO ids supplied to the builder UNSORTED + with a
# duplicate, so the vector proves de-dup + the §5.10 canonical-byte sort. The ids
# are fixed v4 UUIDs (the builder validates + sorts; it never mints them).
_STIX_OBJECT_REFS: list[str] = [
    "relationship--ffffffff-0000-4000-bbbb-000000000003",
    "incident--7c8d2f10-0000-4000-8000-000000000001",
    "incident--7c8d2f10-0000-4000-8000-000000000001",  # duplicate -> deduped
    "marking-definition--0badf00d-0000-4000-a000-000000000004",
    "identity--a1b2c3d4-0000-4000-9000-000000000002",
]


def _fixed_clock() -> datetime:
    return datetime(2026, 8, 10, 0, 0, 0, tzinfo=UTC)


def _deterministic_urn_generator() -> Any:
    counter = {"n": 0}

    def _gen(urn_type: URNType) -> str:
        counter["n"] += 1
        return f"urn:acef:{urn_type.value}:00000000-0000-0000-0000-{counter['n']:012x}"

    return _gen


def _new_pkg() -> Package:
    return Package(
        producer={"name": "acef-stix-vector", "version": "1.1.0"},
        redaction_policy=RedactionPolicy(version="1.0.0"),
        clock=_fixed_clock,
        urn_generator=_deterministic_urn_generator(),
    )


def _build_card(*, with_stix: bool) -> Package:
    pkg = _new_pkg()
    pkg.add_subject("ai_system", name="Sys", risk_classification="high-risk", modalities=["text"])
    kwargs: dict[str, Any] = {}
    if with_stix:
        kwargs["stix_object_refs"] = list(_STIX_OBJECT_REFS)
    pkg.incident_card(
        public_incident_id=_PUBLIC_INCIDENT_ID,
        harm_core=dict(_HARM_CORE),
        severity_vector="ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I",
        awareness_date="2026-08-01T00:00:00Z",
        eu_ai_act_facts=dict(_EU_FACTS),
        **kwargs,
    )
    return pkg


def _vector_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": "with-stix",
            "with_stix": True,
            "path": "with-stix/card.acef",
            "expect_stix_member": True,
        },
        {
            "name": "without-stix",
            "with_stix": False,
            "path": "without-stix/card.acef",
            "expect_stix_member": False,
        },
    ]


def generate() -> None:
    # Clean only the bundle subdirs we own (idempotent regeneration).
    for sub in ("with-stix", "without-stix"):
        target = _THIS_DIR / sub
        if target.exists():
            shutil.rmtree(target)

    for spec in _vector_specs():
        pkg = _build_card(with_stix=bool(spec["with_stix"]))
        bundle_dir = _THIS_DIR / str(spec["path"])
        bundle_dir.parent.mkdir(parents=True, exist_ok=True)
        pkg.export(str(bundle_dir))

    manifest = {
        "_comment": (
            "F-M8-STIX §5.8 emit-only conformance vectors. Built by generate.py via "
            "the production Package.incident_card(stix_object_refs=...) builder. The "
            "with-stix vector emits a §5.10-sorted, deduped, pattern-valid "
            "taxonomy_crosswalk.stix.object_refs[]; the without-stix vector omits it."
        ),
        "stix_object_refs_input": list(_STIX_OBJECT_REFS),
        "vectors": _vector_specs(),
    }
    (_THIS_DIR / "vectors.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    generate()
