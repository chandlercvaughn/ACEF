"""Shared helpers for v1.1 cross-record validation tests.

Builds minimal on-disk bundles that exercise specific cross-record
behaviors. Bundles are not signed and have no content-hashes.json — the
validator will emit unrelated integrity diagnostics that the tests filter
out by code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_bundle(
    bundle_dir: Path,
    *,
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
    record_file_path: str = "records/all.jsonl",
) -> None:
    """Write a minimal bundle to disk.

    All records go in a single JSONL file. The manifest's `record_files`
    entry is filled in automatically (caller may override by supplying
    `record_files` in `manifest`).
    """
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "records").mkdir(parents=True, exist_ok=True)

    rec_path = bundle_dir / record_file_path
    rec_path.parent.mkdir(parents=True, exist_ok=True)
    rec_path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

    # Inject record_files if absent. We use a single inferred record_type
    # ("risk_register") only if all records share that type; otherwise we
    # let downstream emit ACEF-025 mismatches (tests that care will
    # override record_files explicitly).
    if "record_files" not in manifest:
        # group by record_type → one entry per type → one file per type
        # is the strict spec convention, but tests using mixed types
        # should pass `record_files` explicitly. We default to a single
        # entry pointing at the union file with the first record's type.
        first_type = records[0].get("record_type", "risk_register") if records else "risk_register"
        manifest = dict(manifest)
        manifest["record_files"] = [
            {"path": record_file_path, "record_type": first_type, "count": len(records)},
        ]

    (bundle_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def base_manifest(
    *,
    core_version: str = "1.1.0",
    analysis_mode: str | None = None,
    namespaces: dict[str, Any] | None = None,
    entities_actors: list[dict[str, Any]] | None = None,
    package_id: str = "urn:acef:pkg:11111111-1111-1111-1111-111111111111",
) -> dict[str, Any]:
    """Construct a minimal valid manifest dict."""
    manifest: dict[str, Any] = {
        "metadata": {
            "package_id": package_id,
            "created_at": "2026-01-01T00:00:00Z",
            "timestamp": "2026-01-01T00:00:00Z",
            "producer": {"name": "test-producer", "version": "1.0.0"},
        },
        "versioning": {"core_version": core_version, "profiles_version": "1.0.0"},
        "subjects": [],
        "entities": {
            "components": [],
            "datasets": [],
            "actors": entities_actors or [],
            "relationships": [],
        },
        "profiles": [],
        "audit_trail": [],
    }
    if analysis_mode is not None:
        manifest["analysis_mode"] = analysis_mode
    if namespaces is not None:
        manifest["namespaces"] = namespaces
    return manifest


def base_record(
    *,
    record_id: str,
    record_type: str = "risk_register",
    tenant_label: str | None = None,
    confidentiality: str = "public",
    redaction_policy_version: str | None = None,
    redaction_attestation_ref: str | None = None,
    causation_chain: list[str] | None = None,
    entity_refs: dict[str, list[str]] | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a minimal valid record dict."""
    rec: dict[str, Any] = {
        "record_id": record_id,
        "record_type": record_type,
        "provisions_addressed": [],
        "timestamp": "2026-01-01T00:00:00Z",
        "lifecycle_phase": "development",
        "collector": {"name": "test-tool", "version": "1.0.0"},
        "obligation_role": "provider",
        "confidentiality": confidentiality,
        "trust_level": "self-attested",
        "entity_refs": {
            "subject_refs": [],
            "component_refs": [],
            "dataset_refs": [],
            "actor_refs": [],
        },
        "payload": payload if payload is not None else {},
        "attachments": [],
    }
    if entity_refs is not None:
        rec["entity_refs"] = {
            "subject_refs": entity_refs.get("subject_refs", []),
            "component_refs": entity_refs.get("component_refs", []),
            "dataset_refs": entity_refs.get("dataset_refs", []),
            "actor_refs": entity_refs.get("actor_refs", []),
        }
    if tenant_label is not None:
        rec["tenant_label"] = tenant_label
    if redaction_policy_version is not None:
        rec["redaction_policy_version"] = redaction_policy_version
    if redaction_attestation_ref is not None:
        rec["redaction_attestation_ref"] = redaction_attestation_ref
    if causation_chain is not None:
        rec["causation_chain"] = causation_chain
    return rec


def codes(diagnostics: list[dict[str, Any]]) -> list[str]:
    """Extract the .code values from a structural_errors list."""
    return [d.get("code") for d in diagnostics if isinstance(d, dict)]
