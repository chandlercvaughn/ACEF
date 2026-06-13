"""ACEF CLI — inspect command: bundle summary (incident-aware)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from acef.cli.formatters import print_bundle_info
from acef.errors import ACEFError
from acef.render import render_incident_evidence_console

# Record types that carry RFC-0002 incident evidence. Inspect surfaces these via
# the shared render helpers (no reimplementation — the band() projection and the
# crosswalk ordering live in acef.render).
_INCIDENT_RECORD_TYPES = frozenset({"incident_card", "incident_report"})


def _load_incident_records(path: str) -> list[dict[str, Any]]:
    """Load a bundle and return its incident record envelopes as plain dicts.

    Reuses :func:`acef.loader.load` (directory OR archive) and the
    :class:`~acef.models.records.RecordEnvelope` ``to_dict`` projection, yielding
    the ``{record_type, payload, ...}`` shape the ``acef.render`` incident helpers
    consume. Returns ``[]`` when the bundle has no incident records, or when the
    bundle cannot be loaded for record extraction (inspect's manifest summary has
    already been emitted at that point — record extraction is best-effort and
    never crashes inspect or flips its exit code).
    """
    try:
        from acef.loader import load

        pkg = load(path)
    except (ACEFError, OSError, ValueError):
        # Record extraction is a best-effort enrichment on top of the manifest
        # summary. A load failure here does not change inspect's contract; the
        # manifest view is still shown and inspect exits as it otherwise would.
        return []

    records: list[dict[str, Any]] = []
    for envelope in pkg.records:
        if envelope.record_type in _INCIDENT_RECORD_TYPES:
            # to_jsonl_dict() yields the {record_type, payload, ...} envelope
            # shape the acef.render incident helpers consume.
            records.append(envelope.to_jsonl_dict())
    return records


@click.command("inspect")
@click.argument("path")
@click.option("--format", "fmt", default="pretty", type=click.Choice(["pretty", "json"]))
def inspect_cmd(path: str, fmt: str) -> None:
    """Inspect an ACEF Evidence Bundle at PATH.

    Shows metadata, subjects, entities, records, and profiles. When the bundle
    carries ``incident_card`` / ``incident_report`` records, the RFC-0002 incident
    evidence (public_incident_id, severity band, harm class, taxonomy crosswalk)
    is surfaced too — reusing :func:`acef.render.render_incident_evidence_console`
    in ``pretty`` mode and an ``incident_records`` array in ``json`` mode.
    """
    bundle_path = Path(path)

    if not bundle_path.exists():
        click.echo(f"Error: Path does not exist: {path}", err=True)
        raise SystemExit(1)

    if bundle_path.suffix == ".gz" or str(bundle_path).endswith(".tar.gz"):
        from acef.loader import load

        try:
            pkg = load(path)
        except Exception as exc:
            click.echo(f"Error: Failed to load archive {path}: {exc}", err=True)
            raise SystemExit(1) from exc
        manifest_data = pkg.build_manifest().to_dict()
    else:
        manifest_file = bundle_path / "acef-manifest.json"
        if not manifest_file.exists():
            click.echo(f"Error: No acef-manifest.json found in {path}", err=True)
            raise SystemExit(1)
        try:
            manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            # Surface the parse error as a structured ACEF-050 message
            # rather than letting the raw traceback escape.
            click.echo(
                f"Error: acef-manifest.json is not valid JSON [ACEF-050]: {exc}",
                err=True,
            )
            raise SystemExit(1) from exc
        except OSError as exc:
            click.echo(f"Error: Cannot read manifest: {exc}", err=True)
            raise SystemExit(1) from exc

    # Surface RFC-0002 incident evidence when present (§5.x). Record extraction
    # reuses the loader + the render helpers; it is additive to the manifest
    # summary and never changes inspect's exit code.
    incident_records = _load_incident_records(path)

    if fmt == "json":
        out: dict[str, Any] = dict(manifest_data)
        if incident_records:
            out["incident_records"] = incident_records
        click.echo(json.dumps(out, indent=2))
    else:
        print_bundle_info(manifest_data)
        if incident_records:
            rendered = render_incident_evidence_console(incident_records)
            if rendered:
                click.echo()
                click.echo(rendered)
