"""ACEF CLI — inspect command: bundle summary (incident-aware).

``inspect`` is a SUMMARY command. Two confidentiality / cost invariants govern its
incident enrichment (roborev on 79670175):

1. Confidentiality (default-safe). ``Package.report_incident()`` stores its
   source-backed evidence under the private ``payload.card_source`` subtree (with
   the regulator-only ``eu_ai_act_facts`` block) and emits the record
   ``regulator-only``. ``inspect --format json`` MUST NOT dump that raw envelope by
   default — doing so publishes confidential, regulator-only content to anyone who
   can run inspect. By DEFAULT the JSON path emits only a PROJECTION-SAFE incident
   summary (the SAME fields the console path surfaces), built via the shared
   :mod:`acef.render` field-resolution helpers — never the raw ``card_source`` /
   ``eu_ai_act_facts`` subtree. The raw envelope is gated behind the EXPLICIT
   ``--include-private`` opt-in the operator must pass knowingly.

2. Cost (no whole-bundle load). Incident enrichment streams ONLY the
   ``incident_card`` / ``incident_report`` record files named in the manifest
   (filtered by ``record_type``), via the loader's per-file JSONL reader — it does
   NOT call :func:`acef.loader.load`, which reads EVERY record file AND all
   artifacts into memory and (for archives) extracts a SECOND time. An archive is
   extracted exactly ONCE (via :func:`acef.loader.extract_archive_raw`) and BOTH
   the manifest summary and the incident records are read from that single
   extraction.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from acef.cli.formatters import print_bundle_info

# Reuse the shared incident field-resolution helpers from acef.render so the
# projection-safe summary surfaces exactly what the console/markdown renderers do
# (record-type-aware resolution, the shipped band() projection, the deterministic
# crosswalk ordering) — never a hand-dumped envelope. Imported by name so the
# resolution targets the real ``acef.render`` submodule (the ``acef`` package
# rebinds its ``render`` attribute to a different function in __init__).
from acef.render import (
    _as_dict,
    _crosswalk_edition,
    _incident_payload,
    _ordered_crosswalk_members,
    _resolve_incident_field,
    render_incident_evidence_console,
)

# band() lives in acef.validation.incident_rules; import it from its source (not
# re-exported through acef.render) so the severity_band the summary surfaces is the
# SAME shipped projection the renderers use — never recomputed.
from acef.validation.incident_rules import band

# Record types that carry RFC-0002 incident evidence. Inspect surfaces these via
# the shared render helpers (no reimplementation — the band() projection, the
# record-type-aware field resolution, and the crosswalk ordering live in
# acef.render).
_INCIDENT_RECORD_TYPES = frozenset({"incident_card", "incident_report"})


def _incident_record_paths(manifest_data: dict[str, Any]) -> list[str]:
    """Return the relative paths of the manifest's incident record files.

    Reads the manifest's ``record_files`` array and keeps only entries whose
    ``record_type`` is an incident type, so the caller streams ONLY those files
    (never every record file, never artifacts). Malformed / non-incident entries
    are skipped silently — record extraction is best-effort enrichment on top of
    the manifest summary and never crashes inspect or flips its exit code.
    """
    paths: list[str] = []
    record_files = manifest_data.get("record_files", [])
    if not isinstance(record_files, list):
        return paths
    for entry in record_files:
        if not isinstance(entry, dict):
            continue
        if entry.get("record_type") not in _INCIDENT_RECORD_TYPES:
            continue
        path = entry.get("path")
        if isinstance(path, str) and path:
            paths.append(path)
    return paths


def _stream_incident_records(bundle_root: Path, manifest_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Stream the incident record envelopes from ``bundle_root`` (no full load).

    Reuses the loader's per-record-file JSONL reader (:func:`acef.loader._parse_jsonl`)
    and path validator (:func:`acef.loader._validate_path`) to read ONLY the
    incident record files named in the manifest — avoiding the whole-bundle
    :func:`acef.loader.load` (which loads every record file AND all artifacts).
    Returns the raw ``{record_type, payload, ...}`` envelope dicts (the shape the
    :mod:`acef.render` incident helpers consume), filtered to incident records.
    Any read/parse failure on a single file is swallowed (best-effort enrichment);
    the manifest summary is still shown and inspect exits as it otherwise would.
    """
    from acef.errors import ACEFError
    from acef.loader import _parse_jsonl, _validate_path

    records: list[dict[str, Any]] = []
    for rel_path in _incident_record_paths(manifest_data):
        try:
            _validate_path(rel_path)
        except (ACEFError, ValueError):
            # A spec-§3.1.1-violating record path is rejected by the validator/
            # verifier proper; inspect's best-effort enrichment just skips it.
            continue
        record_file = bundle_root / rel_path
        if not record_file.exists():
            continue
        try:
            raw_records = _parse_jsonl(record_file)
        except (ACEFError, OSError, ValueError):
            continue
        for raw in raw_records:
            if isinstance(raw, dict) and raw.get("record_type") in _INCIDENT_RECORD_TYPES:
                records.append(raw)
    return records


def _incident_summaries(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Project incident record envelopes to PROJECTION-SAFE summaries.

    For each ``incident_card`` / ``incident_report`` envelope, emits ONLY the
    fields the console path surfaces — ``public_incident_id``, ``id_grade``,
    ``severity_vector`` + derived ``severity_band``, ``harm_class``, and the
    ``taxonomy_crosswalk`` framework labels (with version-pin edition) — resolved
    via the SAME :mod:`acef.render` helpers the console/markdown renderers use
    (record-type aware: a source-backed report's evidence lives under
    ``card_source``). It NEVER emits the raw ``card_source`` / ``eu_ai_act_facts``
    subtree or the full payload, so a default ``inspect --format json`` cannot leak
    regulator-only content. Non-incident / non-dict records are skipped.
    """
    summaries: list[dict[str, Any]] = []
    for record in records:
        resolved = _incident_payload(record)
        if resolved is None:
            continue
        record_type, payload = resolved

        summary: dict[str, Any] = {"record_type": record_type}

        record_id = record.get("record_id")
        if isinstance(record_id, str) and record_id:
            summary["record_id"] = record_id

        public_id = _resolve_incident_field(payload, record_type, "public_incident_id")
        if isinstance(public_id, str) and public_id:
            summary["public_incident_id"] = public_id

        id_grade = _resolve_incident_field(payload, record_type, "id_grade")
        if isinstance(id_grade, str) and id_grade:
            summary["id_grade"] = id_grade

        severity_vector = _resolve_incident_field(payload, record_type, "severity_vector")
        if isinstance(severity_vector, str) and severity_vector:
            summary["severity_vector"] = severity_vector
            band_value = band(severity_vector)
            # band() returns None for an unparseable vector; surface that verbatim
            # rather than inventing a band (mirrors the renderers).
            summary["severity_band"] = band_value if band_value is not None else "unparseable"

        harm_core = _as_dict(_resolve_incident_field(payload, record_type, "harm_core"))
        harm_class = harm_core.get("harm_class")
        if isinstance(harm_class, str) and harm_class:
            summary["harm_class"] = harm_class

        crosswalk = _as_dict(payload.get("taxonomy_crosswalk"))
        member_keys = _ordered_crosswalk_members(crosswalk)
        if member_keys:
            members: list[dict[str, Any]] = []
            for key in member_keys:
                member = _as_dict(crosswalk.get(key))
                entry: dict[str, Any] = {"framework": key}
                edition = _crosswalk_edition(member)
                if edition is not None:
                    entry["edition"] = edition
                members.append(entry)
            summary["taxonomy_crosswalk"] = members

        summaries.append(summary)
    return summaries


def _read_directory_inputs(bundle_path: Path, path: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read the manifest + incident record envelopes from a DIRECTORY bundle.

    Parses ``acef-manifest.json`` ONCE and streams only the incident record files
    it names — no whole-bundle load, no artifact load.

    Raises:
        SystemExit: with a clean ``Error:`` message + exit code 1 when the manifest
            is missing / unreadable / not valid JSON.
    """
    manifest_file = bundle_path / "acef-manifest.json"
    if not manifest_file.exists():
        click.echo(f"Error: No acef-manifest.json found in {path}", err=True)
        raise SystemExit(1)
    try:
        manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        # Surface a malformed manifest (invalid JSON OR non-UTF-8 bytes — the
        # ``read_text(encoding="utf-8")`` decode raises ``UnicodeDecodeError``,
        # which is a ``ValueError`` subclass distinct from ``json.JSONDecodeError``
        # and is NOT an ``OSError``) as a structured ACEF-050 message rather than
        # letting the raw traceback escape. Both failures converge on this single
        # user-facing error path.
        click.echo(
            f"Error: acef-manifest.json is not valid JSON [ACEF-050]: {exc}",
            err=True,
        )
        raise SystemExit(1) from exc
    except OSError as exc:
        click.echo(f"Error: Cannot read manifest: {exc}", err=True)
        raise SystemExit(1) from exc

    if not isinstance(manifest_data, dict):
        click.echo(
            f"Error: acef-manifest.json is not a JSON object [ACEF-050]: {path}",
            err=True,
        )
        raise SystemExit(1)

    incident_records = _stream_incident_records(bundle_path, manifest_data)
    return manifest_data, incident_records


def _read_archive_inputs(path: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read the manifest + incident record envelopes from an ARCHIVE bundle.

    Extracts the archive EXACTLY ONCE via :func:`acef.loader.extract_archive_raw`
    and reads BOTH the manifest and the incident record files from that single
    extraction — never round-tripping through :func:`acef.loader.load` (which loads
    every record + all artifacts and extracts a SECOND time).

    Raises:
        SystemExit: with a clean ``Error:`` message + exit code 1 when the archive
            cannot be extracted or its manifest is missing / invalid.
    """
    from acef.errors import ACEFError
    from acef.loader import extract_archive_raw

    try:
        with extract_archive_raw(path) as bundle_root:
            manifest_file = bundle_root / "acef-manifest.json"
            if not manifest_file.exists():
                click.echo(f"Error: No acef-manifest.json found in {path}", err=True)
                raise SystemExit(1)
            try:
                manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                # A malformed archive manifest (invalid JSON OR non-UTF-8 bytes)
                # converges on the SAME ACEF-050 clean-error path as the directory
                # read. ``UnicodeDecodeError`` (a ``ValueError`` subclass, NOT an
                # ``OSError``) would otherwise escape the outer
                # ``except (ACEFError, OSError)`` as an uncaught traceback.
                click.echo(
                    f"Error: acef-manifest.json is not valid JSON [ACEF-050]: {exc}",
                    err=True,
                )
                raise SystemExit(1) from exc
            if not isinstance(manifest_data, dict):
                click.echo(
                    f"Error: acef-manifest.json is not a JSON object [ACEF-050]: {path}",
                    err=True,
                )
                raise SystemExit(1)
            # Stream the incident records WHILE the extraction dir is still alive.
            incident_records = _stream_incident_records(bundle_root, manifest_data)
            return manifest_data, incident_records
    except (ACEFError, OSError) as exc:
        click.echo(f"Error: Failed to load archive {path}: {exc}", err=True)
        raise SystemExit(1) from exc


@click.command("inspect")
@click.argument("path")
@click.option("--format", "fmt", default="pretty", type=click.Choice(["pretty", "json"]))
@click.option(
    "--include-private",
    "include_private",
    is_flag=True,
    default=False,
    help=(
        "Emit the RAW incident record envelopes (including the regulator-only "
        "card_source / eu_ai_act_facts subtree) in --format json output. OFF by "
        "default; the default JSON path emits only a projection-safe summary."
    ),
)
def inspect_cmd(path: str, fmt: str, include_private: bool) -> None:
    """Inspect an ACEF Evidence Bundle at PATH.

    Shows metadata, subjects, entities, records, and profiles. When the bundle
    carries ``incident_card`` / ``incident_report`` records, the RFC-0002 incident
    evidence (public_incident_id, severity band, harm class, taxonomy crosswalk)
    is surfaced too — reusing :func:`acef.render.render_incident_evidence_console`
    in ``pretty`` mode.

    ``--format json`` emits a PROJECTION-SAFE incident summary by default (the same
    fields the console surfaces), NOT the raw record envelopes. Pass
    ``--include-private`` to emit the raw envelopes (which include the
    regulator-only ``card_source`` / ``eu_ai_act_facts`` subtree) — an explicit,
    knowing opt-in.
    """
    bundle_path = Path(path)

    if not bundle_path.exists():
        click.echo(f"Error: Path does not exist: {path}", err=True)
        raise SystemExit(1)

    is_archive = bundle_path.suffix == ".gz" or str(bundle_path).endswith(".tar.gz")
    if is_archive:
        manifest_data, incident_records = _read_archive_inputs(path)
    else:
        manifest_data, incident_records = _read_directory_inputs(bundle_path, path)

    if fmt == "json":
        out: dict[str, Any] = dict(manifest_data)
        if incident_records:
            if include_private:
                # Explicit opt-in: emit the raw envelopes verbatim (the operator
                # knowingly asked for the regulator-only subtree).
                out["incident_records"] = incident_records
            else:
                # Default-safe: projection-safe summaries only — never the raw
                # card_source / eu_ai_act_facts subtree.
                out["incident_records"] = _incident_summaries(incident_records)
        click.echo(json.dumps(out, indent=2))
    else:
        print_bundle_info(manifest_data)
        if incident_records:
            rendered = render_incident_evidence_console(incident_records)
            if rendered:
                click.echo()
                click.echo(rendered)
