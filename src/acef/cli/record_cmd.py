"""ACEF CLI — record command: add records to a bundle."""

from __future__ import annotations

import json

import click

from acef.loader import load


@click.command("record")
@click.argument("bundle_path")
@click.option("--type", "record_type", required=True, help="Record type")
@click.option("--provision", "-p", multiple=True, help="Provisions addressed")
@click.option("--payload", required=True, help="JSON payload string or @file.json")
@click.option("--role", default="provider", help="Obligation role")
def record_cmd(
    bundle_path: str,
    record_type: str,
    provision: tuple[str, ...],
    payload: str,
    role: str,
) -> None:
    """Add an evidence record to the bundle at BUNDLE_PATH.

    Re-exports the bundle in place after adding the record. The export is
    NOT atomic — if the process is interrupted between the rmtree and
    rewrite, the bundle may be left without a records/ directory. Always
    work on a copy if interruption matters.
    """
    # Load existing bundle. Surface common load failures as structured
    # ACEF-NNN errors to stderr rather than raw tracebacks.
    try:
        pkg = load(bundle_path)
    except FileNotFoundError as exc:
        click.echo(f"Error: Bundle path not found: {bundle_path}", err=True)
        raise SystemExit(1) from exc
    except Exception as exc:
        click.echo(f"Error: Failed to load bundle {bundle_path}: {exc}", err=True)
        raise SystemExit(1) from exc

    # Parse payload. File reads always force UTF-8 — spec §3.1.1 requires
    # UTF-8 NFC throughout, so platform-default encoding is not safe.
    try:
        if payload.startswith("@"):
            payload_path = payload[1:]
            try:
                with open(payload_path, encoding="utf-8") as f:
                    payload_data = json.load(f)
            except FileNotFoundError as exc:
                click.echo(f"Error: Payload file not found: {payload_path}", err=True)
                raise SystemExit(1) from exc
            except OSError as exc:
                click.echo(f"Error: Cannot read payload file {payload_path}: {exc}", err=True)
                raise SystemExit(1) from exc
        else:
            payload_data = json.loads(payload)
    except json.JSONDecodeError as exc:
        click.echo(f"Error: Invalid JSON payload [ACEF-050]: {exc}", err=True)
        raise SystemExit(1) from exc

    # Add record
    record = pkg.record(
        record_type=record_type,
        provisions=list(provision),
        payload=payload_data,
        obligation_role=role,
    )

    # Re-export. This will rmtree subdirectories of bundle_path that
    # Package.export manages (records/, artifacts/, hashes/, signatures/).
    # Caller is responsible for backing up first if they care.
    try:
        pkg.export(bundle_path)
    except Exception as exc:
        click.echo(
            f"Error: Failed to re-export bundle to {bundle_path}: {exc}\n"
            "Bundle may be in an inconsistent state — restore from backup if needed.",
            err=True,
        )
        raise SystemExit(1) from exc

    click.echo(f"Added {record_type} record: {record.record_id}", err=True)
    click.echo(record.record_id)  # machine-readable id on stdout
