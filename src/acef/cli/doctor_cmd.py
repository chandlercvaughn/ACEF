"""ACEF CLI — doctor command: diagnose bundle issues."""

from __future__ import annotations

import json
import tarfile
import tempfile
from contextlib import ExitStack
from pathlib import Path

import click
from rich.console import Console

from acef.errors import Severity, ValidationDiagnostic

console = Console()


@click.command("doctor")
@click.argument("path")
def doctor_cmd(path: str) -> None:
    """Diagnose issues with an ACEF Evidence Bundle at PATH.

    Checks structure, integrity, references, and common problems for BOTH
    directory bundles and ``.acef.tar.gz`` archives.
    """
    bundle_path = Path(path)
    issues: list[tuple[str, str, str]] = []  # (severity, category, message)

    console.print(f"\n[bold]ACEF Doctor: Examining {path}[/bold]\n")

    # Check bundle exists
    if not bundle_path.exists():
        console.print(f"[red]Bundle not found: {path}[/red]")
        raise SystemExit(1)

    # Resolve the input to a bundle DIRECTORY. An archive is extracted (raw,
    # preserving the on-disk file set EXACTLY) into a temp dir that stays alive
    # for the duration of every check below. This is the single fix that makes
    # archive inputs run the SAME structure / manifest / integrity / record
    # checks as directory inputs — previously the archive branch only called
    # ``load(path)`` and returned BEFORE any integrity check, so a tampered
    # archive (e.g. ``hashes/merkle-tree.json`` stripped, or a content-hash
    # mismatch) exited 0 while ``validate`` rejected it (roborev Medium).
    is_archive = bundle_path.is_file() and (bundle_path.suffix == ".gz" or str(bundle_path).endswith(".tar.gz"))

    with ExitStack() as stack:
        if is_archive:
            console.print("[yellow]Archive bundle — extracting for analysis...[/yellow]")
            try:
                bundle_dir = _extract_archive(bundle_path, stack)
            except Exception as e:  # noqa: BLE001 — surface any extraction fault, never crash doctor
                console.print(f"[red]Archive could not be extracted: {e}[/red]")
                raise SystemExit(1) from e
            console.print("[green]Archive extracted[/green]")
        else:
            bundle_dir = bundle_path

        # Check directory structure
        _check_structure(bundle_dir, issues)

        # Check manifest
        _check_manifest(bundle_dir, issues)

        # Check integrity — DELEGATED to the canonical validator so doctor's
        # severity + exit status MATCH ``validate`` / ``check_integrity`` for
        # every integrity condition, for both directory and archive inputs.
        _check_integrity(bundle_dir, issues)

        # Check records
        _check_records(bundle_dir, issues)

    # Report
    console.print()
    if not issues:
        console.print("[green bold]No issues found! Bundle looks healthy.[/green bold]")
        return  # Exit 0 (clean)

    for severity, category, message in issues:
        if severity == "error":
            console.print(f"  [red][{category}][/red] {message}")
        elif severity == "warning":
            console.print(f"  [yellow][{category}][/yellow] {message}")
        else:
            console.print(f"  [dim][{category}][/dim] {message}")

    errors = sum(1 for s, _, _ in issues if s == "error")
    warnings = sum(1 for s, _, _ in issues if s == "warning")
    console.print(f"\n[bold]Summary: {errors} errors, {warnings} warnings[/bold]")

    # Errors fail the command; warnings remain advisory (exit 0). CI
    # consumers can now actually detect a broken bundle via exit code.
    if errors > 0:
        raise SystemExit(1)


def _extract_archive(archive_path: Path, stack: ExitStack) -> Path:
    """Safely extract a ``.acef.tar.gz`` archive into a temp dir and return the
    bundle root directory.

    Reuses the loader's vetted safety primitives (``_validate_tar_safety`` +
    ``_safe_tar_extract``) — the SAME safe-extract path ``load()`` uses — so
    doctor never introduces a second, unsafe extractor. The temp directory is
    registered on ``stack`` and is cleaned up when the caller's ``with`` block
    exits, AFTER every check has run against the extracted files. Crucially this
    extracts the archive bytes VERBATIM (it does NOT round-trip through
    ``load()`` + ``export()``, which would regenerate ``content-hashes.json`` /
    ``merkle-tree.json`` and silently heal tampering), so the integrity check
    sees the archive's real on-disk state.
    """
    from acef.loader import _safe_tar_extract, _validate_tar_safety

    tmpdir = Path(stack.enter_context(tempfile.TemporaryDirectory()))
    with tarfile.open(str(archive_path), "r:gz") as tar:
        _validate_tar_safety(tar)
        _safe_tar_extract(tar, tmpdir)

    # Find the bundle root: a single nested directory is the bundle root
    # (the canonical archive layout); otherwise the temp dir itself is the
    # bundle root. Mirrors loader._load_archive.
    extracted = list(tmpdir.iterdir())
    if len(extracted) == 1 and extracted[0].is_dir():
        return extracted[0]
    return tmpdir


def _check_structure(bundle_path: Path, issues: list[tuple[str, str, str]]) -> None:
    """Check bundle directory structure."""
    console.print("Checking structure...")

    if not (bundle_path / "acef-manifest.json").exists():
        issues.append(("error", "structure", "Missing acef-manifest.json"))
        return

    console.print("  [green]acef-manifest.json found[/green]")

    for dirname in ("records", "artifacts", "hashes", "signatures"):
        if (bundle_path / dirname).exists():
            console.print(f"  [green]{dirname}/ present[/green]")
        elif dirname in ("records",):
            issues.append(("warning", "structure", f"Missing {dirname}/ directory"))
        else:
            console.print(f"  [dim]{dirname}/ not present (optional)[/dim]")


def _check_manifest(bundle_path: Path, issues: list[tuple[str, str, str]]) -> None:
    """Check manifest validity."""
    console.print("\nChecking manifest...")
    manifest_path = bundle_path / "acef-manifest.json"

    if not manifest_path.exists():
        return

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        console.print("  [green]Valid JSON[/green]")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        # A malformed manifest — invalid JSON OR non-UTF-8 bytes — must surface as
        # a clean ACEF-050 issue (counted as an error → exit 1), NEVER a raw
        # traceback. ``read_text(encoding="utf-8")`` raises ``UnicodeDecodeError``
        # (a ``ValueError`` subclass distinct from ``json.JSONDecodeError`` and NOT
        # an ``OSError``) on non-UTF-8 manifest bytes, so it must be caught
        # alongside the JSON error. Mirrors ``inspect``'s ACEF-050 decode handling
        # (acef.cli.inspect_cmd._read_directory_inputs / _read_archive_inputs);
        # both directory and archive manifests reach this branch because
        # ``doctor`` extracts an archive to a temp dir and then reads the manifest
        # from there via this same routine.
        issues.append(("error", "manifest", f"[ACEF-050] Invalid manifest (not valid UTF-8 JSON): {e}"))
        return

    # A successfully-parsed manifest may still be a non-object (a bare JSON
    # scalar/array like ``42`` / ``[]``). Calling ``.get(...)`` on it raises a
    # raw AttributeError; surface a clean ACEF-002 issue instead and stop —
    # ``validate`` reports the same non-object manifest as ACEF-002.
    if not isinstance(data, dict):
        issues.append(
            (
                "error",
                "manifest",
                f"[ACEF-002] Manifest is not a JSON object (got {type(data).__name__})",
            )
        )
        return

    # Check required fields
    metadata = data.get("metadata")
    if not metadata:
        issues.append(("error", "manifest", "Missing metadata block"))
    elif not isinstance(metadata, dict):
        # A present-but-non-object metadata (e.g. ``"metadata": "x"`` / ``5``)
        # would raise a raw AttributeError on ``.get(...)``; report ACEF-002.
        issues.append(("error", "manifest", "[ACEF-002] metadata is not a JSON object"))
    else:
        if not metadata.get("package_id"):
            issues.append(("error", "manifest", "Missing metadata.package_id"))
        if not metadata.get("timestamp"):
            issues.append(("error", "manifest", "Missing metadata.timestamp"))
        if not metadata.get("producer"):
            issues.append(("error", "manifest", "Missing metadata.producer"))
        console.print(f"  [green]Package ID: {metadata.get('package_id', 'N/A')}[/green]")

    versioning = data.get("versioning")
    if not versioning:
        issues.append(("warning", "manifest", "Missing versioning block"))

    subjects = data.get("subjects", [])
    if not isinstance(subjects, list):
        # A present-but-non-array subjects (e.g. ``"subjects": 5``) would raise a
        # raw TypeError on ``len(...)``; report ACEF-002 instead.
        issues.append(("error", "manifest", "[ACEF-002] subjects is not a JSON array"))
    else:
        console.print(f"  Subjects: {len(subjects)}")
        if not subjects:
            issues.append(("warning", "manifest", "No subjects declared"))


# Map the canonical validator severities onto doctor's three console buckets.
# FATAL and ERROR both fail the command (counted as "error" → exit 1), so
# doctor's exit status MATCHES ``validate`` / ``check_integrity``: a condition
# the validator treats as FATAL (e.g. ACEF-010 hash mismatch, ACEF-011 missing
# Merkle tree / root mismatch, ACEF-012/013/014 signature & hash-index faults)
# makes doctor exit non-zero, never 0.
_SEVERITY_TO_BUCKET: dict[Severity, str] = {
    Severity.FATAL: "error",
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "info",
}


def _check_integrity(bundle_path: Path, issues: list[tuple[str, str, str]]) -> None:
    """Check integrity by DELEGATING to the canonical validator.

    Doctor no longer walks the hash files itself. It calls
    :func:`acef.validation.integrity_checker.check_integrity` — the exact
    routine Phase 2 of ``validate`` runs — and maps the returned
    :class:`ValidationDiagnostic`\\ s into doctor's console report. This makes
    doctor's verdict (severity + exit status) MATCH ``validate`` for every
    integrity condition (missing/invalid content-hashes.json, hash mismatch,
    missing/invalid merkle-tree.json, Merkle root mismatch, signature faults),
    for BOTH directory and archive inputs — closing the divergence roborev
    flagged twice on this command (the bespoke walk had a different severity
    for a missing Merkle tree, and the archive path skipped integrity entirely).
    """
    console.print("\nChecking integrity...")

    from acef.validation.integrity_checker import check_integrity

    diagnostics: list[ValidationDiagnostic] = check_integrity(bundle_path)

    if not diagnostics:
        console.print("  [green]Integrity verified (hashes, Merkle root, signatures)[/green]")
        return

    for diag in diagnostics:
        bucket = _SEVERITY_TO_BUCKET.get(diag.severity, "error")
        location = f" ({diag.path})" if diag.path else ""
        issues.append((bucket, "integrity", f"{diag.code}: {diag.message}{location}"))


def _check_records(bundle_path: Path, issues: list[tuple[str, str, str]]) -> None:
    """Check record files."""
    console.print("\nChecking records...")

    records_dir = bundle_path / "records"
    if not records_dir.exists():
        console.print("  [dim]No records directory[/dim]")
        return

    jsonl_files = list(records_dir.rglob("*.jsonl"))
    console.print(f"  Found {len(jsonl_files)} record file(s)")

    total_records = 0
    for jsonl_file in jsonl_files:
        try:
            count = 0
            with open(jsonl_file, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        json.loads(line)
                        count += 1
                    except json.JSONDecodeError:
                        issues.append(("error", "records", f"Invalid JSON at {jsonl_file.name}:{line_num}"))
            total_records += count
        except Exception as e:
            issues.append(("error", "records", f"Failed to read {jsonl_file.name}: {e}"))

    console.print(f"  Total records: {total_records}")
