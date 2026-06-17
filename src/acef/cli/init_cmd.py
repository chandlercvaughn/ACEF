"""ACEF CLI — init command: scaffold an empty bundle."""

from __future__ import annotations

from pathlib import Path

import click

from acef.package import Package


@click.command("init")
@click.argument("path")
@click.option("--producer-name", default="acef-cli", help="Producer tool name")
@click.option("--producer-version", default="0.1.0", help="Producer tool version")
@click.option("--subject-name", default=None, help="Initial subject name")
@click.option("--subject-type", default="ai_system", type=click.Choice(["ai_system", "ai_model"]))
@click.option(
    "--risk-classification",
    default="minimal-risk",
    type=click.Choice(["high-risk", "gpai", "gpai-systemic", "limited-risk", "minimal-risk"]),
)
@click.option(
    "--modality",
    "modalities",
    multiple=True,
    default=("text",),
    type=click.Choice(["text", "image", "audio", "video", "multimodal"]),
    help="Subject input/output modality (repeatable). A subject MUST declare >=1; defaults to text.",
)
@click.option("--force", is_flag=True, default=False, help="Overwrite a non-empty existing directory at PATH")
def init_cmd(
    path: str,
    producer_name: str,
    producer_version: str,
    subject_name: str | None,
    subject_type: str,
    risk_classification: str,
    modalities: tuple[str, ...],
    force: bool,
) -> None:
    """Initialize a new ACEF Evidence Bundle at PATH.

    Creates a minimal valid bundle directory structure. Refuses to write
    into a non-empty directory unless ``--force`` is given, because the
    export step rmtree's ``records/``, ``artifacts/``, ``hashes/``, and
    ``signatures/`` subdirectories.
    """
    target = Path(path)

    if target.exists() and not target.is_dir():
        click.echo(
            f"Error: {path} exists but is not a directory; cannot initialize here.",
            err=True,
        )
        raise SystemExit(1)

    if target.is_dir() and any(target.iterdir()) and not force:
        manifest = target / "acef-manifest.json"
        if not manifest.exists():
            # Not an existing bundle and not empty — refuse rather than
            # silently rmtree managed subdirs that a user expected to keep.
            click.echo(
                f"Error: {path} exists and is non-empty but is not an ACEF bundle "
                "(no acef-manifest.json). Refusing to write here — pass --force to override.",
                err=True,
            )
            raise SystemExit(1)

    pkg = Package(producer={"name": producer_name, "version": producer_version})

    # The frozen manifest schema requires subjects[] minItems:1, so a VALID bundle
    # always has >=1 subject. `acef init` is documented as producing a minimal VALID
    # bundle, so it always scaffolds a subject — using --subject-name when given, else a
    # default DERIVED from the target path (a bare `init <path>` previously emitted zero
    # subjects -> schema-invalid). The default must NOT be literal placeholder text:
    # stamping "Initial Subject (rename me)" as real subject metadata let a scaffold carry
    # explicit placeholder compliance data through `acef validate` (exit 0) and CI (roborev
    # on 6700802). Deriving from the bundle directory name (sans the `.acef` convention
    # suffix) yields a concrete, user-chosen identifier; only a nameless target (filesystem
    # root) falls back to a stable generic.
    derived_name = target.resolve().name
    if derived_name.endswith(".acef"):
        derived_name = derived_name[: -len(".acef")]
    default_subject_name = derived_name or "acef-subject"
    pkg.add_subject(
        subject_type=subject_type,
        name=subject_name or default_subject_name,
        risk_classification=risk_classification,
        modalities=list(modalities),
    )

    try:
        pkg.export(path)
    except OSError as exc:
        click.echo(f"Error: Cannot write bundle to {path}: {exc}", err=True)
        raise SystemExit(1) from exc

    click.echo(f"Created ACEF bundle at: {path}")
    click.echo(f"Package ID: {pkg.metadata.package_id}")
