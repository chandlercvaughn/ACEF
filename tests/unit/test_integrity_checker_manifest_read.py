"""Regression: the integrity checker's manifest-timestamp reads must degrade
gracefully on a non-UTF-8 / unreadable ``acef-manifest.json``.

Both ``check_integrity`` (via ``_check_signatures``) and ``get_signature_info``
read ``acef-manifest.json`` to anchor x5c cert-validity against the manifest
``metadata.timestamp`` (spec §3.1.3). That read is wrapped in
``try: json.loads(manifest_path.read_text(encoding="utf-8")) ... except``.

The manifest timestamp is an OPTIONAL anchor: a malformed or unreadable manifest
here MUST degrade gracefully (the timestamp anchor becomes unavailable →
cert-validity falls back to its no-timestamp behavior), exactly the way the
sibling reads in the same module already do
(content-hashes.json :69, merkle-tree.json :150, the ``.jws`` reads :288/:470 —
each catches ``(json.JSONDecodeError, UnicodeDecodeError, OSError)``).

Pre-fix the two manifest reads caught ONLY ``json.JSONDecodeError``, so a
non-UTF-8 manifest (``Path.read_text`` raises ``UnicodeDecodeError``, a
``ValueError`` subclass, NOT ``json.JSONDecodeError``) or an ``OSError`` on a
read race escaped as a RAW traceback:

    UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 0:
    invalid start byte

reproduced end-to-end through ``acef doctor <bundle>`` (raw traceback printed).
This file pins the graceful-degradation contract at both call sites and through
the CLI.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acef.validation.integrity_checker import check_integrity, get_signature_info

# A non-UTF-8 manifest: a UTF-16 BOM (0xff 0xfe) prefixes otherwise-JSON bytes.
# ``Path.read_text(encoding="utf-8")`` raises ``UnicodeDecodeError`` on byte 0xff.
_NON_UTF8_MANIFEST = b'\xff\xfe{"metadata":{"timestamp":"2026-01-01T00:00:00Z"}}'


def _make_signed_bundle_with_manifest(bundle_dir: Path, manifest_bytes: bytes) -> None:
    """Build a bundle whose ``signatures/`` directory is present (so the
    manifest-timestamp read is REACHED) with a valid content-hashes.json (``{}``)
    + merkle-tree.json (``{"root":"abc"}``), and the given raw manifest bytes.

    The ``signatures/`` directory must exist and ``hashes/content-hashes.json``
    must pass the integrity type gate (a flat ``{}`` mapping) so
    ``check_integrity`` proceeds INTO ``_check_signatures`` — the function that
    reads the manifest timestamp. The ``.jws`` file content is irrelevant to the
    crash under test (the manifest is read BEFORE any per-signature work).
    """
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "hashes").mkdir(parents=True, exist_ok=True)
    (bundle_dir / "hashes" / "content-hashes.json").write_text(json.dumps({}), encoding="utf-8")
    (bundle_dir / "hashes" / "merkle-tree.json").write_text(json.dumps({"root": "abc"}), encoding="utf-8")
    sig_dir = bundle_dir / "signatures"
    sig_dir.mkdir(parents=True, exist_ok=True)
    (sig_dir / "x.jws").write_text("a.b.c", encoding="utf-8")
    (bundle_dir / "acef-manifest.json").write_bytes(manifest_bytes)


def test_check_integrity_non_utf8_manifest_does_not_raise(tmp_path: Path) -> None:
    """A non-UTF-8 ``acef-manifest.json`` must not make ``check_integrity`` raise
    a raw ``UnicodeDecodeError`` from its manifest-timestamp read; it degrades
    (the timestamp anchor is unavailable) and returns diagnostics."""
    bundle_dir = tmp_path / "nonutf8.acef"
    _make_signed_bundle_with_manifest(bundle_dir, _NON_UTF8_MANIFEST)

    try:
        diagnostics = check_integrity(bundle_dir)
    except UnicodeDecodeError as exc:  # pragma: no cover — the bug under test
        pytest.fail(
            "check_integrity raised a raw UnicodeDecodeError on a non-UTF-8 "
            f"manifest (it must degrade gracefully): {exc!r}"
        )
    # It returns a list (the manifest-timestamp anchor simply became unavailable;
    # the signature path still ran and may report the synthetic JWS as invalid).
    assert isinstance(diagnostics, list)


def test_get_signature_info_non_utf8_manifest_does_not_raise(tmp_path: Path) -> None:
    """The IDENTICAL manifest-timestamp read in ``get_signature_info`` must also
    degrade gracefully on a non-UTF-8 manifest, returning ``(count, algorithms)``
    rather than raising ``UnicodeDecodeError``."""
    bundle_dir = tmp_path / "nonutf8sig.acef"
    _make_signed_bundle_with_manifest(bundle_dir, _NON_UTF8_MANIFEST)

    try:
        count, algorithms = get_signature_info(bundle_dir)
    except UnicodeDecodeError as exc:  # pragma: no cover — the bug under test
        pytest.fail(
            "get_signature_info raised a raw UnicodeDecodeError on a non-UTF-8 "
            f"manifest (it must degrade gracefully): {exc!r}"
        )
    assert isinstance(count, int)
    assert isinstance(algorithms, list)


def test_manifest_read_oserror_degrades(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An ``OSError`` on the manifest-timestamp read (e.g. a read race after the
    ``.exists()`` check) must degrade gracefully at BOTH call sites rather than
    escape as a raw traceback.

    The OSError is injected by monkeypatching ``Path.read_text`` to raise for the
    ``acef-manifest.json`` path ONLY (every other read — content-hashes.json,
    merkle-tree.json, the .jws files — uses the real implementation), so the
    fault lands EXACTLY on the manifest-timestamp read under test.
    """
    bundle_dir = tmp_path / "oserror.acef"
    # Valid manifest bytes — the OSError comes from the patched read, not the
    # content, proving the guard handles a read-time fault not just bad bytes.
    _make_signed_bundle_with_manifest(
        bundle_dir,
        b'{"metadata":{"timestamp":"2026-01-01T00:00:00Z"}}',
    )

    real_read_text = Path.read_text

    def _patched_read_text(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "acef-manifest.json":
            raise OSError("simulated read race on manifest")
        return real_read_text(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", _patched_read_text)

    try:
        diagnostics = check_integrity(bundle_dir)
        count, algorithms = get_signature_info(bundle_dir)
    except OSError as exc:  # pragma: no cover — the bug under test
        pytest.fail(f"an OSError on the manifest-timestamp read escaped (it must degrade gracefully): {exc!r}")
    assert isinstance(diagnostics, list)
    assert isinstance(count, int)
    assert isinstance(algorithms, list)


def test_doctor_non_utf8_manifest_exits_cleanly_no_traceback(tmp_path: Path) -> None:
    """End-to-end: ``acef doctor <bundle>`` on a bundle with a non-UTF-8 manifest
    must exit with a clean SystemExit (non-zero because the manifest is bad), NOT
    blow up with a raw ``UnicodeDecodeError`` traceback escaping the command.

    Before the fix, ``doctor`` printed the ACEF-050 manifest issue (its own
    ``_check_manifest`` catches the decode error) and then crashed in
    ``_check_integrity`` → ``check_integrity`` → ``_check_signatures`` with a raw
    UnicodeDecodeError traceback.
    """
    from click.testing import CliRunner

    from acef.cli.doctor_cmd import doctor_cmd

    bundle_dir = tmp_path / "doctor.acef"
    _make_signed_bundle_with_manifest(bundle_dir, _NON_UTF8_MANIFEST)

    runner = CliRunner()
    result = runner.invoke(doctor_cmd, [str(bundle_dir)])

    # The command must terminate via SystemExit (a controlled exit), NOT propagate
    # an uncaught exception. CliRunner stores any uncaught exception on
    # ``result.exception`` with a non-SystemExit type.
    assert not isinstance(result.exception, UnicodeDecodeError), (
        f"acef doctor leaked a raw UnicodeDecodeError on a non-UTF-8 manifest: {result.exception!r}\n{result.output}"
    )
    # A bad manifest is an error → doctor exits non-zero, but cleanly.
    assert result.exit_code == 1, f"expected clean exit 1, got {result.exit_code}; output={result.output}"
    # The ACEF-050 manifest diagnostic from _check_manifest is still surfaced.
    assert "ACEF-050" in result.output
