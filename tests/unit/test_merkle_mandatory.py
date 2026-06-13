"""Merkle-tree presence is mandatory — spec §3.1.3 step (d) cannot be silently skipped.

Finding loader-roundtrip-4 / VAL-FIX-LOADER-004: ``check_integrity`` only
verified the Merkle root inside ``if merkle_path.exists():`` with no ``else``
branch. When ``hashes/merkle-tree.json`` is absent (in a bundle that DOES carry
``hashes/content-hashes.json``), step (d)'s mandatory recompute-and-compare was
skipped with ZERO diagnostics. Because ``hashes/`` lives outside the hash domain
(spec line 526-528), ``content-hashes.json`` does not list ``merkle-tree.json``,
so its deletion is otherwise undetectable: an adversary or buggy producer can
strip the file to bypass the FATAL step (d) check.

Spec §3.1.3 step (d) (line 562): "Recompute the Merkle tree from
content-hashes.json ... Compare root against merkle-tree.json. Mismatch is FATAL
(ACEF-011)." Layout (line 501/528) lists ``hashes/merkle-tree.json`` as a bundle
file. A bundle whose required Merkle file is missing cannot satisfy the root
comparison, so the correct verdict is the step-(d) FATAL code ACEF-011 at
``/hashes/merkle-tree.json``.
"""

from __future__ import annotations

import json
from pathlib import Path

from acef.export import export_directory
from acef.package import Package
from acef.validation.integrity_checker import check_integrity


def _merkle_diagnostics(diagnostics: list) -> list:
    """Diagnostics that point at the Merkle file."""
    return [d for d in diagnostics if d.path == "/hashes/merkle-tree.json"]


class TestMerkleMandatory:
    """A bundle that carries content-hashes.json MUST also carry merkle-tree.json."""

    def test_absent_merkle_tree_is_fatal(self, minimal_package: Package, tmp_dir: Path) -> None:
        """Deleting merkle-tree.json (content-hashes.json present) → FATAL ACEF-011.

        RED proof: before the fix ``check_integrity`` returns NO Merkle
        diagnostic for this bundle (the ``if merkle_path.exists():`` gate
        silently skips step (d)).
        """
        bundle_dir = tmp_dir / "bundle.acef"
        export_directory(minimal_package, str(bundle_dir))

        merkle_path = bundle_dir / "hashes" / "merkle-tree.json"
        content_hashes_path = bundle_dir / "hashes" / "content-hashes.json"
        assert merkle_path.exists()
        assert content_hashes_path.exists()
        merkle_path.unlink()
        assert not merkle_path.exists()

        diagnostics = check_integrity(bundle_dir)

        merkle_diags = _merkle_diagnostics(diagnostics)
        assert merkle_diags, "Missing merkle-tree.json bypassed mandatory step (d) — no diagnostic emitted"
        assert len(merkle_diags) == 1
        diag = merkle_diags[0]
        assert diag.code == "ACEF-011"
        assert diag.severity.value == "fatal"
        assert "merkle-tree.json" in diag.message
        # No false content-hash mismatch: content layer is intact, only the
        # Merkle file is missing.
        assert not any(d.code == "ACEF-010" for d in diagnostics)

    def test_complete_bundle_still_clean(self, minimal_package: Package, tmp_dir: Path) -> None:
        """A complete, untouched valid bundle → no integrity diagnostics (no false positive)."""
        bundle_dir = tmp_dir / "bundle.acef"
        export_directory(minimal_package, str(bundle_dir))

        diagnostics = check_integrity(bundle_dir)

        assert diagnostics == [], f"Complete valid bundle produced unexpected diagnostics: {diagnostics!r}"

    def test_present_merkle_wrong_root_still_mismatch(self, minimal_package: Package, tmp_dir: Path) -> None:
        """A merkle-tree.json that IS present but carries the WRONG root → ACEF-011 mismatch.

        Guards that the existing present-but-wrong path is unchanged by the
        absent-file branch.
        """
        bundle_dir = tmp_dir / "bundle.acef"
        export_directory(minimal_package, str(bundle_dir))

        merkle_path = bundle_dir / "hashes" / "merkle-tree.json"
        merkle_data = json.loads(merkle_path.read_text(encoding="utf-8"))
        merkle_data["root"] = "00" * 32  # deliberately wrong root
        merkle_path.write_text(json.dumps(merkle_data), encoding="utf-8")

        diagnostics = check_integrity(bundle_dir)

        merkle_diags = _merkle_diagnostics(diagnostics)
        assert len(merkle_diags) == 1
        diag = merkle_diags[0]
        assert diag.code == "ACEF-011"
        assert "mismatch" in diag.message.lower()

    def test_no_content_hashes_no_double_report(self, tmp_dir: Path) -> None:
        """A bundle with NO content-hashes.json → single ACEF-014, NOT also a Merkle diagnostic.

        The absent-Merkle branch must only fire when content-hashes.json exists
        (a real integrity layer); a bundle lacking the hash index entirely is
        already fatally reported once and short-circuits before the Merkle
        check, so it must not be double-reported.
        """
        bundle_dir = tmp_dir / "empty-bundle"
        (bundle_dir / "hashes").mkdir(parents=True)
        # No content-hashes.json, no merkle-tree.json.

        diagnostics = check_integrity(bundle_dir)

        assert len(diagnostics) == 1
        assert diagnostics[0].code == "ACEF-014"
        assert diagnostics[0].path == "/hashes/content-hashes.json"
        assert not _merkle_diagnostics(diagnostics)
