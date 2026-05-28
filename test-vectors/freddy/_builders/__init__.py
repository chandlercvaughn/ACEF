"""Builders for `test-vectors/freddy/` conformance bundles.

Each module in this package builds one bundle (pass/fail/fake-green) by
writing a minimal acef-manifest.json + records/*.jsonl + (optionally)
content-hashes.json + README.md to a target directory.

The builders deliberately write JSON dicts directly rather than going
through ``acef.Package``: the conformance vectors test the validator's
end-to-end behavior on bundles whose record-payload shapes match the
v1.1 schemas exactly. Using a deterministic clock + URN list in
``_common.py`` keeps the bundles byte-deterministic across runs.

See ``test-vectors/freddy/build_all.py`` for the orchestrator.
"""
