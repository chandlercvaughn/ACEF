/**
 * export-cli: load a directory bundle and emit its deterministic
 * `.acef.tar.gz` bytes to stdout.
 *
 * Used by the Python-side cross-language parity test
 * `tests/conformance/test_freddy_cross_language_parity.py`
 * (VAL-PARITY-002 / VAL-PARITY-003) to compare archive bytes against
 * Python's `acef.export.export_archive`.
 *
 * Usage:
 *   node dist/cli/export-cli.js <bundle-dir> <bundle-name>
 *
 * where <bundle-name> is the tar root directory name BOTH SDKs agree on
 * (e.g. "verified-delivery.acef"). The mtime is derived from the bundle's
 * own manifest metadata.timestamp inside the exporter, exactly as Python
 * does — so it is NOT passed on the command line.
 *
 * The CLI writes RAW gzipped bytes to stdout. Do NOT pipe through anything
 * that reinterprets bytes/newlines.
 */

import { loadBundle } from "../loader.js";
import { exportArchiveFromDirectory } from "../bundle_export.js";

const bundleDir = process.argv[2];
const bundleName = process.argv[3];

if (typeof bundleDir !== "string" || bundleDir.length === 0) {
    process.stderr.write("usage: export-cli <bundle-dir> <bundle-name>\n");
    process.exit(2);
}
if (typeof bundleName !== "string" || bundleName.length === 0) {
    process.stderr.write("usage: export-cli <bundle-dir> <bundle-name>\n");
    process.exit(2);
}

try {
    const loaded = loadBundle(bundleDir);
    const gz = exportArchiveFromDirectory(loaded, bundleName);
    process.stdout.write(gz);
} catch (err) {
    const msg = err instanceof Error ? err.stack ?? err.message : String(err);
    process.stderr.write(`export-cli failed: ${msg}\n`);
    process.exit(1);
}
