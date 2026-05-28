/**
 * gzip-cli: read a file path from argv[2], emit deterministic gzip bytes to stdout.
 *
 * Used by Python-side cross-language test
 * `tests/conformance/test_gzip_determinism.py` (VAL-PARITY-001) to compare
 * against `acef.exporter_gzip.deterministic_gzip`.
 *
 * Usage:
 *   node dist-test/test/gzip-cli.js <path-to-file>
 *
 * The CLI writes raw gzipped bytes to stdout — DO NOT pipe through
 * anything that would re-interpret newlines (e.g., text-mode `print`).
 */

import { readFileSync } from "node:fs";
import { deterministicGzip } from "../src/index.js";

const path = process.argv[2];
if (typeof path !== "string" || path.length === 0) {
    process.stderr.write("usage: gzip-cli <input-file>\n");
    process.exit(2);
}

const input: Buffer = readFileSync(path);
const out: Buffer = deterministicGzip(input);
process.stdout.write(out);
