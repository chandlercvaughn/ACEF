/**
 * jcs-cli: read a JSON document from stdin, write RFC 8785 canonical bytes to stdout.
 *
 * Used by Python-side cross-language test `tests/conformance/test_cross_lang_jcs.py`
 * (VAL-TS-005) to compare against `acef.integrity.canonicalize`.
 */

import { readFileSync } from "node:fs";
import { canonicalize } from "../src/index.js";

const raw = readFileSync(0, "utf-8"); // fd 0 = stdin
const value = JSON.parse(raw);
const bytes = canonicalize(value);
// Write raw bytes to stdout (NOT JSON-stringified).
process.stdout.write(Buffer.from(bytes));
