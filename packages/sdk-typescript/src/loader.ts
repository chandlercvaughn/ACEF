/**
 * ACEF loader — directory-bundle deserialization for cross-language parity.
 *
 * Ports the read path of `src/acef/loader.py:_load_directory` to the extent
 * required for re-export byte-parity (VAL-PARITY-002 / VAL-PARITY-003). The
 * goal of this module is NOT to reconstruct the full Pydantic object graph —
 * it is to reproduce, byte-for-byte, the manifest dict that Python's
 * `loader.load(...)` → `Package.build_manifest()` → `Manifest.to_dict()`
 * pipeline emits, plus the raw record objects.
 *
 * Why a bespoke rebuild rather than echoing the on-disk manifest?
 * The rebuild reproduces Python's load → build_manifest → to_dict transform,
 * which recomputes `record_files` (sharding) and applies each model's
 * known-field defaults + `model_dump(mode="json", exclude_none=True)`. It is
 * NOT a verbatim echo of the on-disk manifest.
 *
 * The load → build_manifest path is LOSSLESS to the open core (spec §6.4 rule
 * 5 / §6.5): the manifest top-level v1.1 fields `analysis_mode` (X5) and
 * `namespaces` (X6), any top-level vendor x-* extension, and any extra
 * metadata key (`metadata.created_at`, vendor x-*) are PRESERVED on re-export.
 * Python carries them via `Package._analysis_mode` / `_namespaces` /
 * `_manifest_extras` (re-emitted by `build_manifest()`) and via
 * `PackageMetadata`'s `extra='allow'` passthrough; the TS exporter
 * (`bundle_export.rebuildManifestForExport` / `rebuildMetadata`) mirrors this
 * exactly so `python_reexport == ts_reexport` holds byte-for-byte.
 */

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";

import { assertNoDuplicateMemberNames } from "./integrity.js";

/** A raw record object as parsed from a `records/*.jsonl` line. */
export type RawRecord = Record<string, unknown>;

/** Result of loading a directory bundle for re-export. */
export interface LoadedBundle {
    /** The raw manifest JSON object exactly as on disk. */
    manifestRaw: Record<string, unknown>;
    /** All records parsed from every `records/*.jsonl` file, in file+line order. */
    records: RawRecord[];
    /** Artifact relative paths → file contents (for hash-domain re-export). */
    attachments: Map<string, Buffer>;
}

function readJsonl(path: string): RawRecord[] {
    const text = readFileSync(path, "utf-8");
    const out: RawRecord[] = [];
    for (const rawLine of text.split("\n")) {
        const line = rawLine.trim();
        if (line.length === 0) continue;
        // I-JSON (RFC 7493 §2.3): reject a duplicate member name BEFORE JSON.parse
        // de-dups it (last-wins), so a hash-domain duplicate is not silently
        // collapsed before re-export hashes the rebuilt JSON.
        assertNoDuplicateMemberNames(line);
        out.push(JSON.parse(line) as RawRecord);
    }
    return out;
}

/**
 * Load a directory bundle. Mirrors `loader._load_directory` for the subset
 * of behavior relevant to re-export (manifest dict + records + artifacts).
 */
export function loadBundle(dirPath: string): LoadedBundle {
    const manifestPath = join(dirPath, "acef-manifest.json");
    if (!existsSync(manifestPath)) {
        throw new Error(`No acef-manifest.json found in ${dirPath}`);
    }
    const manifestText = readFileSync(manifestPath, "utf-8");
    assertNoDuplicateMemberNames(manifestText); // I-JSON (RFC 7493 §2.3), before last-wins JSON.parse
    const manifestRaw = JSON.parse(manifestText) as Record<string, unknown>;

    // Read records by following manifest.record_files (matches Python loader,
    // which reads exactly the files listed in record_files, in list order).
    const records: RawRecord[] = [];
    const recordFiles = (manifestRaw["record_files"] as Array<Record<string, unknown>> | undefined) ?? [];
    for (const rf of recordFiles) {
        const rfPath = rf["path"];
        if (typeof rfPath !== "string" || rfPath.length === 0) {
            throw new Error("record_files entry missing 'path' field");
        }
        const full = join(dirPath, rfPath);
        if (!existsSync(full)) {
            throw new Error(`Record file listed in manifest but not found on disk: ${rfPath}`);
        }
        records.push(...readJsonl(full));
    }

    // Load artifacts (hash-domain files under artifacts/). Mirrors Python
    // loader's recursive read of artifacts/.
    const attachments = new Map<string, Buffer>();
    const artifactsDir = join(dirPath, "artifacts");
    if (existsSync(artifactsDir) && statSync(artifactsDir).isDirectory()) {
        const walk = (rel: string): void => {
            const abs = join(dirPath, rel);
            for (const name of readdirSync(abs).sort()) {
                const childRel = `${rel}/${name}`;
                const childAbs = join(dirPath, childRel);
                const st = statSync(childAbs);
                if (st.isDirectory()) {
                    walk(childRel);
                } else if (st.isFile()) {
                    attachments.set(childRel, readFileSync(childAbs));
                }
            }
        };
        walk("artifacts");
    }

    return { manifestRaw, records, attachments };
}
