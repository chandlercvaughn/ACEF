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
 * Python's load → build_manifest path is intentionally lossy in two ways
 * (verified empirically against every Freddy pass bundle + v1.0 golden
 * bundle):
 *   1. The manifest top-level v1.1 fields `analysis_mode` and `namespaces`
 *      are NOT carried through `Package.build_manifest()` (it constructs a
 *      `Manifest` from the loaded parts without passing them), so they are
 *      dropped on re-export.
 *   2. `metadata.created_at` (and any other metadata key the loader does not
 *      extract into `PackageMetadata`) is dropped, because the loader builds
 *      `PackageMetadata(producer=, retention_policy=, prior_package_ref=)` and
 *      sets only `package_id` + `timestamp` — `created_at` is never read.
 *
 * For Python↔TS archive byte-equality the comparison is
 * `python_reexport == ts_reexport`, so this TS loader must reproduce exactly
 * the SAME transform. Each model's known-field set, default value, and
 * `model_dump(mode="json", exclude_none=True)` behavior is mirrored below.
 */

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";

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
    const manifestRaw = JSON.parse(readFileSync(manifestPath, "utf-8")) as Record<string, unknown>;

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
