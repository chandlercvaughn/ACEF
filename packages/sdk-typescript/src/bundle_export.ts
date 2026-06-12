/**
 * ACEF directory + archive exporter — byte-equal to Python's
 * `acef.export.export_directory` / `export_archive` (VAL-PARITY-002/003).
 *
 * The export pipeline is:
 *   1. Rebuild the manifest dict via `rebuildManifestForExport`, reproducing
 *      Python's `loader.load(...)` → `Package.build_manifest()` →
 *      `Manifest.to_dict()` (= `model_dump(mode="json", exclude_none=True)`)
 *      transform exactly. This drops manifest-level `analysis_mode`/`namespaces`
 *      and `metadata.created_at` (and any other key not read into a model),
 *      and recomputes `record_files` from the records.
 *   2. Write records as JSONL: group by record_type, sort each group by
 *      (timestamp, record_id), shard per `computeShardBoundaries`, JCS each
 *      record line + trailing "\n".
 *   3. Compute content-hashes.json + merkle-tree.json identically to
 *      `acef.integrity`.
 *   4. Assemble a USTAR tar (root dir, sorted dirs, sorted files) with the
 *      exact TarInfo settings Python's `tarfile` emits for these short names,
 *      then wrap with `deterministicGzip`.
 *
 * The hash domain (content-hashes.json) covers acef-manifest.json + records/
 * + artifacts/ — mirroring `compute_content_hashes`. The directory layout
 * also emits empty artifacts/, hashes/, signatures/ directories so the tar
 * dir entries match Python's `os.walk` of the exported tree.
 */

import { createHash } from "node:crypto";
import { canonicalize, sha256Hex, buildMerkleTree } from "./integrity.js";
import { deterministicGzip } from "./exporter.js";
import type { LoadedBundle, RawRecord } from "./loader.js";

/** Maximum records per shard (spec §3.1.1). */
const SHARD_RECORD_LIMIT = 100_000;
/** Maximum shard size in bytes (256 MB). */
const SHARD_SIZE_LIMIT = 256 * 1024 * 1024;

/* ------------------------------------------------------------------------- *
 * Manifest rebuild — mirror of loader + Pydantic model_dump(exclude_none)
 * ------------------------------------------------------------------------- */

type Obj = Record<string, unknown>;

function asObj(v: unknown): Obj {
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {};
}
function asArr(v: unknown): unknown[] {
    return Array.isArray(v) ? v : [];
}

/** Pick keys from `src` in `keys` that are present (not undefined). */
function pick(src: Obj, keys: string[]): Obj {
    const out: Obj = {};
    for (const k of keys) {
        if (src[k] !== undefined) out[k] = src[k];
    }
    return out;
}

/**
 * Reproduce `PackageMetadata` round-trip. The Python loader builds
 * `PackageMetadata(producer=, retention_policy=, prior_package_ref=)` then
 * sets `package_id` and `timestamp`. `Manifest.to_dict()` runs
 * `model_dump(mode="json", exclude_none=True)`.
 *
 * Declared metadata fields: package_id, timestamp, producer,
 * prior_package_ref (None→dropped), retention_policy (None→dropped).
 * `created_at` and any other on-disk metadata key are NOT read → dropped.
 */
function rebuildMetadata(raw: Obj): Obj {
    const out: Obj = {};
    const producer = asObj(raw["producer"]);
    // ProducerInfo declares name + version (both required). exclude_none keeps
    // present values; producer is required so it is always emitted.
    out["producer"] = pick(producer, ["name", "version"]);

    // package_id + timestamp always present (loader sets them; required-ish).
    if (raw["package_id"] !== undefined) out["package_id"] = raw["package_id"];
    if (raw["timestamp"] !== undefined) out["timestamp"] = raw["timestamp"];

    // prior_package_ref: emitted only if non-null on disk (exclude_none).
    if (raw["prior_package_ref"] !== undefined && raw["prior_package_ref"] !== null) {
        out["prior_package_ref"] = raw["prior_package_ref"];
    }

    // retention_policy: RetentionPolicy(min_retention_days>=0,
    // personal_data_interplay None→dropped). Emitted only if present.
    if (raw["retention_policy"] !== undefined && raw["retention_policy"] !== null) {
        const rp = asObj(raw["retention_policy"]);
        const rpOut: Obj = {};
        if (rp["min_retention_days"] !== undefined) rpOut["min_retention_days"] = rp["min_retention_days"];
        if (rp["personal_data_interplay"] !== undefined && rp["personal_data_interplay"] !== null) {
            rpOut["personal_data_interplay"] = rp["personal_data_interplay"];
        }
        out["retention_policy"] = rpOut;
    }
    return out;
}

/** Versioning(core_version="1.0.0", profiles_version="1.0.0"). Both required defaults. */
function rebuildVersioning(raw: Obj): Obj {
    return {
        core_version: raw["core_version"] !== undefined ? raw["core_version"] : "1.0.0",
        profiles_version: raw["profiles_version"] !== undefined ? raw["profiles_version"] : "1.0.0",
    };
}

const SUBJECT_KNOWN = [
    "subject_id",
    "subject_type",
    "name",
    "version",
    "provider",
    "risk_classification",
    "modalities",
    "lifecycle_phase",
    "lifecycle_timeline",
];

/**
 * Subject round-trip. Loader reconstructs known fields + applies defaults +
 * preserves extras (via `_extras`). model_dump(exclude_none) — Subject has no
 * Optional[None]-default fields, so all known fields emit. lifecycle_timeline
 * entries: LifecycleEntry(phase, start_date, end_date None→dropped) + extras.
 */
function rebuildSubject(raw: Obj): Obj {
    const out: Obj = {};
    out["subject_id"] = raw["subject_id"] !== undefined ? raw["subject_id"] : "";
    out["subject_type"] = raw["subject_type"] !== undefined ? raw["subject_type"] : "ai_system";
    out["name"] = raw["name"] !== undefined ? raw["name"] : "";
    out["version"] = raw["version"] !== undefined ? raw["version"] : "1.0.0";
    out["provider"] = raw["provider"] !== undefined ? raw["provider"] : "";
    out["risk_classification"] = raw["risk_classification"] !== undefined ? raw["risk_classification"] : "minimal-risk";
    out["modalities"] = raw["modalities"] !== undefined ? raw["modalities"] : [];
    out["lifecycle_phase"] = raw["lifecycle_phase"] !== undefined ? raw["lifecycle_phase"] : "development";

    const timeline = asArr(raw["lifecycle_timeline"]).map((e) => {
        const ent = asObj(e);
        const eo: Obj = {};
        if (ent["phase"] !== undefined) eo["phase"] = ent["phase"];
        if (ent["start_date"] !== undefined) eo["start_date"] = ent["start_date"];
        if (ent["end_date"] !== undefined && ent["end_date"] !== null) eo["end_date"] = ent["end_date"];
        // extras (extra='allow')
        for (const [k, v] of Object.entries(ent)) {
            if (!["phase", "start_date", "end_date"].includes(k) && v !== undefined) eo[k] = v;
        }
        return eo;
    });
    out["lifecycle_timeline"] = timeline;

    // extras preserved by loader's _extras(sub_data, _SUBJECT_KNOWN)
    for (const [k, v] of Object.entries(raw)) {
        if (!SUBJECT_KNOWN.includes(k) && v !== undefined) out[k] = v;
    }
    return out;
}

const COMP_KNOWN = ["component_id", "name", "type", "version", "subject_refs", "provider"];
function rebuildComponent(raw: Obj): Obj {
    const out: Obj = {};
    out["component_id"] = raw["component_id"] !== undefined ? raw["component_id"] : "";
    out["name"] = raw["name"] !== undefined ? raw["name"] : "";
    out["type"] = raw["type"] !== undefined ? raw["type"] : "model";
    out["version"] = raw["version"] !== undefined ? raw["version"] : "1.0.0";
    out["subject_refs"] = raw["subject_refs"] !== undefined ? raw["subject_refs"] : [];
    out["provider"] = raw["provider"] !== undefined ? raw["provider"] : "";
    for (const [k, v] of Object.entries(raw)) {
        if (!COMP_KNOWN.includes(k) && v !== undefined) out[k] = v;
    }
    return out;
}

const DS_KNOWN = ["dataset_id", "name", "version", "source_type", "modality", "size", "subject_refs"];
function rebuildDataset(raw: Obj): Obj {
    const out: Obj = {};
    out["dataset_id"] = raw["dataset_id"] !== undefined ? raw["dataset_id"] : "";
    out["name"] = raw["name"] !== undefined ? raw["name"] : "";
    out["version"] = raw["version"] !== undefined ? raw["version"] : "1.0.0";
    out["source_type"] = raw["source_type"] !== undefined ? raw["source_type"] : "licensed";
    out["modality"] = raw["modality"] !== undefined ? raw["modality"] : "text";
    // size: DatasetSize|dict default {records:0,size_gb:0.0}. Loader passes the
    // dict through verbatim when present; the model accepts dict OR DatasetSize.
    out["size"] = raw["size"] !== undefined ? raw["size"] : { records: 0, size_gb: 0.0 };
    out["subject_refs"] = raw["subject_refs"] !== undefined ? raw["subject_refs"] : [];
    for (const [k, v] of Object.entries(raw)) {
        if (!DS_KNOWN.includes(k) && v !== undefined) out[k] = v;
    }
    return out;
}

const ACT_KNOWN = ["actor_id", "role", "name", "organization"];
function rebuildActor(raw: Obj): Obj {
    const out: Obj = {};
    out["actor_id"] = raw["actor_id"] !== undefined ? raw["actor_id"] : "";
    out["role"] = raw["role"] !== undefined ? raw["role"] : "provider";
    out["name"] = raw["name"] !== undefined ? raw["name"] : "";
    out["organization"] = raw["organization"] !== undefined ? raw["organization"] : "";
    // authority_class: Optional[None]. Emitted only if present (exclude_none).
    // It is NOT in _ACTOR_KNOWN, so the loader carries it through as an extra
    // (extra='allow'), then model_dump emits it (a declared field with value).
    for (const [k, v] of Object.entries(raw)) {
        if (!ACT_KNOWN.includes(k) && v !== undefined && v !== null) out[k] = v;
    }
    return out;
}

const REL_KNOWN = ["source_ref", "target_ref", "relationship_type", "description"];
function rebuildRelationship(raw: Obj): Obj {
    const out: Obj = {};
    out["source_ref"] = raw["source_ref"] !== undefined ? raw["source_ref"] : "";
    out["target_ref"] = raw["target_ref"] !== undefined ? raw["target_ref"] : "";
    out["relationship_type"] = raw["relationship_type"] !== undefined ? raw["relationship_type"] : "calls";
    out["description"] = raw["description"] !== undefined ? raw["description"] : "";
    for (const [k, v] of Object.entries(raw)) {
        if (!REL_KNOWN.includes(k) && v !== undefined) out[k] = v;
    }
    return out;
}

/** EntitiesBlock with all four lists (always present via default_factory). */
function rebuildEntities(raw: Obj): Obj {
    return {
        components: asArr(raw["components"]).map((c) => rebuildComponent(asObj(c))),
        datasets: asArr(raw["datasets"]).map((d) => rebuildDataset(asObj(d))),
        actors: asArr(raw["actors"]).map((a) => rebuildActor(asObj(a))),
        relationships: asArr(raw["relationships"]).map((r) => rebuildRelationship(asObj(r))),
    };
}

/** ProfileEntry(profile_id, template_version="1.0.0", applicable_provisions=[]). */
function rebuildProfile(raw: Obj): Obj {
    const out: Obj = {};
    out["profile_id"] = raw["profile_id"] !== undefined ? raw["profile_id"] : "";
    out["template_version"] = raw["template_version"] !== undefined ? raw["template_version"] : "1.0.0";
    out["applicable_provisions"] =
        raw["applicable_provisions"] !== undefined ? raw["applicable_provisions"] : [];
    // ProfileEntry constructed via **prof_data — extras preserved.
    for (const [k, v] of Object.entries(raw)) {
        if (!["profile_id", "template_version", "applicable_provisions"].includes(k) && v !== undefined) out[k] = v;
    }
    return out;
}

/** AuditTrailEntry(event_type, timestamp, actor_ref="", description=""). */
function rebuildAuditEntry(raw: Obj): Obj {
    const out: Obj = {};
    if (raw["event_type"] !== undefined) out["event_type"] = raw["event_type"];
    if (raw["timestamp"] !== undefined) out["timestamp"] = raw["timestamp"];
    out["actor_ref"] = raw["actor_ref"] !== undefined ? raw["actor_ref"] : "";
    out["description"] = raw["description"] !== undefined ? raw["description"] : "";
    for (const [k, v] of Object.entries(raw)) {
        if (!["event_type", "timestamp", "actor_ref", "description"].includes(k) && v !== undefined) out[k] = v;
    }
    return out;
}

/* ------------------------------------------------------------------------- *
 * Records: sort + shard
 * ------------------------------------------------------------------------- */

function recordTimestamp(r: RawRecord): string {
    const t = r["timestamp"];
    return typeof t === "string" ? t : "";
}
function recordId(r: RawRecord): string {
    const id = r["record_id"];
    return typeof id === "string" ? id : "";
}

/** Sort records by (timestamp, record_id) ascending. Mirrors `sort_records`. */
function sortRecords(records: RawRecord[]): RawRecord[] {
    return [...records].sort((a, b) => {
        const ta = recordTimestamp(a);
        const tb = recordTimestamp(b);
        if (ta < tb) return -1;
        if (ta > tb) return 1;
        const ia = recordId(a);
        const ib = recordId(b);
        if (ia < ib) return -1;
        if (ia > ib) return 1;
        return 0;
    });
}

/**
 * Split a sorted record list into shards. Mirrors `compute_shard_boundaries`:
 * fits into one shard when <= 100k records AND total canonical size + newline
 * per record <= 256 MB; otherwise greedy split.
 */
function computeShardBoundaries(records: RawRecord[]): RawRecord[][] {
    if (records.length <= SHARD_RECORD_LIMIT) {
        let totalSize = 0;
        for (const rec of records) {
            totalSize += canonicalize(rec).length + 1;
        }
        if (totalSize <= SHARD_SIZE_LIMIT) {
            return [records];
        }
    }
    const shards: RawRecord[][] = [];
    let current: RawRecord[] = [];
    let currentSize = 0;
    for (const rec of records) {
        const recSize = canonicalize(rec).length + 1;
        const shouldSplit =
            current.length >= SHARD_RECORD_LIMIT ||
            (currentSize + recSize > SHARD_SIZE_LIMIT && current.length > 0);
        if (shouldSplit) {
            shards.push(current);
            current = [];
            currentSize = 0;
        }
        current.push(rec);
        currentSize += recSize;
    }
    if (current.length > 0) shards.push(current);
    return shards;
}

/* ------------------------------------------------------------------------- *
 * Public: rebuild manifest, build in-memory directory, assemble archive
 * ------------------------------------------------------------------------- */

/** A virtual bundle directory: relative-path → file bytes; plus dir set. */
export interface VirtualBundle {
    /** Map of forward-slash relative path → file content. */
    files: Map<string, Buffer>;
    /** Set of forward-slash relative directory paths (no leading bundle name). */
    dirs: Set<string>;
    /** mtime (epoch seconds) derived from manifest metadata.timestamp. */
    mtime: number;
}

/**
 * Rebuild the manifest dict exactly as Python's load→build_manifest→to_dict
 * pipeline does, recomputing record_files from `records`.
 */
export function rebuildManifestForExport(manifestRaw: Obj, records: RawRecord[]): Obj {
    const metadataRaw = asObj(manifestRaw["metadata"]);
    const versioningRaw = asObj(manifestRaw["versioning"]);
    const entitiesRaw = asObj(manifestRaw["entities"]);

    // Recompute record_files: group by type, sort, shard. Mirrors
    // Package.build_manifest().
    const byType = new Map<string, RawRecord[]>();
    for (const rec of records) {
        const rt = typeof rec["record_type"] === "string" ? (rec["record_type"] as string) : "";
        if (!byType.has(rt)) byType.set(rt, []);
        byType.get(rt)!.push(rec);
    }
    const recordFiles: Obj[] = [];
    for (const recordType of [...byType.keys()].sort()) {
        const sorted = sortRecords(byType.get(recordType)!);
        const shards = computeShardBoundaries(sorted);
        if (shards.length === 1) {
            recordFiles.push({
                path: `records/${recordType}.jsonl`,
                record_type: recordType,
                count: shards[0]!.length,
            });
        } else {
            for (let i = 0; i < shards.length; i++) {
                const shardNum = String(i + 1).padStart(4, "0");
                recordFiles.push({
                    path: `records/${recordType}/${recordType}.${shardNum}.jsonl`,
                    record_type: recordType,
                    count: shards[i]!.length,
                });
            }
        }
    }

    // Build the manifest in the SAME shape build_manifest()+to_dict() emits.
    // Note: analysis_mode + namespaces are intentionally NOT carried (Python's
    // build_manifest does not pass them to Manifest).
    return {
        metadata: rebuildMetadata(metadataRaw),
        versioning: rebuildVersioning(versioningRaw),
        subjects: asArr(manifestRaw["subjects"]).map((s) => rebuildSubject(asObj(s))),
        entities: rebuildEntities(entitiesRaw),
        profiles: asArr(manifestRaw["profiles"]).map((p) => rebuildProfile(asObj(p))),
        record_files: recordFiles,
        audit_trail: asArr(manifestRaw["audit_trail"]).map((a) => rebuildAuditEntry(asObj(a))),
    };
}

/** Derive the deterministic mtime from manifest metadata.timestamp. */
function deriveMtime(manifestRaw: Obj): number {
    const metadata = asObj(manifestRaw["metadata"]);
    const ts = metadata["timestamp"];
    if (typeof ts !== "string" || ts.length === 0) return 0;
    // Python: int(datetime.fromisoformat(ts.replace("Z","+00:00")).timestamp())
    const normalized = ts.replace("Z", "+00:00");
    const ms = Date.parse(normalized);
    if (Number.isNaN(ms)) return 0;
    return Math.floor(ms / 1000);
}

/**
 * Build the in-memory directory representation of a re-exported bundle.
 *
 * Files written (matching export_directory):
 *   - records/<type>.jsonl (or sharded subdir) — JCS lines + "\n"
 *   - acef-manifest.json — JCS of rebuilt manifest
 *   - hashes/content-hashes.json — JCS of content hash map
 *   - hashes/merkle-tree.json — JCS of merkle tree
 *   - artifacts/<path> — verbatim attachment bytes
 * Empty managed dirs (artifacts, hashes, signatures) are always present.
 */
export function buildVirtualBundle(loaded: LoadedBundle): VirtualBundle {
    const files = new Map<string, Buffer>();
    const dirs = new Set<string>();

    // Managed subdirectories always created by export_directory.
    dirs.add("records");
    dirs.add("artifacts");
    dirs.add("hashes");
    dirs.add("signatures");

    // Records, grouped by type, sorted, sharded.
    const byType = new Map<string, RawRecord[]>();
    for (const rec of loaded.records) {
        const rt = typeof rec["record_type"] === "string" ? (rec["record_type"] as string) : "";
        if (!byType.has(rt)) byType.set(rt, []);
        byType.get(rt)!.push(rec);
    }
    for (const recordType of [...byType.keys()].sort()) {
        const sorted = sortRecords(byType.get(recordType)!);
        const shards = computeShardBoundaries(sorted);
        if (shards.length === 1) {
            files.set(`records/${recordType}.jsonl`, jsonlBytes(shards[0]!));
        } else {
            dirs.add(`records/${recordType}`);
            for (let i = 0; i < shards.length; i++) {
                const shardNum = String(i + 1).padStart(4, "0");
                files.set(`records/${recordType}/${recordType}.${shardNum}.jsonl`, jsonlBytes(shards[i]!));
            }
        }
    }

    // Attachments (artifacts/). Each path already prefixed with "artifacts/".
    for (const [relPath, content] of loaded.attachments.entries()) {
        files.set(relPath, content);
        // Record intermediate dirs.
        const parts = relPath.split("/");
        for (let i = 1; i < parts.length; i++) {
            dirs.add(parts.slice(0, i).join("/"));
        }
    }

    // Manifest.
    const manifest = rebuildManifestForExport(loaded.manifestRaw, loaded.records);
    files.set("acef-manifest.json", Buffer.from(canonicalize(manifest)));

    // content-hashes.json (hash domain = manifest + records/ + artifacts/).
    const contentHashes = computeContentHashes(files);
    files.set("hashes/content-hashes.json", Buffer.from(canonicalize(contentHashes)));

    // merkle-tree.json.
    const merkle = buildMerkleTree(contentHashes);
    files.set("hashes/merkle-tree.json", Buffer.from(canonicalize(merkle)));

    return { files, dirs, mtime: deriveMtime(loaded.manifestRaw) };
}

/** JCS each record + "\n", concatenate. Mirrors `_write_jsonl`. */
function jsonlBytes(records: RawRecord[]): Buffer {
    const chunks: Buffer[] = [];
    for (const rec of records) {
        chunks.push(Buffer.from(canonicalize(rec)));
        chunks.push(Buffer.from("\n", "utf-8"));
    }
    return Buffer.concat(chunks);
}

/**
 * Compute content-hashes.json over the hash domain. Mirrors
 * `acef.integrity.compute_content_hashes`:
 *   - acef-manifest.json
 *   - everything under records/
 *   - everything under artifacts/
 * Hashing rules (`sha256_file`):
 *   - .json → parse + JCS + sha256(canonical)
 *   - .jsonl → per-line JCS + "\n", streamed into one sha256
 *   - other → raw bytes
 * The result is key-sorted.
 */
function computeContentHashes(files: Map<string, Buffer>): Record<string, string> {
    const hashes: Record<string, string> = {};
    for (const [path, content] of files.entries()) {
        const inDomain =
            path === "acef-manifest.json" ||
            path.startsWith("records/") ||
            path.startsWith("artifacts/");
        if (!inDomain) continue;
        hashes[path] = hashFile(path, content);
    }
    // Sort keys.
    const sorted: Record<string, string> = {};
    for (const k of Object.keys(hashes).sort()) sorted[k] = hashes[k]!;
    return sorted;
}

/** Hash a file's content per `sha256_file` rules based on suffix. */
function hashFile(path: string, content: Buffer): string {
    if (path.endsWith(".json")) {
        const obj = JSON.parse(content.toString("utf-8")) as unknown;
        return sha256Hex(canonicalize(obj));
    }
    if (path.endsWith(".jsonl")) {
        const text = content.toString("utf-8");
        const h = createHash("sha256");
        if (text.length === 0) return h.digest("hex");
        let lines = text.split("\n");
        if (lines.length > 0 && lines[lines.length - 1] === "") lines = lines.slice(0, -1);
        for (const line of lines) {
            const obj = JSON.parse(line) as unknown;
            h.update(Buffer.from(canonicalize(obj)));
            h.update(Buffer.from("\n", "utf-8"));
        }
        return h.digest("hex");
    }
    return createHash("sha256").update(content).digest("hex");
}

/* ------------------------------------------------------------------------- *
 * USTAR tar writer
 * ------------------------------------------------------------------------- */

const TAR_BLOCK = 512;
/**
 * Python tarfile's RECORDSIZE: the archive is zero-padded to a multiple of
 * this (20 blocks). `tarfile.close()` writes the two trailing zero blocks
 * then pads up to the next RECORDSIZE boundary, so byte-equal output MUST
 * reproduce this final padding.
 */
const TAR_RECORDSIZE = TAR_BLOCK * 20;

/** Write an octal numeric field of `width` chars (incl. trailing NUL). */
function writeOctal(header: Buffer, offset: number, value: number, width: number): void {
    // Python's tarfile uses width-1 octal digits, zero-padded, then NUL.
    const digits = width - 1;
    const oct = value.toString(8).padStart(digits, "0");
    header.write(oct, offset, digits, "ascii");
    header[offset + digits] = 0x00;
}

/** Write a string field, NUL-padded to `width`. Truncates at width. */
function writeString(header: Buffer, offset: number, value: string, width: number): void {
    const bytes = Buffer.from(value, "utf-8");
    const n = Math.min(bytes.length, width);
    bytes.copy(header, offset, 0, n);
    // remaining already zero (Buffer.alloc)
}

/**
 * Build one 512-byte USTAR header. Mirrors the bytes Python's `tarfile`
 * emits. Python's `export_archive` pins `format=tarfile.USTAR_FORMAT`
 * explicitly (Python's library DEFAULT is PAX_FORMAT, not GNU — PAX would
 * emit an `x` extended-header block for any non-ASCII UTF-8 member name and
 * diverge from this writer). With both runtimes on USTAR, the bytes are
 * identical for every member name < 100 bytes (ASCII or non-ASCII): USTAR
 * stores the raw UTF-8 name directly in name[0:100] with the prefix unused.
 *
 * Field layout (POSIX.1-1988 USTAR):
 *   name[100] mode[8] uid[8] gid[8] size[12] mtime[12] chksum[8] typeflag[1]
 *   linkname[100] magic[6] version[2] uname[32] gname[32]
 *   devmajor[8] devminor[8] prefix[155] pad[12]
 *
 * uid/gid set to 0, uname/gname empty. magic "ustar\0", version "00".
 * devmajor/devminor are NOT written (left as NUL) — matches Python tarfile
 * which only writes them for CHRTYPE/BLKTYPE.
 */
function buildTarHeader(name: string, mode: number, size: number, mtime: number, typeflag: string): Buffer {
    const h = Buffer.alloc(TAR_BLOCK);
    writeString(h, 0, name, 100);
    writeOctal(h, 100, mode & 0o7777, 8);
    writeOctal(h, 108, 0, 8); // uid
    writeOctal(h, 116, 0, 8); // gid
    writeOctal(h, 124, size, 12);
    writeOctal(h, 136, mtime, 12);
    // chksum: filled with spaces first, computed after.
    h.write("        ", 148, 8, "ascii");
    h.write(typeflag, 156, 1, "ascii");
    // linkname[100] @ 157 — empty.
    h.write("ustar\0", 257, 6, "ascii"); // magic[6]
    h.write("00", 263, 2, "ascii"); // version[2]
    // uname[32] @ 265 — empty. gname[32] @ 297 — empty.
    // devmajor[8] @ 329, devminor[8] @ 337 — left NUL (Python writes these as
    // NUL for non-device entries).
    // prefix[155] @ 345 — empty.

    // Compute checksum: unsigned sum of all 512 header bytes (with chksum
    // field as 8 spaces). Written as 6-digit octal + NUL + space.
    let sum = 0;
    for (let i = 0; i < TAR_BLOCK; i++) sum += h[i]!;
    const chk = (sum & 0o777777).toString(8).padStart(6, "0");
    h.write(chk, 148, 6, "ascii");
    h[154] = 0x00;
    h[155] = 0x20; // space
    return h;
}

const DIRTYPE = "5";
const REGTYPE = "0";

/**
 * Assemble a deterministic .acef.tar.gz from a virtual bundle.
 *
 * Tar member order (mirrors export_archive):
 *   1. root dir "<bundleName>/"
 *   2. all subdirectories, sorted, as "<bundleName>/<dir>/"
 *   3. all files, sorted, as "<bundleName>/<relpath>"
 * Files are padded to 512-byte boundaries; the archive ends with two zero
 * blocks. The whole tar is then gzipped via `deterministicGzip`.
 *
 * @throws Error if any member name reaches the 100-char USTAR name limit
 *   (which would force GNU/PAX long-name extension handling Python applies
 *   but this writer does not implement).
 */
export function buildArchive(virtual: VirtualBundle, bundleName: string): Buffer {
    const blocks: Buffer[] = [];

    const assertShortName = (n: string): void => {
        if (Buffer.byteLength(n, "utf-8") >= 100) {
            throw new Error(
                `Tar member name >= 100 bytes requires GNU/PAX long-name handling, not implemented: ${n}`,
            );
        }
    };

    // 1. Root directory.
    const rootName = `${bundleName}/`;
    assertShortName(rootName);
    blocks.push(buildTarHeader(rootName, 0o755, 0, virtual.mtime, DIRTYPE));

    // 2. Subdirectories, sorted.
    const sortedDirs = [...virtual.dirs].sort();
    for (const d of sortedDirs) {
        const name = `${bundleName}/${d}/`;
        assertShortName(name);
        blocks.push(buildTarHeader(name, 0o755, 0, virtual.mtime, DIRTYPE));
    }

    // 3. Files, sorted.
    const sortedFiles = [...virtual.files.keys()].sort();
    for (const f of sortedFiles) {
        const content = virtual.files.get(f)!;
        const name = `${bundleName}/${f}`;
        assertShortName(name);
        blocks.push(buildTarHeader(name, 0o644, content.length, virtual.mtime, REGTYPE));
        blocks.push(content);
        const rem = content.length % TAR_BLOCK;
        if (rem !== 0) blocks.push(Buffer.alloc(TAR_BLOCK - rem));
    }

    // Two trailing zero blocks, then pad the whole archive up to the next
    // RECORDSIZE (20-block) boundary, exactly as Python tarfile.close() does.
    blocks.push(Buffer.alloc(TAR_BLOCK * 2));

    let tar = Buffer.concat(blocks);
    const rem = tar.length % TAR_RECORDSIZE;
    if (rem !== 0) {
        tar = Buffer.concat([tar, Buffer.alloc(TAR_RECORDSIZE - rem)]);
    }
    return deterministicGzip(tar);
}

/**
 * High-level convenience: load a directory bundle and produce the
 * deterministic .acef.tar.gz bytes, byte-equal to Python's export_archive.
 */
export function exportArchiveFromDirectory(loaded: LoadedBundle, bundleName: string): Buffer {
    const virtual = buildVirtualBundle(loaded);
    return buildArchive(virtual, bundleName);
}
