/**
 * Unit tests for the directory + USTAR-tar exporter (`bundle_export.ts`).
 *
 * The authoritative cross-language byte-equality assertion (VAL-PARITY-002 /
 * VAL-PARITY-003) lives in the Python test
 * `tests/conformance/test_freddy_cross_language_parity.py`, which drives this
 * exporter via the built CLI. These TS-side tests pin down the structural
 * invariants (USTAR header field bytes, checksum, member ordering, RECORDSIZE
 * padding, manifest-rebuild transform) so a regression is caught at
 * `npm test` time rather than only at the Python conformance tier.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { gunzipSync } from "node:zlib";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";

import { loadBundle } from "../src/loader.js";
import {
    rebuildManifestForExport,
    buildVirtualBundle,
    exportArchiveFromDirectory,
} from "../src/bundle_export.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function repoRoot(): string {
    // After tsc: <repo>/packages/sdk-typescript/dist-test/test/bundle_export.test.js
    return resolve(__dirname, "..", "..", "..", "..");
}

const VERIFIED_DELIVERY = join(
    repoRoot(),
    "test-vectors",
    "freddy",
    "pass",
    "verified-delivery.acef",
);

const TAR_BLOCK = 512;

/** Decode a NUL-terminated ASCII field from a tar header block. */
function field(block: Buffer, offset: number, width: number): string {
    let end = offset;
    while (end < offset + width && block[end] !== 0x00) end++;
    return block.toString("ascii", offset, end);
}

/** Recompute the USTAR header checksum (sum of bytes with chksum = 8 spaces). */
function recomputeChecksum(block: Buffer): number {
    const copy = Buffer.from(block);
    copy.fill(0x20, 148, 156);
    let sum = 0;
    for (let i = 0; i < TAR_BLOCK; i++) sum += copy[i]!;
    return sum;
}

test("loadBundle reads manifest + records for verified-delivery", () => {
    if (!existsSync(VERIFIED_DELIVERY)) {
        // Bundle fixtures live in the Python repo; skip if running standalone.
        return;
    }
    const loaded = loadBundle(VERIFIED_DELIVERY);
    assert.ok(loaded.manifestRaw["metadata"], "manifest has metadata");
    // verified-delivery has 4 record types, 1 record each.
    assert.equal(loaded.records.length, 4);
    const types = loaded.records.map((r) => r["record_type"]).sort();
    assert.deepEqual(types, [
        "authorized_test_scope",
        "delivery_verdict",
        "finding_record",
        "harness_attestation",
    ]);
});

test("rebuildManifestForExport PRESERVES v1.1 analysis_mode and metadata.created_at", () => {
    if (!existsSync(VERIFIED_DELIVERY)) return;
    const loaded = loadBundle(VERIFIED_DELIVERY);
    // Sanity: the on-disk manifest DOES carry these fields.
    assert.equal(loaded.manifestRaw["analysis_mode"], "subscriber");
    const metaRaw = loaded.manifestRaw["metadata"] as Record<string, unknown>;
    assert.equal(metaRaw["created_at"], "2026-05-01T00:00:00Z");

    const m = rebuildManifestForExport(loaded.manifestRaw, loaded.records);
    // Lossless export to the open core (spec §6.4 rule 5 / §6.5): the rebuilt
    // manifest (matching Python build_manifest → to_dict) PRESERVES the v1.1
    // open-core field analysis_mode (X5) and the extra metadata key created_at
    // verbatim. This mirrors the Python bundle-level round-trip test
    // (tests/unit/test_lossless_roundtrip_bundle.py) and is required for the
    // VAL-PARITY-002/003 cross-language byte-equality contract to hold with
    // BOTH SDKs spec-correct.
    assert.equal(m["analysis_mode"], "subscriber", "analysis_mode must be preserved");
    const meta = m["metadata"] as Record<string, unknown>;
    assert.equal(meta["created_at"], "2026-05-01T00:00:00Z", "metadata.created_at must be preserved");
    assert.ok(meta["package_id"], "package_id retained");
    assert.ok(meta["timestamp"], "timestamp retained");
    // record_files recomputed: one per record type.
    const rf = m["record_files"] as Array<Record<string, unknown>>;
    assert.equal(rf.length, 4);
    for (const e of rf) {
        assert.match(e["path"] as string, /^records\/.+\.jsonl$/);
        assert.equal(e["count"], 1);
    }
});

test("rebuildManifestForExport PRESERVES namespaces (X6), top-level x-*, and metadata x-*", () => {
    // The verified-delivery fixture carries analysis_mode + metadata.created_at
    // but no vendor x-* / namespaces, so feed a synthetic manifest through the
    // SAME rebuild transform to pin down the remaining lossless guarantees
    // (mirrors the Python test's x-* / namespaces assertions). The transform is
    // pure, so this needs no on-disk fixture.
    const manifestRaw: Record<string, unknown> = {
        metadata: {
            package_id: "urn:acef:pkg:11111111-1111-1111-1111-111111111111",
            timestamp: "2026-01-01T00:00:00Z",
            producer: { name: "test-producer", version: "1.0.0" },
            created_at: "2025-12-31T23:59:59Z",
            "x-vendor/meta": { team: "compliance" },
        },
        versioning: { core_version: "1.1.0", profiles_version: "1.0.0" },
        subjects: [],
        entities: { components: [], datasets: [], actors: [], relationships: [] },
        profiles: [],
        record_files: [],
        audit_trail: [],
        analysis_mode: "subscriber",
        namespaces: { "x-test/extension": { foo: "bar", nested: { k: [1, 2] } } },
        "x-vendor-top/meta": { k: "v", n: 42 },
    };

    const m = rebuildManifestForExport(manifestRaw, []);

    // X5 + X6 open-core fields preserved.
    assert.equal(m["analysis_mode"], "subscriber");
    assert.deepEqual(m["namespaces"], { "x-test/extension": { foo: "bar", nested: { k: [1, 2] } } });
    // Top-level vendor x-* extension preserved.
    assert.deepEqual(m["x-vendor-top/meta"], { k: "v", n: 42 });
    // Metadata extras (vendor x-* + created_at) preserved.
    const meta = m["metadata"] as Record<string, unknown>;
    assert.deepEqual(meta["x-vendor/meta"], { team: "compliance" });
    assert.equal(meta["created_at"], "2025-12-31T23:59:59Z");
});

test("buildVirtualBundle emits the full export_directory file set", () => {
    if (!existsSync(VERIFIED_DELIVERY)) return;
    const loaded = loadBundle(VERIFIED_DELIVERY);
    const vb = buildVirtualBundle(loaded);
    const paths = [...vb.files.keys()].sort();
    assert.ok(paths.includes("acef-manifest.json"));
    assert.ok(paths.includes("hashes/content-hashes.json"));
    assert.ok(paths.includes("hashes/merkle-tree.json"));
    assert.ok(paths.includes("records/authorized_test_scope.jsonl"));
    // Managed empty dirs present for tar layout parity.
    for (const d of ["records", "artifacts", "hashes", "signatures"]) {
        assert.ok(vb.dirs.has(d), `dir ${d} must be present`);
    }
    // mtime derived from metadata.timestamp 2026-05-01T00:00:00Z.
    assert.equal(vb.mtime, 1777593600);
});

test("F6: deriveMtime mirrors the Python strict RFC3339 checker (accept/reject + exact mtime parity)", () => {
    if (!existsSync(VERIFIED_DELIVERY)) return;
    const loaded = loadBundle(VERIFIED_DELIVERY);
    const meta = loaded.manifestRaw["metadata"] as Record<string, unknown>;
    const mtimeOf = (ts: string): number => {
        meta["timestamp"] = ts;
        return buildVirtualBundle(loaded).mtime;
    };
    // ACCEPTED — exact epoch-second parity with the Python exporter (values computed from
    // int(datetime.fromisoformat(...).timestamp())).
    assert.equal(mtimeOf("2024-01-15T10:30:00Z"), 1705314600);
    assert.equal(mtimeOf("2024-01-15t10:30:00Z"), 1705314600); // lowercase t (RFC 3339 §5.6)
    assert.equal(mtimeOf("2024-01-15T10:30:00z"), 1705314600); // lowercase z
    assert.equal(mtimeOf("2024-01-15T10:30:00+02:00"), 1705307400);
    assert.equal(mtimeOf("2024-01-15T10:30:00-05:30"), 1705334400);
    assert.equal(mtimeOf("2024-02-29T00:00:00Z"), 1709164800); // valid leap day
    assert.equal(mtimeOf("2024-01-15T10:30:00.999Z"), 1705314600); // fractional truncated
    assert.equal(mtimeOf("0001-01-01T00:00:00Z"), -62135596800); // min year, far pre-epoch
    assert.equal(mtimeOf("1969-12-31T23:59:59Z"), -1); // pre-epoch, no fraction
    // pre-epoch + positive fractional: Python int() truncates toward zero (-1s + 0.999s -> 0).
    assert.equal(mtimeOf("1969-12-31T23:59:59.999Z"), 0);
    assert.equal(mtimeOf("1969-12-31T23:59:59.0001Z"), 0);
    // Python carries only MICROSECOND precision: a sub-microsecond-only fractional counts
    // as zero, so a negative base second stays negative.
    assert.equal(mtimeOf("1969-12-31T23:59:59.000001Z"), 0); // 1 microsecond -> positive
    assert.equal(mtimeOf("1969-12-31T23:59:59.0000001Z"), -1); // sub-microsecond -> zero
    assert.equal(mtimeOf("1969-12-31T23:59:59.0000009Z"), -1); // sub-microsecond -> zero
    // REJECTED — every input the Python checker rejects must throw ACEF-002, never emit an
    // archive with a divergent mtime.
    for (const bad of [
        "20240115T103000Z", // basic form
        "0000-01-01T00:00:00Z", // year 0000 (Python datetime MINYEAR is 1)
        "2023-02-29T00:00:00Z", // impossible calendar day (non-leap Feb 29)
        "2024-13-01T00:00:00Z", // month 13
        "2024-01-15T10:30:60Z", // leap second :60
        "2024-01-15T24:00:00Z", // hour 24
        "2024-01-15T10:30:00+25:00", // out-of-range offset
        "not-a-date",
        "",
    ]) {
        meta["timestamp"] = bad;
        assert.throws(() => buildVirtualBundle(loaded), /ACEF-002/, `must reject ${JSON.stringify(bad)}`);
    }
});

test("each JSONL file ends with a single trailing newline", () => {
    if (!existsSync(VERIFIED_DELIVERY)) return;
    const loaded = loadBundle(VERIFIED_DELIVERY);
    const vb = buildVirtualBundle(loaded);
    for (const [path, content] of vb.files.entries()) {
        if (!path.endsWith(".jsonl")) continue;
        assert.equal(content[content.length - 1], 0x0a, `${path} must end with \\n`);
        assert.notEqual(content[content.length - 2], 0x0a, `${path} must not have blank trailing line`);
    }
});

test("archive is a valid gzip wrapping a USTAR tar with correct headers", () => {
    if (!existsSync(VERIFIED_DELIVERY)) return;
    const gz = exportArchiveFromDirectory(loadBundle(VERIFIED_DELIVERY), "verified-delivery.acef");
    // gzip header per spec §3.1.3.
    assert.deepEqual([...gz.subarray(0, 10)], [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);
    const tar = gunzipSync(gz);
    // RECORDSIZE padding: length is a multiple of 20 blocks.
    assert.equal(tar.length % (TAR_BLOCK * 20), 0, "tar must be padded to a 10240 multiple");

    const root = tar.subarray(0, TAR_BLOCK);
    assert.equal(field(root, 0, 100), "verified-delivery.acef/");
    assert.equal(field(root, 100, 8), "0000755"); // dir mode 0755
    assert.equal(field(root, 257, 6), "ustar"); // magic (NUL-trimmed)
    assert.equal(root[156], 0x35); // typeflag '5' DIRTYPE
    // uid/gid zero.
    assert.equal(field(root, 108, 8), "0000000");
    assert.equal(field(root, 116, 8), "0000000");

    // Checksum field round-trips.
    const declaredChk = parseInt(field(root, 148, 8).trim(), 8);
    assert.equal(declaredChk, recomputeChecksum(root) & 0o777777);
});

test("first regular-file header uses mode 0644 and REGTYPE", () => {
    if (!existsSync(VERIFIED_DELIVERY)) return;
    const gz = exportArchiveFromDirectory(loadBundle(VERIFIED_DELIVERY), "verified-delivery.acef");
    const tar = gunzipSync(gz);
    // Scan header blocks for the first regular file (typeflag '0' REGTYPE).
    // Directory headers have no content blocks; the first REGTYPE header is
    // reached by stepping one block at a time until we leave the dir entries.
    let found = false;
    for (let off = 0; off + TAR_BLOCK <= tar.length; off += TAR_BLOCK) {
        const block = tar.subarray(off, off + TAR_BLOCK);
        const name = field(block, 0, 100);
        if (name.length === 0) break; // hit trailing zero blocks
        if (block[156] === 0x30) {
            // '0' REGTYPE — the first regular file header.
            assert.equal(field(block, 100, 8), "0000644", `${name} mode must be 0644`);
            found = true;
            break;
        }
        // Only directory headers ('5') precede the first file; they carry no
        // content blocks, so a single-block step is correct here.
    }
    assert.ok(found, "expected at least one regular-file header");
});

test("output is deterministic across repeated exports", () => {
    if (!existsSync(VERIFIED_DELIVERY)) return;
    const a = exportArchiveFromDirectory(loadBundle(VERIFIED_DELIVERY), "verified-delivery.acef");
    const b = exportArchiveFromDirectory(loadBundle(VERIFIED_DELIVERY), "verified-delivery.acef");
    assert.ok(a.equals(b), "two exports of the same bundle must be byte-identical");
});
