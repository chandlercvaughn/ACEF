/**
 * jws-cli: subprocess driver for Python<->TS JWS interop tests (VAL-TS-006).
 *
 * Subcommands:
 *
 *   sign   --alg RS256|ES256 --key <pem-path> --kid <id> --payload-stdin
 *     Read raw payload bytes from stdin, output the detached JWS string to stdout.
 *
 *   verify --alg RS256|ES256 --key <pem-path> --jws-stdin --payload <hex-or-path>
 *     Read JWS from stdin, payload from --payload arg, exit 0 if verified, 1 otherwise.
 *
 *   verify-jws-stdin --pubkey <pem-path> --payload-path <path>
 *     Read JWS from stdin, payload bytes from file. Exit 0 OK, 1 fail.
 *
 *   sign-stdin --privkey <pem-path> --kid <id> --payload-path <path>
 *     Read nothing (key + payload from files), output JWS to stdout.
 *
 * The CLI is intentionally minimal — Python test harness writes payload to
 * a tempfile, runs `node jws-cli.js sign-stdin --privkey k.pem --kid k --payload-path p.bin`,
 * captures stdout JWS, then verifies via Python's verify_detached_jws.
 */

import { readFileSync } from "node:fs";
import { argv } from "node:process";

import { createDetachedJws, verifyDetachedJws } from "../src/index.js";

interface ArgMap {
    [k: string]: string;
}

function parseArgs(args: string[]): ArgMap {
    const out: ArgMap = {};
    for (let i = 0; i < args.length; i++) {
        const a = args[i]!;
        if (a.startsWith("--")) {
            const key = a.slice(2);
            const next = args[i + 1];
            if (next !== undefined && !next.startsWith("--")) {
                out[key] = next;
                i++;
            } else {
                out[key] = "true";
            }
        }
    }
    return out;
}

function main(): void {
    const args = argv.slice(2);
    const cmd = args[0];
    const opts = parseArgs(args.slice(1));

    if (cmd === "sign-stdin") {
        const privPem = readFileSync(opts["privkey"]!, "utf-8");
        const payload = readFileSync(opts["payload-path"]!);
        const jws = createDetachedJws(payload, privPem, { kid: opts["kid"]! });
        process.stdout.write(jws);
        return;
    }

    if (cmd === "verify-jws-stdin") {
        const pubPem = readFileSync(opts["pubkey"]!, "utf-8");
        const payload = readFileSync(opts["payload-path"]!);
        const jws = readFileSync(0, "utf-8").trim();
        try {
            verifyDetachedJws(jws, payload, pubPem);
            process.exit(0);
        } catch (e) {
            process.stderr.write(`[VERIFY-FAIL] ${(e as Error).message}\n`);
            process.exit(1);
        }
    }

    process.stderr.write(`Unknown command: ${cmd}\n`);
    process.exit(2);
}

main();
