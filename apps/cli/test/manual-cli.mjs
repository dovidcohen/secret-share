// CLI lifecycle against a running `pnpm dev:api` (build the CLI first: pnpm --filter shareasecret build).
// Usage: node apps/cli/test/manual-cli.mjs [server]
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname, join as pjoin } from "node:path";
import { tmpdir } from "node:os";

const server = process.argv[2] ?? "http://localhost:8787";
const bin = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "cli.cjs");
const env = { ...process.env, SHAREASECRET_SERVER: server };

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

/** Runs the CLI; returns {status, stdout(Buffer)}. */
function cli(args, input) {
  try {
    const stdout = execFileSync(process.execPath, [bin, ...args], {
      env,
      input,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { status: 0, stdout };
  } catch (e) {
    return { status: e.status ?? 1, stdout: e.stdout ?? Buffer.alloc(0) };
  }
}

/** Like cli() but also captures stderr (spawnSync captures it on success too). */
function cli2(args, input) {
  const r = spawnSync(process.execPath, [bin, ...args], { env, input });
  return { status: r.status ?? 1, stdout: r.stdout, stderr: r.stderr };
}

// send --json -> receive round-trips arbitrary bytes
const secret = randomBytes(2048);
const sent = cli(["send", "--json", "--ttl", "5m"], secret);
check("send exits 0", sent.status === 0);
const { code, link, expiresAt } = JSON.parse(sent.stdout.toString());
check("json has code/link/expiresAt", Boolean(code && link && expiresAt > Date.now()));

const got = cli(["receive", code]);
check("receive exits 0", got.status === 0);
check("bytes identical", got.stdout.equals(secret));

// read-once: second claim is gone
check("re-receive exits 5", cli(["receive", code]).status === 5);

// wrong words burn attempts (fresh drop, same mailbox id, wrong words)
const burn = cli(["send"], "attempt-counter");
const burnCode = burn.stdout.toString().trim();
const wrongWords = `${burnCode.split("-").slice(0, 2).join("-")}-tiger-ocean-cable-ruby-drum`;
check("wrong words exit 3", cli(["receive", wrongWords]).status === 3);

// revoke kills the drop
check("revoke exits 0", cli(["revoke", burnCode]).status === 0);
check("receive after revoke exits 5", cli(["receive", burnCode]).status === 5);

// receive accepts the full link form
const linked = cli(["send", "--json"], "via-link");
check(
  "receive via link",
  cli(["receive", JSON.parse(linked.stdout.toString()).link]).stdout.toString() === "via-link",
);

// usage errors
check("empty stdin exits 2", cli(["send"], "").status === 2);
check("bad ttl exits 2", cli(["send", "--ttl", "8d"], "x").status === 2);
check("bad code exits 2", cli(["receive", "nonsense"]).status === 2);
check("oversize exits 6", cli(["send"], Buffer.alloc(11_000)).status === 6);

// captured stdout must not leak the code to stderr (CI-log safety)
const leak = cli2(["send"], "leak-check");
const leakCode = leak.stdout.toString().trim();
check("piped send: code on stdout only", leakCode.length > 0 && !leak.stderr.toString().includes(leakCode));

// receive --output: 0600, refuses overwrite
const outFile = pjoin(tmpdir(), `sas-test-${Date.now()}.txt`);
try {
  const wrote = cli2(["receive", leakCode, "--output", outFile]);
  check("receive --output exits 0", wrote.status === 0);
  check("--output wrote the secret", readFileSync(outFile, "utf8") === "leak-check");
  const again = cli2(["send"], "second");
  const clobber = cli2(["receive", again.stdout.toString().trim(), "--output", outFile]);
  check("--output refuses overwrite", clobber.status === 1 && clobber.stderr.toString().includes("refusing"));
} finally {
  if (existsSync(outFile)) rmSync(outFile);
}

// code on stdin instead of argv (keeps it out of history/process list)
const viaStdin = cli2(["send"], "code-via-stdin");
const got2 = cli2(["receive"], viaStdin.stdout.toString());
check("receive reads code from piped stdin", got2.status === 0 && got2.stdout.toString() === "code-via-stdin");

process.exit(failures ? 1 : 0);
