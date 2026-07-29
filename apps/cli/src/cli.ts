import { parseArgs } from "node:util";
import {
  CodeFormatError,
  decryptSecret,
  deriveKeys,
  encryptSecret,
  formatCode,
  generateCode,
  parseCode,
  SecretTooLargeError,
} from "@secret-share/crypto";
import { DEFAULT_TTL_SECONDS, MAX_SECRET_BYTES } from "@secret-share/protocol";
import { version } from "../package.json";
import {
  BadTagError,
  claimDrop,
  DropExistsError,
  DropGoneError,
  DropNotFoundError,
  parkDrop,
  revokeDrop,
} from "./api.js";
import { formatTtl, parseTtl, TtlFormatError } from "./ttl.js";

const DEFAULT_SERVER = "https://shareasecret.io";

/** Exit codes are stable so scripts can branch on them. */
const EXIT = {
  ok: 0,
  error: 1,
  usage: 2,
  badCode: 3,
  notFound: 4,
  gone: 5,
  tooLarge: 6,
} as const;

const USAGE = `shareasecret — read-once, end-to-end encrypted secret sharing (shareasecret.io)

Usage:
  shareasecret send [--ttl <duration>] [--json]     read secret from stdin, print share code
  shareasecret receive <code>                       claim the secret, write it to stdout
  shareasecret revoke <code>                        burn a drop you sent before it is read

Options:
  --ttl <duration>   expiry for send: 90s, 30m, 2h, 1d (min 60s, max 7d, default 1d)
  --json             machine-readable output on stdout (send only)
  --server <url>     API origin (or SHAREASECRET_SERVER; default ${DEFAULT_SERVER})
  -h, --help         show this help
  -v, --version      print version

The five words in the code are the encryption key. They never reach the server,
and the drop burns after one read or 5 wrong attempts.

Examples:
  cat id_ed25519 | shareasecret send --ttl 2h
  shareasecret receive XKQ2-M7PT-tiger-ocean-cable-ruby-drum > id_ed25519

Exit codes: 0 ok, 1 error, 2 usage, 3 wrong code, 4 not found, 5 already read/expired, 6 too large`;

class CliError extends Error {
  override name = "CliError";
  constructor(
    message: string,
    public exitCode: number,
  ) {
    super(message);
  }
}

/**
 * Throws instead of process.exit(): a hard exit races libuv handle teardown on
 * Windows (async.c assert) and can clobber the exit code; setting
 * process.exitCode and letting the loop drain is always safe.
 */
function fail(message: string, code: number): never {
  throw new CliError(message, code);
}

/** Reads all of stdin, bailing out early once the secret is over the limit. */
async function readStdin(): Promise<Uint8Array> {
  if (process.stdin.isTTY) {
    process.stderr.write(
      "Type or paste the secret, then press Ctrl+D (Ctrl+Z then Enter on Windows):\n",
    );
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
    total += (chunk as Buffer).length;
    if (total > MAX_SECRET_BYTES) {
      fail(`secret exceeds ${MAX_SECRET_BYTES} bytes (10 KB)`, EXIT.tooLarge);
    }
  }
  return new Uint8Array(Buffer.concat(chunks));
}

/** Accepts a bare code, dashed/spaced words, or a full /r# link. */
function codeFromArgs(positionals: string[]): ReturnType<typeof parseCode> {
  let input = positionals.join(" ");
  if (/^https?:\/\//i.test(input)) {
    const hash = new URL(input).hash;
    if (!hash) fail("that link has no #code fragment", EXIT.usage);
    input = decodeURIComponent(hash.slice(1));
  }
  try {
    return parseCode(input);
  } catch (e) {
    if (e instanceof CodeFormatError) fail(e.message, EXIT.usage);
    throw e;
  }
}

async function send(server: string, ttl: string | undefined, json: boolean) {
  let ttlSeconds = DEFAULT_TTL_SECONDS;
  if (ttl !== undefined) {
    try {
      ttlSeconds = parseTtl(ttl);
    } catch (e) {
      if (e instanceof TtlFormatError) fail(e.message, EXIT.usage);
      throw e;
    }
  }

  const plaintext = await readStdin();
  if (plaintext.length === 0) fail("nothing to send — stdin was empty", EXIT.usage);

  // 40-bit mailbox ids can collide with a live drop; a fresh code fixes it.
  for (let attempt = 0; ; attempt++) {
    const code = generateCode();
    const keys = await deriveKeys(code);
    let blob: Uint8Array;
    try {
      blob = await encryptSecret(keys, plaintext);
    } catch (e) {
      if (e instanceof SecretTooLargeError) fail(e.message, EXIT.tooLarge);
      throw e;
    }
    try {
      const expiresAt = await parkDrop(server, keys, blob, ttlSeconds);
      const display = formatCode(code);
      const link = `${server}/r#${display}`;
      if (json) {
        process.stdout.write(
          `${JSON.stringify({ code: display, link, expiresAt, ttlSeconds })}\n`,
        );
      } else {
        process.stderr.write(
          [
            "",
            "Share code (read-once, speak it or send it over any channel):",
            "",
            `  ${display}`,
            "",
            `Link:    ${link}`,
            `Expires: ${new Date(expiresAt).toLocaleString()} (${formatTtl(ttlSeconds)})`,
            `Receive: shareasecret receive ${display}`,
            `Revoke:  shareasecret revoke ${display}`,
            "",
          ].join("\n"),
        );
        process.stdout.write(`${display}\n`);
      }
      return;
    } catch (e) {
      if (e instanceof DropExistsError && attempt < 2) continue;
      throw e;
    }
  }
}

async function receive(server: string, positionals: string[]) {
  if (positionals.length === 0) fail("missing share code", EXIT.usage);
  const code = codeFromArgs(positionals);
  const keys = await deriveKeys(code);
  let blob: Uint8Array;
  try {
    blob = await claimDrop(server, keys);
  } catch (e) {
    if (e instanceof BadTagError) fail(e.message, EXIT.badCode);
    if (e instanceof DropNotFoundError) {
      fail("no drop at that code — expired, revoked, or never existed", EXIT.notFound);
    }
    if (e instanceof DropGoneError) {
      fail("already read or burned — read-once means it is gone", EXIT.gone);
    }
    throw e;
  }
  const plaintext = await decryptSecret(keys, blob);
  process.stdout.write(plaintext);
  // Keep a TTY prompt tidy without altering piped bytes.
  if (process.stdout.isTTY && plaintext.at(-1) !== 0x0a) process.stdout.write("\n");
}

async function revoke(server: string, positionals: string[]) {
  if (positionals.length === 0) fail("missing share code", EXIT.usage);
  const code = codeFromArgs(positionals);
  const keys = await deriveKeys(code);
  await revokeDrop(server, keys);
  process.stderr.write("Drop revoked (or already gone). The code is now useless.\n");
}

function parseCliArgs() {
  try {
    return parseArgs({
      args: process.argv.slice(2),
      allowPositionals: true,
      options: {
        ttl: { type: "string" },
        json: { type: "boolean", default: false },
        server: { type: "string" },
        help: { type: "boolean", short: "h", default: false },
        version: { type: "boolean", short: "v", default: false },
      },
    });
  } catch (e) {
    fail(`${e instanceof Error ? e.message : e} — try --help`, EXIT.usage);
  }
}

async function main() {
  const { values, positionals } = parseCliArgs();

  if (values.version) {
    process.stdout.write(`${version}\n`);
    return;
  }
  const [command, ...rest] = positionals;
  if (values.help || !command) {
    process.stdout.write(`${USAGE}\n`);
    if (!command && !values.help) process.exitCode = EXIT.usage;
    return;
  }

  const server = (
    values.server ??
    process.env["SHAREASECRET_SERVER"] ??
    DEFAULT_SERVER
  ).replace(/\/+$/, "");

  switch (command) {
    case "send":
      return send(server, values.ttl, values.json);
    case "receive":
    case "recv":
      return receive(server, rest);
    case "revoke":
      return revoke(server, rest);
    default:
      fail(`unknown command "${command}" — try --help`, EXIT.usage);
  }
}

main().catch((e: unknown) => {
  if (e instanceof CliError) {
    process.stderr.write(`error: ${e.message}\n`);
    process.exitCode = e.exitCode;
    return;
  }
  const msg =
    e instanceof TypeError && /fetch/i.test(String(e.message))
      ? `network error — is the server reachable? (${e.message})`
      : e instanceof Error
        ? e.message
        : String(e);
  process.stderr.write(`error: ${msg}\n`);
  process.exitCode = EXIT.error;
});
