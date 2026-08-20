import { closeSync, openSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { basename } from "node:path";
import { parseArgs } from "node:util";
import {
  CodeFormatError,
  decodePayload,
  decryptSecret,
  deriveKeys,
  encodeFilePayload,
  encryptSecret,
  formatCode,
  generateCode,
  parseCode,
  sanitizeFilename,
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
  aborted: 130,
} as const;

const USAGE = `shareasecret — read-once, end-to-end encrypted secret sharing (shareasecret.io)

Usage:
  shareasecret send [--ttl <duration>] [--json]       read secret from stdin, print share code
  shareasecret send --file <path> [--ttl] [--json]    send a small file with its name attached
  shareasecret receive [<code>] [--output <file>]     claim the secret (code, link, or omit to be prompted)
  shareasecret revoke [<code>]                        burn a drop you sent before it is read

Options:
  --ttl <duration>     expiry for send: 90s, 30m, 2h, 1d (min 60s, max 7d, default 1d)
  --json               machine-readable output on stdout (send only)
  -f, --file <path>    send: attach this file instead of reading stdin (name travels encrypted)
  -o, --output <file>  receive: write the secret to <file>, created 0600, never overwritten
                       (a file sent with --file or the web attaches saves under its own name)
  --server <url>       API origin (or SHAREASECRET_SERVER; default ${DEFAULT_SERVER})
  -h, --help           show this help
  -v, --version        print version

The five words in the code are the encryption key. They never reach the server,
and the drop burns after one read or 5 wrong attempts.

A code given as an argument lands in shell history and is briefly visible in the
process list; omit it and shareasecret prompts for it without echoing.

Examples:
  cat id_ed25519 | shareasecret send --ttl 2h
  shareasecret send --file release.jks --ttl 2h   # receiver gets the filename too
  shareasecret receive --output id_ed25519        # prompts for the code, no echo
  shareasecret receive XKQ2-M7PT-tiger-ocean-cable-ruby-drum > note.txt

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
      "Reading secret from the terminal — note it stays visible in scrollback; piping is safer.\n" +
        "Finish with Ctrl+D (Ctrl+Z then Enter on Windows):\n",
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

/** Prompts on the TTY without echoing — keeps the code out of scrollback. */
function promptCodeHidden(): Promise<string> {
  process.stderr.write("Share code (input hidden): ");
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let buf = "";
    const done = (err?: Error) => {
      stdin.setRawMode?.(false);
      stdin.pause();
      stdin.off("data", onData);
      process.stderr.write("\n");
      err ? reject(err) : resolve(buf);
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") return done();
        // raw mode: Ctrl+C (ETX) and Ctrl+D (EOT) arrive as bytes, not signals
        if (ch === "\u0003" || ch === "\u0004") {
          return done(new CliError("aborted", EXIT.aborted));
        }
        if (ch === "\u007f" || ch === "\b") buf = buf.slice(0, -1);
        else buf += ch;
      }
    };
    stdin.on("data", onData);
  });
}

/** Yes/no question on the TTY — only ever called when stdin is interactive. */
function confirmOnTty(question: string): Promise<boolean> {
  process.stderr.write(question);
  return new Promise((resolve) => {
    const stdin = process.stdin;
    stdin.resume();
    stdin.setEncoding("utf8");
    stdin.once("data", (line) => {
      stdin.pause();
      resolve(/^y(es)?$/i.test(String(line).trim()));
    });
  });
}

/** First non-empty line of piped stdin — lets scripts avoid argv entirely. */
async function readCodeFromPipe(): Promise<string> {
  let text = "";
  for await (const chunk of process.stdin) text += chunk.toString();
  return text.split(/\r?\n/).find((l) => l.trim().length > 0) ?? "";
}

/** Accepts a bare code, dashed/spaced words, or a full /r# link. */
function parseCodeInput(input: string): ReturnType<typeof parseCode> {
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

/** Code from argv if given, else hidden TTY prompt, else first line of stdin. */
async function resolveCode(positionals: string[]): Promise<ReturnType<typeof parseCode>> {
  if (positionals.length > 0) return parseCodeInput(positionals.join(" "));
  const raw = process.stdin.isTTY ? await promptCodeHidden() : await readCodeFromPipe();
  if (raw.trim().length === 0) fail("missing share code", EXIT.usage);
  return parseCodeInput(raw);
}

async function send(server: string, ttl: string | undefined, json: boolean, filePath?: string) {
  let ttlSeconds = DEFAULT_TTL_SECONDS;
  if (ttl !== undefined) {
    try {
      ttlSeconds = parseTtl(ttl);
    } catch (e) {
      if (e instanceof TtlFormatError) fail(e.message, EXIT.usage);
      throw e;
    }
  }

  let plaintext: Uint8Array;
  if (filePath !== undefined) {
    let data: Uint8Array;
    try {
      data = new Uint8Array(readFileSync(filePath));
    } catch (e) {
      fail(`cannot read ${filePath}: ${(e as NodeJS.ErrnoException).message}`, EXIT.error);
    }
    if (data.length === 0) fail(`nothing to send — ${filePath} is empty`, EXIT.usage);
    plaintext = encodeFilePayload(basename(filePath), "application/octet-stream", data);
    if (plaintext.length > MAX_SECRET_BYTES) {
      fail(`${filePath} exceeds ${MAX_SECRET_BYTES} bytes (10 KB) with metadata`, EXIT.tooLarge);
    }
  } else {
    plaintext = await readStdin();
    if (plaintext.length === 0) fail("nothing to send — stdin was empty", EXIT.usage);
  }

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
      const expiry = `${new Date(expiresAt).toLocaleString()} (${formatTtl(ttlSeconds)})`;
      if (json) {
        process.stdout.write(
          `${JSON.stringify({ code: display, link, expiresAt, ttlSeconds })}\n`,
        );
      } else if (!process.stdout.isTTY) {
        // stdout is captured ($(...), a pipe, CI): the code goes there and ONLY
        // there — echoing it to stderr would leak the capability into logs.
        process.stderr.write(`Read-once drop parked; share code on stdout. Expires ${expiry}.\n`);
        process.stdout.write(`${display}\n`);
      } else {
        process.stderr.write(
          [
            "",
            "Share code (read-once, speak it or send it over any channel):",
            "",
            `  ${display}`,
            "",
            `Link:    ${link}`,
            `Expires: ${expiry}`,
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

async function receive(server: string, positionals: string[], output: string | undefined) {
  const code = await resolveCode(positionals);

  // Claiming burns the read-once drop, so every local failure that can be
  // detected up front must happen BEFORE the claim. Reserving the output file
  // first (wx: fails on existing, 0600 from the first byte) means a bad path,
  // existing file, or permission problem costs nothing — the drop survives.
  // On Windows the mode is advisory; the file inherits the folder's ACL.
  let fd: number | undefined;
  if (output !== undefined) {
    try {
      fd = openSync(output, "wx", 0o600);
    } catch (e) {
      const err = e as NodeJS.ErrnoException;
      if (err.code === "EEXIST") {
        fail(`refusing to overwrite existing file: ${output} (drop not claimed)`, EXIT.error);
      }
      fail(`cannot create ${output}: ${err.message} (drop not claimed)`, EXIT.error);
    }
  }

  const keys = await deriveKeys(code);
  let plaintext: Uint8Array;
  try {
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
    plaintext = await decryptSecret(keys, blob);
  } catch (e) {
    // Claim failed — remove the empty reservation so a retry can reuse the path.
    if (fd !== undefined) {
      try {
        closeSync(fd);
        unlinkSync(output as string);
      } catch {
        /* the reservation is empty; leaving it behind is harmless */
      }
    }
    throw e;
  }

  // A file envelope (sent with --file, or the web's attach button) carries the
  // sender's filename; anything else passes through byte-for-byte as before.
  let fileName: string | null = null;
  let outBytes = plaintext;
  try {
    const payload = decodePayload(plaintext);
    if (payload.kind === "file") {
      fileName = payload.name;
      outBytes = payload.data;
    }
  } catch {
    // Malformed envelope — the drop is already burned, so emit the raw bytes
    // rather than lose them.
  }

  if (fd === undefined && fileName !== null && process.stdout.isTTY) {
    // A file arrived without --output on a terminal. The drop is burned, so
    // the bytes must land somewhere — save under the sender's (sanitized)
    // name in the current directory, never overwriting.
    const saved = writeToUnusedName(fileName, outBytes);
    if (saved !== null) {
      process.stderr.write(`Saved ${outBytes.length} bytes to ${saved} (mode 0600).\n`);
      return;
    }
    process.stderr.write(
      `warning: could not create a file for "${fileName}" here — writing raw bytes to stdout\n`,
    );
  }

  if (fd !== undefined) {
    // writeSync may write fewer bytes than the buffer holds — loop until
    // every byte lands, or a truncated credential would pass as success.
    let written = 0;
    try {
      while (written < outBytes.length) {
        written += writeSync(fd, outBytes, written, outBytes.length - written);
      }
      closeSync(fd);
    } catch (e) {
      // The drop is already burned. The caller chose --output, so the secret
      // must NOT be auto-disclosed on stdout (CI logs, pipes). Keep whatever
      // landed in the 0600 file and only offer stdout recovery interactively.
      try {
        closeSync(fd);
      } catch {
        /* already closed by the failed write path */
      }
      process.stderr.write(
        `error: writing ${output} failed after the drop was claimed (${(e as Error).message}); ` +
          `${written} of ${outBytes.length} bytes were written and left in place (mode 0600)\n`,
      );
      if (process.stdin.isTTY && (await confirmOnTty("Print the secret to stdout instead? [y/N] "))) {
        process.stdout.write(outBytes);
        if (process.stdout.isTTY && outBytes.at(-1) !== 0x0a) process.stdout.write("\n");
      }
      process.exitCode = EXIT.error;
      return;
    }
    const origin = fileName !== null ? ` (sender named it ${fileName})` : "";
    process.stderr.write(`Wrote ${outBytes.length} bytes to ${output}${origin} (mode 0600).\n`);
    return;
  }

  process.stdout.write(outBytes);
  // Keep a TTY prompt tidy without altering piped bytes.
  if (process.stdout.isTTY && outBytes.at(-1) !== 0x0a) process.stdout.write("\n");
}

/**
 * Lands received bytes under the sender's filename without overwriting
 * anything: name, then "name (1)", "name (2)"... Returns the path used, or
 * null if 50 candidates already exist (caller falls back to stdout).
 */
function writeToUnusedName(name: string, bytes: Uint8Array): string | null {
  const safe = sanitizeFilename(name);
  const dot = safe.lastIndexOf(".");
  const [stem, ext] = dot > 0 ? [safe.slice(0, dot), safe.slice(dot)] : [safe, ""];
  for (let n = 0; n < 50; n++) {
    const candidate = n === 0 ? safe : `${stem} (${n})${ext}`;
    let fd: number;
    try {
      fd = openSync(candidate, "wx", 0o600);
    } catch {
      continue;
    }
    let written = 0;
    while (written < bytes.length) {
      written += writeSync(fd, bytes, written, bytes.length - written);
    }
    closeSync(fd);
    return candidate;
  }
  return null;
}

async function revoke(server: string, positionals: string[]) {
  const code = await resolveCode(positionals);
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
        file: { type: "string", short: "f" },
        output: { type: "string", short: "o" },
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
      return send(server, values.ttl, values.json, values.file);
    case "receive":
    case "recv":
      return receive(server, rest, values.output);
    case "revoke":
      return revoke(server, rest);
    default:
      fail(`unknown command "${command}" — try --help`, EXIT.usage);
  }
}

main().catch((e: unknown) => {
  if (e instanceof CliError) {
    if (e.exitCode !== EXIT.aborted) process.stderr.write(`error: ${e.message}\n`);
    process.exitCode = e.exitCode;
    return;
  }
  const msg =
    e instanceof Error && e.name === "TimeoutError"
      ? "network timeout — the server did not respond within 15s"
      : e instanceof TypeError && /fetch/i.test(String(e.message))
        ? `network error — is the server reachable? (${e.message})`
        : e instanceof Error
          ? e.message
          : String(e);
  process.stderr.write(`error: ${msg}\n`);
  process.exitCode = EXIT.error;
});
