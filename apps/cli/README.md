# shareasecret

Pass a small secret (SSH key, API token, password — up to 10 KB) to exactly one
person, from the terminal. End-to-end encrypted, **read-once**, auto-expiring.
The CLI for [shareasecret.io](https://shareasecret.io) — fully interoperable
with the web app in both directions.

```sh
cat id_ed25519 | npx shareasecret@0.2.0 send --ttl 2h
# Share code (read-once, speak it or send it over any channel):
#
#   XKQ2-M7PT-tiger-ocean-cable-ruby-drum

npx shareasecret@0.2.0 send --file release.jks       # send a small file; its name travels
                                                     # encrypted and arrives with the bytes
npx shareasecret@0.2.0 receive --output id_ed25519   # prompts for the code (input hidden),
                                                     # writes the file 0600, never overwrites
npx shareasecret@0.2.0 revoke                        # burn before it's read; prompts the same way
```

Examples pin the version deliberately — pinned invocations run bit-identical,
inspectable code every time, unlike a web page (or an unpinned `npx`), which
trusts what's served at that moment.

The recipient doesn't need the CLI — the code also works at
`https://shareasecret.io/r#<code>`, and `receive` accepts that full link.

## How it works

- `XKQ2-M7PT` — a random 40-bit mailbox id. The only part the server ever sees.
- The five words — 64.6 bits of key entropy, **never transmitted**.
  `Argon2id(words, salt=mailboxId)` → HKDF → AES-256-GCM key and auth tags.
- The server stores only ciphertext and hashed tags, deletes on first read,
  burns the drop after 5 wrong attempts, and sweeps expired drops.

Same protocol and crypto code as the web app; the server cannot read your
secret, and neither can anyone without the exact code.

## Usage

```
shareasecret send [--ttl <duration>] [--json]        read secret from stdin, print share code
shareasecret send --file <path> [--ttl] [--json]     send a small file with its name attached
shareasecret receive [<code|link>] [-o <file>]       claim the secret (omit code to be prompted)
shareasecret revoke [<code>]                         burn a drop you sent before it is read
```

- `--ttl` — expiry: `90s`, `30m`, `2h`, `1d` (min 60s, max 7d, default 1d)
- `--json` — machine-readable `{code, link, expiresAt, ttlSeconds}` on stdout
- `-f, --file <path>` — send this file instead of reading stdin; the filename
  rides inside the encrypted payload, and the web receive page offers it as a
  download under that name (fully interoperable with the web app's attach button)
- `-o, --output <file>` — receive: create the file `0600` from the first byte
  (no umask window), refuse to overwrite; on Windows the mode is advisory.
  Receiving a file sent with a name and no `--output` on a terminal saves it
  under that (sanitized) name in the current directory instead of printing
  binary; piped output always gets the raw bytes
- Codes as arguments land in shell history and the process list — omit the code
  and `receive`/`revoke` prompt for it without echoing (scripts: pipe it to stdin)
- stderr never duplicates the code: when stdout is captured
  (`CODE=$(… | shareasecret send)`, CI), the code goes to stdout *only* —
  capture or redirect stdout explicitly, keep `set -x` tracing off, and mask
  the captured value in your CI system
- Exit codes: `0` ok, `1` error, `2` usage, `3` wrong code, `4` not found,
  `5` already read or expired, `6` too large

Requires Node ≥ 20. No runtime dependencies. The web page is re-fetched on every
visit; a pinned package is not — `npx shareasecret@<version>` runs bit-identical,
inspectable code each time. The protocol matches the web app; the terminal adds
its own risk surface (history, scrollback, process list, file permissions, CI
logs), which the flags above are designed to close.

## License

Source-available for inspection and security review — see the
[repository](https://github.com/dovidcohen/secret-share). All rights reserved;
this package may be used as-is but not copied, modified, or redistributed
without permission.
