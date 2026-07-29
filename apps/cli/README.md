# shareasecret

Pass a small secret (SSH key, API token, password — up to 10 KB) to exactly one
person, from the terminal. End-to-end encrypted, **read-once**, auto-expiring.
The CLI for [shareasecret.io](https://shareasecret.io) — fully interoperable
with the web app in both directions.

```sh
cat id_ed25519 | npx shareasecret send --ttl 2h
# Share code (read-once, speak it or send it over any channel):
#
#   XKQ2-M7PT-tiger-ocean-cable-ruby-drum

npx shareasecret receive XKQ2-M7PT-tiger-ocean-cable-ruby-drum > id_ed25519
npx shareasecret revoke  XKQ2-M7PT-tiger-ocean-cable-ruby-drum   # burn before it's read
```

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
shareasecret send [--ttl <duration>] [--json]     read secret from stdin, print share code
shareasecret receive <code|link>                  claim the secret, write it to stdout
shareasecret revoke <code>                        burn a drop you sent before it is read
```

- `--ttl` — expiry: `90s`, `30m`, `2h`, `1d` (min 60s, max 7d, default 1d)
- `--json` — machine-readable `{code, link, expiresAt, ttlSeconds}` on stdout
- `send` prints the bare code on stdout (decoration on stderr), so
  `CODE=$(... | shareasecret send)` works; `receive` writes raw secret bytes
- Exit codes: `0` ok, `1` error, `2` usage, `3` wrong code, `4` not found,
  `5` already read or expired, `6` too large

Requires Node ≥ 20. No runtime dependencies.

## License

Source-available for inspection and security review — see the
[repository](https://github.com/dovidcohen/secret-share). All rights reserved;
this package may be used as-is but not copied, modified, or redistributed
without permission.
