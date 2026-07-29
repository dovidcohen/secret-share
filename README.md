# Secret Share

**Live at [shareasecret.io](https://shareasecret.io)**

Pass a small secret (SSH key, API token, password — up to 10 KB) to exactly one
person. End-to-end encrypted, transferred **directly browser-to-browser** when both
people are online, parked as an **encrypted dead drop** when they're not. Read-once,
auto-expiring, and the server never sees plaintext or key material.

## How it works

The sender gets a speakable share code like

```
XKQ2-M7PT-tiger-ocean-cable-ruby-drum
```

- `XKQ2-M7PT` — a random 40-bit **mailbox id**. The only part the server ever sees;
  used for routing and storage, carries zero key entropy.
- five EFF-wordlist words — **64.6 bits of key entropy**, never transmitted.
  `Argon2id(words, salt=mailboxId)` → HKDF fans out into the blob key, the live
  session key material, and two auth tags.

**Park-first hybrid flow:** the sender's browser encrypts the secret (AES-256-GCM)
and parks the ciphertext on the server immediately, then stays connected to a
signaling room. If the receiver arrives while the sender is online, the secret is
re-sent **directly** over a WebRTC DataChannel (encrypted again under a per-session
key with mutual key-confirmation *before* any secret bytes flow) and the parked copy
is deleted. If the sender is gone, the receiver claims the parked ciphertext by
presenting a claim tag derived from the code, and the server deletes it on read.

Read-once is enforced everywhere: one claim, 5 failed attempts burn the drop, a
delivered live transfer is never re-offered, and TTL alarms sweep leftovers.

## Architecture

| Piece | Tech |
|---|---|
| `apps/web` | React + Vite + TS single-page app |
| `apps/cli` | `shareasecret` terminal client (Node ≥20, zero runtime deps, single-file bundle) |
| `workers/api` | One Cloudflare Worker: REST + WebSocket signaling + static assets |
| `MailboxDO` | One Durable Object per mailbox (SQLite storage): drop, attempt counter, TTL alarm, signaling room |
| `packages/crypto` | Argon2id (hash-wasm) + WebCrypto (HKDF, AES-GCM, HMAC), code gen/parse |
| `packages/protocol` | zod schemas shared by client and server |

Durable Object storage (not KV) because read-once needs transactional
read-and-delete — KV's eventual consistency could serve a "deleted" secret from
another edge for up to a minute.

## CLI

Same protocol, same crypto (the CLI bundles `packages/crypto` unchanged — Node's
WebCrypto), no browser. Uses the parked path only, so it interoperates with the
web app in both directions: send from the terminal, open in a browser, or vice
versa.

```sh
cat id_ed25519 | shareasecret send --ttl 2h
# Share code (read-once, speak it or send it over any channel):
#
#   XKQ2-M7PT-tiger-ocean-cable-ruby-drum

shareasecret receive XKQ2-M7PT-tiger-ocean-cable-ruby-drum > id_ed25519
shareasecret revoke  XKQ2-M7PT-tiger-ocean-cable-ruby-drum   # burn before it's read
```

`send` prints the bare code on stdout; when stdout is captured (subshell, pipe,
CI) stderr carries no code or link, so logs can't leak the capability. `--json`
emits `{code, link, expiresAt, ttlSeconds}`. `receive` accepts the full `/r#`
link, prompts for the code with input hidden when it's omitted (keeps it out of
shell history), and `--output <file>` creates key files `0600` with no umask
window and no overwrites. Exit codes are stable for scripting: 0 ok, 2 usage,
3 wrong code, 4 not found, 5 already read/expired, 6 too large. Point it at a
dev server with `--server` or `SHAREASECRET_SERVER`.

Build: `pnpm build:cli` → `apps/cli/dist/cli.cjs` (self-contained, shebanged).

## Development

```sh
pnpm install
pnpm test                 # unit + integration suites (35 tests)
pnpm dev:api              # wrangler dev on :8787 (API + built SPA)
pnpm dev:web              # vite on :5173, proxies /api and /ws to :8787
```

Manual verification scripts (against a running `pnpm dev:api`):

```sh
node workers/api/test/manual-drops.mjs   # REST lifecycle incl. 75s TTL test
node workers/api/test/manual-ws.mjs      # signaling: presence, relay, roles
node apps/web/test/e2e.mjs               # Playwright: live P2P, async claim, WebRTC-blocked fallback
node apps/cli/test/manual-cli.mjs        # CLI lifecycle: round-trip, read-once, revoke, exit codes
```

The e2e script expects the **built** SPA on :8787: `pnpm build` first.

## Deploy

```sh
pnpm --filter @secret-share/api exec wrangler login
pnpm deploy
```

Notes:
- The `unsafe.bindings` rate-limit config (30 creates+joins/min/IP) is the
  open-beta Workers rate-limiting binding; a zone WAF rule on `/api/*` is an
  equivalent alternative.
- TURN relay (Cloudflare Realtime) is supported for the ~10-15% of peer pairs
  that can't hole-punch. Create a TURN key in the dashboard
  (dash.cloudflare.com → Realtime → TURN), then:
  `wrangler secret put TURN_KEY_ID` and `wrangler secret put TURN_KEY_API_TOKEN`.
  Without the secrets the app runs STUN-only and P2P failures fall back to the
  async drop (except direct-only mode, which needs the live path to succeed).
  The relay carries DTLS ciphertext with the payload E2E-encrypted on top.

## Security model, honestly stated

- The server stores only ciphertext, hashed auth tags, and timestamps. A full
  server compromise yields blobs that cost an Argon2id (64 MiB, t=3) evaluation
  per guess against ~65 bits of entropy, per mailbox salt.
- The signaling server cannot MITM the live path: frame keys derive from the
  code, and each side proves knowledge via HMAC key-confirmation before the
  secret moves.
- **Residual trust:** this is a web app; you trust the JavaScript we serve at the
  moment you use it. Mitigations: published source and the `shareasecret` CLI
  (pinnable to an exact npm version). Still on the roadmap: reproducible builds,
  subresource integrity.
- Share links carry the code in the URL **fragment** (never sent over HTTP);
  `Referrer-Policy: no-referrer` and `Cache-Control: no-store` throughout.

## License

Source-available for inspection and security review. **All rights reserved** —
this code may not be copied, modified, or redistributed without permission.
