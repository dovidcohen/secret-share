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
| `workers/api` | One Cloudflare Worker: REST + WebSocket signaling + static assets |
| `MailboxDO` | One Durable Object per mailbox (SQLite storage): drop, attempt counter, TTL alarm, signaling room |
| `packages/crypto` | Argon2id (hash-wasm) + WebCrypto (HKDF, AES-GCM, HMAC), code gen/parse |
| `packages/protocol` | zod schemas shared by client and server |

Durable Object storage (not KV) because read-once needs transactional
read-and-delete — KV's eventual consistency could serve a "deleted" secret from
another edge for up to a minute.

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
- ICE is STUN-only for now; peers that can't hole-punch fall back to the async
  drop automatically. Add a TURN credentials endpoint (Cloudflare Realtime)
  later if live-path success rates matter.

## Security model, honestly stated

- The server stores only ciphertext, hashed auth tags, and timestamps. A full
  server compromise yields blobs that cost an Argon2id (64 MiB, t=3) evaluation
  per guess against ~65 bits of entropy, per mailbox salt.
- The signaling server cannot MITM the live path: frame keys derive from the
  code, and each side proves knowledge via HMAC key-confirmation before the
  secret moves.
- **Residual trust:** this is a web app; you trust the JavaScript we serve at the
  moment you use it. Mitigations on the roadmap: published source, reproducible
  builds, subresource integrity, a CLI client.
- Share links carry the code in the URL **fragment** (never sent over HTTP);
  `Referrer-Policy: no-referrer` and `Cache-Control: no-store` throughout.
