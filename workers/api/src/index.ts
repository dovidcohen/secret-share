import { MAILBOX_ID_REGEX, TurnRequestSchema } from "@secret-share/protocol";
import { checkUsage } from "./usage.js";

export { MailboxDO } from "./mailbox.js";

const DROP_ROUTE = /^\/api\/drops\/([0-9A-HJKMNP-TV-Z]{8})(\/claim)?$/;
const WS_ROUTE = /^\/ws\/([0-9A-HJKMNP-TV-Z]{8})$/;

const SECURITY_HEADERS: Record<string, string> = {
  // 'wasm-unsafe-eval' is required for the Argon2 WASM module; everything else is same-origin only.
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; " +
    "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; " +
    "object-src 'none'; frame-ancestors 'none'",
  "Strict-Transport-Security": "max-age=31536000",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

function mailboxIdFor(pathname: string): string | null {
  const m = DROP_ROUTE.exec(pathname) ?? WS_ROUTE.exec(pathname);
  const id = m?.[1];
  return id && MAILBOX_ID_REGEX.test(id) ? id : null;
}

/** Drop creation and room joins share the general IP limiter; claims are per-mailbox. */
function isRateLimited(request: Request, pathname: string): boolean {
  return (
    (request.method === "PUT" && DROP_ROUTE.test(pathname)) || WS_ROUTE.test(pathname)
  );
}

/**
 * Mints short-lived TURN credentials from Cloudflare Realtime. Gated on a
 * turnToken issued over an open signaling session (verified by the mailbox DO)
 * plus a dedicated stricter IP limiter, so this can't be farmed as a free
 * generic relay. The relay only ever carries DTLS ciphertext (the payload is
 * additionally end-to-end encrypted), so TURN preserves the zero-knowledge model.
 */
async function mintTurnCredentials(request: Request, env: Env): Promise<Response> {
  if (!env.TURN_KEY_ID || !env.TURN_KEY_API_TOKEN) {
    return Response.json({ error: "TURN_NOT_CONFIGURED" }, { status: 404 });
  }

  if (env.TURN_LIMITER) {
    const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
    const { success } = await env.TURN_LIMITER.limit({ key: ip });
    if (!success) return Response.json({ error: "RATE_LIMITED" }, { status: 429 });
  }

  const body = TurnRequestSchema.safeParse(await request.json().catch(() => null));
  if (!body.success) return Response.json({ error: "BAD_REQUEST" }, { status: 400 });

  const stub = env.MAILBOX.get(env.MAILBOX.idFromName(body.data.mailboxId));
  const verify = await stub.fetch("https://mailbox/internal/turn-verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: body.data.turnToken }),
  });
  if (verify.status !== 204) {
    return Response.json({ error: "BAD_TOKEN" }, { status: 403 });
  }
  const upstream = await fetch(
    `https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_KEY_ID}/credentials/generate-ice-servers`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.TURN_KEY_API_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ttl: 600 }),
    },
  );
  if (!upstream.ok) {
    return Response.json({ error: "TURN_UNAVAILABLE" }, { status: 503 });
  }
  const data = (await upstream.json()) as { iceServers: unknown };
  const iceServers = Array.isArray(data.iceServers) ? data.iceServers : [data.iceServers];
  return Response.json(
    { iceServers },
    { headers: { "Cache-Control": "no-store" } },
  );
}

async function handle(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const { pathname } = url;

  // Plaintext HTTP must never serve the app: an on-path attacker could swap
  // the JS or read secrets pre-encryption. 308 preserves method for API calls.
  // (`wrangler dev` rewrites request URLs to the route host over http, so
  // local dev is exempted via .dev.vars rather than by hostname.)
  if (url.protocol === "http:" && env.ENVIRONMENT !== "dev") {
    url.protocol = "https:";
    return Response.redirect(url.toString(), 308);
  }

  // Canonical host: www duplicates the apex in search indexes otherwise.
  // Fragments (where share codes live) survive redirects client-side.
  if (url.hostname.startsWith("www.")) {
    url.hostname = url.hostname.slice(4);
    return Response.redirect(url.toString(), 301);
  }

  if (pathname.startsWith("/api/") || pathname.startsWith("/ws/")) {
    if (env.CREATE_LIMITER && isRateLimited(request, pathname)) {
      const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
      const { success } = await env.CREATE_LIMITER.limit({ key: ip });
      if (!success) {
        return Response.json({ error: "RATE_LIMITED" }, { status: 429 });
      }
    }

    if (pathname === "/api/turn" && request.method === "POST") {
      return mintTurnCredentials(request, env);
    }

    const mailboxId = mailboxIdFor(pathname);
    if (!mailboxId) {
      return Response.json({ error: "NOT_FOUND" }, { status: 404 });
    }

    // One DO instance per mailbox: routing, storage, and signaling all converge here.
    const stub = env.MAILBOX.get(env.MAILBOX.idFromName(mailboxId));
    return stub.fetch(request);
  }

  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env): Promise<Response> {
    const res = await handle(request, env);
    // Uniform security headers on everything — assets, API, and redirects.
    // 101s are exempt: a WebSocket upgrade response cannot be reconstructed.
    if (res.status === 101) return res;
    const hardened = new Response(res.body, res);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) hardened.headers.set(k, v);
    return hardened;
  },

  async scheduled(_controller, env, ctx): Promise<void> {
    ctx.waitUntil(checkUsage(env));
  },
} satisfies ExportedHandler<Env>;
