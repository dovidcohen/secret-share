import { MAILBOX_ID_REGEX } from "@secret-share/protocol";

export { MailboxDO } from "./mailbox.js";

const DROP_ROUTE = /^\/api\/drops\/([0-9A-HJKMNP-TV-Z]{8})(\/claim)?$/;
const WS_ROUTE = /^\/ws\/([0-9A-HJKMNP-TV-Z]{8})$/;

const SECURITY_HEADERS: Record<string, string> = {
  // 'wasm-unsafe-eval' is required for the Argon2 WASM module; everything else is same-origin only.
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; " +
    "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; " +
    "object-src 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

function mailboxIdFor(pathname: string): string | null {
  const m = DROP_ROUTE.exec(pathname) ?? WS_ROUTE.exec(pathname);
  const id = m?.[1];
  return id && MAILBOX_ID_REGEX.test(id) ? id : null;
}

/** Drop creation, room joins, and TURN minting are IP-limited; claims per-mailbox. */
function isRateLimited(request: Request, pathname: string): boolean {
  return (
    (request.method === "PUT" && DROP_ROUTE.test(pathname)) ||
    WS_ROUTE.test(pathname) ||
    pathname === "/api/turn"
  );
}

/**
 * Mints short-lived TURN credentials from Cloudflare Realtime. The relay only
 * ever carries DTLS ciphertext (the payload is additionally end-to-end
 * encrypted under the session key), so TURN preserves the zero-knowledge model.
 */
async function mintTurnCredentials(env: Env): Promise<Response> {
  if (!env.TURN_KEY_ID || !env.TURN_KEY_API_TOKEN) {
    return Response.json({ error: "TURN_NOT_CONFIGURED" }, { status: 404 });
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

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;

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

      if (pathname === "/api/turn" && request.method === "GET") {
        return mintTurnCredentials(env);
      }

      const mailboxId = mailboxIdFor(pathname);
      if (!mailboxId) {
        return Response.json({ error: "NOT_FOUND" }, { status: 404 });
      }

      // One DO instance per mailbox: routing, storage, and signaling all converge here.
      const stub = env.MAILBOX.get(env.MAILBOX.idFromName(mailboxId));
      return stub.fetch(request);
    }

    const res = await env.ASSETS.fetch(request);
    const hardened = new Response(res.body, res);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) hardened.headers.set(k, v);
    return hardened;
  },
} satisfies ExportedHandler<Env>;
