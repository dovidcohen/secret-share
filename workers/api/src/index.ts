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

/** Only drop creation and room joins are IP-limited; claims are limited per-mailbox. */
function isRateLimited(request: Request, pathname: string): boolean {
  return (
    (request.method === "PUT" && DROP_ROUTE.test(pathname)) || WS_ROUTE.test(pathname)
  );
}

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;

    if (pathname.startsWith("/api/") || pathname.startsWith("/ws/")) {
      const mailboxId = mailboxIdFor(pathname);
      if (!mailboxId) {
        return Response.json({ error: "NOT_FOUND" }, { status: 404 });
      }

      if (env.CREATE_LIMITER && isRateLimited(request, pathname)) {
        const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
        const { success } = await env.CREATE_LIMITER.limit({ key: ip });
        if (!success) {
          return Response.json({ error: "RATE_LIMITED" }, { status: 429 });
        }
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
