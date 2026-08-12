import {
  CreateGrantRequestSchema,
  GrantTokenSchema,
  MAILBOX_ID_REGEX,
  TurnRequestSchema,
} from "@secret-share/protocol";
import { checkUsage } from "./usage.js";
import { resolveTenant } from "./tenant/registry.js";
import type { TenantConfig } from "./tenant/schema.js";
import { marketingRedirect, rewriteHtmlForTenant, serveLogo } from "./branding.js";
import { handleAuth } from "./auth/routes.js";
import { readValidSession } from "./auth/session.js";
import { handleAdmin } from "./admin.js";
import { entitlement, entitlementDenied, handleStripeWebhook } from "./billing.js";
import { PUBLIC_USAGE_ID, recordUsage } from "./usagedo.js";
import { sendDailyDigest } from "./usage.js";
import { stubFetch } from "./stubfetch.js";

export { MailboxDO } from "./mailbox.js";
export { UsageDO } from "./usagedo.js";

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
  // camera=(self): the optical (QR) transfer scans with getUserMedia; same-origin only.
  "Permissions-Policy": "camera=(self), microphone=(), geolocation=()",
};

function mailboxIdFor(pathname: string): string | null {
  const m = DROP_ROUTE.exec(pathname) ?? WS_ROUTE.exec(pathname);
  const id = m?.[1];
  return id && MAILBOX_ID_REGEX.test(id) ? id : null;
}

/** Drop creation, room joins, and IdP round-trips share the general IP limiter. */
function isRateLimited(request: Request, pathname: string): boolean {
  return (
    (request.method === "PUT" && DROP_ROUTE.test(pathname)) ||
    WS_ROUTE.test(pathname) ||
    pathname === "/api/grants" ||
    pathname === "/auth/login" ||
    pathname === "/auth/callback"
  );
}

function json(status: number, body: unknown): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** GET /api/stats?from=&to= — daily public drop_created/drop_claimed counts. */
async function publicStats(request: Request, url: URL, env: Env): Promise<Response> {
  if (!env.STATS_TOKEN) return json(404, { error: "NOT_FOUND" });
  const auth = request.headers.get("Authorization") ?? "";
  const presented = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!timingSafeEqual(presented, env.STATS_TOKEN)) {
    return json(401, { error: "AUTH_REQUIRED" });
  }
  const stub = env.USAGE.get(env.USAGE.idFromName(`usage:${PUBLIC_USAGE_ID}`));
  const from = url.searchParams.get("from") ?? "";
  const to = url.searchParams.get("to") ?? "";
  const res = await stubFetch(
    stub,
    `https://usage/internal/read?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
  );
  return json(res.status, await res.json());
}

/**
 * Tenant mailboxes live in a namespaced DO ("tenantId:XKQ2M7PT"); ":" is
 * outside the Crockford alphabet, so tenant pools can never collide with the
 * public pool or each other.
 */
function mailboxDoName(mailboxId: string, tenant: TenantConfig | null): string {
  return tenant ? `${tenant.tenantId}:${mailboxId}` : mailboxId;
}

/**
 * Mints short-lived TURN credentials from Cloudflare Realtime. Gated on a
 * turnToken issued over an open signaling session (verified by the mailbox DO)
 * plus a dedicated stricter IP limiter, so this can't be farmed as a free
 * generic relay. The relay only ever carries DTLS ciphertext (the payload is
 * additionally end-to-end encrypted), so TURN preserves the zero-knowledge model.
 */
async function mintTurnCredentials(
  request: Request,
  env: Env,
  tenant: TenantConfig | null,
): Promise<Response> {
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

  const stub = env.MAILBOX.get(
    env.MAILBOX.idFromName(mailboxDoName(body.data.mailboxId, tenant)),
  );
  const verify = await stubFetch(stub, "https://mailbox/internal/turn-verify", {
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

/**
 * CSRF belt-and-braces on top of SameSite=Lax: browser-sent cross-site
 * mutations carry an Origin header that won't match. Absent Origin
 * (non-browser clients) passes — this complements cookies, it doesn't replace
 * the session check.
 */
function crossSiteOrigin(request: Request, url: URL): boolean {
  const origin = request.headers.get("Origin");
  return origin !== null && origin !== url.origin;
}

/** Mints a one-time guest-send grant; the employee must hold a session. */
async function mintGrant(
  request: Request,
  url: URL,
  tenant: TenantConfig,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  if (!tenant.features.guestGrants) return json(404, { error: "NOT_FOUND" });
  if (crossSiteOrigin(request, url)) return json(403, { error: "NOT_ALLOWED" });
  const entitled = entitlement(tenant);
  if (!entitled.ok) return entitlementDenied(entitled.reason);
  const session = await readValidSession(request, tenant, env);
  if (!session) return json(401, { error: "AUTH_REQUIRED" });

  const body = CreateGrantRequestSchema.safeParse(await request.json().catch(() => null));
  if (!body.success) return json(400, { error: "BAD_REQUEST" });

  const stub = env.MAILBOX.get(
    env.MAILBOX.idFromName(mailboxDoName(body.data.mailboxId, tenant)),
  );
  const res = await stubFetch(stub, "https://mailbox/internal/grant-create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ttlSeconds: body.data.ttlSeconds }),
  });
  if (res.status === 201) recordUsage(env, ctx, tenant.tenantId, "grant_minted");
  return res;
}

/**
 * Decides how a mailbox request is authorized on a tenant host and stamps the
 * trusted x-ss-auth header for the DO. Returns a Response to short-circuit
 * with (401/403), or the header value to forward.
 */
async function tenantMailboxAuth(
  request: Request,
  url: URL,
  pathname: string,
  tenant: TenantConfig,
  env: Env,
): Promise<{ header: string } | { deny: Response }> {
  const isCreate = request.method === "PUT" && DROP_ROUTE.test(pathname);
  const isSenderWs =
    WS_ROUTE.test(pathname) && url.searchParams.get("role") === "sender";

  if (!isCreate && !isSenderWs) return { header: "public" };

  // Sending is the paid surface; claiming stays open above so already-sent
  // secrets outlive a lapsed subscription.
  const entitled = entitlement(tenant);
  if (!entitled.ok) return { deny: entitlementDenied(entitled.reason) };

  const session = await readValidSession(request, tenant, env);
  if (session) {
    if (isCreate && crossSiteOrigin(request, url)) {
      return { deny: json(403, { error: "NOT_ALLOWED" }) };
    }
    return { header: "session" };
  }

  if (isCreate) {
    // Guest-send: a one-time grant minted by an employee stands in for a session.
    const grant = GrantTokenSchema.safeParse(request.headers.get("X-Guest-Grant"));
    if (grant.success && tenant.features.guestGrants) {
      return { header: `grant ${grant.data}` };
    }
  }
  return { deny: json(401, { error: "AUTH_REQUIRED" }) };
}

async function handle(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
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
  // EXACTLY the apex www — a blanket startsWith("www.") would bounce
  // www.secrets.customer.com (OAuth codes, /give fragments) across origins.
  if (url.hostname === "www.shareasecret.io") {
    url.hostname = "shareasecret.io";
    return Response.redirect(url.toString(), 301);
  }

  // Dev-only: `wrangler dev` rewrites every request URL to the route host, so
  // local e2e simulates tenant hosts via a header instead. Inert in production.
  const hostname =
    env.ENVIRONMENT === "dev"
      ? (request.headers.get("x-dev-tenant-host") ?? url.hostname)
      : url.hostname;
  const resolution = await resolveTenant(hostname, env);
  if (resolution.kind === "unknown") {
    // Unprovisioned subdomains and stray custom hostnames must not serve
    // SPA clones — neither app nor API.
    return pathname.startsWith("/api/") || pathname.startsWith("/ws/")
      ? json(404, { error: "NOT_FOUND" })
      : new Response("Not found", { status: 404 });
  }
  const tenant = resolution.kind === "tenant" ? resolution.tenant : null;

  // Production-only: under `wrangler dev`/vitest every request shares one
  // simulated IP bucket, which turns local suites into 429 flakes.
  const limited =
    env.ENVIRONMENT !== "dev" &&
    env.CREATE_LIMITER &&
    isRateLimited(request, pathname)
      ? !(
          await env.CREATE_LIMITER.limit({
            key: request.headers.get("CF-Connecting-IP") ?? "unknown",
          })
        ).success
      : false;

  // Dev-only (wrangler dev / vitest): lets the tenant e2e forge a session
  // with the real epoch instead of needing a live IdP. Unreachable in
  // production; knowing the epoch grants nothing without SESSION_SECRET.
  if (tenant && env.ENVIRONMENT === "dev" && pathname === "/internal-dev/epoch") {
    const { getSessionEpoch } = await import("./auth/epoch.js");
    return json(200, { epoch: await getSessionEpoch(env, tenant.tenantId, { fresh: true }) });
  }

  if (tenant && pathname.startsWith("/auth/")) {
    if (limited) return json(429, { error: "RATE_LIMITED" });
    const res = await handleAuth(request, url, tenant, env);
    const location = res.headers.get("Location") ?? "";
    if (pathname === "/auth/callback" && res.status === 302 && !location.includes("auth_error=")) {
      recordUsage(env, ctx, tenant.tenantId, "login");
    }
    return res;
  }

  if (pathname.startsWith("/api/") || pathname.startsWith("/ws/")) {
    if (limited) return json(429, { error: "RATE_LIMITED" });

    if (tenant) {
      if (pathname === "/api/tenant/logo" && request.method === "GET") {
        return serveLogo(request, tenant, env);
      }
      if (pathname.startsWith("/api/admin/")) {
        return handleAdmin(request, url, tenant, env);
      }
      if (pathname === "/api/grants" && request.method === "POST") {
        return mintGrant(request, url, tenant, env, ctx);
      }
    }

    if (pathname === "/api/turn" && request.method === "POST") {
      return mintTurnCredentials(request, env, tenant);
    }

    // Stripe subscription lifecycle; the HMAC over the raw body is the auth.
    if (pathname === "/api/billing/webhook" && request.method === "POST") {
      return handleStripeWebhook(request, env);
    }

    // Public product metrics (real sends/claims per day), token-gated so
    // business numbers aren't world-readable. Works on any host.
    if (pathname === "/api/stats" && request.method === "GET") {
      return publicStats(request, url, env);
    }

    const mailboxId = mailboxIdFor(pathname);
    if (!mailboxId) {
      return json(404, { error: "NOT_FOUND" });
    }

    // The DO trusts x-ss-auth, so it must always be (re)stamped here —
    // external values never survive.
    let authHeader = "public";
    if (tenant) {
      const decision = await tenantMailboxAuth(request, url, pathname, tenant, env);
      if ("deny" in decision) return decision.deny;
      authHeader = decision.header;
    }
    const forwarded = new Request(request);
    forwarded.headers.set("x-ss-auth", authHeader);
    forwarded.headers.delete("X-Guest-Grant");

    // One DO instance per mailbox: routing, storage, and signaling all converge here.
    const stub = env.MAILBOX.get(env.MAILBOX.idFromName(mailboxDoName(mailboxId, tenant)));
    const res = await stubFetch(stub, forwarded);

    // Metered for tenants and the public product alike; the public pool uses
    // a reserved counter id (tenant ids are [a-z0-9-], so no collision).
    const usageId = tenant ? tenant.tenantId : PUBLIC_USAGE_ID;
    if (request.method === "PUT" && res.status === 201) {
      recordUsage(env, ctx, usageId, "drop_created");
    } else if (pathname.endsWith("/claim") && res.status === 200) {
      recordUsage(env, ctx, usageId, "drop_claimed");
    }
    return res;
  }

  if (tenant) {
    const redirect = marketingRedirect(url);
    if (redirect) return redirect;
    const asset = await env.ASSETS.fetch(request);
    const type = asset.headers.get("Content-Type") ?? "";
    return type.includes("text/html") ? rewriteHtmlForTenant(asset, tenant) : asset;
  }

  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const res = await handle(request, env, ctx);
    // Uniform security headers on everything — assets, API, and redirects.
    // 101s are exempt: a WebSocket upgrade response cannot be reconstructed.
    if (res.status === 101) return res;
    const hardened = new Response(res.body, res);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) hardened.headers.set(k, v);
    return hardened;
  },

  async scheduled(controller, env, ctx): Promise<void> {
    // Daily digest at 13:00 UTC (~morning US Eastern); the 6-hourly trigger
    // keeps doing the free-tier cap check.
    if (controller.cron === "0 13 * * *") {
      ctx.waitUntil(sendDailyDigest(env));
    } else {
      ctx.waitUntil(checkUsage(env));
    }
  },
} satisfies ExportedHandler<Env>;
