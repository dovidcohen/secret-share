import { z } from "zod";
import { invalidateTenant, loadTenant } from "./tenant/registry.js";
import { TenantConfigSchema, type TenantConfig } from "./tenant/schema.js";
import { readValidSession } from "./auth/session.js";
import { bumpSessionEpoch } from "./auth/epoch.js";
import { isAdminIdentity } from "./auth/routes.js";

/**
 * /api/admin/* — tenant hosts only, session required, and the admin bit is
 * re-checked against the LIVE config (not the cookie's `adm` snapshot) so
 * removing an admin email takes effect immediately.
 *
 * Deliberately narrow: issuer/clientId/hostnames/adminEmails are script-only
 * (scripts/provision-tenant.mjs) — an admin can restyle the tenant but can't
 * repoint its identity provider or lock the operator out.
 */

const MAX_LOGO_BYTES = 200 * 1024;
// SVG rejected: script-in-svg makes it a stored-XSS vector if ever fetched top-level.
const LOGO_TYPES = new Set(["image/png", "image/jpeg", "image/webp"]);

const AdminEditSchema = z.object({
  displayName: z.string().min(1).max(80).optional(),
  productName: z.string().max(80).optional(),
  theme: z
    .object({
      primaryColor: z
        .string()
        .regex(/^#[0-9a-f]{6}$/i)
        .nullable()
        .optional(),
      footerText: z.string().max(200).nullable().optional(),
    })
    .optional(),
  oidc: z
    .object({
      allowedEmailDomains: z.array(z.string().min(1)).max(20).optional(),
      allowedGroups: z.array(z.string().min(1)).max(50).optional(),
    })
    .optional(),
  features: z
    .object({
      guestGrants: z.boolean().optional(),
      liveSend: z.boolean().optional(),
    })
    .optional(),
});

function json(status: number, body: unknown): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

export async function handleAdmin(
  request: Request,
  url: URL,
  tenant: TenantConfig,
  env: Env,
): Promise<Response> {
  // Fresh read: the resolver's copy may be minutes stale, and admin rights /
  // session revocation must reflect the config as written, not as cached.
  const live = (await loadTenant(tenant.tenantId, env, { fresh: true })) ?? tenant;
  const session = await readValidSession(request, live, env);
  if (!session) return json(401, { error: "AUTH_REQUIRED" });
  if (!isAdminIdentity(live, session.sub, session.email)) {
    return json(403, { error: "NOT_ALLOWED" });
  }

  if (url.pathname === "/api/admin/tenant" && request.method === "GET") {
    return json(200, live);
  }
  if (url.pathname === "/api/admin/tenant" && request.method === "PUT") {
    return editTenant(request, live, env);
  }
  if (url.pathname === "/api/admin/tenant/logo" && request.method === "PUT") {
    return uploadLogo(request, live, env);
  }
  if (url.pathname === "/api/admin/usage" && request.method === "GET") {
    return usage(url, live, env);
  }
  if (url.pathname === "/api/admin/tenant/revoke-sessions" && request.method === "POST") {
    // Emergency cutoff: every outstanding session (including the caller's)
    // stops validating. The epoch write is serialized in the tenant DO, so
    // no concurrent config save can undo it; per-isolate latency ≤ ~30 s.
    await bumpSessionEpoch(env, live.tenantId);
    return json(200, { revoked: true });
  }
  return json(404, { error: "NOT_FOUND" });
}

async function saveTenant(tenant: TenantConfig, env: Env): Promise<void> {
  tenant.updatedAt = Date.now();
  await env.TENANTS.put(`tenant:${tenant.tenantId}`, JSON.stringify(tenant));
  invalidateTenant(tenant);
}

async function editTenant(
  request: Request,
  live: TenantConfig,
  env: Env,
): Promise<Response> {
  const body = AdminEditSchema.safeParse(await request.json().catch(() => null));
  if (!body.success) return json(400, { error: "BAD_REQUEST" });
  const edit = body.data;

  const next: TenantConfig = structuredClone(live);
  if (edit.displayName !== undefined) next.displayName = edit.displayName;
  if (edit.productName !== undefined) next.productName = edit.productName || undefined;
  if (edit.theme) {
    if (edit.theme.primaryColor !== undefined) {
      next.theme.primaryColor = edit.theme.primaryColor ?? undefined;
    }
    if (edit.theme.footerText !== undefined) {
      next.theme.footerText = edit.theme.footerText ?? undefined;
    }
  }
  if (edit.oidc?.allowedEmailDomains !== undefined) {
    next.oidc.allowedEmailDomains = edit.oidc.allowedEmailDomains.map((d) =>
      d.toLowerCase(),
    );
  }
  if (edit.oidc?.allowedGroups !== undefined) {
    next.oidc.allowedGroups = edit.oidc.allowedGroups;
  }
  if (edit.features?.guestGrants !== undefined) {
    next.features.guestGrants = edit.features.guestGrants;
  }
  if (edit.features?.liveSend !== undefined) {
    next.features.liveSend = edit.features.liveSend;
  }

  const validated = TenantConfigSchema.safeParse(next);
  if (!validated.success) return json(400, { error: "BAD_REQUEST" });
  await saveTenant(validated.data, env);
  // Authorization-policy edits revoke outstanding sessions: a user removed
  // from the allowed set must not coast on a cookie for the rest of the day.
  // The epoch lives in the tenant DO — never in this config document — so a
  // concurrent cosmetic save can't resurrect a revoked value.
  const policyChanged =
    JSON.stringify(next.oidc.allowedEmailDomains) !==
      JSON.stringify(live.oidc.allowedEmailDomains) ||
    JSON.stringify(next.oidc.allowedGroups) !== JSON.stringify(live.oidc.allowedGroups);
  if (policyChanged) await bumpSessionEpoch(env, live.tenantId);
  return json(200, { ...validated.data, sessionsRevoked: policyChanged });
}

async function uploadLogo(
  request: Request,
  live: TenantConfig,
  env: Env,
): Promise<Response> {
  const contentType = request.headers.get("Content-Type") ?? "";
  if (!LOGO_TYPES.has(contentType)) {
    return json(415, { error: "UNSUPPORTED_TYPE" });
  }
  const bytes = await request.arrayBuffer();
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_LOGO_BYTES) {
    return json(413, { error: "TOO_LARGE" });
  }
  await env.TENANTS.put(`logo:${live.tenantId}`, bytes, {
    metadata: { contentType },
  });
  live.theme.logoVersion += 1;
  await saveTenant(live, env);
  return json(200, { logoVersion: live.theme.logoVersion });
}

async function usage(url: URL, live: TenantConfig, env: Env): Promise<Response> {
  if (!env.USAGE) return json(200, { days: [] });
  const stub = env.USAGE.get(env.USAGE.idFromName(`usage:${live.tenantId}`));
  const from = url.searchParams.get("from") ?? "";
  const to = url.searchParams.get("to") ?? "";
  const res = await stub.fetch(
    `https://usage/internal/read?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
  );
  return json(res.status, await res.json());
}
