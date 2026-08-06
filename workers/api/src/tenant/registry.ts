import { TenantConfigSchema, type TenantConfig } from "./schema.js";

/**
 * Hostname -> tenant resolution, on the hot path of every request.
 *
 * - Apex hosts are hardwired to "public" so shareasecret.io never pays a KV
 *   read and keeps byte-identical pre-tenant behavior.
 * - Tenant hosts resolve host:<hostname> -> tenant:<tenantId> in KV, fronted
 *   by a per-isolate memory cache so warm isolates do zero KV reads.
 * - Unknown hosts are "unknown" (the caller 404s) in production — an
 *   unprovisioned *.shareasecret.io subdomain must not serve an SPA clone.
 *   Under `wrangler dev`/vitest (ENVIRONMENT=dev) unknown hosts fall back to
 *   public so local hosts and test hosts behave like the apex.
 */

const APEX_HOSTS = new Set(["shareasecret.io", "www.shareasecret.io"]);

export type TenantResolution =
  | { kind: "public" }
  | { kind: "tenant"; tenant: TenantConfig }
  | { kind: "unknown" };

const MEMORY_TTL_MS = 60_000;
const KV_CACHE_TTL_S = 300;

interface CacheEntry {
  resolution: TenantResolution;
  freshUntil: number;
}

const cache = new Map<string, CacheEntry>();

/** Test hook: memory caching would leak state across vitest cases otherwise. */
export function clearTenantCache(): void {
  cache.clear();
}

export async function resolveTenant(
  hostname: string,
  env: Env,
): Promise<TenantResolution> {
  if (APEX_HOSTS.has(hostname)) return { kind: "public" };

  const cached = cache.get(hostname);
  if (cached && cached.freshUntil > Date.now()) return cached.resolution;

  const resolution = await lookup(hostname, env);
  cache.set(hostname, { resolution, freshUntil: Date.now() + MEMORY_TTL_MS });
  return resolution;
}

async function lookup(hostname: string, env: Env): Promise<TenantResolution> {
  const hostEntry = await env.TENANTS.get(`host:${hostname}`, {
    type: "json",
    cacheTtl: KV_CACHE_TTL_S,
  }).catch(() => null);
  const tenantId = (hostEntry as { tenantId?: string } | null)?.tenantId;
  if (!tenantId) {
    return env.ENVIRONMENT === "dev" ? { kind: "public" } : { kind: "unknown" };
  }

  const tenant = await loadTenant(tenantId, env);
  return tenant ? { kind: "tenant", tenant } : { kind: "unknown" };
}

/** Direct tenant load (admin API re-reads config on every request to pick up edits). */
export async function loadTenant(
  tenantId: string,
  env: Env,
  opts: { fresh?: boolean } = {},
): Promise<TenantConfig | null> {
  const raw = await env.TENANTS.get(
    `tenant:${tenantId}`,
    opts.fresh ? { type: "json" } : { type: "json", cacheTtl: KV_CACHE_TTL_S },
  ).catch(() => null);
  const parsed = TenantConfigSchema.safeParse(raw);
  if (!parsed.success) {
    if (raw !== null) console.error(`Malformed tenant config for ${tenantId}`);
    return null;
  }
  return parsed.data;
}

/** Invalidate after an admin write so the same isolate serves the update immediately. */
export function invalidateTenant(tenant: TenantConfig): void {
  for (const host of tenant.hostnames) cache.delete(host);
}
