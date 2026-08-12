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

/**
 * KV read that never lets an error read as "key absent". Under
 * vitest/miniflare KV is backed by a Durable Object that can throw a
 * retryable "invalidated" transient mid-run (production KV can blip too);
 * mapped to null, that error would — in dev — silently misroute a tenant
 * host to the public product. Retries, then propagates a real failure.
 */
async function kvGetJson(env: Env, key: string, cacheTtl?: number): Promise<unknown> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await env.TENANTS.get(
        key,
        cacheTtl ? { type: "json", cacheTtl } : { type: "json" },
      );
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError;
}

async function lookup(hostname: string, env: Env): Promise<TenantResolution> {
  const hostEntry = await kvGetJson(env, `host:${hostname}`, KV_CACHE_TTL_S);
  const tenantId = (hostEntry as { tenantId?: string } | null)?.tenantId;
  if (!tenantId) {
    return env.ENVIRONMENT === "dev" ? { kind: "public" } : { kind: "unknown" };
  }

  const tenant = await loadTenant(tenantId, env);
  if (!tenant) return { kind: "unknown" };
  // A host: mapping must be corroborated by the tenant's own hostname list —
  // a stale or mistakenly written mapping must not route a domain to a
  // tenant that doesn't claim it.
  if (!tenant.hostnames.includes(hostname)) return { kind: "unknown" };
  return { kind: "tenant", tenant };
}

/** Direct tenant load (admin API re-reads config on every request to pick up edits). */
export async function loadTenant(
  tenantId: string,
  env: Env,
  opts: { fresh?: boolean } = {},
): Promise<TenantConfig | null> {
  const raw = await kvGetJson(
    env,
    `tenant:${tenantId}`,
    opts.fresh ? undefined : KV_CACHE_TTL_S,
  );
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

/** Persist a config (admin edits, billing webhook) and drop the stale cache copy. */
export async function saveTenant(tenant: TenantConfig, env: Env): Promise<void> {
  tenant.updatedAt = Date.now();
  await env.TENANTS.put(`tenant:${tenant.tenantId}`, JSON.stringify(tenant));
  invalidateTenant(tenant);
}
