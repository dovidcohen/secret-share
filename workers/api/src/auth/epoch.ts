/**
 * Session-epoch access. The authoritative value lives in the per-tenant DO
 * (strongly consistent; see usagedo.ts); a short per-isolate cache keeps the
 * request path from paying a DO round-trip every time. The cache TTL is the
 * upper bound on revocation latency per isolate — 30 s, versus the hours a
 * cookie would otherwise remain valid.
 */

import { stubFetch } from "../stubfetch.js";

const EPOCH_CACHE_TTL_MS = 30_000;

const cache = new Map<string, { epoch: string; freshUntil: number }>();

/** Test hook. */
export function clearEpochCache(): void {
  cache.clear();
}

async function fetchEpoch(env: Env, tenantId: string, bump: boolean): Promise<string> {
  const stub = env.USAGE.get(env.USAGE.idFromName(`usage:${tenantId}`));
  const res = await stubFetch(
    stub,
    bump ? "https://usage/internal/epoch-bump" : "https://usage/internal/epoch",
    bump ? { method: "POST" } : undefined,
  );
  if (!res.ok) throw new Error(`epoch fetch failed (${res.status})`);
  const { epoch } = (await res.json()) as { epoch: string };
  return epoch;
}

/** Cached read for the request path; `fresh` bypasses the cache (login mint). */
export async function getSessionEpoch(
  env: Env,
  tenantId: string,
  opts: { fresh?: boolean } = {},
): Promise<string> {
  if (!opts.fresh) {
    const cached = cache.get(tenantId);
    if (cached && cached.freshUntil > Date.now()) return cached.epoch;
  }
  const epoch = await fetchEpoch(env, tenantId, false);
  cache.set(tenantId, { epoch, freshUntil: Date.now() + EPOCH_CACHE_TTL_MS });
  return epoch;
}

/** Revokes every outstanding session for the tenant; returns the new epoch. */
export async function bumpSessionEpoch(env: Env, tenantId: string): Promise<string> {
  const epoch = await fetchEpoch(env, tenantId, true);
  cache.set(tenantId, { epoch, freshUntil: Date.now() + EPOCH_CACHE_TTL_MS });
  return epoch;
}
