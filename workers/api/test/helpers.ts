// Shared plumbing for tenant-aware tests: KV seeding and session cookies.
import { env } from "cloudflare:test";
import { mintSessionCookie } from "../src/auth/session.js";
import type { TenantConfig } from "../src/tenant/schema.js";

let counter = 0;

export function uniqueTenantId(): string {
  // isolatedStorage is off (Windows EBUSY) — unique ids keep tests independent.
  return `t${Date.now().toString(36)}${(counter++).toString(36)}x`;
}

export function tenantHost(tenant: TenantConfig): string {
  return tenant.hostnames[0] as string;
}

export async function seedTenant(
  overrides: {
    oidc?: Partial<TenantConfig["oidc"]>;
    features?: Partial<TenantConfig["features"]>;
    theme?: Partial<TenantConfig["theme"]>;
    adminEmails?: string[];
    displayName?: string;
    footerText?: string;
  } = {},
): Promise<TenantConfig> {
  const tenantId = uniqueTenantId();
  const now = Date.now();
  const tenant: TenantConfig = {
    v: 1,
    tenantId,
    displayName: overrides.displayName ?? "Acme Corp",
    hostnames: [`${tenantId}.shareasecret.io`],
    theme: { logoVersion: 0, ...overrides.theme },
    oidc: {
      issuer: "https://idp.test/v2.0",
      clientId: "test-client",
      clientAuth: "pkce_public",
      scopes: "openid profile email",
      allowedEmailDomains: [],
      allowedGroups: [],
      ...overrides.oidc,
    },
    adminEmails: overrides.adminEmails ?? ["admin@acme.test"],
    features: { guestGrants: true, liveSend: true, ...overrides.features },
    createdAt: now,
    updatedAt: now,
  };
  await env.TENANTS.put(`tenant:${tenantId}`, JSON.stringify(tenant));
  await env.TENANTS.put(
    `host:${tenantHost(tenant)}`,
    JSON.stringify({ tenantId }),
  );
  return tenant;
}

/** `Cookie:` header value for a signed-in user of the given tenant. */
export async function sessionCookie(
  tenantId: string,
  email = "employee@acme.test",
  adm = false,
): Promise<string> {
  const setCookie = await mintSessionCookie(
    { tid: tenantId, sub: "test-sub", email, adm },
    env,
  );
  return setCookie.split(";")[0] as string;
}

let mailboxCounter = 0;
export function mailboxId(): string {
  return `T${(mailboxCounter++).toString(36).toUpperCase().padStart(3, "0")}${Date.now()
    .toString(36)
    .toUpperCase()
    .slice(-4)}`
    .replace(/[ILOU]/g, "X")
    .slice(0, 8)
    .padEnd(8, "0");
}

export function toB64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function makeTags() {
  const claim = crypto.getRandomValues(new Uint8Array(32));
  const sender = crypto.getRandomValues(new Uint8Array(32));
  const h = async (b: Uint8Array) =>
    toB64url(new Uint8Array(await crypto.subtle.digest("SHA-256", b)));
  return {
    claimTag: toB64url(claim),
    senderTag: toB64url(sender),
    claimTagHash: await h(claim),
    senderTagHash: await h(sender),
  };
}

export function dropBody(t: Awaited<ReturnType<typeof makeTags>>): string {
  return JSON.stringify({
    claimTagHash: t.claimTagHash,
    senderTagHash: t.senderTagHash,
    ciphertext: "AQIDBAUG",
    ttlSeconds: 3600,
  });
}
