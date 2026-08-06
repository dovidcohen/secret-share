// Regression tests for the 2026-08 security-audit findings.
import { SELF, env, fetchMock } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { clearTenantCache, resolveTenant } from "../src/tenant/registry.js";
import {
  dropBody,
  mailboxId,
  makeTags,
  seedTenant,
  sessionCookie,
  tenantHost,
  toB64url,
  uniqueTenantId,
} from "./helpers.js";

beforeAll(() => {
  fetchMock.activate();
  fetchMock.disableNetConnect();
});
beforeEach(() => clearTenantCache());
afterEach(() => fetchMock.assertNoPendingInterceptors());

// ---------- HIGH: www redirect scoped to the apex only ----------

describe("www redirect scope", () => {
  it("redirects exactly www.shareasecret.io", async () => {
    const res = await SELF.fetch("https://www.shareasecret.io/r", {
      redirect: "manual",
    });
    expect(res.status).toBe(301);
    expect(res.headers.get("Location")).toBe("https://shareasecret.io/r");
  });

  it("never redirects a www. tenant/custom hostname (no cross-origin code leak)", async () => {
    // Would previously have bounced /auth/callback?code=... to a different origin.
    const res = await SELF.fetch(
      "https://www.secrets.customer.example/auth/callback?code=SECRET&state=x",
      { redirect: "manual" },
    );
    expect(res.status).not.toBe(301);
    expect(res.headers.get("Location") ?? "").not.toContain("code=SECRET");
  });
});

// ---------- MED: session versioning / revocation ----------

describe("session versioning", () => {
  it("a session minted under an older sessionVersion is refused", async () => {
    const tenant = await seedTenant({ sessionVersion: 2 });
    const host = tenantHost(tenant);
    const id = mailboxId();
    const t = await makeTags();

    const stale = await SELF.fetch(`https://${host}/api/drops/${id}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Cookie: await sessionCookie(tenant.tenantId, "employee@acme.test", false, 1),
      },
      body: dropBody(t),
    });
    expect(stale.status).toBe(401);

    const current = await SELF.fetch(`https://${host}/api/drops/${id}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Cookie: await sessionCookie(tenant.tenantId, "employee@acme.test", false, 2),
      },
      body: dropBody(t),
    });
    expect(current.status).toBe(201);
  });

  it("revoke-sessions bumps the version and cuts off the caller too", async () => {
    const tenant = await seedTenant({ adminEmails: ["admin@acme.test"] });
    const host = tenantHost(tenant);
    const adminCookie = await sessionCookie(tenant.tenantId, "admin@acme.test", true, 1);

    const before = await SELF.fetch(`https://${host}/api/admin/tenant`, {
      headers: { Cookie: adminCookie },
    });
    expect(before.status).toBe(200);

    const revoke = await SELF.fetch(`https://${host}/api/admin/tenant/revoke-sessions`, {
      method: "POST",
      headers: { Cookie: adminCookie },
    });
    expect(revoke.status).toBe(200);
    expect(((await revoke.json()) as { sessionVersion: number }).sessionVersion).toBe(2);

    clearTenantCache();
    const after = await SELF.fetch(`https://${host}/api/admin/tenant`, {
      headers: { Cookie: adminCookie },
    });
    expect(after.status).toBe(401);
  });

  it("editing authorization policy revokes outstanding sessions", async () => {
    const tenant = await seedTenant({ adminEmails: ["admin@acme.test"] });
    const host = tenantHost(tenant);
    const adminCookie = await sessionCookie(tenant.tenantId, "admin@acme.test", true, 1);

    const edit = await SELF.fetch(`https://${host}/api/admin/tenant`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Cookie: adminCookie },
      body: JSON.stringify({ oidc: { allowedEmailDomains: ["acme.test"] } }),
    });
    expect(edit.status).toBe(200);
    expect(((await edit.json()) as { sessionVersion: number }).sessionVersion).toBe(2);

    // Cosmetic edits do NOT revoke sessions.
    const cosmetic = await SELF.fetch(`https://${host}/api/admin/tenant`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Cookie: await sessionCookie(tenant.tenantId, "admin@acme.test", true, 2),
      },
      body: JSON.stringify({ displayName: "Acme Renamed" }),
    });
    expect(cosmetic.status).toBe(200);
    expect(((await cosmetic.json()) as { sessionVersion: number }).sessionVersion).toBe(2);
  });
});

// ---------- MED: identity claims ----------

async function testRsaKey() {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as {
    n: string;
    e: string;
  };
  return { pair, jwk: { kty: "RSA", kid: "test-key", use: "sig", n: jwk.n, e: jwk.e } };
}

async function signIdToken(
  claims: Record<string, unknown>,
  privateKey: CryptoKey,
): Promise<string> {
  const enc = (o: unknown) => toB64url(new TextEncoder().encode(JSON.stringify(o)));
  const input = `${enc({ alg: "RS256", typ: "JWT", kid: "test-key" })}.${enc(claims)}`;
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(input),
  );
  return `${input}.${toB64url(new Uint8Array(sig))}`;
}

/** Drives login->callback against a mocked IdP; returns the callback response. */
async function runCallback(
  flow: string,
  tenantOidc: Record<string, unknown>,
  idTokenClaims: (nonce: string, clientId: string) => Record<string, unknown>,
) {
  const issuer = `https://idp.test/${flow}/v2.0`;
  const tenant = await seedTenant({
    oidc: { issuer, ...tenantOidc } as never,
  });
  const host = tenantHost(tenant);
  fetchMock
    .get("https://idp.test")
    .intercept({ path: `/${flow}/v2.0/.well-known/openid-configuration` })
    .reply(
      200,
      {
        issuer,
        authorization_endpoint: `https://idp.test/${flow}/authorize`,
        token_endpoint: `https://idp.test/${flow}/token`,
        jwks_uri: `https://idp.test/${flow}/jwks`,
      },
      { headers: { "content-type": "application/json" } },
    );
  const login = await SELF.fetch(`https://${host}/auth/login`, { redirect: "manual" });
  const authorize = new URL(login.headers.get("Location")!);
  const txnCookie = (login.headers.get("Set-Cookie") ?? "").split(";")[0] as string;
  const { pair, jwk } = await testRsaKey();
  const idToken = await signIdToken(
    idTokenClaims(authorize.searchParams.get("nonce")!, tenant.oidc.clientId),
    pair.privateKey,
  );
  fetchMock
    .get("https://idp.test")
    .intercept({ path: `/${flow}/token`, method: "POST" })
    .reply(200, { id_token: idToken }, { headers: { "content-type": "application/json" } });
  fetchMock
    .get("https://idp.test")
    .intercept({ path: `/${flow}/jwks` })
    .reply(200, { keys: [jwk] }, { headers: { "content-type": "application/json" } });
  return SELF.fetch(
    `https://${host}/auth/callback?code=x&state=${encodeURIComponent(
      authorize.searchParams.get("state")!,
    )}`,
    { redirect: "manual", headers: { Cookie: txnCookie } },
  );
}

function baseClaims(nonce: string, clientId: string): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: "", // set by caller via spread order
    aud: clientId,
    sub: "u1",
    iat: now,
    exp: now + 600,
    nonce,
  };
}

describe("identity claim hardening", () => {
  it("rejects an explicitly unverified email", async () => {
    const res = await runCallback("sec-ev", {}, (nonce, clientId) => ({
      ...baseClaims(nonce, clientId),
      iss: "https://idp.test/sec-ev/v2.0",
      email: "someone@acme.test",
      email_verified: false,
    }));
    expect(res.headers.get("Location")).toContain("auth_error=NO_VERIFIED_EMAIL");
  });

  it("ignores preferred_username at non-Entra issuers", async () => {
    // No email claim; preferred_username must NOT stand in at a generic IdP.
    const res = await runCallback("sec-pu", {}, (nonce, clientId) => ({
      ...baseClaims(nonce, clientId),
      iss: "https://idp.test/sec-pu/v2.0",
      preferred_username: "spoofed-admin@acme.test",
    }));
    expect(res.headers.get("Location")).toContain("auth_error=NO_EMAIL_CLAIM");
  });

  it("rejects multi-audience tokens without a matching azp", async () => {
    const res = await runCallback("sec-azp", {}, (nonce, clientId) => ({
      ...baseClaims(nonce, clientId),
      iss: "https://idp.test/sec-azp/v2.0",
      aud: [clientId, "some-other-relying-party"],
      email: "someone@acme.test",
    }));
    expect(res.headers.get("Location")).toContain("auth_error=BAD_AZP");
  });
});

// ---------- LOW: discovery document strictness ----------

describe("OIDC discovery strictness", () => {
  it("rejects discovery documents with plaintext endpoints", async () => {
    const issuer = "https://idp.test/sec-http/v2.0";
    const tenant = await seedTenant({ oidc: { issuer } });
    fetchMock
      .get("https://idp.test")
      .intercept({ path: "/sec-http/v2.0/.well-known/openid-configuration" })
      .reply(
        200,
        {
          issuer,
          authorization_endpoint: "https://idp.test/sec-http/authorize",
          // The token exchange would carry the client secret over plaintext.
          token_endpoint: "http://idp.test/sec-http/token",
          jwks_uri: "https://idp.test/sec-http/jwks",
        },
        { headers: { "content-type": "application/json" } },
      );
    const login = await SELF.fetch(`https://${tenantHost(tenant)}/auth/login`, {
      redirect: "manual",
    });
    expect(login.headers.get("Location")).toContain("auth_error=IDP_UNREACHABLE");
  });
});

// ---------- MED: hostname mapping integrity ----------

describe("hostname mapping integrity", () => {
  it("a host mapping not corroborated by the tenant's hostname list is unknown", async () => {
    const tenant = await seedTenant();
    const rogue = `${uniqueTenantId()}.shareasecret.io`;
    // Stale/mistaken mapping pointing at a tenant that doesn't claim the host.
    await env.TENANTS.put(`host:${rogue}`, JSON.stringify({ tenantId: tenant.tenantId }));
    expect((await resolveTenant(rogue, env)).kind).toBe("unknown");
    // The tenant's real hostname still resolves.
    expect((await resolveTenant(tenantHost(tenant), env)).kind).toBe("tenant");
  });
});
