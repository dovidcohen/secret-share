import { SELF, env, fetchMock } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { clearTenantCache } from "../src/tenant/registry.js";
import { mintSessionCookie, readSession } from "../src/auth/session.js";
import {
  dropBody,
  mailboxId,
  makeTags,
  seedTenant,
  sessionCookie,
  tenantHost,
  toB64url,
} from "./helpers.js";

beforeAll(() => {
  fetchMock.activate();
  fetchMock.disableNetConnect();
});
beforeEach(() => clearTenantCache());
afterEach(() => fetchMock.assertNoPendingInterceptors());

// ---------- session cookie codec ----------

describe("session cookies", () => {
  function requestWithCookie(cookie: string): Request {
    return new Request("https://t.shareasecret.io/auth/me", {
      headers: { Cookie: cookie },
    });
  }

  it("round-trips a session", async () => {
    const setCookie = await mintSessionCookie(
      { tid: "acme", sub: "s1", email: "a@b.co", adm: true, epo: "e1" },
      env,
    );
    const cookie = setCookie.split(";")[0] as string;
    const session = await readSession(requestWithCookie(cookie), "acme", env);
    expect(session?.email).toBe("a@b.co");
    expect(session?.adm).toBe(true);
  });

  it("rejects tampered tokens and tenant mismatches", async () => {
    const setCookie = await mintSessionCookie(
      { tid: "acme", sub: "s1", email: "a@b.co", adm: false, epo: "e1" },
      env,
    );
    const cookie = setCookie.split(";")[0] as string;
    // wrong tenant: the MAC key is HKDF'd per tenant
    expect(await readSession(requestWithCookie(cookie), "other", env)).toBeNull();
    // flipped payload byte
    const [name, token] = cookie.split("=") as [string, string];
    const tampered = `${name}=${token.slice(0, 10)}${token[10] === "A" ? "B" : "A"}${token.slice(11)}`;
    expect(await readSession(requestWithCookie(tampered), "acme", env)).toBeNull();
  });
});

// ---------- id_token validation via full login flow ----------

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

describe("OIDC login flow", () => {
  it("login -> IdP -> callback mints a session; /auth/me reflects it", async () => {
    // Distinct issuer per test: discovery/JWKS are KV-cached by issuer hash.
    const issuer = "https://idp.test/flow1/v2.0";
    const tenant = await seedTenant({
      oidc: { issuer, allowedEmailDomains: ["acme.test"] },
    });
    const host = tenantHost(tenant);

    fetchMock
      .get("https://idp.test")
      .intercept({ path: "/flow1/v2.0/.well-known/openid-configuration" })
      .reply(
        200,
        {
          issuer,
          authorization_endpoint: "https://idp.test/flow1/authorize",
          token_endpoint: "https://idp.test/flow1/token",
          jwks_uri: "https://idp.test/flow1/jwks",
        },
        { headers: { "content-type": "application/json" } },
      );

    // 1) /auth/login parks the txn cookie and redirects to the IdP
    const login = await SELF.fetch(
      `https://${host}/auth/login?return_to=/request`,
      { redirect: "manual" },
    );
    expect(login.status).toBe(302);
    const authorize = new URL(login.headers.get("Location")!);
    expect(authorize.origin + authorize.pathname).toBe("https://idp.test/flow1/authorize");
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    const state = authorize.searchParams.get("state")!;
    const nonce = authorize.searchParams.get("nonce")!;
    const txnCookie = (login.headers.get("Set-Cookie") ?? "").split(";")[0] as string;
    expect(txnCookie.startsWith("ss_txn=")).toBe(true);

    // 2) IdP "authenticates" and calls back with a code
    const { pair, jwk } = await testRsaKey();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signIdToken(
      {
        iss: issuer,
        aud: tenant.oidc.clientId,
        sub: "user-1",
        email: "Employee@ACME.test",
        email_verified: true,
        name: "Test Employee",
        iat: now,
        exp: now + 600,
        nonce,
      },
      pair.privateKey,
    );
    fetchMock
      .get("https://idp.test")
      .intercept({ path: "/flow1/token", method: "POST" })
      .reply(200, { id_token: idToken }, { headers: { "content-type": "application/json" } });
    fetchMock
      .get("https://idp.test")
      .intercept({ path: "/flow1/jwks" })
      .reply(200, { keys: [jwk] }, { headers: { "content-type": "application/json" } });

    const callback = await SELF.fetch(
      `https://${host}/auth/callback?code=fake-code&state=${encodeURIComponent(state)}`,
      { redirect: "manual", headers: { Cookie: txnCookie } },
    );
    expect(callback.status).toBe(302);
    expect(callback.headers.get("Location")).toBe(`https://${host}/request`);
    const setCookies = callback.headers.getSetCookie();
    const session = setCookies.find((c) => c.startsWith("ss_session="))!;
    expect(session).toBeTruthy();

    // 3) /auth/me sees the session
    const me = await SELF.fetch(`https://${host}/auth/me`, {
      headers: { Cookie: session.split(";")[0] as string },
    });
    expect(me.status).toBe(200);
    const body = (await me.json()) as { email: string; isAdmin: boolean };
    expect(body.email).toBe("employee@acme.test");
    expect(body.isAdmin).toBe(false);
  });

  it("rejects a callback whose state does not match the txn cookie", async () => {
    const issuer = "https://idp.test/flow2/v2.0";
    const tenant = await seedTenant({ oidc: { issuer } });
    const host = tenantHost(tenant);

    fetchMock
      .get("https://idp.test")
      .intercept({ path: "/flow2/v2.0/.well-known/openid-configuration" })
      .reply(
        200,
        {
          issuer,
          authorization_endpoint: "https://idp.test/flow2/authorize",
          token_endpoint: "https://idp.test/flow2/token",
          jwks_uri: "https://idp.test/flow2/jwks",
        },
        { headers: { "content-type": "application/json" } },
      );

    const login = await SELF.fetch(`https://${host}/auth/login`, { redirect: "manual" });
    const txnCookie = (login.headers.get("Set-Cookie") ?? "").split(";")[0] as string;
    const callback = await SELF.fetch(
      `https://${host}/auth/callback?code=x&state=WRONG`,
      { redirect: "manual", headers: { Cookie: txnCookie } },
    );
    expect(callback.status).toBe(302);
    expect(callback.headers.get("Location")).toContain("auth_error=BAD_STATE");
  });

  it("enforces the allowed email domain", async () => {
    const issuer = "https://idp.test/flow3/v2.0";
    const tenant = await seedTenant({
      oidc: { issuer, allowedEmailDomains: ["acme.test"] },
    });
    const host = tenantHost(tenant);

    fetchMock
      .get("https://idp.test")
      .intercept({ path: "/flow3/v2.0/.well-known/openid-configuration" })
      .reply(
        200,
        {
          issuer,
          authorization_endpoint: "https://idp.test/flow3/authorize",
          token_endpoint: "https://idp.test/flow3/token",
          jwks_uri: "https://idp.test/flow3/jwks",
        },
        { headers: { "content-type": "application/json" } },
      );

    const login = await SELF.fetch(`https://${host}/auth/login`, { redirect: "manual" });
    const authorize = new URL(login.headers.get("Location")!);
    const txnCookie = (login.headers.get("Set-Cookie") ?? "").split(";")[0] as string;

    const { pair, jwk } = await testRsaKey();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signIdToken(
      {
        iss: issuer,
        aud: tenant.oidc.clientId,
        sub: "user-2",
        email: "outsider@evil.test",
        email_verified: true,
        iat: now,
        exp: now + 600,
        nonce: authorize.searchParams.get("nonce"),
      },
      pair.privateKey,
    );
    fetchMock
      .get("https://idp.test")
      .intercept({ path: "/flow3/token", method: "POST" })
      .reply(200, { id_token: idToken }, { headers: { "content-type": "application/json" } });
    fetchMock
      .get("https://idp.test")
      .intercept({ path: "/flow3/jwks" })
      .reply(200, { keys: [jwk] }, { headers: { "content-type": "application/json" } });

    const callback = await SELF.fetch(
      `https://${host}/auth/callback?code=x&state=${encodeURIComponent(
        authorize.searchParams.get("state")!,
      )}`,
      { redirect: "manual", headers: { Cookie: txnCookie } },
    );
    expect(callback.headers.get("Location")).toContain("auth_error=DOMAIN_NOT_ALLOWED");
  });
});

// ---------- gating ----------

describe("tenant host gating", () => {
  it("PUT requires a session (401 bare, 201 with cookie)", async () => {
    const tenant = await seedTenant();
    const host = tenantHost(tenant);
    const id = mailboxId();
    const t = await makeTags();

    const bare = await SELF.fetch(`https://${host}/api/drops/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: dropBody(t),
    });
    expect(bare.status).toBe(401);
    expect(((await bare.json()) as { error: string }).error).toBe("AUTH_REQUIRED");

    // Spoofed internal header must not help.
    const spoofed = await SELF.fetch(`https://${host}/api/drops/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", "x-ss-auth": "session" },
      body: dropBody(t),
    });
    expect(spoofed.status).toBe(401);

    const authed = await SELF.fetch(`https://${host}/api/drops/${id}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Cookie: await sessionCookie(tenant.tenantId),
      },
      body: dropBody(t),
    });
    expect(authed.status).toBe(201);
  });

  it("claim and revoke stay open; receiver WS open; sender WS gated", async () => {
    const tenant = await seedTenant();
    const host = tenantHost(tenant);
    const id = mailboxId();
    const t = await makeTags();
    const cookie = await sessionCookie(tenant.tenantId);

    await SELF.fetch(`https://${host}/api/drops/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: dropBody(t),
    });

    const senderWs = await SELF.fetch(`https://${host}/ws/${id}?role=sender`, {
      headers: { Upgrade: "websocket" },
    });
    expect(senderWs.status).toBe(401);

    const senderWsAuthed = await SELF.fetch(`https://${host}/ws/${id}?role=sender`, {
      headers: { Upgrade: "websocket", Cookie: cookie },
    });
    expect(senderWsAuthed.status).toBe(101);
    senderWsAuthed.webSocket?.accept();
    senderWsAuthed.webSocket?.close();

    const receiverWs = await SELF.fetch(`https://${host}/ws/${id}?role=receiver`, {
      headers: { Upgrade: "websocket" },
    });
    expect(receiverWs.status).toBe(101);
    receiverWs.webSocket?.accept();
    receiverWs.webSocket?.close();

    const claim = await SELF.fetch(`https://${host}/api/drops/${id}/claim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ claimTag: t.claimTag }),
    });
    expect(claim.status).toBe(200);
  });

  it("tenant mailboxes are namespaced away from the public pool", async () => {
    const tenant = await seedTenant();
    const host = tenantHost(tenant);
    const id = mailboxId();
    const t = await makeTags();

    // Park on the tenant host…
    await SELF.fetch(`https://${host}/api/drops/${id}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Cookie: await sessionCookie(tenant.tenantId),
      },
      body: dropBody(t),
    });

    // …the public pool must have nothing under the same mailbox id.
    const publicClaim = await SELF.fetch(`https://shareasecret.io/api/drops/${id}/claim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ claimTag: t.claimTag }),
    });
    expect(publicClaim.status).toBe(404);
  });
});
