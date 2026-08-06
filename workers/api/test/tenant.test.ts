import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { clearTenantCache, resolveTenant } from "../src/tenant/registry.js";
import {
  dropBody,
  mailboxId,
  makeTags,
  seedTenant,
  tenantHost,
  uniqueTenantId,
} from "./helpers.js";

beforeEach(() => clearTenantCache());

describe("tenant resolution", () => {
  it("apex hosts are public without touching KV", async () => {
    expect(await resolveTenant("shareasecret.io", env)).toEqual({ kind: "public" });
    expect(await resolveTenant("www.shareasecret.io", env)).toEqual({ kind: "public" });
  });

  it("unknown hosts fall back to public in dev but 404 in production", async () => {
    expect((await resolveTenant("nobody.shareasecret.io", env)).kind).toBe("public");
    const prodEnv = { ...env, ENVIRONMENT: undefined } as Env;
    expect((await resolveTenant("nobody2.shareasecret.io", prodEnv)).kind).toBe("unknown");
  });

  it("resolves a provisioned tenant by hostname", async () => {
    const tenant = await seedTenant();
    const got = await resolveTenant(tenantHost(tenant), env);
    expect(got.kind).toBe("tenant");
    if (got.kind === "tenant") expect(got.tenant.tenantId).toBe(tenant.tenantId);
  });

  it("treats malformed tenant config as unknown", async () => {
    const id = uniqueTenantId();
    await env.TENANTS.put(`tenant:${id}`, JSON.stringify({ not: "a tenant" }));
    await env.TENANTS.put(`host:${id}.shareasecret.io`, JSON.stringify({ tenantId: id }));
    expect((await resolveTenant(`${id}.shareasecret.io`, env)).kind).toBe("unknown");
  });
});

describe("public behavior is unchanged", () => {
  it("drop lifecycle still works on the apex, even with a spoofed auth header", async () => {
    const id = mailboxId();
    const t = await makeTags();
    const res = await SELF.fetch(`https://shareasecret.io/api/drops/${id}`, {
      method: "PUT",
      // The Worker must overwrite this before the DO sees it.
      headers: { "Content-Type": "application/json", "x-ss-auth": "grant AAAA" },
      body: dropBody(t),
    });
    expect(res.status).toBe(201);

    const claim = await SELF.fetch(`https://shareasecret.io/api/drops/${id}/claim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ claimTag: t.claimTag }),
    });
    expect(claim.status).toBe(200);
  });

  it("auth endpoints do not exist on the apex (path falls through to the SPA)", async () => {
    const res = await SELF.fetch("https://shareasecret.io/auth/me");
    // SPA fallback serves HTML — the point is there is no JSON auth API here.
    expect(res.headers.get("Content-Type") ?? "").toContain("text/html");
  });

  it("grant minting does not exist on the apex", async () => {
    const res = await SELF.fetch("https://shareasecret.io/api/grants", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mailboxId: mailboxId() }),
    });
    expect(res.status).toBe(404);
  });
});

describe("tenant logo", () => {
  it("serves uploaded bytes with the stored content type", async () => {
    const tenant = await seedTenant({ theme: { logoVersion: 3 } });
    await env.TENANTS.put(`logo:${tenant.tenantId}`, new Uint8Array([1, 2, 3]).buffer, {
      metadata: { contentType: "image/webp" },
    });
    const res = await SELF.fetch(`https://${tenantHost(tenant)}/api/tenant/logo`);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/webp");
    expect(res.headers.get("ETag")).toBe('"v3"');
  });

  it("404s when no logo was uploaded", async () => {
    const tenant = await seedTenant();
    const res = await SELF.fetch(`https://${tenantHost(tenant)}/api/tenant/logo`);
    expect(res.status).toBe(404);
  });
});
