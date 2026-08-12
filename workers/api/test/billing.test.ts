import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { clearTenantCache } from "../src/tenant/registry.js";
import {
  dropBody,
  mailboxId,
  makeTags,
  seedTenant,
  sessionCookie,
  tenantHost,
} from "./helpers.js";

beforeEach(() => clearTenantCache());

const DAY = 86_400_000;

async function putDrop(host: string, cookie: string, id: string, body: string) {
  return SELF.fetch(`https://${host}/api/drops/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body,
  });
}

/** Signs a webhook body exactly the way Stripe does. */
async function stripeSigned(body: string, opts: { ts?: number; secret?: string } = {}) {
  const ts = opts.ts ?? Math.floor(Date.now() / 1000);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(opts.secret ?? "whsec_test"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${ts}.${body}`),
  );
  const hex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return SELF.fetch("https://shareasecret.io/api/billing/webhook", {
    method: "POST",
    headers: { "Stripe-Signature": `t=${ts},v1=${hex}` },
    body,
  });
}

function subscriptionEvent(
  type: string,
  tenantId: string,
  status: string,
  priceId = "price_biz_m",
  extra: Record<string, unknown> = {},
) {
  return JSON.stringify({
    type,
    data: {
      object: {
        id: "sub_123",
        status,
        customer: "cus_123",
        metadata: { tenantId },
        items: {
          data: [{ price: { id: priceId }, current_period_end: 1_900_000_000 }],
        },
        ...extra,
      },
    },
  });
}

describe("entitlement gating", () => {
  it("blocks sending on a canceled tenant with 402; claiming stays open", async () => {
    const active = await seedTenant({
      billing: { plan: "team", status: "active" },
    });
    const host = tenantHost(active);
    const cookie = await sessionCookie(active.tenantId);
    const id = mailboxId();
    const t = await makeTags();
    expect((await putDrop(host, cookie, id, dropBody(t))).status).toBe(201);

    // The org's subscription dies with a secret still parked.
    await env.TENANTS.put(
      `tenant:${active.tenantId}`,
      JSON.stringify({ ...active, billing: { plan: "team", status: "canceled" } }),
    );
    clearTenantCache();

    const denied = await putDrop(host, cookie, mailboxId(), dropBody(await makeTags()));
    expect(denied.status).toBe(402);
    expect(((await denied.json()) as { error: string }).error).toBe("PLAN_INACTIVE");

    // Grant minting is sender-side too.
    const grant = await SELF.fetch(`https://${host}/api/grants`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify({ mailboxId: mailboxId() }),
    });
    expect(grant.status).toBe(402);

    // The already-sent secret must still be claimable — no session, lapsed org.
    const claim = await SELF.fetch(`https://${host}/api/drops/${id}/claim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ claimTag: t.claimTag }),
    });
    expect(claim.status).toBe(200);
  });

  it("blocks an expired trial, allows a running one", async () => {
    const expired = await seedTenant({
      billing: { plan: "trial", status: "trialing", trialEndsAt: Date.now() - DAY },
    });
    const cookieExpired = await sessionCookie(expired.tenantId);
    const denied = await putDrop(
      tenantHost(expired),
      cookieExpired,
      mailboxId(),
      dropBody(await makeTags()),
    );
    expect(denied.status).toBe(402);
    expect(((await denied.json()) as { reason: string }).reason).toBe("trial_expired");

    const running = await seedTenant({
      billing: { plan: "trial", status: "trialing", trialEndsAt: Date.now() + 13 * DAY },
    });
    const cookieRunning = await sessionCookie(running.tenantId);
    const ok = await putDrop(
      tenantHost(running),
      cookieRunning,
      mailboxId(),
      dropBody(await makeTags()),
    );
    expect(ok.status).toBe(201);
  });

  it("legacy tenants without a billing block stay fully entitled", async () => {
    const legacy = await seedTenant(); // no billing key at all
    const cookie = await sessionCookie(legacy.tenantId);
    const res = await putDrop(
      tenantHost(legacy),
      cookie,
      mailboxId(),
      dropBody(await makeTags()),
    );
    expect(res.status).toBe(201);
  });
});

describe("stripe webhook", () => {
  it("rejects a missing, wrong, or stale signature", async () => {
    const body = subscriptionEvent("customer.subscription.updated", "nobody", "active");
    const unsigned = await SELF.fetch("https://shareasecret.io/api/billing/webhook", {
      method: "POST",
      body,
    });
    expect(unsigned.status).toBe(400);

    const wrongKey = await stripeSigned(body, { secret: "whsec_wrong" });
    expect(wrongKey.status).toBe(400);

    const stale = await stripeSigned(body, {
      ts: Math.floor(Date.now() / 1000) - 3600,
    });
    expect(stale.status).toBe(400);
  });

  it("applies the subscription lifecycle to the tenant config", async () => {
    const tenant = await seedTenant({
      billing: { plan: "trial", status: "trialing", trialEndsAt: Date.now() + DAY },
    });

    // Payment lands: plan comes from the price id, status goes active.
    const paid = await stripeSigned(
      subscriptionEvent("customer.subscription.created", tenant.tenantId, "active", "price_biz_m"),
    );
    expect(paid.status).toBe(200);
    let stored = (await env.TENANTS.get(`tenant:${tenant.tenantId}`, "json")) as {
      billing: Record<string, unknown>;
    };
    expect(stored.billing).toMatchObject({
      plan: "business",
      status: "active",
      stripeCustomerId: "cus_123",
      stripeSubscriptionId: "sub_123",
      currentPeriodEnd: 1_900_000_000_000,
    });

    // Portal cancel = end-of-period: still active + entitled, flag recorded.
    const winding = await stripeSigned(
      subscriptionEvent("customer.subscription.updated", tenant.tenantId, "active", "price_biz_m", {
        cancel_at_period_end: true,
      }),
    );
    expect(winding.status).toBe(200);
    stored = (await env.TENANTS.get(`tenant:${tenant.tenantId}`, "json")) as typeof stored;
    expect(stored.billing).toMatchObject({ status: "active", cancelAtPeriodEnd: true });

    // Renewing via the portal clears the flag again.
    const renewed = await stripeSigned(
      subscriptionEvent("customer.subscription.updated", tenant.tenantId, "active"),
    );
    expect(renewed.status).toBe(200);
    stored = (await env.TENANTS.get(`tenant:${tenant.tenantId}`, "json")) as typeof stored;
    expect(stored.billing.cancelAtPeriodEnd).toBeUndefined();

    // Cancellation blocks sending immediately.
    const gone = await stripeSigned(
      subscriptionEvent("customer.subscription.deleted", tenant.tenantId, "canceled"),
    );
    expect(gone.status).toBe(200);
    stored = (await env.TENANTS.get(`tenant:${tenant.tenantId}`, "json")) as typeof stored;
    expect(stored.billing).toMatchObject({ plan: "business", status: "canceled" });

    clearTenantCache();
    const cookie = await sessionCookie(tenant.tenantId);
    const denied = await putDrop(
      tenantHost(tenant),
      cookie,
      mailboxId(),
      dropBody(await makeTags()),
    );
    expect(denied.status).toBe(402);
  });

  it("ignores events for unknown tenants without failing", async () => {
    const res = await stripeSigned(
      subscriptionEvent("customer.subscription.updated", "no-such-tenant", "active"),
    );
    expect(res.status).toBe(200);
  });
});

describe("admin billing surface", () => {
  it("summarizes the plan for admins and hides Stripe ids", async () => {
    const tenant = await seedTenant({
      billing: {
        plan: "team",
        status: "active",
        stripeCustomerId: "cus_123",
        stripeSubscriptionId: "sub_123",
      },
    });
    const cookie = await sessionCookie(tenant.tenantId, "admin@acme.test", true);
    const res = await SELF.fetch(`https://${tenantHost(tenant)}/api/admin/billing`, {
      headers: { Cookie: cookie },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ plan: "team", status: "active", sendingBlocked: null });
    expect(JSON.stringify(body)).not.toContain("cus_123");
    expect(JSON.stringify(body)).not.toContain("sub_123");
  });

  it("requires an admin session", async () => {
    const tenant = await seedTenant({
      billing: { plan: "team", status: "active" },
    });
    const employee = await sessionCookie(tenant.tenantId); // not an admin
    const res = await SELF.fetch(`https://${tenantHost(tenant)}/api/admin/billing`, {
      headers: { Cookie: employee },
    });
    expect(res.status).toBe(403);
  });
});
