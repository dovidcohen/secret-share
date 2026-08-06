import { SELF } from "cloudflare:test";
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

async function mint(host: string, cookie: string | null, id: string) {
  return SELF.fetch(`https://${host}/api/grants`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(cookie ? { Cookie: cookie } : {}),
    },
    body: JSON.stringify({ mailboxId: id }),
  });
}

async function guestPut(host: string, id: string, grant: string, body: string) {
  return SELF.fetch(`https://${host}/api/drops/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Guest-Grant": grant },
    body,
  });
}

describe("guest-send grants", () => {
  it("full loop: mint -> guest PUT -> employee claim; reuse refused", async () => {
    const tenant = await seedTenant();
    const host = tenantHost(tenant);
    const cookie = await sessionCookie(tenant.tenantId);
    const id = mailboxId();
    const t = await makeTags();

    expect((await mint(host, null, id)).status).toBe(401);

    const minted = await mint(host, cookie, id);
    expect(minted.status).toBe(201);
    const { grant, expiresAt } = (await minted.json()) as {
      grant: string;
      expiresAt: number;
    };
    expect(grant).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(expiresAt).toBeGreaterThan(Date.now());

    // Only one outstanding grant per mailbox.
    expect((await mint(host, cookie, id)).status).toBe(409);

    // Guest parks without any session.
    const put = await guestPut(host, id, grant, dropBody(t));
    expect(put.status).toBe(201);

    // The same link a second time: "used", not a bare conflict.
    const reuse = await guestPut(host, id, grant, dropBody(await makeTags()));
    expect(reuse.status).toBe(403);
    expect(((await reuse.json()) as { error: string }).error).toBe("GRANT_USED");

    // Employee claims with the code they kept — no session needed.
    const claim = await SELF.fetch(`https://${host}/api/drops/${id}/claim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ claimTag: t.claimTag }),
    });
    expect(claim.status).toBe(200);

    // Even after the claim burns the drop, the link reads as used.
    const afterClaim = await guestPut(host, id, grant, dropBody(await makeTags()));
    expect(afterClaim.status).toBe(403);
    expect(((await afterClaim.json()) as { error: string }).error).toBe("GRANT_USED");
  });

  it("wrong tokens burn the grant after 5 attempts", async () => {
    const tenant = await seedTenant();
    const host = tenantHost(tenant);
    const id = mailboxId();
    const minted = await mint(host, await sessionCookie(tenant.tenantId), id);
    const { grant } = (await minted.json()) as { grant: string };

    const wrong = grant.slice(0, 42) + (grant.endsWith("A") ? "B" : "A");
    for (let i = 0; i < 5; i++) {
      const res = await guestPut(host, id, wrong, dropBody(await makeTags()));
      expect(res.status).toBe(403);
      expect(((await res.json()) as { error: string }).error).toBe("BAD_GRANT");
    }
    // Burned: even the real token is now refused.
    const real = await guestPut(host, id, grant, dropBody(await makeTags()));
    expect(real.status).toBe(403);
    expect(((await real.json()) as { error: string }).error).toBe("GRANT_EXPIRED");
  });

  it("a grant for a mailbox that never had one reads as expired", async () => {
    const tenant = await seedTenant();
    const res = await guestPut(
      tenantHost(tenant),
      mailboxId(),
      "A".repeat(43),
      dropBody(await makeTags()),
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("GRANT_EXPIRED");
  });

  it("cannot mint a grant for an occupied mailbox", async () => {
    const tenant = await seedTenant();
    const host = tenantHost(tenant);
    const cookie = await sessionCookie(tenant.tenantId);
    const id = mailboxId();
    await SELF.fetch(`https://${host}/api/drops/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: dropBody(await makeTags()),
    });
    expect((await mint(host, cookie, id)).status).toBe(409);
  });

  it("respects the guestGrants feature flag", async () => {
    const tenant = await seedTenant({ features: { guestGrants: false } });
    const res = await mint(
      tenantHost(tenant),
      await sessionCookie(tenant.tenantId),
      mailboxId(),
    );
    expect(res.status).toBe(404);
  });
});
