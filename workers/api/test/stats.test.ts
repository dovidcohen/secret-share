import { SELF, env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { mailboxId, makeTags, dropBody } from "./helpers.js";
import { computePublicDigest } from "../src/usage.js";

const APEX = "https://shareasecret.io";

async function stats(token: string | null) {
  return SELF.fetch(`${APEX}/api/stats?from=2000-01-01&to=2099-01-01`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
}

/** waitUntil metering lands just after the response; poll briefly. */
async function publicCount(kind: string): Promise<number> {
  for (let i = 0; i < 20; i++) {
    const res = await stats("test-stats-token");
    const { days } = (await res.json()) as { days: { kind: string; count: number }[] };
    const total = days.filter((d) => d.kind === kind).reduce((n, d) => n + d.count, 0);
    if (total > 0) return total;
    await new Promise((r) => setTimeout(r, 25));
  }
  return 0;
}

describe("public stats endpoint", () => {
  it("requires the bearer token", async () => {
    expect((await stats(null)).status).toBe(401);
    expect((await stats("wrong")).status).toBe(401);
    expect((await stats("test-stats-token")).status).toBe(200);
  });

  it("counts a real public send and claim", async () => {
    const before = await publicCount("drop_created").catch(() => 0);
    const id = mailboxId();
    const t = await makeTags();

    const put = await SELF.fetch(`${APEX}/api/drops/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: dropBody(t),
    });
    expect(put.status).toBe(201);

    const claim = await SELF.fetch(`${APEX}/api/drops/${id}/claim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ claimTag: t.claimTag }),
    });
    expect(claim.status).toBe(200);

    expect(await publicCount("drop_created")).toBeGreaterThan(before);
    expect(await publicCount("drop_claimed")).toBeGreaterThan(0);
  });
});

describe("daily digest", () => {
  it("rolls today's public activity into the yesterday/week figures", async () => {
    // A real public send lands under today's date...
    const id = mailboxId();
    const t = await makeTags();
    await SELF.fetch(`${APEX}/api/drops/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: dropBody(t),
    });
    await publicCount("drop_created"); // let the fire-and-forget write settle

    // ...so viewed from "tomorrow", it counts as yesterday and in the week.
    const digest = await computePublicDigest(env, Date.now() + 86_400_000);
    expect(digest.sentYesterday).toBeGreaterThan(0);
    expect(digest.sentWeek).toBeGreaterThanOrEqual(digest.sentYesterday);
  });
});
