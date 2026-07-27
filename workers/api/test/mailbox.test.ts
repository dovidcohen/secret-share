// In-process integration tests via @cloudflare/vitest-pool-workers.
// Mirrors the manual scripts (test/manual-drops.mjs, test/manual-ws.mjs) so CI
// can cover the DO without a running `wrangler dev`.
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const tagBytes = () => crypto.getRandomValues(new Uint8Array(32));

function toB64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function makeTags() {
  const claim = tagBytes();
  const sender = tagBytes();
  const h = async (b: Uint8Array) =>
    toB64url(new Uint8Array(await crypto.subtle.digest("SHA-256", b)));
  return {
    claimTag: toB64url(claim),
    senderTag: toB64url(sender),
    claimTagHash: await h(claim),
    senderTagHash: await h(sender),
  };
}

let counter = 0;
function mailboxId(): string {
  // unique per test run; valid crockford
  return `T${(counter++).toString(36).toUpperCase().padStart(3, "0")}${Date.now()
    .toString(36)
    .toUpperCase()
    .slice(-4)}`
    .replace(/[ILOU]/g, "X")
    .slice(0, 8)
    .padEnd(8, "0");
}

async function create(id: string, t: Awaited<ReturnType<typeof makeTags>>, ttlSeconds = 3600) {
  return SELF.fetch(`https://x/api/drops/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      claimTagHash: t.claimTagHash,
      senderTagHash: t.senderTagHash,
      ciphertext: "AQIDBAUG",
      ttlSeconds,
    }),
  });
}

async function claim(id: string, claimTag: string) {
  return SELF.fetch(`https://x/api/drops/${id}/claim`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ claimTag }),
  });
}

describe("drop lifecycle", () => {
  it("create -> claim -> re-claim GONE", async () => {
    const id = mailboxId();
    const t = await makeTags();
    expect((await create(id, t)).status).toBe(201);
    expect((await create(id, t)).status).toBe(409);

    const res = await claim(id, t.claimTag);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { ciphertext: string }).ciphertext).toBe("AQIDBAUG");

    expect((await claim(id, t.claimTag)).status).toBe(410);
  });

  it("burns after 5 bad claim tags", async () => {
    const id = mailboxId();
    const t = await makeTags();
    await create(id, t);
    for (let i = 1; i <= 4; i++) {
      const res = await claim(id, toB64url(tagBytes()));
      expect(res.status).toBe(403);
      expect(((await res.json()) as { attemptsLeft: number }).attemptsLeft).toBe(5 - i);
    }
    expect((await claim(id, toB64url(tagBytes()))).status).toBe(410);
    expect((await claim(id, t.claimTag)).status).toBe(410);
  });

  it("sender revoke wipes the drop", async () => {
    const id = mailboxId();
    const t = await makeTags();
    await create(id, t);
    const bad = await SELF.fetch(`https://x/api/drops/${id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ senderTag: toB64url(tagBytes()) }),
    });
    expect(bad.status).toBe(403);
    const ok = await SELF.fetch(`https://x/api/drops/${id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ senderTag: t.senderTag }),
    });
    expect(ok.status).toBe(204);
    expect((await claim(id, t.claimTag)).status).toBe(410);
  });

  it("validates input shape", async () => {
    expect((await SELF.fetch("https://x/api/drops/bad-id!", { method: "PUT" })).status).toBe(404);
    const id = mailboxId();
    const res = await SELF.fetch(`https://x/api/drops/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ claimTagHash: "short" }),
    });
    expect(res.status).toBe(400);
  });
});

describe("websocket signaling", () => {
  function connect(id: string, role: string) {
    return SELF.fetch(`https://x/ws/${id}?role=${role}`, {
      headers: { Upgrade: "websocket" },
    });
  }

  function collect(ws: WebSocket): { messages: unknown[]; next: (t: string, ms?: number) => Promise<any> } {
    const messages: any[] = [];
    ws.addEventListener("message", (e) => messages.push(JSON.parse(e.data as string)));
    return {
      messages,
      next: async (t: string, ms = 3000) => {
        const deadline = Date.now() + ms;
        for (;;) {
          const found = messages.find((m) => m.t === t);
          if (found) return found;
          if (Date.now() > deadline) return null;
          await new Promise((r) => setTimeout(r, 25));
        }
      },
    };
  }

  it("relays signals between roles and tracks presence", async () => {
    const id = mailboxId();
    const sRes = await connect(id, "sender");
    expect(sRes.status).toBe(101);
    const sender = sRes.webSocket!;
    sender.accept();
    const s = collect(sender);
    expect((await s.next("joined")).peerPresent).toBe(false);

    const rRes = await connect(id, "receiver");
    const receiver = rRes.webSocket!;
    receiver.accept();
    const r = collect(receiver);
    expect((await r.next("joined")).peerPresent).toBe(true);
    expect(await s.next("peer-joined")).toBeTruthy();

    sender.send(JSON.stringify({ t: "signal", payload: { kind: "offer", sdp: "v=0" } }));
    expect((await r.next("signal")).payload.sdp).toBe("v=0");

    receiver.close();
    expect(await s.next("peer-left")).toBeTruthy();
    sender.close();
  });

  it("rejects bad roles and non-upgrade requests", async () => {
    const id = mailboxId();
    expect((await connect(id, "admin")).status).toBe(400);
    expect((await SELF.fetch(`https://x/ws/${id}?role=sender`)).status).toBe(426);
  });

  it("rejects cross-site browser origins", async () => {
    const id = mailboxId();
    const res = await SELF.fetch(`https://x/ws/${id}?role=sender`, {
      headers: { Upgrade: "websocket", Origin: "https://evil.example" },
    });
    expect(res.status).toBe(403);
  });

  it("issues a turn token in joined", async () => {
    const id = mailboxId();
    const res = await connect(id, "sender");
    const ws = res.webSocket!;
    ws.accept();
    const c = collect(ws);
    const joined = await c.next("joined");
    expect(joined.turnToken).toMatch(/^[A-Za-z0-9_-]{22}$/);
    ws.close();
  });
});

describe("turn credentials", () => {
  it("reports not-configured when secrets are absent", async () => {
    const res = await SELF.fetch("https://x/api/turn", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mailboxId: "XKQ2M7PT", turnToken: "A".repeat(22) }),
    });
    expect(res.status).toBe(404);
    expect(((await res.json()) as { error: string }).error).toBe("TURN_NOT_CONFIGURED");
  });
});
