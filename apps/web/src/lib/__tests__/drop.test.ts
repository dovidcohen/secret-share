import { afterEach, describe, expect, it, vi } from "vitest";
import { toB64url, type DerivedKeys } from "@secret-share/crypto";
import {
  GrantRejectedError,
  SessionExpiredError,
  parkDrop,
} from "../drop.js";

const KEYS = {
  mailboxId: "XKQ2M7PT",
  claimTag: toB64url(new Uint8Array(32).fill(1)),
  senderTag: toB64url(new Uint8Array(32).fill(2)),
} as unknown as DerivedKeys;

const BLOB = new Uint8Array([1, 2, 3]);

function mockFetch(status: number, body: unknown) {
  const fn = vi.fn(async () => new Response(JSON.stringify(body), { status }));
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => vi.unstubAllGlobals());

describe("parkDrop error mapping", () => {
  it("maps 401 to SessionExpiredError", async () => {
    mockFetch(401, { error: "AUTH_REQUIRED" });
    await expect(parkDrop(KEYS, BLOB, 3600)).rejects.toBeInstanceOf(SessionExpiredError);
  });

  it("maps grant 403s to typed reasons", async () => {
    mockFetch(403, { error: "GRANT_USED" });
    await expect(parkDrop(KEYS, BLOB, 3600, { grant: "g".repeat(43) })).rejects.toMatchObject({
      reason: "used",
    });
    mockFetch(403, { error: "GRANT_EXPIRED" });
    await expect(parkDrop(KEYS, BLOB, 3600, { grant: "g".repeat(43) })).rejects.toMatchObject({
      reason: "expired",
    });
    mockFetch(403, { error: "BAD_GRANT" });
    const err = await parkDrop(KEYS, BLOB, 3600, { grant: "g".repeat(43) }).catch((e) => e);
    expect(err).toBeInstanceOf(GrantRejectedError);
    expect(err.reason).toBe("invalid");
  });

  it("sends the grant as a header, never in the URL", async () => {
    const fn = mockFetch(201, { expiresAt: Date.now() + 1000 });
    await parkDrop(KEYS, BLOB, 3600, { grant: "g".repeat(43) });
    const [url, init] = fn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/drops/XKQ2M7PT");
    expect((init.headers as Record<string, string>)["X-Guest-Grant"]).toBe("g".repeat(43));
  });
});
