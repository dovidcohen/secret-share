import { describe, expect, it } from "vitest";
import {
  ClientMessageSchema,
  CreateDropRequestSchema,
  MAILBOX_ID_REGEX,
  ServerMessageSchema,
  SignalPayloadSchema,
} from "../index.js";

describe("ws messages", () => {
  it("accepts a valid signal", () => {
    const m = ClientMessageSchema.parse({
      t: "signal",
      payload: { kind: "offer", sdp: "v=0..." },
    });
    expect(m.t).toBe("signal");
  });

  it("rejects unknown message types", () => {
    expect(() => ClientMessageSchema.parse({ t: "nope" })).toThrow();
  });

  it("rejects oversized sdp", () => {
    expect(() =>
      SignalPayloadSchema.parse({ kind: "offer", sdp: "x".repeat(20_001) }),
    ).toThrow();
  });

  it("round-trips a server signal relay", () => {
    const payload = { kind: "ice", candidate: "candidate:1", sdpMid: "0", sdpMLineIndex: 0 };
    const m = ServerMessageSchema.parse({ t: "signal", payload });
    expect(m.t).toBe("signal");
  });
});

describe("rest schemas", () => {
  const tag = "A".repeat(43);

  it("accepts a valid create and applies default ttl", () => {
    const req = CreateDropRequestSchema.parse({
      claimTagHash: tag,
      senderTagHash: tag,
      ciphertext: "abc123_-",
    });
    expect(req.ttlSeconds).toBe(86_400);
  });

  it("rejects bad mailbox ids (I, L, O, U excluded)", () => {
    for (const bad of ["XKQ2M7PI", "XKQ2M7PL", "XKQ2M7PO", "XKQ2M7PU", "short", ""]) {
      expect(MAILBOX_ID_REGEX.test(bad)).toBe(false);
    }
  });

  it("rejects out-of-range ttl", () => {
    const base = { claimTagHash: tag, senderTagHash: tag, ciphertext: "a" };
    expect(() => CreateDropRequestSchema.parse({ ...base, ttlSeconds: 59 })).toThrow();
    expect(() => CreateDropRequestSchema.parse({ ...base, ttlSeconds: 604_801 })).toThrow();
  });
});
