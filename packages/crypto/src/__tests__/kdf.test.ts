import { describe, expect, it } from "vitest";
import { argon2id as nobleArgon2id } from "@noble/hashes/argon2";
import { argon2id as wasmArgon2id } from "hash-wasm";
import { deriveKeys, hkdfSha256, tagHash } from "../kdf.js";
import { fromB64url, randomBytes, toB64url, utf8 } from "../encoding.js";
import type { ShareCode } from "../code.js";

const hex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (s: string) =>
  new Uint8Array(s.match(/../g)!.map((x) => parseInt(x, 16)));

describe("HKDF-SHA256 known-answer tests (RFC 5869)", () => {
  it("test case 1", async () => {
    const okm = await hkdfSha256(
      new Uint8Array(22).fill(0x0b),
      fromHex("000102030405060708090a0b0c"),
      fromHex("f0f1f2f3f4f5f6f7f8f9"),
      42,
    );
    expect(hex(okm)).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
  });

  it("test case 3 (empty salt and info)", async () => {
    const okm = await hkdfSha256(
      new Uint8Array(22).fill(0x0b),
      new Uint8Array(0),
      new Uint8Array(0),
      42,
    );
    expect(hex(okm)).toBe(
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    );
  });
});

describe("Argon2id cross-implementation check", () => {
  it("hash-wasm and @noble/hashes agree (10 random inputs, m=1MiB t=2 p=1)", async () => {
    for (let i = 0; i < 10; i++) {
      const password = toB64url(randomBytes(12));
      const salt = randomBytes(16);
      const wasm = await wasmArgon2id({
        password,
        salt,
        parallelism: 1,
        iterations: 2,
        memorySize: 1024,
        hashLength: 32,
        outputType: "binary",
      });
      const noble = nobleArgon2id(utf8(password), salt, {
        t: 2,
        m: 1024,
        p: 1,
        dkLen: 32,
      });
      expect(hex(wasm)).toBe(hex(noble));
    }
  }, 30_000);
});

describe("deriveKeys", () => {
  // Fixed code so any accidental change to Argon2/HKDF params or info strings
  // fails loudly. Changing these values is a deliberate protocol version bump.
  const FIXED: ShareCode = {
    mailboxId: "XKQ2M7PT",
    words: ["tiger", "ocean", "cable", "ruby", "drum"],
    code: "XKQ2-M7PT-tiger-ocean-cable-ruby-drum",
  };

  it("matches the pinned protocol snapshot", async () => {
    const keys = await deriveKeys(FIXED);
    expect(keys.mailboxId).toBe("XKQ2M7PT");
    expect(keys.claimTag).toBe("evG8SmGhuFIuNYNg2NtuKFOmWmPV8Nrzx0gsPm3JhSM");
    expect(keys.senderTag).toBe("3JfGgzETTkzfgF9EOipJSrMNrdPuKDtMFbzqdheDhIQ");
    expect(toB64url(keys.sessionIkm)).toBe("ZgUMbXbtdyjW-673PwX08N_LLgeSbfUIQv26W8EVClQ");
  }, 60_000);

  it("derives independent tags and hashes them consistently", async () => {
    const keys = await deriveKeys(FIXED);
    expect(keys.claimTag).not.toBe(keys.senderTag);
    expect(fromB64url(keys.claimTag)).toHaveLength(32);
    const h1 = await tagHash(keys.claimTag);
    const h2 = await tagHash(keys.claimTag);
    expect(h1).toBe(h2);
    expect(h1).not.toBe(keys.claimTag);
    expect(fromB64url(h1)).toHaveLength(32);
  }, 60_000);
});
