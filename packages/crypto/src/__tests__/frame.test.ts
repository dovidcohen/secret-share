import { describe, expect, it } from "vitest";
import { decryptFrame, encryptFrame } from "../frame.js";
import { confirmationMac, deriveSessionKeys } from "../kdf.js";
import { constantTimeEqual, randomBytes, utf8 } from "../encoding.js";

async function session(ikm?: Uint8Array, sSalt?: Uint8Array, rSalt?: Uint8Array) {
  const sessionIkm = ikm ?? randomBytes(32);
  const senderSalt = sSalt ?? randomBytes(16);
  const receiverSalt = rSalt ?? randomBytes(16);
  const keys = await deriveSessionKeys({ sessionIkm }, senderSalt, receiverSalt);
  return { keys, sessionIkm, senderSalt, receiverSalt };
}

describe("frame crypto", () => {
  it("round-trips in both directions", async () => {
    const { keys } = await session();
    const pt = utf8("chunk of an ssh key");
    expect(await decryptFrame(keys, "s2r", 0, await encryptFrame(keys, "s2r", 0, pt))).toEqual(pt);
    expect(await decryptFrame(keys, "r2s", 7, await encryptFrame(keys, "r2s", 7, pt))).toEqual(pt);
  });

  it("binds direction and sequence number", async () => {
    const { keys } = await session();
    const frame = await encryptFrame(keys, "s2r", 3, utf8("data"));
    await expect(decryptFrame(keys, "r2s", 3, frame)).rejects.toThrow();
    await expect(decryptFrame(keys, "s2r", 4, frame)).rejects.toThrow();
  });

  it("different session salts give different keys for the same code", async () => {
    const ikm = randomBytes(32);
    const a = await session(ikm);
    const b = await session(ikm); // fresh random salts
    const frame = await encryptFrame(a.keys, "s2r", 0, utf8("data"));
    await expect(decryptFrame(b.keys, "s2r", 0, frame)).rejects.toThrow();
  });
});

describe("confirmation MAC", () => {
  it("matches for peers with the same code and transcript, split by role", async () => {
    const ikm = randomBytes(32);
    const sSalt = randomBytes(16);
    const rSalt = randomBytes(16);
    const sender = await deriveSessionKeys({ sessionIkm: ikm }, sSalt, rSalt);
    const receiver = await deriveSessionKeys({ sessionIkm: ikm }, sSalt, rSalt);

    const fromReceiver = await confirmationMac(receiver, "XKQ2M7PT", sSalt, rSalt, "receiver");
    const senderExpects = await confirmationMac(sender, "XKQ2M7PT", sSalt, rSalt, "receiver");
    expect(constantTimeEqual(fromReceiver, senderExpects)).toBe(true);

    // role separation: a peer cannot reflect our own MAC back at us
    const senderMac = await confirmationMac(sender, "XKQ2M7PT", sSalt, rSalt, "sender");
    expect(constantTimeEqual(senderMac, fromReceiver)).toBe(false);
  });

  it("differs for a peer holding different key material", async () => {
    const sSalt = randomBytes(16);
    const rSalt = randomBytes(16);
    const good = await deriveSessionKeys({ sessionIkm: randomBytes(32) }, sSalt, rSalt);
    const evil = await deriveSessionKeys({ sessionIkm: randomBytes(32) }, sSalt, rSalt);
    const a = await confirmationMac(good, "XKQ2M7PT", sSalt, rSalt, "receiver");
    const b = await confirmationMac(evil, "XKQ2M7PT", sSalt, rSalt, "receiver");
    expect(constantTimeEqual(a, b)).toBe(false);
  });
});

describe("constantTimeEqual", () => {
  it("compares correctly", () => {
    expect(constantTimeEqual(utf8("abc"), utf8("abc"))).toBe(true);
    expect(constantTimeEqual(utf8("abc"), utf8("abd"))).toBe(false);
    expect(constantTimeEqual(utf8("abc"), utf8("ab"))).toBe(false);
  });
});
