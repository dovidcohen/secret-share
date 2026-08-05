import { describe, expect, it } from "vitest";
import { randomBytes, utf8 } from "@secret-share/crypto";
import {
  KEY_QR_PREFIX,
  deriveOpticalKeys,
  encodeKeyQr,
  generateIdentity,
  parseKeyQr,
} from "../ecdh.js";
import { openContainer, sealContainer } from "../container.js";

describe("optical ECDH", () => {
  it("both sides derive the same key and safety number", async () => {
    const receiver = await generateIdentity();
    const sender = await generateIdentity();
    const sessionId = 0x1234abcd;

    const senderSide = await deriveOpticalKeys(
      sender.privateKey,
      receiver.publicRaw,
      sessionId,
      sender.publicRaw,
      receiver.publicRaw,
    );
    const receiverSide = await deriveOpticalKeys(
      receiver.privateKey,
      sender.publicRaw,
      sessionId,
      sender.publicRaw,
      receiver.publicRaw,
    );

    expect(senderSide.safetyNumber).toBe(receiverSide.safetyNumber);
    expect(senderSide.safetyNumber).toMatch(/^[0-9A-Z]{8}$/);

    // keys are non-extractable, so prove equality by encrypt/decrypt round-trip
    const data = randomBytes(2_000);
    const sealed = await sealContainer(data, { name: "k.bin", mime: "application/octet-stream" }, {
      key: senderSide.key,
      senderPub: sender.publicRaw,
      sessionId,
    });
    const { data: out } = await openContainer(sealed, {
      sessionId,
      deriveKey: async (senderPub) => {
        // the receiver learns the sender's epk from the container itself
        const keys = await deriveOpticalKeys(
          receiver.privateKey,
          senderPub,
          sessionId,
          senderPub,
          receiver.publicRaw,
        );
        return keys.key;
      },
    });
    expect(out).toEqual(data);
  });

  it("a different session or keypair changes both key and safety number", async () => {
    const receiver = await generateIdentity();
    const sender = await generateIdentity();
    const a = await deriveOpticalKeys(sender.privateKey, receiver.publicRaw, 1, sender.publicRaw, receiver.publicRaw);
    const b = await deriveOpticalKeys(sender.privateKey, receiver.publicRaw, 2, sender.publicRaw, receiver.publicRaw);
    expect(a.safetyNumber).not.toBe(b.safetyNumber);

    const eve = await generateIdentity();
    const c = await deriveOpticalKeys(eve.privateKey, receiver.publicRaw, 1, eve.publicRaw, receiver.publicRaw);
    expect(c.safetyNumber).not.toBe(a.safetyNumber);
  });

  it("key QR encodes and parses round-trip", async () => {
    const { publicRaw } = await generateIdentity();
    const qr = encodeKeyQr(publicRaw);
    expect(qr.startsWith(KEY_QR_PREFIX)).toBe(true);
    expect(parseKeyQr(qr)).toEqual(publicRaw);
  });

  it("parseKeyQr rejects malformed input", () => {
    expect(parseKeyQr("https://example.com")).toBeNull();
    expect(parseKeyQr(KEY_QR_PREFIX + "not-base64!!!")).toBeNull();
    expect(parseKeyQr(KEY_QR_PREFIX)).toBeNull();
    // right length, wrong point-format byte
    const bad = new Uint8Array(65).fill(7);
    expect(parseKeyQr(KEY_QR_PREFIX + Buffer.from(bad).toString("base64url"))).toBeNull();
    expect(parseKeyQr("")).toBeNull();
  });

  it("wrong receiver key fails decryption cleanly", async () => {
    const receiver = await generateIdentity();
    const wrongReceiver = await generateIdentity();
    const sender = await generateIdentity();
    const sessionId = 5;
    const { key } = await deriveOpticalKeys(
      sender.privateKey,
      receiver.publicRaw,
      sessionId,
      sender.publicRaw,
      receiver.publicRaw,
    );
    const sealed = await sealContainer(utf8("attack at dawn"), { name: null, mime: "text/plain" }, {
      key,
      senderPub: sender.publicRaw,
      sessionId,
    });
    await expect(
      openContainer(sealed, {
        sessionId,
        deriveKey: async (senderPub) => {
          const keys = await deriveOpticalKeys(
            wrongReceiver.privateKey,
            senderPub,
            sessionId,
            senderPub,
            wrongReceiver.publicRaw,
          );
          return keys.key;
        },
      }),
    ).rejects.toThrow(/decryption failed/);
  });
});
