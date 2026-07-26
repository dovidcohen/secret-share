import { describe, expect, it } from "vitest";
import {
  BlobFormatError,
  MAX_SECRET_BYTES,
  SecretTooLargeError,
  decryptSecret,
  encryptSecret,
} from "../blob.js";
import { utf8 } from "../encoding.js";

async function fakeKeys(mailboxId: string) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const kBlob = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
  return { kBlob, mailboxId, raw };
}

const SSH_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK
-----END OPENSSH PRIVATE KEY-----`;

describe("blob encrypt/decrypt", () => {
  it("round-trips byte-identically", async () => {
    const keys = await fakeKeys("XKQ2M7PT");
    const pt = utf8(SSH_KEY);
    const blob = await encryptSecret(keys, pt);
    expect(blob[0]).toBe(0x01);
    expect(await decryptSecret(keys, blob)).toEqual(pt);
  });

  it("produces distinct ciphertexts for the same plaintext (random IV)", async () => {
    const keys = await fakeKeys("XKQ2M7PT");
    const a = await encryptSecret(keys, utf8("same"));
    const b = await encryptSecret(keys, utf8("same"));
    expect(a).not.toEqual(b);
  });

  it("rejects every single-bit flip", async () => {
    const keys = await fakeKeys("XKQ2M7PT");
    const blob = await encryptSecret(keys, utf8("short secret"));
    for (let byte = 0; byte < blob.length; byte++) {
      const tampered = blob.slice();
      tampered[byte]! ^= 0x01;
      await expect(decryptSecret(keys, tampered)).rejects.toThrow();
    }
  });

  it("binds the ciphertext to the mailbox id (AAD)", async () => {
    const keys = await fakeKeys("XKQ2M7PT");
    const blob = await encryptSecret(keys, utf8("bound"));
    await expect(
      decryptSecret({ kBlob: keys.kBlob, mailboxId: "AAAAAAAA" }, blob),
    ).rejects.toThrow();
  });

  it("rejects the wrong key", async () => {
    const a = await fakeKeys("XKQ2M7PT");
    const b = await fakeKeys("XKQ2M7PT");
    const blob = await encryptSecret(a, utf8("mine"));
    await expect(decryptSecret(b, blob)).rejects.toThrow();
  });

  it("enforces the size cap and blob format", async () => {
    const keys = await fakeKeys("XKQ2M7PT");
    await expect(
      encryptSecret(keys, new Uint8Array(MAX_SECRET_BYTES + 1)),
    ).rejects.toThrow(SecretTooLargeError);
    await expect(decryptSecret(keys, new Uint8Array(5))).rejects.toThrow(BlobFormatError);
    const blob = await encryptSecret(keys, utf8("x"));
    const badVersion = blob.slice();
    badVersion[0] = 0x02;
    await expect(decryptSecret(keys, badVersion)).rejects.toThrow(BlobFormatError);
  });
});
