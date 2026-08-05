import { describe, expect, it } from "vitest";
import { randomBytes, utf8 } from "@secret-share/crypto";
import {
  CONTAINER_FLAG_ENCRYPTED,
  CONTAINER_FLAG_GZIP,
  ContainerFormatError,
  IntegrityError,
  MAX_TRANSFER_BYTES,
  TransferTooLargeError,
  containerIsEncrypted,
  openContainer,
  sealContainer,
} from "../container.js";
import { FountainDecoder, FountainEncoder } from "../fountain.js";

async function testKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", randomBytes(32) as BufferSource, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

const fakeEpk = (() => {
  const b = new Uint8Array(65);
  b[0] = 0x04;
  return b;
})();

describe("container", () => {
  it("round-trips pasted text", async () => {
    const data = utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nhunter2\n-----END-----");
    const sealed = await sealContainer(data, { name: null, mime: "text/plain" });
    const { meta, data: out } = await openContainer(sealed, { sessionId: 1 });
    expect(out).toEqual(data);
    expect(meta.name).toBeNull();
    expect(meta.mime).toBe("text/plain");
    expect(meta.size).toBe(data.length);
  });

  it("round-trips a binary file with name and mime", async () => {
    const data = randomBytes(10_000);
    const sealed = await sealContainer(data, { name: "backup.tar.gz", mime: "application/gzip" });
    const { meta, data: out } = await openContainer(sealed, { sessionId: 1 });
    expect(out).toEqual(data);
    expect(meta.name).toBe("backup.tar.gz");
  });

  it("gzips compressible payloads and skips gzip for incompressible ones", async () => {
    const compressible = new Uint8Array(20_000).fill(0x41);
    const sealedC = await sealContainer(compressible, { name: null, mime: "text/plain" });
    expect(sealedC[5]! & CONTAINER_FLAG_GZIP).not.toBe(0);
    expect(sealedC.length).toBeLessThan(compressible.length / 10);
    expect((await openContainer(sealedC, { sessionId: 1 })).data).toEqual(compressible);

    const incompressible = randomBytes(20_000);
    const sealedR = await sealContainer(incompressible, { name: null, mime: "application/octet-stream" });
    expect(sealedR[5]! & CONTAINER_FLAG_GZIP).toBe(0);
    expect((await openContainer(sealedR, { sessionId: 1 })).data).toEqual(incompressible);
  });

  it("rejects tampered bodies via SHA-256", async () => {
    const data = randomBytes(5_000); // incompressible → body carried raw
    const sealed = await sealContainer(data, { name: null, mime: "application/octet-stream" });
    const tampered = sealed.slice();
    tampered[tampered.length - 1]! ^= 0x01;
    await expect(openContainer(tampered, { sessionId: 1 })).rejects.toThrow(IntegrityError);
  });

  it("rejects garbage, truncation, and the size cap", async () => {
    await expect(openContainer(new Uint8Array(3), { sessionId: 1 })).rejects.toThrow(
      ContainerFormatError,
    );
    await expect(openContainer(utf8("QQQQxxxxxxxx"), { sessionId: 1 })).rejects.toThrow(
      ContainerFormatError,
    );
    const sealed = await sealContainer(randomBytes(100), { name: null, mime: "x" });
    await expect(openContainer(sealed.subarray(0, 8), { sessionId: 1 })).rejects.toThrow(
      ContainerFormatError,
    );
    await expect(
      sealContainer(new Uint8Array(MAX_TRANSFER_BYTES + 1), { name: null, mime: "x" }),
    ).rejects.toThrow(TransferTooLargeError);
    await expect(sealContainer(new Uint8Array(0), { name: null, mime: "x" })).rejects.toThrow(
      ContainerFormatError,
    );
  });

  it("encrypts: round-trip, pubkey passthrough, flag visible", async () => {
    const key = await testKey();
    const data = randomBytes(3_000);
    const sealed = await sealContainer(
      data,
      { name: "secret.bin", mime: "application/octet-stream" },
      { key, senderPub: fakeEpk, sessionId: 77 },
    );
    expect(containerIsEncrypted(sealed)).toBe(true);
    expect(sealed[5]! & CONTAINER_FLAG_ENCRYPTED).not.toBe(0);
    let seenPub: Uint8Array | null = null;
    const { meta, data: out } = await openContainer(sealed, {
      sessionId: 77,
      deriveKey: (pub) => {
        seenPub = pub;
        return Promise.resolve(key);
      },
    });
    expect(out).toEqual(data);
    expect(meta.name).toBe("secret.bin");
    expect(seenPub).toEqual(fakeEpk);
  });

  it("encrypted: rejects wrong key, wrong sessionId (AAD), and missing key source", async () => {
    const key = await testKey();
    const sealed = await sealContainer(randomBytes(500), { name: null, mime: "x" }, {
      key,
      senderPub: fakeEpk,
      sessionId: 77,
    });
    await expect(
      openContainer(sealed, { sessionId: 77, deriveKey: () => testKey() }),
    ).rejects.toThrow(IntegrityError);
    await expect(
      openContainer(sealed, { sessionId: 78, deriveKey: () => Promise.resolve(key) }),
    ).rejects.toThrow(IntegrityError);
    await expect(openContainer(sealed, { sessionId: 77 })).rejects.toThrow(ContainerFormatError);
  });

  it("hides metadata when encrypted (filename not in the clear)", async () => {
    const key = await testKey();
    const sealed = await sealContainer(utf8("x".repeat(200)), { name: "payroll-2026.xlsx", mime: "x" }, {
      key,
      senderPub: fakeEpk,
      sessionId: 1,
    });
    const asText = new TextDecoder("latin1").decode(sealed);
    expect(asText).not.toContain("payroll");
  });

  it("rejects a declared size outside 1..MAX (before any decompression)", async () => {
    // hand-craft: valid prefix + meta claiming an absurd size
    const metaJson = utf8(
      JSON.stringify({ name: null, mime: "x", size: MAX_TRANSFER_BYTES + 1, sha256: "AA" }),
    );
    const metaLen = new Uint8Array(2);
    new DataView(metaLen.buffer).setUint16(0, metaJson.length);
    const crafted = new Uint8Array([
      0x4f, 0x51, 0x52, 0x31, 0x01, 0x00, // "OQR1", v1, no flags
      ...metaLen, ...metaJson, 1, 2, 3,
    ]);
    await expect(openContainer(crafted, { sessionId: 1 })).rejects.toThrow(
      /declared size out of range/,
    );
  });

  it("aborts a gzip bomb the moment output exceeds the declared size", async () => {
    // gzip of 1 MiB of zeros (~1 KiB compressed) with meta claiming 100 bytes
    const bomb = new Uint8Array(1024 * 1024);
    const gz = new Uint8Array(
      await new Response(
        new Blob([bomb]).stream().pipeThrough(new CompressionStream("gzip")),
      ).arrayBuffer(),
    );
    expect(gz.length).toBeLessThan(10_000);
    const metaJson = utf8(JSON.stringify({ name: null, mime: "x", size: 100, sha256: "AA" }));
    const metaLen = new Uint8Array(2);
    new DataView(metaLen.buffer).setUint16(0, metaJson.length);
    const crafted = new Uint8Array([
      0x4f, 0x51, 0x52, 0x31, 0x01, 0x01, // "OQR1", v1, gzip flag
      ...metaLen, ...metaJson, ...gz,
    ]);
    await expect(openContainer(crafted, { sessionId: 1 })).rejects.toThrow(
      /exceeds declared size/,
    );
  });

  it("travels intact through the fountain layer (integration)", async () => {
    const data = randomBytes(40_000);
    const sealed = await sealContainer(data, { name: "img.png", mime: "image/png" });
    const enc = new FountainEncoder(sealed, 624, 0xf0f0f0f0);
    const dec = new FountainDecoder(enc.params);
    for (let seq = 5; !dec.complete; seq++) dec.addFrame(seq, enc.payload(seq)); // mid-stream lock
    const { meta, data: out } = await openContainer(dec.data(), { sessionId: 0xf0f0f0f0 });
    expect(out).toEqual(data);
    expect(meta.name).toBe("img.png");
  });
});
