import { describe, expect, it } from "vitest";
import {
  PAYLOAD_MAGIC,
  PayloadFormatError,
  decodePayload,
  encodeFilePayload,
  filePayloadOverhead,
  sanitizeFilename,
} from "../payload.js";
import { utf8 } from "../encoding.js";

describe("payload envelope", () => {
  it("round-trips a file payload", () => {
    const data = crypto.getRandomValues(new Uint8Array(2048));
    const bytes = encodeFilePayload("keystore.jks", "application/octet-stream", data);
    const p = decodePayload(bytes);
    expect(p.kind).toBe("file");
    if (p.kind !== "file") return;
    expect(p.name).toBe("keystore.jks");
    expect(p.mime).toBe("application/octet-stream");
    expect(new Uint8Array(p.data)).toEqual(data);
  });

  it("treats plain text as text — legacy payloads keep working", () => {
    const p = decodePayload(utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nabc"));
    expect(p).toEqual({ kind: "text", text: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc" });
  });

  it("does not mistake text for an envelope even with a partial magic match", () => {
    // Raw bytes that share a prefix with the magic but diverge.
    const p = decodePayload(new Uint8Array([0x00, 0x73, 0x73, 0x66, 0x02, 0x41]));
    expect(p.kind).toBe("text");
  });

  it("overhead prediction matches the real envelope", () => {
    const data = new Uint8Array(100);
    const bytes = encodeFilePayload("a.p12", "application/x-pkcs12", data);
    expect(bytes.length).toBe(filePayloadOverhead("a.p12", "application/x-pkcs12") + data.length);
  });

  it("supports empty files and empty mime", () => {
    const p = decodePayload(encodeFilePayload("empty.txt", "", new Uint8Array(0)));
    expect(p.kind).toBe("file");
    if (p.kind !== "file") return;
    expect(p.data.length).toBe(0);
  });

  it("sanitizes hostile filenames on encode and decode", () => {
    expect(sanitizeFilename("..\\..\\evil.exe")).toBe("evil.exe");
    expect(sanitizeFilename("/etc/passwd")).toBe("passwd");
    expect(sanitizeFilename("..")).toBe("attachment");
    expect(sanitizeFilename("")).toBe("attachment");
    expect(sanitizeFilename("a\x00b\nc.txt")).toBe("abc.txt");
    expect(sanitizeFilename("x".repeat(500)).length).toBe(255);

    const p = decodePayload(encodeFilePayload("../../up.txt", "text/plain", utf8("x")));
    if (p.kind !== "file") throw new Error("expected file");
    expect(p.name).toBe("up.txt");
  });

  it("rejects truncated or malformed envelopes", () => {
    const ok = encodeFilePayload("f.txt", "text/plain", utf8("body"));
    expect(() => decodePayload(ok.subarray(0, PAYLOAD_MAGIC.length + 1))).toThrow(
      PayloadFormatError,
    );
    // Declared metaLen runs past the end.
    const bad = ok.slice();
    new DataView(bad.buffer).setUint16(PAYLOAD_MAGIC.length, 0xffff, false);
    expect(() => decodePayload(bad)).toThrow(PayloadFormatError);
    // Meta is not JSON.
    const junkMeta = new Uint8Array([...PAYLOAD_MAGIC, 0x00, 0x02, 0x41, 0x41]);
    expect(() => decodePayload(junkMeta)).toThrow(PayloadFormatError);
  });
});
