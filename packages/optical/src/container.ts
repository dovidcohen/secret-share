import { concatBytes, randomBytes, sha256, toB64url, utf8 } from "@secret-share/crypto";

/**
 * Container — the bytes the fountain code actually carries.
 *
 * ["OQR1"][1B version][1B flags] then either:
 *   plain:     [2B metaLen][meta JSON][body]
 *   encrypted: [65B sender ephemeral P-256 pubkey][12B IV][AES-256-GCM(plain)+tag]
 *
 * meta JSON = { name, mime, size, sha256 } where sha256 covers the ORIGINAL
 * payload (pre-gzip), verified after reassembly as the end-to-end check.
 * Encrypting the whole plain section keeps the filename confidential too.
 */

import { MAX_TRANSFER_BYTES } from "./constants.js";

export const CONTAINER_VERSION = 0x01;
export const CONTAINER_FLAG_GZIP = 0b01;
export const CONTAINER_FLAG_ENCRYPTED = 0b10;
export { MAX_TRANSFER_BYTES };
export const EPK_BYTES = 65; // raw uncompressed P-256 point

const MAGIC = utf8("OQR1");
const IV_BYTES = 12;
const PREFIX_BYTES = MAGIC.length + 2; // magic + version + flags

export class ContainerFormatError extends Error {
  override name = "ContainerFormatError";
}

export class IntegrityError extends Error {
  override name = "IntegrityError";
}

export class TransferTooLargeError extends Error {
  override name = "TransferTooLargeError";
}

export interface PayloadMeta {
  /** Filename, or null for pasted text. */
  name: string | null;
  mime: string;
  /** Original payload size in bytes. */
  size: number;
  /** base64url SHA-256 of the original payload. */
  sha256: string;
}

export interface EncryptionContext {
  key: CryptoKey;
  /** Sender's ephemeral raw P-256 public key (65 bytes). */
  senderPub: Uint8Array;
  sessionId: number;
}

function aad(sessionId: number): Uint8Array {
  return utf8(`shareasecret/optical/v1/${sessionId >>> 0}`);
}

async function pipeThrough(
  data: Uint8Array,
  transform: { readable: ReadableStream<Uint8Array>; writable: WritableStream<BufferSource> },
): Promise<Uint8Array> {
  const writer = transform.writable.getWriter();
  const done = writer.write(data as BufferSource).then(() => writer.close());
  // Promise.all so a failure on either side (e.g. corrupt gzip) rejects cleanly.
  const [buf] = await Promise.all([new Response(transform.readable).arrayBuffer(), done]);
  return new Uint8Array(buf);
}

async function tryGzip(data: Uint8Array): Promise<Uint8Array | null> {
  if (typeof CompressionStream === "undefined") return null;
  return pipeThrough(data, new CompressionStream("gzip"));
}

/**
 * Bounded incremental gunzip. The stream comes off an untrusted camera, so a
 * tiny frame sequence could declare a gzip bomb — abort the moment output
 * exceeds what the (already-validated) metadata declared.
 */
async function gunzip(data: Uint8Array, limit: number): Promise<Uint8Array> {
  if (typeof DecompressionStream === "undefined") {
    throw new ContainerFormatError("gzip container but DecompressionStream unavailable");
  }
  const ds = new DecompressionStream("gzip");
  const writer = ds.writable.getWriter();
  // Writer-side rejections (corrupt input, cancelled readable) surface on the
  // reader side too — swallow here to avoid an unhandled rejection.
  void writer
    .write(data as BufferSource)
    .then(() => writer.close())
    .catch(() => undefined);
  const reader = ds.readable.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > limit) {
        await reader.cancel().catch(() => undefined);
        throw new IntegrityError("decompressed data exceeds declared size");
      }
      chunks.push(value);
    }
  } catch (e) {
    if (e instanceof IntegrityError) throw e;
    throw new ContainerFormatError("corrupt gzip body");
  }
  return concatBytes(...chunks);
}

export async function sealContainer(
  data: Uint8Array,
  meta: { name: string | null; mime: string },
  enc?: EncryptionContext,
): Promise<Uint8Array> {
  if (data.length === 0) throw new ContainerFormatError("empty payload");
  if (data.length > MAX_TRANSFER_BYTES) {
    throw new TransferTooLargeError(`payload exceeds ${MAX_TRANSFER_BYTES} bytes`);
  }
  const digest = await sha256(data);

  let body = data;
  let flags = 0;
  const zipped = await tryGzip(data);
  if (zipped && zipped.length < data.length) {
    body = zipped;
    flags |= CONTAINER_FLAG_GZIP;
  }

  const metaJson = utf8(
    JSON.stringify({
      name: meta.name,
      mime: meta.mime,
      size: data.length,
      sha256: toB64url(digest),
    } satisfies PayloadMeta),
  );
  if (metaJson.length > 0xffff) throw new ContainerFormatError("meta too large");
  const metaLen = new Uint8Array(2);
  new DataView(metaLen.buffer).setUint16(0, metaJson.length);
  const plain = concatBytes(metaLen, metaJson, body);

  if (!enc) {
    return concatBytes(MAGIC, new Uint8Array([CONTAINER_VERSION, flags]), plain);
  }
  if (enc.senderPub.length !== EPK_BYTES) throw new ContainerFormatError("bad sender pubkey");
  const iv = randomBytes(IV_BYTES);
  const ct = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource,
      additionalData: aad(enc.sessionId) as BufferSource,
    },
    enc.key,
    plain as BufferSource,
  );
  return concatBytes(
    MAGIC,
    new Uint8Array([CONTAINER_VERSION, flags | CONTAINER_FLAG_ENCRYPTED]),
    enc.senderPub,
    iv,
    new Uint8Array(ct),
  );
}

/** Peek whether a reassembled container is encrypted without opening it. */
export function containerIsEncrypted(container: Uint8Array): boolean {
  return container.length >= PREFIX_BYTES && ((container[5] ?? 0) & CONTAINER_FLAG_ENCRYPTED) !== 0;
}

export async function openContainer(
  container: Uint8Array,
  opts: {
    sessionId: number;
    /** Called with the sender's ephemeral pubkey; must return the AES-GCM key. */
    deriveKey?: (senderPub: Uint8Array) => Promise<CryptoKey>;
  },
): Promise<{ meta: PayloadMeta; data: Uint8Array }> {
  if (
    container.length < PREFIX_BYTES + 2 ||
    !MAGIC.every((b, i) => container[i] === b) ||
    container[4] !== CONTAINER_VERSION
  ) {
    throw new ContainerFormatError("unrecognized container");
  }
  const flags = container[5]!;

  let plain: Uint8Array;
  if (flags & CONTAINER_FLAG_ENCRYPTED) {
    if (!opts.deriveKey) throw new ContainerFormatError("encrypted container, no key source");
    const minLen = PREFIX_BYTES + EPK_BYTES + IV_BYTES + 16;
    if (container.length < minLen) throw new ContainerFormatError("truncated container");
    const senderPub = container.subarray(PREFIX_BYTES, PREFIX_BYTES + EPK_BYTES);
    const iv = container.subarray(PREFIX_BYTES + EPK_BYTES, PREFIX_BYTES + EPK_BYTES + IV_BYTES);
    const ct = container.subarray(PREFIX_BYTES + EPK_BYTES + IV_BYTES);
    const key = await opts.deriveKey(senderPub.slice());
    try {
      plain = new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: iv as BufferSource,
            additionalData: aad(opts.sessionId) as BufferSource,
          },
          key,
          ct as BufferSource,
        ),
      );
    } catch {
      throw new IntegrityError("decryption failed — wrong key or tampered stream");
    }
  } else {
    plain = container.subarray(PREFIX_BYTES);
  }

  if (plain.length < 2) throw new ContainerFormatError("truncated container");
  const metaLen = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint16(0);
  if (plain.length < 2 + metaLen) throw new ContainerFormatError("truncated container");
  let meta: PayloadMeta;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(plain.subarray(2, 2 + metaLen)));
    const m = parsed as Record<string, unknown>;
    if (
      typeof m !== "object" ||
      m === null ||
      (m["name"] !== null && typeof m["name"] !== "string") ||
      typeof m["mime"] !== "string" ||
      typeof m["size"] !== "number" ||
      typeof m["sha256"] !== "string"
    ) {
      throw new Error("shape");
    }
    meta = {
      name: m["name"] as string | null,
      mime: m["mime"] as string,
      size: m["size"] as number,
      sha256: m["sha256"] as string,
    };
  } catch {
    throw new ContainerFormatError("bad container metadata");
  }
  // Validate the declared size BEFORE any decompression — it bounds the gunzip.
  if (!Number.isInteger(meta.size) || meta.size < 1 || meta.size > MAX_TRANSFER_BYTES) {
    throw new ContainerFormatError("declared size out of range");
  }

  const body = plain.subarray(2 + metaLen);
  const data = flags & CONTAINER_FLAG_GZIP ? await gunzip(body, meta.size) : body;
  if (data.length !== meta.size) throw new IntegrityError("size mismatch");
  if (toB64url(await sha256(data)) !== meta.sha256) throw new IntegrityError("SHA-256 mismatch");
  return { meta, data };
}
