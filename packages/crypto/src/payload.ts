import { concatBytes, utf8 } from "./encoding.js";

/**
 * Plaintext payload envelope — what goes INSIDE encryptSecret / the live path.
 *
 * Text secrets stay raw UTF-8 bytes, exactly as they always were, so every
 * existing drop, sender, and receiver keeps working. A file attachment is:
 *
 *   [5B PAYLOAD_MAGIC][2B metaLen BE][meta JSON][file bytes]
 *
 * meta JSON = { name, mime }. Integrity/authenticity come from the layer
 * below (AES-GCM blob, or the live path's per-frame encryption + SHA ack),
 * so the envelope carries no digest of its own.
 *
 * The magic starts with a NUL byte: a textarea cannot produce one, and pasted
 * text never starts with NUL, so a raw-text payload can never be mistaken for
 * an envelope. (CLI stdin can carry arbitrary bytes; five fixed bytes make an
 * accidental match practically impossible.)
 */

/** "\0" + "ssf" + version 0x01 */
export const PAYLOAD_MAGIC = new Uint8Array([0x00, 0x73, 0x73, 0x66, 0x01]);

const META_LEN_BYTES = 2;
/** Filesystems cap names at 255 bytes; stay well under so creation can't fail on length. */
export const MAX_FILENAME_BYTES = 160;

export class PayloadFormatError extends Error {
  override name = "PayloadFormatError";
}

export interface FilePayload {
  kind: "file";
  name: string;
  mime: string;
  data: Uint8Array;
}

export interface TextPayload {
  kind: "text";
  text: string;
}

export type Payload = FilePayload | TextPayload;

/**
 * The name arrives from the other side of the wire and ends up in a download
 * attribute or on disk, so strip everything that lets it lie or misbehave:
 * directory components, ASCII controls, zero-width/bidi format characters
 * (which can visually disguise an extension), Windows-eaten trailing dots and
 * spaces, reserved device names (CON, NUL, COM1...), and leading dots (no
 * planted dotfiles). Capped by UTF-8 bytes so file creation can't fail on
 * filesystem name-length limits.
 */
export function sanitizeFilename(name: string): string {
  const base = name.split(/[/\\]/).pop() ?? "";
  let clean = base
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x1f\x7f]/g, "")
    .replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, "")
    .trim()
    .replace(/[. ]+$/, "");
  const chars = [...clean];
  while (chars.length > 0 && utf8(chars.join("")).length > MAX_FILENAME_BYTES) chars.pop();
  clean = chars.join("");
  if (clean === "") return "attachment";
  if (clean.startsWith(".")) clean = `attachment${clean}`;
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i.test(clean)) clean = `attachment-${clean}`;
  return clean;
}

/** Envelope size for a file of `dataLength` bytes — lets UIs show limits up front. */
export function filePayloadOverhead(name: string, mime: string): number {
  const metaJson = utf8(JSON.stringify({ name: sanitizeFilename(name), mime }));
  return PAYLOAD_MAGIC.length + META_LEN_BYTES + metaJson.length;
}

export function encodeFilePayload(name: string, mime: string, data: Uint8Array): Uint8Array {
  const metaJson = utf8(JSON.stringify({ name: sanitizeFilename(name), mime }));
  if (metaJson.length > 0xffff) throw new PayloadFormatError("File metadata too large");
  const metaLen = new Uint8Array(META_LEN_BYTES);
  new DataView(metaLen.buffer).setUint16(0, metaJson.length, false);
  return concatBytes(PAYLOAD_MAGIC, metaLen, metaJson, data);
}

function isEnvelope(bytes: Uint8Array): boolean {
  return (
    bytes.length >= PAYLOAD_MAGIC.length && PAYLOAD_MAGIC.every((b, i) => bytes[i] === b)
  );
}

/**
 * Interprets decrypted plaintext bytes: an envelope becomes a file payload,
 * anything else is legacy/plain text. Throws PayloadFormatError only on a
 * truncated or malformed envelope — never on plain text.
 */
export function decodePayload(bytes: Uint8Array): Payload {
  if (!isEnvelope(bytes)) {
    return { kind: "text", text: new TextDecoder().decode(bytes) };
  }
  const headerEnd = PAYLOAD_MAGIC.length + META_LEN_BYTES;
  if (bytes.length < headerEnd) throw new PayloadFormatError("Truncated file payload");
  const metaLen = new DataView(bytes.buffer, bytes.byteOffset + PAYLOAD_MAGIC.length, META_LEN_BYTES).getUint16(0, false);
  if (bytes.length < headerEnd + metaLen) throw new PayloadFormatError("Truncated file payload");
  let name: string;
  let mime: string;
  try {
    const meta: unknown = JSON.parse(
      new TextDecoder().decode(bytes.subarray(headerEnd, headerEnd + metaLen)),
    );
    const m = meta as Record<string, unknown>;
    if (typeof m !== "object" || m === null || typeof m["name"] !== "string" || typeof m["mime"] !== "string") {
      throw new Error("shape");
    }
    name = m["name"];
    mime = m["mime"];
  } catch {
    throw new PayloadFormatError("Malformed file payload metadata");
  }
  return {
    kind: "file",
    name: sanitizeFilename(name),
    mime,
    data: bytes.subarray(headerEnd + metaLen),
  };
}
