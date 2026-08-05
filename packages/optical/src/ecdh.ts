import { concatBytes, fromB64url, hkdfSha256, toCrockford, toB64url, utf8 } from "@secret-share/crypto";
import { EPK_BYTES } from "./container.js";

/**
 * Encrypted-mode key agreement. Nothing secret is ever displayed or typed:
 * the receiver shows its ephemeral P-256 public key as a static QR, the
 * sender scans it, and both sides derive the AES key via ECDH + HKDF. A
 * camera that records both screens learns two public keys and nothing else.
 *
 * P-256 because it is the one ECDH curve with universal WebCrypto support
 * and raw (65-byte uncompressed point) import/export.
 */

const V = "shareasecret/optical/v1";
export const KEY_QR_PREFIX = "SASO1:R:";

export interface OpticalIdentity {
  privateKey: CryptoKey;
  /** Raw uncompressed point, 65 bytes, starts 0x04. */
  publicRaw: Uint8Array;
}

export async function generateIdentity(): Promise<OpticalIdentity> {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { privateKey: pair.privateKey, publicRaw };
}

/** Text content of the receiver's key QR. */
export function encodeKeyQr(publicRaw: Uint8Array): string {
  return KEY_QR_PREFIX + toB64url(publicRaw);
}

/** null for anything that isn't a well-formed key QR. */
export function parseKeyQr(text: string): Uint8Array | null {
  if (!text.startsWith(KEY_QR_PREFIX)) return null;
  try {
    const bytes = fromB64url(text.slice(KEY_QR_PREFIX.length));
    return bytes.length === EPK_BYTES && bytes[0] === 0x04 ? bytes : null;
  } catch {
    return null;
  }
}

export interface OpticalSessionKeys {
  key: CryptoKey;
  /** 8 Crockford chars both sides display for eyeball comparison. */
  safetyNumber: string;
}

/**
 * Both sides call this with the SAME (sessionId, senderPub, receiverPub)
 * ordering; only privateKey/peerPublicRaw swap roles.
 */
export async function deriveOpticalKeys(
  privateKey: CryptoKey,
  peerPublicRaw: Uint8Array,
  sessionId: number,
  senderPub: Uint8Array,
  receiverPub: Uint8Array,
): Promise<OpticalSessionKeys> {
  const peer = await crypto.subtle.importKey(
    "raw",
    peerPublicRaw as BufferSource,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, privateKey, 256),
  );
  const sid = new Uint8Array(4);
  new DataView(sid.buffer).setUint32(0, sessionId >>> 0);
  const salt = concatBytes(sid, senderPub, receiverPub);
  const [keyRaw, safetyRaw] = await Promise.all([
    hkdfSha256(shared, salt, utf8(`${V}/key`), 32),
    hkdfSha256(shared, salt, utf8(`${V}/safety`), 5),
  ]);
  const key = await crypto.subtle.importKey(
    "raw",
    keyRaw as BufferSource,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
  return { key, safetyNumber: toCrockford(safetyRaw) };
}
