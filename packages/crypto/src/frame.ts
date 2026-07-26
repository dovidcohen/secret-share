import type { SessionKeys } from "./kdf.js";
import { utf8 } from "./encoding.js";

export type FrameDirection = "s2r" | "r2s";

/**
 * Deterministic 12-byte IV: 4-byte direction tag + 8-byte big-endian sequence.
 * Safe because kFrame is unique per session (per-session salts in the HKDF),
 * and each (direction, seq) pair is used at most once within a session.
 */
function frameIv(dir: FrameDirection, seq: number): Uint8Array {
  const iv = new Uint8Array(12);
  iv.set(utf8(dir === "s2r" ? "s2r\0" : "r2s\0"), 0);
  new DataView(iv.buffer).setBigUint64(4, BigInt(seq), false);
  return iv;
}

function aad(dir: FrameDirection, seq: number): Uint8Array {
  return utf8(`secret-share/v1/frame/${dir}/${seq}`);
}

export async function encryptFrame(
  session: Pick<SessionKeys, "kFrame">,
  dir: FrameDirection,
  seq: number,
  data: Uint8Array,
): Promise<Uint8Array> {
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: frameIv(dir, seq) as BufferSource, additionalData: aad(dir, seq) as BufferSource },
    session.kFrame,
    data as BufferSource,
  );
  return new Uint8Array(ct);
}

export async function decryptFrame(
  session: Pick<SessionKeys, "kFrame">,
  dir: FrameDirection,
  seq: number,
  frame: Uint8Array,
): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: frameIv(dir, seq) as BufferSource, additionalData: aad(dir, seq) as BufferSource },
    session.kFrame,
    frame as BufferSource,
  );
  return new Uint8Array(pt);
}
