import { HEADER_BYTES, OPTICAL_MAGIC, OPTICAL_VERSION } from "./constants.js";
import type { SessionParams } from "./fountain.js";
import { validateParams } from "./fountain.js";

/**
 * Wire frame = [20B header][blockSize payload], all integers big-endian.
 * Every frame is self-describing so a receiver can lock on mid-stream.
 * No per-frame checksum: QR's Reed-Solomon guarantees a decoded symbol is
 * intact, and the container SHA-256 is the end-to-end check.
 */

export interface FrameHeader extends SessionParams {
  seq: number;
}

export function packFrame(params: SessionParams, seq: number, payload: Uint8Array): Uint8Array {
  if (payload.length !== params.blockSize) throw new RangeError("payload/blockSize mismatch");
  const out = new Uint8Array(HEADER_BYTES + payload.length);
  const dv = new DataView(out.buffer);
  dv.setUint8(0, OPTICAL_MAGIC);
  dv.setUint8(1, OPTICAL_VERSION);
  dv.setUint32(2, params.sessionId);
  dv.setUint32(6, seq);
  dv.setUint16(10, params.k);
  dv.setUint16(12, params.blockSize);
  dv.setUint32(14, params.totalLen);
  dv.setUint8(18, params.flags);
  dv.setUint8(19, 0);
  out.set(payload, HEADER_BYTES);
  return out;
}

/** null for anything that isn't one of our frames (foreign QR, wrong version). */
export function parseFrame(
  bytes: Uint8Array,
): { header: FrameHeader; payload: Uint8Array } | null {
  if (bytes.length <= HEADER_BYTES) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (dv.getUint8(0) !== OPTICAL_MAGIC || dv.getUint8(1) !== OPTICAL_VERSION) return null;
  const header: FrameHeader = {
    sessionId: dv.getUint32(2),
    seq: dv.getUint32(6),
    k: dv.getUint16(10),
    blockSize: dv.getUint16(12),
    totalLen: dv.getUint32(14),
    flags: dv.getUint8(18),
  };
  if (!validateParams(header)) return null;
  const payload = bytes.subarray(HEADER_BYTES);
  if (payload.length !== header.blockSize) return null;
  return { header, payload };
}

/** Same transfer? Frames from another session mean the sender restarted. */
export function sameSession(a: SessionParams, b: SessionParams): boolean {
  return (
    a.sessionId === b.sessionId &&
    a.k === b.k &&
    a.blockSize === b.blockSize &&
    a.totalLen === b.totalLen &&
    a.flags === b.flags
  );
}
