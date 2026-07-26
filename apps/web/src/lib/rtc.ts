import {
  FRAME_TYPE,
  HelloPayloadSchema,
  LIVE_TIMEOUT_MS,
  SECRET_CHUNK_BYTES,
  type HelloPayload,
  type SignalPayload,
} from "@secret-share/protocol";
import {
  confirmationMac,
  constantTimeEqual,
  decryptFrame,
  deriveSessionKeys,
  encryptFrame,
  fromB64url,
  randomBytes,
  sha256,
  toB64url,
  utf8,
  type DerivedKeys,
  type SessionKeys,
} from "@secret-share/crypto";
import type { Signaling } from "./ws.js";

const ICE_SERVERS: RTCIceServer[] = [
  { urls: ["stun:stun.cloudflare.com:3478", "stun:stun.l.google.com:19302"] },
];

export class LiveTransferError extends Error {
  override name = "LiveTransferError";
}

// ---------- binary framing ----------

function buildFrame(type: number, payload: Uint8Array): ArrayBuffer {
  const out = new Uint8Array(1 + payload.length);
  out[0] = type;
  out.set(payload, 1);
  return out.buffer;
}

function buildSecretChunk(idx: number, total: number, ciphertext: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + ciphertext.length);
  new DataView(out.buffer).setUint16(0, idx, false);
  new DataView(out.buffer).setUint16(2, total, false);
  out.set(ciphertext, 4);
  return out;
}

interface Frame {
  type: number;
  payload: Uint8Array;
}

function parseFrame(data: unknown): Frame | null {
  if (!(data instanceof ArrayBuffer) || data.byteLength < 1) return null;
  const bytes = new Uint8Array(data);
  return { type: bytes[0] as number, payload: bytes.subarray(1) };
}

/** Buffers incoming frames and lets protocol code await the next one. */
class FrameReader {
  private queue: Frame[] = [];
  private waiters: Array<() => void> = [];
  private closed = false;

  constructor(dc: RTCDataChannel) {
    dc.addEventListener("message", (e) => {
      const frame = parseFrame(e.data);
      if (frame) {
        this.queue.push(frame);
        this.wake();
      }
    });
    dc.addEventListener("close", () => {
      this.closed = true;
      this.wake();
    });
    dc.addEventListener("error", () => {
      this.closed = true;
      this.wake();
    });
  }

  private wake(): void {
    const ws = this.waiters;
    this.waiters = [];
    for (const w of ws) w();
  }

  async next(expectedType: number, timeoutMs: number): Promise<Uint8Array> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const frame = this.queue.shift();
      if (frame) {
        if (frame.type !== expectedType) {
          throw new LiveTransferError(
            `Unexpected frame 0x${frame.type.toString(16)}, wanted 0x${expectedType.toString(16)}`,
          );
        }
        return frame.payload;
      }
      if (this.closed) throw new LiveTransferError("Channel closed mid-transfer");
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new LiveTransferError("Timed out waiting for peer");
      await new Promise<void>((r) => {
        this.waiters.push(r);
        setTimeout(r, Math.min(remaining, 250));
      });
    }
  }
}

// ---------- handshake pieces shared by both roles ----------

function sendHello(dc: RTCDataChannel, role: "sender" | "receiver", salt: Uint8Array): void {
  const hello: HelloPayload = { v: 1, role, sessionSalt: toB64url(salt) };
  dc.send(buildFrame(FRAME_TYPE.HELLO, utf8(JSON.stringify(hello))));
}

async function readHello(
  reader: FrameReader,
  expectedRole: "sender" | "receiver",
  timeoutMs: number,
): Promise<Uint8Array> {
  const raw = await reader.next(FRAME_TYPE.HELLO, timeoutMs);
  const hello = HelloPayloadSchema.safeParse(JSON.parse(new TextDecoder().decode(raw)));
  if (!hello.success || hello.data.role !== expectedRole) {
    throw new LiveTransferError("Bad hello from peer");
  }
  return fromB64url(hello.data.sessionSalt);
}

async function verifyConfirm(
  session: SessionKeys,
  keys: DerivedKeys,
  senderSalt: Uint8Array,
  receiverSalt: Uint8Array,
  fromRole: "sender" | "receiver",
  received: Uint8Array,
): Promise<void> {
  const expected = await confirmationMac(session, keys.mailboxId, senderSalt, receiverSalt, fromRole);
  if (!constantTimeEqual(expected, received)) {
    throw new LiveTransferError("Key confirmation failed — the peer does not hold this code");
  }
}

// ---------- WebRTC plumbing ----------

function wireIce(pc: RTCPeerConnection, signaling: Signaling): void {
  pc.addEventListener("icecandidate", (e) => {
    if (!e.candidate?.candidate) return;
    signaling.send({
      t: "signal",
      payload: {
        kind: "ice",
        candidate: e.candidate.candidate,
        sdpMid: e.candidate.sdpMid,
        sdpMLineIndex: e.candidate.sdpMLineIndex,
      },
    });
  });
}

function applySignals(pc: RTCPeerConnection, signaling: Signaling): () => void {
  return signaling.on((msg) => {
    if (msg.t !== "signal") return;
    const p: SignalPayload = msg.payload;
    if (p.kind === "answer") {
      void pc.setRemoteDescription({ type: "answer", sdp: p.sdp }).catch(() => {});
    } else if (p.kind === "ice") {
      void pc
        .addIceCandidate({
          candidate: p.candidate,
          sdpMid: p.sdpMid,
          sdpMLineIndex: p.sdpMLineIndex,
        })
        .catch(() => {});
    }
  });
}

function waitForOpen(dc: RTCDataChannel, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    if (dc.readyState === "open") return resolve();
    const timer = setTimeout(
      () => reject(new LiveTransferError("DataChannel never opened")),
      timeoutMs,
    );
    dc.addEventListener(
      "open",
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
    dc.addEventListener(
      "close",
      () => {
        clearTimeout(timer);
        reject(new LiveTransferError("DataChannel closed before opening"));
      },
      { once: true },
    );
  });
}

// ---------- sender ----------

/**
 * Full sender-side live transfer: offer -> DataChannel -> hello/confirm ->
 * encrypted chunks -> verified ack. Resolves once the receiver proved it
 * decrypted the exact plaintext; the caller then tells the server "delivered".
 */
export async function senderLiveTransfer(
  signaling: Signaling,
  keys: DerivedKeys,
  plaintext: Uint8Array,
  timeoutMs: number = LIVE_TIMEOUT_MS,
): Promise<void> {
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  const dc = pc.createDataChannel("secret", { ordered: true });
  dc.binaryType = "arraybuffer";
  const reader = new FrameReader(dc);
  const unsubscribe = applySignals(pc, signaling);
  wireIce(pc, signaling);

  try {
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    signaling.send({ t: "signal", payload: { kind: "offer", sdp: offer.sdp ?? "" } });
    await waitForOpen(dc, timeoutMs);

    const senderSalt = randomBytes(16);
    sendHello(dc, "sender", senderSalt);
    const receiverSalt = await readHello(reader, "receiver", timeoutMs);
    const session = await deriveSessionKeys(keys, senderSalt, receiverSalt);

    // Receiver proves knowledge of the code BEFORE any secret bytes flow.
    const receiverConfirm = await reader.next(FRAME_TYPE.CONFIRM, timeoutMs);
    await verifyConfirm(session, keys, senderSalt, receiverSalt, "receiver", receiverConfirm);
    dc.send(
      buildFrame(
        FRAME_TYPE.CONFIRM,
        await confirmationMac(session, keys.mailboxId, senderSalt, receiverSalt, "sender"),
      ),
    );

    const total = Math.max(1, Math.ceil(plaintext.length / SECRET_CHUNK_BYTES));
    for (let idx = 0; idx < total; idx++) {
      const chunk = plaintext.subarray(idx * SECRET_CHUNK_BYTES, (idx + 1) * SECRET_CHUNK_BYTES);
      const ct = await encryptFrame(session, "s2r", idx, chunk);
      dc.send(buildFrame(FRAME_TYPE.SECRET, buildSecretChunk(idx, total, ct)));
    }

    const ackCt = await reader.next(FRAME_TYPE.ACK, timeoutMs);
    const ackHash = await decryptFrame(session, "r2s", 0, ackCt);
    if (!constantTimeEqual(ackHash, await sha256(plaintext))) {
      throw new LiveTransferError("Receiver acknowledged the wrong payload");
    }
    dc.send(buildFrame(FRAME_TYPE.BYE, new Uint8Array(0)));
  } finally {
    unsubscribe();
    try {
      dc.close();
    } catch {}
    pc.close();
  }
}

// ---------- receiver ----------

/**
 * Receiver side: answers the sender's offer, proves code knowledge first,
 * then decrypts and acknowledges. Resolves with the plaintext.
 */
export async function receiverLiveTransfer(
  signaling: Signaling,
  keys: DerivedKeys,
  offerSdp: string,
  timeoutMs: number = LIVE_TIMEOUT_MS,
): Promise<Uint8Array> {
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  const unsubscribe = signaling.on((msg) => {
    if (msg.t !== "signal" || msg.payload.kind !== "ice") return;
    void pc
      .addIceCandidate({
        candidate: msg.payload.candidate,
        sdpMid: msg.payload.sdpMid,
        sdpMLineIndex: msg.payload.sdpMLineIndex,
      })
      .catch(() => {});
  });
  wireIce(pc, signaling);

  const dcPromise = new Promise<RTCDataChannel>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new LiveTransferError("No DataChannel from sender")),
      timeoutMs,
    );
    pc.addEventListener("datachannel", (e) => {
      clearTimeout(timer);
      resolve(e.channel);
    });
  });

  try {
    await pc.setRemoteDescription({ type: "offer", sdp: offerSdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    signaling.send({ t: "signal", payload: { kind: "answer", sdp: answer.sdp ?? "" } });

    const dc = await dcPromise;
    dc.binaryType = "arraybuffer";
    const reader = new FrameReader(dc);
    await waitForOpen(dc, timeoutMs);

    const receiverSalt = randomBytes(16);
    sendHello(dc, "receiver", receiverSalt);
    const senderSalt = await readHello(reader, "sender", timeoutMs);
    const session = await deriveSessionKeys(keys, senderSalt, receiverSalt);

    dc.send(
      buildFrame(
        FRAME_TYPE.CONFIRM,
        await confirmationMac(session, keys.mailboxId, senderSalt, receiverSalt, "receiver"),
      ),
    );
    const senderConfirm = await reader.next(FRAME_TYPE.CONFIRM, timeoutMs);
    await verifyConfirm(session, keys, senderSalt, receiverSalt, "sender", senderConfirm);

    const chunks: Uint8Array[] = [];
    let total = 1;
    for (let idx = 0; idx < total; idx++) {
      const payload = await reader.next(FRAME_TYPE.SECRET, timeoutMs);
      const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
      const gotIdx = view.getUint16(0, false);
      total = view.getUint16(2, false);
      if (gotIdx !== idx || total < 1 || total > 4) {
        throw new LiveTransferError("Bad chunk sequence");
      }
      chunks.push(await decryptFrame(session, "s2r", idx, payload.subarray(4)));
    }
    const plaintext = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let off = 0;
    for (const c of chunks) {
      plaintext.set(c, off);
      off += c.length;
    }

    dc.send(buildFrame(FRAME_TYPE.ACK, await encryptFrame(session, "r2s", 0, await sha256(plaintext))));
    // Wait for the sender's BYE so the ACK flushes before we tear down the channel.
    await reader.next(FRAME_TYPE.BYE, 3000).catch(() => {});
    return plaintext;
  } finally {
    unsubscribe();
    pc.close();
  }
}
