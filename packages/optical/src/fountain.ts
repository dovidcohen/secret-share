import {
  FRAME_FLAGS_MASK,
  MAX_BLOCK_BYTES,
  MAX_CONTAINER_BYTES,
  MAX_K,
} from "./constants.js";
import { FrameRng } from "./prng.js";
import { robustSolitonCdf, sampleDegree } from "./soliton.js";

/** Everything a receiver needs to lock onto a stream — carried in every frame. */
export interface SessionParams {
  /** Random u32 per transfer; a change mid-stream means a new transfer. */
  sessionId: number;
  /** Number of source blocks. */
  k: number;
  /** Bytes per block (frame payload size). */
  blockSize: number;
  /** Exact container byte length (last block is zero-padded). */
  totalLen: number;
  /** Frame-header flags (FRAME_FLAG_*). */
  flags: number;
}

/**
 * Frames arrive from an untrusted camera: a hostile QR can claim anything.
 * Reject parameter combinations we would never produce so a decoder can't
 * be talked into allocating unbounded state.
 */
export function validateParams(p: SessionParams): boolean {
  return (
    Number.isInteger(p.k) &&
    p.k >= 1 &&
    p.k <= MAX_K &&
    Number.isInteger(p.blockSize) &&
    p.blockSize >= 1 &&
    p.blockSize <= MAX_BLOCK_BYTES &&
    Number.isInteger(p.totalLen) &&
    p.totalLen >= 1 &&
    p.totalLen <= MAX_CONTAINER_BYTES &&
    (p.flags & ~FRAME_FLAGS_MASK) === 0 &&
    Math.ceil(p.totalLen / p.blockSize) === p.k
  );
}

/**
 * Block index set for frame `seq` — a pure function of (sessionId, seq, k),
 * shared by encoder and decoder. Frames seq < k are systematic (degree 1,
 * block = seq) so a clean uninterrupted pass needs zero XOR work; later
 * frames sample the robust soliton distribution.
 */
export function blockIndicesFor(
  sessionId: number,
  k: number,
  cdf: Float64Array,
  seq: number,
): number[] {
  if (seq < k) return [seq];
  const rng = new FrameRng(sessionId, seq);
  const d = sampleDegree(cdf, rng);
  // Floyd's sampling: d distinct indices in [0, k)
  const set = new Set<number>();
  for (let i = k - d; i < k; i++) {
    const j = rng.nextInt(i + 1);
    set.add(set.has(j) ? i : j);
  }
  return [...set];
}

function xorInto(target: Uint8Array, src: Uint8Array): void {
  for (let i = 0; i < target.length; i++) target[i] = (target[i] ?? 0) ^ (src[i] ?? 0);
}

export class PayloadTooLargeError extends Error {
  override name = "PayloadTooLargeError";
}

export class FountainEncoder {
  readonly params: SessionParams;
  private readonly blocks: Uint8Array[];
  private readonly cdf: Float64Array;

  constructor(data: Uint8Array, blockSize: number, sessionId: number, flags = 0) {
    if (data.length === 0) throw new RangeError("empty payload");
    const k = Math.ceil(data.length / blockSize);
    if (k > MAX_K) {
      throw new PayloadTooLargeError(`payload needs ${k} blocks; max ${MAX_K}`);
    }
    this.params = { sessionId: sessionId >>> 0, k, blockSize, totalLen: data.length, flags };
    this.blocks = [];
    for (let i = 0; i < k; i++) {
      const block = new Uint8Array(blockSize); // zero-padded tail
      block.set(data.subarray(i * blockSize, (i + 1) * blockSize));
      this.blocks.push(block);
    }
    this.cdf = robustSolitonCdf(k);
  }

  /** XOR-combined payload for frame `seq`; always exactly blockSize bytes. */
  payload(seq: number): Uint8Array {
    const out = new Uint8Array(this.params.blockSize);
    for (const idx of blockIndicesFor(this.params.sessionId, this.params.k, this.cdf, seq)) {
      xorInto(out, this.blocks[idx]!);
    }
    return out;
  }
}

interface PendingFrame {
  unknowns: Set<number>;
  data: Uint8Array;
}

export interface FountainProgress {
  /**
   * Blocks fully decoded. Misleading as a progress bar when locking on
   * mid-stream: peeling holds coded frames pending until coverage suffices,
   * then resolves in one cascade — use `collected` for smooth progress.
   */
  resolved: number;
  k: number;
  framesSeen: number;
  /** Frames accepted as (probably) innovative — climbs ~1 per useful frame toward ~k. */
  collected: number;
}

export class FountainDecoder {
  readonly params: SessionParams;
  private readonly cdf: Float64Array;
  private readonly blocks: (Uint8Array | null)[];
  private resolvedCount = 0;
  private collectedCount = 0;
  private pendingCount = 0;
  private readonly seen = new Set<number>();
  private readonly byBlock = new Map<number, Set<PendingFrame>>();
  /** Hostile-input ceilings: a healthy transfer needs ~1.15k frames. */
  private readonly seenCap: number;
  private readonly pendingCap: number;

  constructor(params: SessionParams) {
    if (!validateParams(params)) throw new RangeError("invalid session params");
    this.params = params;
    this.cdf = robustSolitonCdf(params.k);
    this.blocks = new Array<Uint8Array | null>(params.k).fill(null);
    this.seenCap = params.k * 16 + 1024;
    this.pendingCap = params.k * 2 + 64;
  }

  get complete(): boolean {
    return this.resolvedCount === this.params.k;
  }

  get progress(): FountainProgress {
    return {
      resolved: this.resolvedCount,
      k: this.params.k,
      framesSeen: this.seen.size,
      collected: this.collectedCount,
    };
  }

  /** Ingest one frame payload; returns true if it advanced decoding. */
  addFrame(seq: number, payload: Uint8Array): boolean {
    if (this.complete) return false;
    if (payload.length !== this.params.blockSize) return false;
    if (!Number.isInteger(seq) || seq < 0 || seq > 0xffffffff) return false;
    if (this.seen.has(seq)) return false; // camera sees each displayed frame 2-3×
    if (this.seen.size >= this.seenCap) return false; // stream is garbage — stop accumulating
    this.seen.add(seq);

    const indices = blockIndicesFor(this.params.sessionId, this.params.k, this.cdf, seq);
    const unknowns = new Set<number>();
    const data = payload.slice();
    for (const idx of indices) {
      const known = this.blocks[idx];
      if (known) xorInto(data, known);
      else unknowns.add(idx);
    }
    if (unknowns.size === 0) return false; // fully redundant
    this.collectedCount++;

    if (unknowns.size === 1) {
      this.resolve(unknowns.values().next().value as number, data);
      return true;
    }
    if (this.pendingCount >= this.pendingCap) {
      this.collectedCount--; // not stored, so it didn't really count
      return false;
    }
    const frame: PendingFrame = { unknowns, data };
    for (const idx of unknowns) {
      let waiting = this.byBlock.get(idx);
      if (!waiting) this.byBlock.set(idx, (waiting = new Set()));
      waiting.add(frame);
    }
    this.pendingCount++;
    return true;
  }

  /** Peeling cascade — iterative so a long chain can't blow the stack. */
  private resolve(blockIdx: number, blockData: Uint8Array): void {
    const queue: Array<[number, Uint8Array]> = [[blockIdx, blockData]];
    while (queue.length > 0) {
      const [idx, bytes] = queue.pop()!;
      if (this.blocks[idx]) continue; // resolved via another path meanwhile
      this.blocks[idx] = bytes;
      this.resolvedCount++;
      const waiting = this.byBlock.get(idx);
      if (!waiting) continue;
      this.byBlock.delete(idx);
      for (const frame of waiting) {
        xorInto(frame.data, bytes);
        frame.unknowns.delete(idx);
        if (frame.unknowns.size === 1) {
          const last = frame.unknowns.values().next().value as number;
          this.byBlock.get(last)?.delete(frame);
          this.pendingCount--;
          queue.push([last, frame.data]);
        }
      }
    }
  }

  /** Reassembled container bytes, trimmed to totalLen; throws if incomplete. */
  data(): Uint8Array {
    if (!this.complete) throw new Error("fountain decode incomplete");
    const out = new Uint8Array(this.params.totalLen);
    for (let i = 0; i < this.params.k; i++) {
      const off = i * this.params.blockSize;
      const block = this.blocks[i]!;
      out.set(block.subarray(0, Math.min(block.length, out.length - off)), off);
    }
    return out;
  }
}
