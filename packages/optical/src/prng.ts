/**
 * Deterministic PRNG for fountain frames. The receiver re-derives each
 * frame's block set from (sessionId, seq) alone, so the sequence must be
 * bit-identical on every JS engine — only u32 integer ops here, never
 * Math.random or engine-variant float math.
 */

const GOLDEN = 0x9e3779b9;

/** splitmix32 — expands a 32-bit seed into well-mixed u32s (xoshiro seeding). */
export function splitmix32(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + GOLDEN) >>> 0;
    let z = s;
    z = Math.imul(z ^ (z >>> 16), 0x21f0aaad);
    z = Math.imul(z ^ (z >>> 15), 0x735a2d97);
    return (z ^ (z >>> 15)) >>> 0;
  };
}

function rotl(x: number, k: number): number {
  return ((x << k) | (x >>> (32 - k))) >>> 0;
}

/** xoshiro128** seeded from (sessionId, seq) via splitmix32. */
export class FrameRng {
  private s0: number;
  private s1: number;
  private s2: number;
  private s3: number;

  constructor(sessionId: number, seq: number) {
    // imul(seq, GOLDEN) is injective mod 2^32 (GOLDEN is odd), so every seq
    // within a session seeds a distinct stream.
    const mix = splitmix32((sessionId ^ Math.imul(seq, GOLDEN)) >>> 0);
    this.s0 = mix();
    this.s1 = mix();
    this.s2 = mix();
    this.s3 = mix();
    if ((this.s0 | this.s1 | this.s2 | this.s3) === 0) this.s0 = 1; // all-zero state is a fixed point
  }

  nextU32(): number {
    const r = Math.imul(rotl(Math.imul(this.s1, 5) >>> 0, 7), 9) >>> 0;
    const t = (this.s1 << 9) >>> 0;
    this.s2 = (this.s2 ^ this.s0) >>> 0;
    this.s3 = (this.s3 ^ this.s1) >>> 0;
    this.s1 = (this.s1 ^ this.s2) >>> 0;
    this.s0 = (this.s0 ^ this.s3) >>> 0;
    this.s2 = (this.s2 ^ t) >>> 0;
    this.s3 = rotl(this.s3, 11);
    return r;
  }

  /**
   * Integer in [0, n). Modulo bias is < n/2^32 — statistically irrelevant for
   * n ≤ 2^16, and both sides compute it identically, which is what matters.
   */
  nextInt(n: number): number {
    return this.nextU32() % n;
  }

  /** Uniform in [0, 1) — one draw, one division, both exactly specified. */
  nextFloat(): number {
    return this.nextU32() / 0x1_0000_0000;
  }
}
