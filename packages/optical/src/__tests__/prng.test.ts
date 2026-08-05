import { describe, expect, it } from "vitest";
import { FrameRng, splitmix32 } from "../prng.js";

// These vectors are part of the wire format: a sender and receiver that
// disagree on any of them cannot reconstruct each other's block sets.
// Never update them without bumping OPTICAL_VERSION.
const GOLDEN: Array<{ sessionId: number; seq: number; out: number[] }> = [
  {
    sessionId: 0xdeadbeef,
    seq: 0,
    out: [3842467093, 879304004, 3694663928, 2788030634, 934155191, 702880729, 3422146658, 169081873],
  },
  {
    sessionId: 0xdeadbeef,
    seq: 1,
    out: [918384028, 2289659536, 1254979768, 2357711205, 3708216614, 2253157537, 294037254, 2149283834],
  },
  {
    sessionId: 1,
    seq: 100000,
    out: [2542600603, 3876824757, 2306142348, 3483481029, 3758909895, 1755225701, 3470230265, 3319616226],
  },
];

describe("FrameRng", () => {
  it("matches the golden vectors (wire-format invariant)", () => {
    for (const { sessionId, seq, out } of GOLDEN) {
      const rng = new FrameRng(sessionId, seq);
      expect(out.map(() => rng.nextU32())).toEqual(out);
    }
  });

  it("is deterministic for the same (sessionId, seq)", () => {
    const a = new FrameRng(12345, 678);
    const b = new FrameRng(12345, 678);
    for (let i = 0; i < 100; i++) expect(a.nextU32()).toBe(b.nextU32());
  });

  it("produces distinct streams for adjacent seqs", () => {
    const a = new FrameRng(12345, 678);
    const b = new FrameRng(12345, 679);
    const as = Array.from({ length: 8 }, () => a.nextU32());
    const bs = Array.from({ length: 8 }, () => b.nextU32());
    expect(as).not.toEqual(bs);
  });

  it("nextInt stays in range and nextFloat in [0,1)", () => {
    const rng = new FrameRng(7, 7);
    for (let i = 0; i < 1000; i++) {
      const n = rng.nextInt(17);
      expect(n).toBeGreaterThanOrEqual(0);
      expect(n).toBeLessThan(17);
      const f = rng.nextFloat();
      expect(f).toBeGreaterThanOrEqual(0);
      expect(f).toBeLessThan(1);
    }
  });

  it("splitmix32 is deterministic and covers u32 range", () => {
    const a = splitmix32(0);
    const b = splitmix32(0);
    const seen = new Set<number>();
    for (let i = 0; i < 64; i++) {
      const v = a();
      expect(v).toBe(b());
      expect(Number.isInteger(v)).toBe(true);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(0xffffffff);
      seen.add(v);
    }
    expect(seen.size).toBe(64);
  });
});
