import { describe, expect, it } from "vitest";
import { FrameRng } from "../prng.js";
import { lnDet, robustSolitonCdf, sampleDegree } from "../soliton.js";

describe("lnDet", () => {
  it("agrees with Math.log to double precision across the working range", () => {
    const inputs = [0.5, 1, 2, Math.E, 10, 100, 1000, 2000, 65535, 1e6, 3.7, 0.9999, 1.0001];
    for (const x of inputs) {
      expect(Math.abs(lnDet(x) - Math.log(x))).toBeLessThanOrEqual(4e-16 * Math.max(1, Math.abs(Math.log(x))));
    }
  });

  it("rejects non-positive input", () => {
    expect(() => lnDet(0)).toThrow(RangeError);
    expect(() => lnDet(-3)).toThrow(RangeError);
    expect(() => lnDet(NaN)).toThrow(RangeError);
  });
});

describe("robustSolitonCdf", () => {
  it("is a valid CDF for a range of k", () => {
    for (const k of [1, 2, 3, 10, 100, 1000, 65535]) {
      const cdf = robustSolitonCdf(k);
      expect(cdf.length).toBe(k);
      expect(cdf[k - 1]).toBe(1);
      let prev = 0;
      for (let i = 0; i < k; i++) {
        expect(cdf[i]!).toBeGreaterThanOrEqual(prev);
        expect(cdf[i]!).toBeLessThanOrEqual(1);
        prev = cdf[i]!;
      }
    }
  });

  it("matches a golden slice for k=1000 (wire-format invariant)", () => {
    const cdf = robustSolitonCdf(1000);
    expect(cdf[0]).toBe(0.0077540607625721444);
    expect(cdf[9]).toBe(0.8708206698518195);
  });

  it("samples degrees with the expected robust-soliton shape", () => {
    const k = 1000;
    const cdf = robustSolitonCdf(k);
    const rng = new FrameRng(0xabc, 0xdef);
    const n = 100_000;
    let sum = 0;
    let ones = 0;
    for (let i = 0; i < n; i++) {
      const d = sampleDegree(cdf, rng);
      expect(d).toBeGreaterThanOrEqual(1);
      expect(d).toBeLessThanOrEqual(k);
      sum += d;
      if (d === 1) ones++;
    }
    const mean = sum / n;
    // robust soliton over k=1000: mean degree is O(ln k) — sanity band
    expect(mean).toBeGreaterThan(4);
    expect(mean).toBeLessThan(40);
    // degree-1 mass exists (decoder bootstrap) but is small
    expect(ones / n).toBeGreaterThan(0.001);
    expect(ones / n).toBeLessThan(0.1);
  });
});
