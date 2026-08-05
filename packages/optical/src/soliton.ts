import type { FrameRng } from "./prng.js";

/**
 * Robust soliton degree distribution (Luby transform).
 *
 * The CDF must be bit-identical on sender and receiver across JS engines,
 * because the receiver re-derives every frame's block set from its seq.
 * IEEE-754 +, −, ×, ÷ and sqrt are exactly specified; Math.log is NOT — so
 * the ln used here is built from exactly-specified ops only.
 */

const LN2 = 0.6931471805599453;
const SQRT2 = 1.4142135623730951;

/** Deterministic natural log: bit-exact argument reduction + atanh series. */
export function lnDet(x: number): number {
  if (!(x > 0) || !Number.isFinite(x)) throw new RangeError(`lnDet domain: ${x}`);
  // Decompose x = m·2^e with m ∈ [1, 2) straight from the IEEE bits.
  const buf = new DataView(new ArrayBuffer(8));
  buf.setFloat64(0, x);
  const hi = buf.getUint32(0);
  let e = ((hi >>> 20) & 0x7ff) - 1023;
  if (e === -1023) throw new RangeError(`lnDet subnormal: ${x}`); // never hit by our callers
  buf.setUint32(0, (hi & 0x800fffff) | (1023 << 20));
  let m = buf.getFloat64(0);
  // Reduce m to [√½, √2) so |z| ≤ 3−2√2 ≈ 0.1716 and the series converges fast.
  if (m > SQRT2) {
    m /= 2;
    e += 1;
  }
  // ln(m) = 2·atanh(z) with z = (m−1)/(m+1); z^33 ≈ 1e-26 ≪ double epsilon.
  const z = (m - 1) / (m + 1);
  const z2 = z * z;
  let term = z;
  let sum = z;
  for (let k = 3; k <= 33; k += 2) {
    term *= z2;
    sum += term / k;
  }
  return e * LN2 + 2 * sum;
}

export const SOLITON_C = 0.03;
export const SOLITON_DELTA = 0.5;

/**
 * Cumulative robust-soliton distribution over degrees 1..k.
 * cdf[d−1] = P(degree ≤ d); the last entry is pinned to exactly 1.
 */
export function robustSolitonCdf(k: number, c = SOLITON_C, delta = SOLITON_DELTA): Float64Array {
  if (!Number.isInteger(k) || k < 1) throw new RangeError(`invalid k: ${k}`);
  if (k === 1) return Float64Array.of(1);

  const r = Math.max(1, c * lnDet(k / delta) * Math.sqrt(k));
  const spike = Math.min(k, Math.max(1, Math.floor(k / r)));

  const pdf = new Float64Array(k);
  // ideal soliton ρ
  pdf[0] = 1 / k;
  for (let d = 2; d <= k; d++) pdf[d - 1] = 1 / (d * (d - 1));
  // robust component τ
  for (let d = 1; d < spike; d++) pdf[d - 1]! += r / (d * k);
  pdf[spike - 1]! += Math.max(0, (r * lnDet(Math.max(r / delta, 1 + 1e-9))) / k);

  const cdf = new Float64Array(k);
  let acc = 0;
  for (let d = 0; d < k; d++) {
    acc += pdf[d]!;
    cdf[d] = acc;
  }
  for (let d = 0; d < k; d++) cdf[d] = cdf[d]! / acc;
  cdf[k - 1] = 1;
  return cdf;
}

/** One PRNG draw → degree in [1, k] by binary search over the CDF. */
export function sampleDegree(cdf: Float64Array, rng: FrameRng): number {
  const u = rng.nextFloat();
  let lo = 0;
  let hi = cdf.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (cdf[mid]! > u) hi = mid;
    else lo = mid + 1;
  }
  return lo + 1;
}
