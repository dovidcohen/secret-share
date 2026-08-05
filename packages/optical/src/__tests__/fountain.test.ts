import { describe, expect, it } from "vitest";
import {
  FountainDecoder,
  FountainEncoder,
  PayloadTooLargeError,
  validateParams,
} from "../fountain.js";
import { packFrame, parseFrame, sameSession } from "../frame.js";
import { MAX_BLOCK_BYTES, MAX_CONTAINER_BYTES, MAX_K } from "../constants.js";
import { FrameRng } from "../prng.js";

function testData(len: number, seed = 1): Uint8Array {
  const rng = new FrameRng(seed, 0);
  const data = new Uint8Array(len);
  for (let i = 0; i < len; i++) data[i] = rng.nextU32() & 0xff;
  return data;
}

describe("fountain encode/decode", () => {
  it("completes from exactly the systematic frames, in order", () => {
    const data = testData(10_000);
    const enc = new FountainEncoder(data, 347, 0x1111);
    const dec = new FountainDecoder(enc.params);
    for (let seq = 0; seq < enc.params.k; seq++) {
      dec.addFrame(seq, enc.payload(seq));
    }
    expect(dec.complete).toBe(true);
    expect(dec.data()).toEqual(data);
  });

  it("recovers under heavy loss and shuffled arrival", () => {
    const data = testData(50_000, 2);
    const enc = new FountainEncoder(data, 624, 0x2222);
    const k = enc.params.k;
    // drop ~40% of frames deterministically, shuffle the survivors
    const survivors: number[] = [];
    const drop = new FrameRng(99, 99);
    for (let seq = 0; seq < k * 3; seq++) {
      if (drop.nextFloat() >= 0.4) survivors.push(seq);
    }
    for (let i = survivors.length - 1; i > 0; i--) {
      const j = drop.nextInt(i + 1);
      [survivors[i], survivors[j]] = [survivors[j]!, survivors[i]!];
    }
    const dec = new FountainDecoder(enc.params);
    let used = 0;
    for (const seq of survivors) {
      if (dec.complete) break;
      dec.addFrame(seq, enc.payload(seq));
      used++;
    }
    expect(dec.complete).toBe(true);
    expect(dec.data()).toEqual(data);
    // fountain overhead should be modest (typically ≤ 1.15×K, allow slack)
    expect(used).toBeLessThan(k * 1.6);
  });

  it("locks on mid-stream (receiver starts at an arbitrary seq)", () => {
    const data = testData(20_000, 3);
    const enc = new FountainEncoder(data, 347, 0x3333);
    const dec = new FountainDecoder(enc.params);
    let lastCollected = 0;
    for (let seq = 137; !dec.complete; seq++) {
      dec.addFrame(seq, enc.payload(seq));
      // `collected` is the smooth progress signal: monotone, no end-avalanche
      expect(dec.progress.collected).toBeGreaterThanOrEqual(lastCollected);
      lastCollected = dec.progress.collected;
      expect(seq).toBeLessThan(137 + enc.params.k * 3); // must terminate
    }
    expect(dec.data()).toEqual(data);
    // nearly every pre-completion frame should have counted toward progress
    expect(lastCollected).toBeGreaterThanOrEqual(enc.params.k * 0.9);
  });

  it("ignores duplicate frames", () => {
    const data = testData(5_000, 4);
    const enc = new FountainEncoder(data, 347, 0x4444);
    const dec = new FountainDecoder(enc.params);
    expect(dec.addFrame(0, enc.payload(0))).toBe(true);
    expect(dec.addFrame(0, enc.payload(0))).toBe(false);
    expect(dec.progress.framesSeen).toBe(1);
  });

  it("handles k=1 (payload smaller than one block)", () => {
    const data = testData(17, 5);
    const enc = new FountainEncoder(data, 347, 0x5555);
    expect(enc.params.k).toBe(1);
    const dec = new FountainDecoder(enc.params);
    dec.addFrame(0, enc.payload(0));
    expect(dec.complete).toBe(true);
    expect(dec.data()).toEqual(data);
  });

  it("round-trips a 512 KiB payload from non-systematic frames only", () => {
    const data = testData(512 * 1024, 6);
    const enc = new FountainEncoder(data, 983, 0x6666);
    const k = enc.params.k;
    const dec = new FountainDecoder(enc.params);
    // start beyond the systematic prefix: every frame is a random XOR combo
    let used = 0;
    for (let seq = k; !dec.complete; seq++) {
      dec.addFrame(seq, enc.payload(seq));
      used++;
      expect(used).toBeLessThan(k * 3); // must terminate
    }
    expect(dec.data()).toEqual(data);
  });

  it("reports progress and refuses data() until complete", () => {
    const data = testData(10_000, 7);
    const enc = new FountainEncoder(data, 347, 0x7777);
    const dec = new FountainDecoder(enc.params);
    expect(() => dec.data()).toThrow(/incomplete/);
    dec.addFrame(0, enc.payload(0));
    expect(dec.progress.resolved).toBe(1);
    expect(dec.progress.k).toBe(enc.params.k);
  });

  it("peekBlock exposes a resolved block early (container-prefix reads)", () => {
    const data = testData(10_000, 12);
    const enc = new FountainEncoder(data, 347, 0x8888);
    const dec = new FountainDecoder(enc.params);
    expect(dec.peekBlock(0)).toBeNull();
    dec.addFrame(1, enc.payload(1)); // some other block first
    expect(dec.peekBlock(0)).toBeNull();
    dec.addFrame(0, enc.payload(0)); // duplicates of seq 0 are fine to re-send
    dec.addFrame(0, enc.payload(0));
    expect(dec.peekBlock(0)).toEqual(data.subarray(0, 347));
    expect(dec.complete).toBe(false);
  });

  it("rejects payloads that exceed MAX_K blocks", () => {
    // claim a huge payload without allocating one: constructor checks first
    expect(() => new FountainEncoder(new Uint8Array((MAX_K + 1) * 10), 10, 1)).toThrow(
      PayloadTooLargeError,
    );
  });
});

describe("frame pack/parse", () => {
  const params = { sessionId: 0xcafe0001, k: 42, blockSize: 347, totalLen: 14_400, flags: 1 };

  it("round-trips header and payload", () => {
    const payload = testData(347, 8);
    const frame = packFrame(params, 7, payload);
    expect(frame.length).toBe(20 + 347);
    const parsed = parseFrame(frame);
    expect(parsed).not.toBeNull();
    expect(parsed!.header).toEqual({ ...params, seq: 7 });
    expect(parsed!.payload).toEqual(payload);
    expect(sameSession(parsed!.header, params)).toBe(true);
  });

  it("rejects foreign bytes, wrong version, and truncation", () => {
    expect(parseFrame(new Uint8Array(0))).toBeNull();
    expect(parseFrame(new Uint8Array(400))).toBeNull(); // zero magic
    const frame = packFrame(params, 7, testData(347, 9));
    frame[1] = 0x02; // future version
    expect(parseFrame(frame)).toBeNull();
    const good = packFrame(params, 7, testData(347, 9));
    expect(parseFrame(good.subarray(0, 100))).toBeNull(); // payload/blockSize mismatch
  });

  it("rejects headers with inconsistent params", () => {
    const frame = packFrame(params, 7, testData(347, 10));
    // corrupt k so ceil(totalLen/blockSize) no longer matches
    frame[10] = 0x00;
    frame[11] = 0x01;
    expect(parseFrame(frame)).toBeNull();
  });

  it("detects a session change", () => {
    expect(sameSession(params, { ...params, sessionId: 0xcafe0002 })).toBe(false);
    expect(sameSession(params, { ...params, flags: 0 })).toBe(false);
  });

  it("rejects hostile parameters a v1 sender would never produce", () => {
    expect(validateParams(params)).toBe(true);
    // unknown flag bits
    expect(validateParams({ ...params, flags: 0x80 })).toBe(false);
    // oversized blocks
    const bigBlock = MAX_BLOCK_BYTES + 1;
    expect(
      validateParams({ ...params, blockSize: bigBlock, k: Math.ceil(params.totalLen / bigBlock) }),
    ).toBe(false);
    // container beyond any legitimate transfer
    const hugeLen = MAX_CONTAINER_BYTES + 1;
    expect(
      validateParams({ ...params, totalLen: hugeLen, k: Math.ceil(hugeLen / params.blockSize) }),
    ).toBe(false);
    // a frame carrying unknown flags is treated as foreign
    const frame = packFrame(params, 7, testData(347, 11));
    frame[18] = 0x81;
    expect(parseFrame(frame)).toBeNull();
    // decoder refuses to construct on hostile params
    expect(() => new FountainDecoder({ ...params, flags: 0x80 })).toThrow(RangeError);
  });
});
