// Phase-0 spike: prove the two external deps do what the optical feature needs.
// 1. qrcode@1.5 byte mode must accept a raw Uint8Array and emit a V17 EC-L symbol.
// 2. zxing-wasm must decode that symbol back to byte-identical binary.
// Run: node apps/web/test/spike-optical.mjs
import QRCode from "qrcode";
import { readBarcodes } from "zxing-wasm/reader";

const V17_L_CAPACITY = 644; // QR v17, byte mode, EC L

// Payload with every byte value represented, plus values >0x7F up front to
// catch any charset mangling immediately.
const payload = new Uint8Array(V17_L_CAPACITY);
for (let i = 0; i < payload.length; i++) payload[i] = (255 - i) & 0xff;

// --- 1. generate ---
const png = await QRCode.toBuffer([{ data: payload, mode: "byte" }], {
  errorCorrectionLevel: "L",
  version: 17,
  margin: 2,
  scale: 4,
});
console.log(`generated: V17-L PNG, ${png.length} bytes, payload ${payload.length} bytes`);

// --- 2. decode ---
const results = await readBarcodes(new Blob([png]), {
  formats: ["QRCode"],
  tryHarder: true,
});
if (results.length !== 1) throw new Error(`expected 1 result, got ${results.length}`);
const got = new Uint8Array(results[0].bytes);
console.log(`decoded:   ${got.length} bytes, isValid=${results[0].isValid}`);

if (got.length !== payload.length) throw new Error(`length mismatch: ${got.length}`);
for (let i = 0; i < payload.length; i++) {
  if (got[i] !== payload[i]) throw new Error(`byte mismatch at ${i}: ${got[i]} != ${payload[i]}`);
}
console.log("PASS: byte-identical round-trip through V17-L QR");

// --- 3. timing: decode cost per frame (rough, Node-side) ---
const t0 = performance.now();
const N = 20;
for (let i = 0; i < N; i++) await readBarcodes(new Blob([png]), { formats: ["QRCode"] });
console.log(`decode avg: ${((performance.now() - t0) / N).toFixed(1)} ms/frame (Node)`);

// --- 4. oversized payload must throw, not truncate ---
try {
  await QRCode.toBuffer([{ data: new Uint8Array(V17_L_CAPACITY + 1), mode: "byte" }], {
    errorCorrectionLevel: "L",
    version: 17,
  });
  throw new Error("oversized payload did NOT throw");
} catch (e) {
  if (/did NOT throw/.test(e.message)) throw e;
  console.log(`PASS: oversized payload rejected (${e.message.slice(0, 60)}...)`);
}
