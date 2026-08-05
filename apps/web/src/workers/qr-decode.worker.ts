/// <reference lib="webworker" />
import { prepareZXingModule, readBarcodes } from "zxing-wasm/reader";
import wasmUrl from "zxing-wasm/reader/zxing_reader.wasm?url";

// Serve the wasm from our own origin (Vite-bundled asset) so decoding keeps
// working with no network once the page has loaded — the air-gap promise.
prepareZXingModule({
  overrides: {
    locateFile: (path: string, prefix: string) =>
      path.endsWith(".wasm") ? wasmUrl : prefix + path,
  },
});

export interface DecodeRequest {
  id: number;
  width: number;
  height: number;
  buffer: ArrayBuffer;
}

export interface DecodeResponse {
  id: number;
  results: Array<{ bytes: Uint8Array; text: string }>;
}

self.onmessage = async (e: MessageEvent<DecodeRequest>) => {
  const { id, width, height, buffer } = e.data;
  let results: DecodeResponse["results"] = [];
  try {
    const image = new ImageData(new Uint8ClampedArray(buffer), width, height);
    const found = await readBarcodes(image, {
      formats: ["QRCode"],
      tryHarder: false, // live loop: a missed frame costs one frame interval, not correctness
      maxNumberOfSymbols: 1,
    });
    results = found.filter((r) => r.isValid).map((r) => ({ bytes: r.bytes, text: r.text }));
  } catch {
    // swallow — a bad frame is just a miss
  }
  (self as unknown as Worker).postMessage({ id, results } satisfies DecodeResponse);
};
