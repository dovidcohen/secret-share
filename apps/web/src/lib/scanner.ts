import type { DecodeRequest, DecodeResponse } from "../workers/qr-decode.worker.js";

export interface ScanResult {
  bytes: Uint8Array;
  text: string;
}

/**
 * One decoded-QR pipeline: ImageData in (transferred), results out.
 * Decoding runs in a Web Worker so a slow frame never stalls the camera.
 */
export class QrDecoder {
  private readonly worker: Worker;
  private nextId = 1;
  private readonly pending = new Map<number, (r: ScanResult[]) => void>();

  constructor() {
    this.worker = new Worker(new URL("../workers/qr-decode.worker.ts", import.meta.url), {
      type: "module",
    });
    this.worker.onmessage = (e: MessageEvent<DecodeResponse>) => {
      const { id, results } = e.data;
      this.pending.get(id)?.(results);
      this.pending.delete(id);
    };
  }

  decode(image: ImageData): Promise<ScanResult[]> {
    const id = this.nextId++;
    return new Promise((resolve) => {
      this.pending.set(id, resolve);
      const msg: DecodeRequest = {
        id,
        width: image.width,
        height: image.height,
        buffer: image.data.buffer as ArrayBuffer,
      };
      this.worker.postMessage(msg, [msg.buffer]);
    });
  }

  dispose(): void {
    this.worker.terminate();
    this.pending.clear();
  }
}

/**
 * A stream of decoded QR results. `camera` is the real thing; `canvas` reads
 * a same-page canvas so tests (and ?loopback mode) can exercise the full
 * render → decode path without camera hardware.
 */
export interface FrameSource {
  /** Start producing results; resolves to a stop/cleanup function. */
  start(onResults: (results: ScanResult[]) => void): Promise<() => void>;
}

export function cameraSource(video: HTMLVideoElement): FrameSource {
  return {
    async start(onResults) {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment", width: { ideal: 1280 }, height: { ideal: 720 } },
        audio: false,
      });
      video.srcObject = stream;
      await video.play();

      const decoder = new QrDecoder();
      const grab = document.createElement("canvas");
      const ctx = grab.getContext("2d", { willReadFrequently: true });
      let stopped = false;
      let busy = false; // one decode in flight; extra camera frames are dropped

      const schedule = () => {
        if (stopped) return;
        if ("requestVideoFrameCallback" in video) {
          video.requestVideoFrameCallback(() => pump());
        } else {
          requestAnimationFrame(() => pump());
        }
      };
      const pump = () => {
        schedule();
        if (stopped || busy || !ctx || video.readyState < 2 || video.videoWidth === 0) return;
        grab.width = video.videoWidth;
        grab.height = video.videoHeight;
        ctx.drawImage(video, 0, 0);
        const image = ctx.getImageData(0, 0, grab.width, grab.height);
        busy = true;
        void decoder.decode(image).then((results) => {
          busy = false;
          if (!stopped && results.length > 0) onResults(results);
        });
      };
      schedule();

      return () => {
        stopped = true;
        decoder.dispose();
        for (const track of stream.getTracks()) track.stop();
        video.srcObject = null;
      };
    },
  };
}

/** Looked up lazily by id each tick — the canvas may not be mounted yet. */
export function canvasSource(canvasId: string, intervalMs = 60): FrameSource {
  return {
    // eslint-disable-next-line @typescript-eslint/require-await
    async start(onResults) {
      const decoder = new QrDecoder();
      let busy = false;
      const timer = setInterval(() => {
        const canvas = document.getElementById(canvasId) as HTMLCanvasElement | null;
        if (busy || !canvas || canvas.width === 0) return;
        const ctx = canvas.getContext("2d");
        if (!ctx) return;
        const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
        busy = true;
        void decoder.decode(image).then((results) => {
          busy = false;
          if (results.length > 0) onResults(results);
        });
      }, intervalMs);
      return () => {
        clearInterval(timer);
        decoder.dispose();
      };
    },
  };
}
