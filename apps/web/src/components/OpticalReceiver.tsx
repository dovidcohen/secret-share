import { useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
import {
  FRAME_FLAG_ENCRYPTED,
  FountainDecoder,
  type FountainProgress,
  type OpticalIdentity,
  type PayloadMeta,
  deriveOpticalKeys,
  encodeKeyQr,
  generateIdentity,
  openContainer,
  parseFrame,
  sameSession,
} from "@secret-share/optical";
import { cameraSource, canvasSource, type FrameSource } from "../lib/scanner.js";
import { CopyButton } from "./CopyButton.js";

type Phase = "idle" | "keyshow" | "scanning" | "done" | "error";

interface Received {
  meta: PayloadMeta;
  data: Uint8Array;
  safety: string;
  url: string; // object URL for file download ("" for text)
}

export function OpticalReceiver({ loopback }: { loopback: boolean }) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [progress, setProgress] = useState<FountainProgress | null>(null);
  const [needsEncrypted, setNeedsEncrypted] = useState(false);
  const [received, setReceived] = useState<Received | null>(null);
  const [error, setError] = useState("");

  const videoRef = useRef<HTMLVideoElement>(null);
  const keyCanvasRef = useRef<HTMLCanvasElement>(null);
  const identityRef = useRef<OpticalIdentity | null>(null);
  const decoderRef = useRef<FountainDecoder | null>(null);
  const candidateRef = useRef<{ key: string; count: number } | null>(null);
  const finishingRef = useRef(false);
  const stopRef = useRef<(() => void) | null>(null);

  useEffect(
    () => () => {
      stopRef.current?.();
      if (received?.url) URL.revokeObjectURL(received.url);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  function fail(e: unknown) {
    stopRef.current?.();
    stopRef.current = null;
    identityRef.current = null;
    setError(e instanceof Error ? e.message : String(e));
    setPhase("error");
  }

  async function showKey() {
    try {
      // Fresh ephemeral key for every pairing — the QR really is one-time,
      // and a compromise of this tab can't unlock earlier recordings.
      identityRef.current = await generateIdentity();
      setPhase("keyshow");
      await new Promise((r) => setTimeout(r, 0)); // wait for the canvas to mount
      await QRCode.toCanvas(keyCanvasRef.current!, encodeKeyQr(identityRef.current.publicRaw), {
        errorCorrectionLevel: "M",
        margin: 2,
        scale: 5,
      });
    } catch (e) {
      fail(e);
    }
  }

  async function startScan() {
    try {
      decoderRef.current = null;
      finishingRef.current = false;
      setNeedsEncrypted(false);
      setProgress(null);
      setPhase("scanning");
      await new Promise((r) => setTimeout(r, 0)); // wait for the <video> to mount
      const source: FrameSource = loopback
        ? canvasSource("optical-sender-canvas")
        : cameraSource(videoRef.current!);
      stopRef.current = await source.start((results) => {
        for (const r of results) onScan(r.bytes);
      });
    } catch (e) {
      if (e instanceof DOMException && e.name === "NotAllowedError") {
        fail(new Error("Camera permission denied — receiving by QR needs the camera."));
      } else {
        fail(e);
      }
    }
  }

  // A sender restart is a burst of consistent frames; require a few in a row
  // before abandoning an in-progress decode so an interleaved hostile QR
  // can't reset reception over and over.
  const SESSION_SWITCH_FRAMES = 5;

  function onScan(bytes: Uint8Array) {
    if (finishingRef.current) return;
    const frame = parseFrame(bytes);
    if (!frame) return; // foreign QR in view — ignore
    let dec = decoderRef.current;
    if (dec && !sameSession(dec.params, frame.header)) {
      const h = frame.header;
      const key = `${h.sessionId}:${h.k}:${h.blockSize}:${h.totalLen}:${h.flags}`;
      const cand = candidateRef.current;
      candidateRef.current = cand?.key === key ? { key, count: cand.count + 1 } : { key, count: 1 };
      if (candidateRef.current.count < SESSION_SWITCH_FRAMES) return;
      dec = null; // consistent new stream — treat as a sender restart
    } else {
      candidateRef.current = null;
    }
    if (!dec) {
      dec = new FountainDecoder(frame.header);
      decoderRef.current = dec;
      candidateRef.current = null;
      setNeedsEncrypted(
        (frame.header.flags & FRAME_FLAG_ENCRYPTED) !== 0 && !identityRef.current,
      );
    }
    dec.addFrame(frame.header.seq, frame.payload);
    setProgress(dec.progress);
    if (dec.complete) {
      finishingRef.current = true;
      void finish(dec);
    }
  }

  async function finish(dec: FountainDecoder) {
    stopRef.current?.();
    stopRef.current = null;
    try {
      let safety = "";
      const { meta, data } = await openContainer(dec.data(), {
        sessionId: dec.params.sessionId,
        deriveKey: async (senderPub) => {
          const identity = identityRef.current;
          if (!identity) {
            throw new Error(
              "This is an encrypted transfer — go back and choose “Receive encrypted” so the sender can scan your pairing code.",
            );
          }
          const keys = await deriveOpticalKeys(
            identity.privateKey,
            senderPub,
            dec.params.sessionId,
            senderPub,
            identity.publicRaw,
          );
          safety = keys.safetyNumber;
          return keys.key;
        },
      });
      const isText = meta.name === null && meta.mime.startsWith("text/");
      const url = isText
        ? ""
        : URL.createObjectURL(new Blob([data.slice().buffer], { type: meta.mime || "application/octet-stream" }));
      identityRef.current = null; // ephemeral key served its purpose
      setReceived({ meta, data, safety, url });
      setPhase("done");
    } catch (e) {
      fail(e);
    }
  }

  if (phase === "idle") {
    return (
      <>
        <h2>Receive by QR</h2>
        <p className="muted">
          Point this device's camera at the sender's screen. Frames can arrive in any
          order — glare or a shaky hand just makes it take a moment longer.
        </p>
        <button className="primary" onClick={() => void startScan()}>
          Start camera
        </button>
        <button onClick={() => void showKey()}>
          Receive encrypted — show a pairing code first
        </button>
      </>
    );
  }

  if (phase === "keyshow") {
    return (
      <>
        <h2>Pairing code</h2>
        <p className="muted">
          Have the sender choose <strong>Encrypted</strong> and scan this code — it's a
          one-time public key; it reveals nothing. Then start your camera.
        </p>
        <div className="optical-stage">
          <canvas ref={keyCanvasRef} id="optical-receiver-key" />
        </div>
        <button className="primary" onClick={() => void startScan()}>
          Sender scanned it — start camera
        </button>
        <button
          onClick={() => {
            identityRef.current = null; // abandoning the pairing invalidates the key
            setPhase("idle");
          }}
        >
          Back
        </button>
      </>
    );
  }

  if (phase === "scanning") {
    // `resolved` avalanches at the end when locking on mid-stream; `collected`
    // climbs one per useful frame, so the bar reflects actual accumulation.
    // Cap at 97% — the exact finish point isn't knowable until it happens.
    const pct = progress
      ? Math.min(
          97,
          Math.round((Math.max(progress.resolved, progress.collected) / progress.k) * 100),
        )
      : 0;
    return (
      <>
        <h2>Scanning…</h2>
        {progress ? (
          <>
            <div className="progress-track">
              <div className="progress-fill" style={{ width: `${pct}%` }} />
            </div>
            <p className="muted">
              ~{pct}% · {progress.framesSeen} frames captured
            </p>
          </>
        ) : (
          <p className="muted">Looking for a stream — line up the sender's QR in view.</p>
        )}
        {!loopback && <video ref={videoRef} className="optical-video" playsInline muted />}
        {needsEncrypted && (
          <p className="danger">
            This stream is encrypted and you haven't shown a pairing code — it can't be
            decrypted when it completes. Go back and choose “Receive encrypted”.
          </p>
        )}
        <button
          onClick={() => {
            stopRef.current?.();
            stopRef.current = null;
            identityRef.current = null;
            decoderRef.current = null;
            candidateRef.current = null;
            setPhase("idle");
          }}
        >
          Cancel
        </button>
      </>
    );
  }

  if (phase === "error") {
    return (
      <>
        <h2>Something went wrong</h2>
        <p className="danger">{error}</p>
        <button onClick={() => setPhase("idle")}>Back</button>
      </>
    );
  }

  const isText = received && received.url === "";
  return (
    <>
      <h2>Received ✓</h2>
      {received?.safety && (
        <p className="muted">
          Safety number — confirm it matches the sender's screen:{" "}
          <span className="safety-number">{received.safety}</span>
        </p>
      )}
      {isText ? (
        <>
          <pre className="secret">{new TextDecoder().decode(received.data)}</pre>
          <CopyButton text={new TextDecoder().decode(received.data)} label="Copy" />
        </>
      ) : (
        received && (
          <p>
            <a href={received.url} download={received.meta.name ?? "received.bin"}>
              <button className="primary">
                Save {received.meta.name ?? "file"} ({(received.meta.size / 1024).toFixed(1)} KiB)
              </button>
            </a>
          </p>
        )
      )}
      <p className="muted">Integrity verified (SHA-256). Nothing was sent over any network.</p>
      <button
        onClick={() => {
          if (received?.url) URL.revokeObjectURL(received.url);
          setReceived(null);
          setPhase("idle");
        }}
      >
        Receive another
      </button>
    </>
  );
}
