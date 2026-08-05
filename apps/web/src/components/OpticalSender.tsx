import { useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
import { randomBytes, utf8 } from "@secret-share/crypto";
import {
  DEFAULT_PROFILE,
  FRAME_FLAG_ENCRYPTED,
  FountainEncoder,
  MAX_TRANSFER_BYTES,
  PROFILES,
  type OpticalProfile,
  deriveOpticalKeys,
  generateIdentity,
  packFrame,
  parseKeyQr,
  sealContainer,
} from "@secret-share/optical";
import { cameraSource, canvasSource, type FrameSource } from "../lib/scanner.js";

type Phase = "compose" | "keyscan" | "confirm" | "streaming" | "error";

interface PendingTransfer {
  data: Uint8Array;
  meta: { name: string | null; mime: string };
  sessionId: number;
  key: CryptoKey;
  senderPub: Uint8Array;
}

const FPS_OPTIONS = [5, 8, 10, 15];

function randomSessionId(): number {
  return new DataView(randomBytes(4).buffer).getUint32(0);
}

/** Screen wake lock while streaming — a sleeping display is a dead transfer. */
function useWakeLock(active: boolean) {
  useEffect(() => {
    if (!active || !("wakeLock" in navigator)) return;
    let sentinel: WakeLockSentinel | null = null;
    let gone = false;
    const acquire = () => {
      void navigator.wakeLock
        .request("screen")
        .then((s) => {
          if (gone) void s.release();
          else sentinel = s;
        })
        .catch(() => undefined); // low battery etc. — not fatal
    };
    const onVisible = () => {
      if (document.visibilityState === "visible") acquire();
    };
    acquire();
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      gone = true;
      document.removeEventListener("visibilitychange", onVisible);
      void sentinel?.release();
    };
  }, [active]);
}

export function OpticalSender({ loopback }: { loopback: boolean }) {
  const [phase, setPhase] = useState<Phase>("compose");
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [profileId, setProfileId] = useState<OpticalProfile["id"]>(DEFAULT_PROFILE.id);
  const [fps, setFps] = useState(10);
  const [encrypted, setEncrypted] = useState(false);
  const [error, setError] = useState("");
  const [safety, setSafety] = useState("");
  const [streamInfo, setStreamInfo] = useState({ k: 0, seq: 0 });

  const canvasRef = useRef<HTMLCanvasElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const cleanupRef = useRef<(() => void) | null>(null);
  const pendingRef = useRef<PendingTransfer | null>(null);

  useWakeLock(phase === "streaming");
  useEffect(() => () => cleanupRef.current?.(), []);

  const profile = PROFILES[profileId];
  const payloadBytes = file ? file.size : utf8(text).length;
  const tooBig = payloadBytes > MAX_TRANSFER_BYTES;
  // ~15% fountain overhead is the expected cost of frame loss
  const etaSeconds = Math.ceil((Math.ceil(payloadBytes / profile.blockSize) * 1.15) / fps);

  function stop() {
    cleanupRef.current?.();
    cleanupRef.current = null;
  }

  function fail(e: unknown) {
    stop();
    setError(e instanceof Error ? e.message : String(e));
    setPhase("error");
  }

  async function start() {
    try {
      const data = file ? new Uint8Array(await file.arrayBuffer()) : utf8(text);
      const meta = file
        ? { name: file.name, mime: file.type || "application/octet-stream" }
        : { name: null, mime: "text/plain" };
      const sessionId = randomSessionId();

      if (!encrypted) {
        stream(await sealContainer(data, meta), sessionId, 0);
        return;
      }

      // Encrypted: scan the receiver's key QR first. Public keys only — a
      // camera recording both screens learns nothing useful.
      setPhase("keyscan");
      // wait a tick so the <video> is mounted
      await new Promise((r) => setTimeout(r, 0));
      const source: FrameSource = loopback
        ? canvasSource("optical-receiver-key")
        : cameraSource(videoRef.current!);
      const stopScan = await source.start((results) => {
        for (const r of results) {
          const receiverPub = parseKeyQr(r.text);
          if (!receiverPub) continue;
          stopScan();
          cleanupRef.current = null;
          void (async () => {
            try {
              const sender = await generateIdentity();
              const keys = await deriveOpticalKeys(
                sender.privateKey,
                receiverPub,
                sessionId,
                sender.publicRaw,
                receiverPub,
              );
              setSafety(keys.safetyNumber);
              // Pause before streaming: a swapped pairing QR means the payload
              // would go to the impostor. Let the sender look before sending.
              pendingRef.current = {
                data,
                meta,
                sessionId,
                key: keys.key,
                senderPub: sender.publicRaw,
              };
              setPhase("confirm");
            } catch (e) {
              fail(e);
            }
          })();
          return;
        }
      });
      cleanupRef.current = stopScan;
    } catch (e) {
      fail(e);
    }
  }

  function stream(container: Uint8Array, sessionId: number, flags: number) {
    const enc = new FountainEncoder(container, profile.blockSize, sessionId, flags);
    setStreamInfo({ k: enc.params.k, seq: 0 });
    setPhase("streaming");
    let seq = 0;
    let rendering = false;
    const timer = setInterval(() => {
      if (rendering || !canvasRef.current) return; // slow render: skip a beat, keep cadence
      rendering = true;
      const frame = packFrame(enc.params, seq, enc.payload(seq));
      const current = seq;
      seq++;
      QRCode.toCanvas(
        canvasRef.current,
        [{ data: new Uint8ClampedArray(frame.buffer, frame.byteOffset, frame.byteLength), mode: "byte" }],
        { errorCorrectionLevel: "L", version: profile.qrVersion, margin: 2, scale: 4 },
        (err) => {
          rendering = false;
          if (err) fail(err);
          else setStreamInfo({ k: enc.params.k, seq: current });
        },
      );
    }, 1000 / fps);
    cleanupRef.current = () => clearInterval(timer);
  }

  if (phase === "compose") {
    return (
      <>
        <h2>Send by QR</h2>
        <p className="muted">
          The data leaves this device as light: a stream of QR codes the receiving
          camera reads. Nothing touches the network — works in airplane mode.
        </p>
        <textarea
          rows={5}
          placeholder="Paste text to send... or attach a file below"
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            if (e.target.value) setFile(null);
          }}
          disabled={!!file}
        />
        <div className="row">
          <label className="muted">
            {file ? (
              <>
                {file.name} ({(file.size / 1024).toFixed(1)} KiB){" "}
                <button onClick={() => setFile(null)}>✕ remove</button>
              </>
            ) : (
              <>
                or file: <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
              </>
            )}
          </label>
        </div>
        <div className="row">
          <label className="muted">
            Density{" "}
            <select value={profileId} onChange={(e) => setProfileId(e.target.value as OpticalProfile["id"])}>
              {Object.values(PROFILES).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </select>
          </label>
          <label className="muted">
            Speed{" "}
            <select value={fps} onChange={(e) => setFps(Number(e.target.value))}>
              {FPS_OPTIONS.map((f) => (
                <option key={f} value={f}>
                  {f} fps
                </option>
              ))}
            </select>
          </label>
        </div>
        <label className="muted checkbox-row">
          <input type="checkbox" checked={encrypted} onChange={(e) => setEncrypted(e.target.checked)} />{" "}
          Encrypted — defeats recordings and onlookers (security cameras, shoulder
          surfers). You'll scan a pairing code from the receiver's screen first; needs
          a camera on this device too. Note: pair directly from the receiver's actual
          screen — the encryption is only as good as the code you scan.
        </label>
        <div className="row">
          <span className={tooBig ? "danger" : "muted"}>
            {payloadBytes.toLocaleString()} bytes
            {payloadBytes > 0 && !tooBig && ` · ~${etaSeconds}s at ${profile.label.split(" ")[0]}`}
            {tooBig && ` — max ${(MAX_TRANSFER_BYTES / 1024 / 1024).toFixed(0)} MiB`}
          </span>
        </div>
        <button className="primary" disabled={(payloadBytes === 0) || tooBig} onClick={() => void start()}>
          {encrypted ? "Scan receiver's code" : "Start streaming"}
        </button>
      </>
    );
  }

  if (phase === "keyscan") {
    return (
      <>
        <h2>Scan the receiver's pairing code</h2>
        <p className="muted">
          On the receiving device choose <strong>Receive → Encrypted</strong>; point
          this camera at the QR code it shows.
        </p>
        {!loopback && <video ref={videoRef} className="optical-video" playsInline muted />}
        <button onClick={() => { stop(); setPhase("compose"); }}>Cancel</button>
      </>
    );
  }

  if (phase === "confirm") {
    return (
      <>
        <h2>Paired — check before sending</h2>
        <p className="muted">
          This safety number was derived from the pairing. The receiver will show the
          same one when the transfer completes — if you want certainty it's their
          device you paired with (not a swapped code), glance at their screen after.
        </p>
        <p className="safety-number" style={{ textAlign: "center" }}>{safety}</p>
        <button
          className="primary"
          onClick={() => {
            const p = pendingRef.current;
            if (!p) return;
            void (async () => {
              try {
                stream(
                  await sealContainer(p.data, p.meta, {
                    key: p.key,
                    senderPub: p.senderPub,
                    sessionId: p.sessionId,
                  }),
                  p.sessionId,
                  FRAME_FLAG_ENCRYPTED,
                );
              } catch (e) {
                fail(e);
              }
            })();
          }}
        >
          Start streaming
        </button>
        <button
          onClick={() => {
            pendingRef.current = null;
            setSafety("");
            setPhase("compose");
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
        <button onClick={() => setPhase("compose")}>Back</button>
      </>
    );
  }

  return (
    <>
      <h2>Streaming…</h2>
      <div className="optical-stage">
        <canvas ref={canvasRef} id="optical-sender-canvas" />
        <span className="muted">
          Point the receiving camera here. Frame {streamInfo.seq + 1} · {streamInfo.k} blocks ·
          loops until you stop it.
        </span>
      </div>
      {safety && (
        <p className="muted">
          Safety number — should match the receiver's screen when it finishes:{" "}
          <span className="safety-number">{safety}</span>
        </p>
      )}
      <button
        className="danger-outline"
        onClick={() => {
          stop();
          setPhase("compose");
          setSafety("");
        }}
      >
        Stop streaming
      </button>
    </>
  );
}
