import { useEffect, useRef, useState } from "react";
import {
  DEFAULT_TTL_SECONDS,
  MAX_SECRET_BYTES,
  MAX_TTL_SECONDS,
} from "@secret-share/protocol";
import {
  deriveKeys,
  encryptSecret,
  generateCode,
  utf8,
  type DerivedKeys,
} from "@secret-share/crypto";
import { DropExistsError, parkDrop, revokeDrop } from "../lib/drop.js";
import { Signaling } from "../lib/ws.js";
import { senderLiveTransfer } from "../lib/rtc.js";
import { CopyButton } from "../components/CopyButton.js";
import { Countdown } from "../components/Countdown.js";

type Phase = "compose" | "sealing" | "ready" | "revoked" | "error";
type LiveStatus = "parked" | "peer-online" | "transferring" | "delivered";

const TTL_OPTIONS = [
  { label: "1 hour", value: 3600 },
  { label: "24 hours", value: DEFAULT_TTL_SECONDS },
  { label: "7 days", value: MAX_TTL_SECONDS },
];

export function Send() {
  const [phase, setPhase] = useState<Phase>("compose");
  const [live, setLive] = useState<LiveStatus>("parked");
  const [secret, setSecret] = useState("");
  const [ttl, setTtl] = useState(DEFAULT_TTL_SECONDS);
  const [code, setCode] = useState("");
  const [expiresAt, setExpiresAt] = useState(0);
  const [error, setError] = useState("");
  const sessionRef = useRef<{ signaling?: Signaling; busy: boolean; delivered?: boolean }>({
    busy: false,
  });
  const keysRef = useRef<DerivedKeys | null>(null);

  const bytes = new TextEncoder().encode(secret).length;
  const tooBig = bytes > MAX_SECRET_BYTES;

  useEffect(() => () => sessionRef.current.signaling?.close(), []);

  async function share() {
    setPhase("sealing");
    setError("");
    try {
      const plaintext = utf8(secret);
      // 409 means a 40-bit mailbox-id collision — regenerate and retry.
      let keys: DerivedKeys | null = null;
      let shareCode = "";
      for (let attempt = 0; attempt < 3 && !keys; attempt++) {
        const candidate = generateCode();
        const candidateKeys = await deriveKeys(candidate);
        try {
          const exp = await parkDrop(candidateKeys, await encryptSecret(candidateKeys, plaintext), ttl);
          setExpiresAt(exp);
          keys = candidateKeys;
          shareCode = candidate.code;
        } catch (e) {
          if (!(e instanceof DropExistsError)) throw e;
        }
      }
      if (!keys) throw new Error("Could not allocate a mailbox, please retry");

      keysRef.current = keys;
      setCode(shareCode);
      setPhase("ready");
      setLive("parked");
      void openLiveUpgrade(keys, plaintext);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPhase("error");
    }
  }

  /** Stay on the signaling room; if the receiver shows up, upgrade to direct P2P. */
  async function openLiveUpgrade(keys: DerivedKeys, plaintext: Uint8Array) {
    try {
      const signaling = await Signaling.connect(keys.mailboxId, "sender");
      sessionRef.current.signaling = signaling;
      signaling.on((msg) => {
        if (msg.t === "peer-joined") {
          // Once delivered, never offer the secret again — read-once applies
          // to the live path too, even for peers presenting the right code.
          if (sessionRef.current.delivered) return;
          setLive("peer-online");
          void attemptLive(signaling, keys, plaintext);
        } else if (msg.t === "peer-left") {
          setLive((s) => (s === "delivered" ? s : "parked"));
        }
      });
    } catch {
      // No live upgrade — the parked drop still covers delivery.
    }
  }

  async function attemptLive(signaling: Signaling, keys: DerivedKeys, plaintext: Uint8Array) {
    if (sessionRef.current.busy) return;
    sessionRef.current.busy = true;
    setLive("transferring");
    try {
      await senderLiveTransfer(signaling, keys, plaintext);
      sessionRef.current.delivered = true;
      signaling.send({ t: "delivered" });
      await signaling.next((m) => m.t === "delivered-ok", 5000);
      setLive("delivered");
    } catch {
      // P2P failed (NAT, timeout, tab switch...) — receiver falls back to the drop.
      setLive("parked");
    } finally {
      sessionRef.current.busy = false;
    }
  }

  async function revoke() {
    if (!keysRef.current) return;
    setPhase("sealing");
    try {
      await revokeDrop(keysRef.current);
      sessionRef.current.signaling?.close();
      setPhase("revoked");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPhase("error");
    }
  }

  if (phase === "compose" || phase === "sealing") {
    return (
      <section className="card">
        <h2>Share a secret</h2>
        <p className="muted">
          Encrypted in your browser before anything leaves it. The server only ever
          sees ciphertext.
        </p>
        <textarea
          autoFocus
          rows={8}
          placeholder="Paste an SSH key, API token, password..."
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          disabled={phase === "sealing"}
        />
        <div className="row">
          <span className={tooBig ? "danger" : "muted"}>
            {bytes.toLocaleString()} / {MAX_SECRET_BYTES.toLocaleString()} bytes
          </span>
          <label className="muted">
            Expires in{" "}
            <select value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
              {TTL_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
        </div>
        <button
          className="primary"
          disabled={!secret || tooBig || phase === "sealing"}
          onClick={() => void share()}
        >
          {phase === "sealing" ? "Sealing…" : "Encrypt & create share code"}
        </button>
      </section>
    );
  }

  if (phase === "revoked") {
    return (
      <section className="card">
        <h2>Secret destroyed</h2>
        <p>The encrypted drop was wiped from the server. The code is now useless.</p>
        <button onClick={() => location.reload()}>Share another secret</button>
      </section>
    );
  }

  if (phase === "error") {
    return (
      <section className="card">
        <h2>Something went wrong</h2>
        <p className="danger">{error}</p>
        <button onClick={() => setPhase("compose")}>Back</button>
      </section>
    );
  }

  const link = `${location.origin}/r#${code}`;
  return (
    <section className="card">
      <h2>Share this code</h2>
      <div className="code-display">
        <code>{code}</code>
        <CopyButton text={code} label="Copy code" />
      </div>
      <div className="code-display">
        <code className="small">{link}</code>
        <CopyButton text={link} label="Copy link" />
      </div>
      <p className="muted">
        Read it over a call, or send the link — the part after <code>#</code> never
        reaches any server.
      </p>
      <p className={`status status-${live}`}>
        {live === "parked" && (
          <>
            Encrypted copy parked — expires in <Countdown until={expiresAt} />. Keep this
            tab open to hand it over directly when the receiver arrives.
          </>
        )}
        {live === "peer-online" && "Receiver is online — connecting directly…"}
        {live === "transferring" && "Receiver connected — transferring directly…"}
        {live === "delivered" &&
          "Delivered directly, browser to browser. No copy remains on the server."}
      </p>
      {live !== "delivered" && (
        <button className="danger-outline" onClick={() => void revoke()}>
          Destroy secret now
        </button>
      )}
    </section>
  );
}
