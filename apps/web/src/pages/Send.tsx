import { useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
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
import {
  DropExistsError,
  PlanInactiveError,
  SessionExpiredError,
  parkDrop,
  revokeDrop,
} from "../lib/drop.js";
import { Signaling } from "../lib/ws.js";
import { senderLiveTransfer } from "../lib/rtc.js";
import { loginUrl } from "../lib/auth.js";
import { useSession } from "../lib/session.js";
import { useTenant } from "../lib/tenant.js";
import { CopyButton } from "../components/CopyButton.js";
import { Countdown } from "../components/Countdown.js";
import { SignInGate } from "../components/SignInGate.js";

type Phase = "compose" | "sealing" | "ready" | "revoked" | "expired" | "error";
type LiveStatus = "parked" | "peer-online" | "transferring" | "delivered";

const TTL_OPTIONS = [
  { label: "1 hour", value: 3600 },
  { label: "24 hours", value: DEFAULT_TTL_SECONDS },
  { label: "7 days", value: MAX_TTL_SECONDS },
];

export function Send() {
  const tenant = useTenant();
  const { state: sessionState } = useSession();
  const [phase, setPhase] = useState<Phase>("compose");
  const [live, setLive] = useState<LiveStatus>("parked");
  const [secret, setSecret] = useState("");
  const [ttl, setTtl] = useState(DEFAULT_TTL_SECONDS);
  const [liveOnly, setLiveOnly] = useState(false);
  const [code, setCode] = useState("");
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [expiresAt, setExpiresAt] = useState(0);
  const [error, setError] = useState("");
  const sessionRef = useRef<{ signaling?: Signaling; busy: boolean; delivered?: boolean }>({
    busy: false,
  });
  const keysRef = useRef<DerivedKeys | null>(null);

  const bytes = new TextEncoder().encode(secret).length;
  const tooBig = bytes > MAX_SECRET_BYTES;

  useEffect(() => () => sessionRef.current.signaling?.close(), []);

  useEffect(() => {
    if (!code) return;
    void QRCode.toDataURL(`${location.origin}/r#${code}`, {
      margin: 1,
      width: 480,
      errorCorrectionLevel: "M",
    }).then(setQrDataUrl);
  }, [code]);

  async function share() {
    setPhase("sealing");
    setError("");
    try {
      const plaintext = utf8(secret);
      let keys: DerivedKeys | null = null;
      let shareCode = "";

      if (liveOnly) {
        // Direct-only: nothing is uploaded, not even ciphertext. The secret
        // lives exclusively in this tab until it is handed over.
        const candidate = generateCode();
        keys = await deriveKeys(candidate, tenant?.tenantId);
        shareCode = candidate.code;
      } else {
        // 409 means a 40-bit mailbox-id collision — regenerate and retry.
        for (let attempt = 0; attempt < 3 && !keys; attempt++) {
          const candidate = generateCode();
          const candidateKeys = await deriveKeys(candidate, tenant?.tenantId);
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
      }

      keysRef.current = keys;
      setCode(shareCode);
      setPhase("ready");
      setLive("parked");
      void openLiveUpgrade(keys, plaintext, liveOnly);
    } catch (e) {
      if (e instanceof SessionExpiredError) {
        // The typed secret stays in state; redirecting this tab would destroy it.
        setPhase("expired");
        return;
      }
      if (e instanceof PlanInactiveError) {
        setError(
          "Sending is paused because your organization's trial or subscription " +
            "has ended. An admin can reactivate it from the Admin page.",
        );
        setPhase("error");
        return;
      }
      setError(e instanceof Error ? e.message : String(e));
      setPhase("error");
    }
  }

  /** Stay on the signaling room; if the receiver shows up, transfer directly. */
  async function openLiveUpgrade(keys: DerivedKeys, plaintext: Uint8Array, directOnly: boolean) {
    try {
      const signaling = await Signaling.connect(keys.mailboxId, "sender");
      sessionRef.current.signaling = signaling;
      signaling.on((msg) => {
        if (msg.t === "peer-joined") {
          // Once delivered, never offer the secret again — read-once applies
          // to the live path too, even for peers presenting the right code.
          if (sessionRef.current.delivered) return;
          setLive("peer-online");
          void attemptLive(signaling, keys, plaintext, directOnly);
        } else if (msg.t === "peer-left") {
          setLive((s) => (s === "delivered" ? s : "parked"));
        }
      });
    } catch (e) {
      if (directOnly) {
        setError("Could not reach the connection service — direct-only sharing needs it to find your receiver.");
        setPhase("error");
      }
      // Otherwise: no live upgrade — the parked drop still covers delivery.
    }
  }

  async function attemptLive(
    signaling: Signaling,
    keys: DerivedKeys,
    plaintext: Uint8Array,
    directOnly: boolean,
  ) {
    if (sessionRef.current.busy) return;
    sessionRef.current.busy = true;
    setLive("transferring");
    try {
      await senderLiveTransfer(signaling, keys, plaintext);
      sessionRef.current.delivered = true;
      if (!directOnly) {
        signaling.send({ t: "delivered", senderTag: keys.senderTag });
        await signaling.next((m) => m.t === "delivered-ok", 5000);
      }
      setLive("delivered");
    } catch {
      // P2P failed (NAT, timeout, tab switch...). With a parked drop the
      // receiver falls back automatically; in direct-only mode they can retry.
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

  if (tenant && sessionState.status === "anon" && (phase === "compose" || phase === "sealing")) {
    return <SignInGate />;
  }

  if (phase === "expired") {
    return (
      <section className="card">
        <h2>Your session expired — your secret is safe in this tab</h2>
        <p className="muted">
          Sign in again in a new tab, then come back here and retry. Nothing you
          typed has been lost or uploaded.
        </p>
        <div className="row">
          <button
            className="primary"
            onClick={() => window.open(loginUrl("/"), "_blank")}
          >
            Sign in again (new tab)
          </button>
          <button onClick={() => void share()}>Retry</button>
        </div>
      </section>
    );
  }

  if (phase === "compose" || phase === "sealing") {
    const checkingSession = tenant !== null && sessionState.status === "loading";
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
          {!liveOnly && (
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
          )}
        </div>
        <label className="muted checkbox-row">
          <input
            type="checkbox"
            checked={liveOnly}
            onChange={(e) => setLiveOnly(e.target.checked)}
          />{" "}
          Direct transfer only — upload nothing, not even encrypted. Requires both of
          you online at the same time; keep this tab open until delivered.
        </label>
        <button
          className="primary"
          disabled={!secret || tooBig || phase === "sealing" || checkingSession}
          onClick={() => void share()}
        >
          {phase === "sealing"
            ? "Sealing…"
            : checkingSession
              ? "Checking sign-in…"
              : "Encrypt & create share code"}
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
      {qrDataUrl && live !== "delivered" && (
        <div className="qr">
          <img src={qrDataUrl} alt={`QR code for ${link}`} />
          <span className="muted">…or scan to receive on a phone</span>
        </div>
      )}
      <p className="muted">
        Read it over a call, or send the link — the part after <code>#</code> never
        reaches any server.
      </p>
      <p className={`status status-${live}`}>
        {live === "parked" &&
          (liveOnly ? (
            <>
              Nothing has been uploaded — the secret exists only in this tab. Keep it
              open; the transfer starts the moment your receiver opens the link.
            </>
          ) : (
            <>
              Encrypted copy parked — expires in <Countdown until={expiresAt} />. Keep
              this tab open to hand it over directly when the receiver arrives.
            </>
          ))}
        {live === "peer-online" && "Receiver is online — connecting directly…"}
        {live === "transferring" && "Receiver connected — transferring directly…"}
        {live === "delivered" &&
          (liveOnly
            ? "Delivered directly, browser to browser. Nothing ever touched the server."
            : "Delivered directly, browser to browser. No copy remains on the server.")}
      </p>
      {live !== "delivered" &&
        (liveOnly ? (
          <button className="danger-outline" onClick={() => location.reload()}>
            Cancel — close this share
          </button>
        ) : (
          <button className="danger-outline" onClick={() => void revoke()}>
            Destroy secret now
          </button>
        ))}
    </section>
  );
}
