import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { generateCode } from "@secret-share/crypto";
import { GrantMintConflictError, mintGrant, packGiveFragment } from "../lib/grant.js";
import { SessionExpiredError } from "../lib/drop.js";
import { loginUrl } from "../lib/auth.js";
import { useSession } from "../lib/session.js";
import { useTenant } from "../lib/tenant.js";
import { CopyButton } from "../components/CopyButton.js";
import { Countdown } from "../components/Countdown.js";
import { SignInGate } from "../components/SignInGate.js";
import { Receive } from "./Receive.js";

type Phase = "idle" | "minting" | "ready" | "waiting" | "error";

interface ActiveRequest {
  code: string;
  link: string;
  expiresAt: number;
}

/**
 * The employee side of "receive a secret from an outsider": the full share
 * code is generated HERE and never leaves this tab — the server only mints a
 * one-time grant for the mailbox id. The vendor's link carries code + grant in
 * the fragment; the employee keeps the code to claim with.
 */
export function Request() {
  const tenant = useTenant();
  const { state } = useSession();
  const [phase, setPhase] = useState<Phase>("idle");
  const [active, setActive] = useState<ActiveRequest | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!active) return;
    void QRCode.toDataURL(active.link, {
      margin: 1,
      width: 480,
      errorCorrectionLevel: "M",
    }).then(setQrDataUrl);
  }, [active]);

  if (!tenant) return null;
  if (state.status === "anon") {
    return <SignInGate title="Sign in to request a secret" />;
  }

  async function create() {
    setPhase("minting");
    setError("");
    try {
      // 409 = 40-bit mailbox-id collision; regenerate like Send does.
      for (let attempt = 0; attempt < 3; attempt++) {
        const candidate = generateCode();
        try {
          const { grant, expiresAt } = await mintGrant(candidate.mailboxId);
          setActive({
            code: candidate.code,
            link: `${location.origin}/give#${packGiveFragment(grant, candidate.code)}`,
            expiresAt,
          });
          setPhase("ready");
          return;
        } catch (e) {
          if (!(e instanceof GrantMintConflictError)) throw e;
        }
      }
      throw new Error("Could not allocate a mailbox, please retry");
    } catch (e) {
      setError(
        e instanceof SessionExpiredError
          ? "Your session expired — sign in again, then retry."
          : e instanceof Error
            ? e.message
            : String(e),
      );
      setPhase("error");
    }
  }

  if (phase === "waiting" && active) {
    return (
      <>
        <section className="card">
          <h2>Waiting for their secret</h2>
          <p className="muted">
            Leave this open — it retrieves the secret the moment they send it.
            Or come back any time and enter your claim code on the Receive tab.
          </p>
        </section>
        <Receive initialCode={active.code} />
      </>
    );
  }

  if (phase === "ready" && active) {
    return (
      <section className="card">
        <h2>Send this link to them</h2>
        <div className="code-display">
          <code className="small">{active.link}</code>
          <CopyButton text={active.link} label="Copy link" />
        </div>
        {qrDataUrl && (
          <div className="qr">
            <img src={qrDataUrl} alt="QR code for the request link" />
            <span className="muted">…or let them scan it</span>
          </div>
        )}
        <h2>Your claim code — keep it</h2>
        <div className="code-display">
          <code>{active.code}</code>
          <CopyButton text={active.code} label="Copy code" />
        </div>
        <p className="muted">
          This is shown once and never stored. You'll need it to retrieve what
          they send — enter it on the Receive tab, or wait here.
        </p>
        <p className="status status-parked">
          The link works exactly once and expires in <Countdown until={active.expiresAt} />.
        </p>
        <div className="row">
          <button className="primary" onClick={() => setPhase("waiting")}>
            Wait for it here
          </button>
          <button
            onClick={() => {
              setActive(null);
              setQrDataUrl("");
              setPhase("idle");
            }}
          >
            Done — new request
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="card">
      <h2>Request a secret</h2>
      <p className="muted">
        Need someone outside {tenant.name} to send <strong>you</strong> a secret?
        Create a one-time request link. They won't need an account, and the link
        works exactly once.
      </p>
      {error && <p className="danger">{error}</p>}
      <button
        className="primary"
        disabled={phase === "minting" || state.status === "loading"}
        onClick={() => void create()}
      >
        {phase === "minting"
          ? "Creating…"
          : state.status === "loading"
            ? "Checking sign-in…"
            : "Create request link"}
      </button>
    </section>
  );
}
