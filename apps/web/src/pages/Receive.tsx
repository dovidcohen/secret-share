import { useEffect, useRef, useState } from "react";
import { LIVE_TIMEOUT_MS } from "@secret-share/protocol";
import {
  CodeFormatError,
  decryptSecret,
  deriveKeys,
  parseCode,
  type DerivedKeys,
} from "@secret-share/crypto";
import {
  BadTagError,
  DropGoneError,
  DropNotFoundError,
  claimDrop,
} from "../lib/drop.js";
import { Signaling } from "../lib/ws.js";
import { receiverLiveTransfer } from "../lib/rtc.js";
import { CopyButton } from "../components/CopyButton.js";

type Phase =
  | "input"
  | "deriving"
  | "connecting"
  | "live"
  | "claiming"
  | "waiting"
  | "done"
  | "error";

export function Receive({ initialCode }: { initialCode: string }) {
  const [phase, setPhase] = useState<Phase>("input");
  const [codeInput, setCodeInput] = useState(initialCode);
  const [secret, setSecret] = useState("");
  const [via, setVia] = useState<"live" | "drop">("drop");
  const [error, setError] = useState("");
  const signalingRef = useRef<Signaling | null>(null);
  const startedRef = useRef(false);

  useEffect(() => {
    // startedRef guards StrictMode's double effect-invocation in dev: a second
    // auto-retrieve would consume the read-once drop and then see 410.
    if (initialCode && !startedRef.current) {
      startedRef.current = true;
      void retrieve(initialCode);
    }
    return () => signalingRef.current?.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function retrieve(raw: string) {
    setError("");
    setPhase("deriving");
    let keys: DerivedKeys;
    try {
      keys = await deriveKeys(parseCode(raw));
    } catch (e) {
      setError(
        e instanceof CodeFormatError
          ? e.message
          : "Could not derive keys from this code",
      );
      setPhase("input");
      return;
    }

    setPhase("connecting");
    let signaling: Signaling | null = null;
    try {
      signaling = await Signaling.connect(keys.mailboxId, "receiver");
      signalingRef.current = signaling;
    } catch {
      // Signaling down? The async claim path can still work.
      await claim(keys);
      return;
    }

    const joined = await signaling.next((m) => m.t === "joined", 5000);
    const state =
      joined && joined.t === "joined"
        ? joined
        : { peerPresent: false, dropAvailable: true };

    if (state.peerPresent) {
      const got = await tryLive(signaling, keys);
      if (got !== null) {
        finish(new TextDecoder().decode(got), "live");
        return;
      }
      // Live failed — the claim surfaces the truth either way: the ciphertext,
      // 410 (already retrieved), or 404 (never parked).
      await claim(keys);
      return;
    }

    if (state.dropAvailable) {
      await claim(keys);
      return;
    }

    // No peer, no drop. Probe the mailbox so "already retrieved" (tombstone)
    // reads differently from "nothing here yet".
    try {
      const blob = await claimDrop(keys);
      finish(new TextDecoder().decode(await decryptSecret(keys, blob)), "drop");
      return;
    } catch (e) {
      if (e instanceof DropGoneError) {
        setError("This secret was already retrieved, destroyed, or has expired.");
        setPhase("error");
        return;
      }
      // 404 or transient error: fall through to waiting for the sender.
    }
    setPhase("waiting");
    signaling.on((msg) => {
      if (msg.t === "peer-joined") {
        void (async () => {
          setPhase("live");
          const got = await tryLive(signaling, keys);
          if (got !== null) finish(new TextDecoder().decode(got), "live");
          else await claim(keys); // sender may have parked it just now
        })();
      }
    });
  }

  /** Waits for the sender's offer, runs the encrypted transfer. Null on any failure. */
  async function tryLive(signaling: Signaling, keys: DerivedKeys): Promise<Uint8Array | null> {
    setPhase("live");
    try {
      const offer = await signaling.next(
        (m) => m.t === "signal" && m.payload.kind === "offer",
        LIVE_TIMEOUT_MS,
      );
      if (!offer || offer.t !== "signal" || offer.payload.kind !== "offer") return null;
      return await receiverLiveTransfer(signaling, keys, offer.payload.sdp);
    } catch {
      return null;
    }
  }

  async function claim(keys: DerivedKeys) {
    setPhase("claiming");
    try {
      const blob = await claimDrop(keys);
      const plaintext = await decryptSecret(keys, blob);
      finish(new TextDecoder().decode(plaintext), "drop");
    } catch (e) {
      if (e instanceof DropGoneError) {
        setError("This secret was already retrieved, destroyed, or has expired.");
      } else if (e instanceof DropNotFoundError) {
        setError("Nothing is parked under this code yet. Ask the sender to check their tab.");
      } else if (e instanceof BadTagError) {
        setError(
          `The code words don't match this mailbox (${e.attemptsLeft} attempts left before it burns). Double-check for typos.`,
        );
      } else {
        setError("The secret could not be decrypted. The code may be wrong or the data corrupted.");
      }
      setPhase("error");
    }
  }

  function finish(text: string, how: "live" | "drop") {
    signalingRef.current?.close();
    setVia(how);
    setSecret(text);
    setPhase("done");
  }

  if (phase === "done") {
    return (
      <section className="card">
        <h2>Secret received</h2>
        <p className="status status-delivered">
          {via === "live"
            ? "Transferred directly from the sender's browser — it never touched the server."
            : "Retrieved and destroyed — the server copy no longer exists."}
        </p>
        <pre className="secret">{secret}</pre>
        <div className="row">
          <CopyButton text={secret} label="Copy secret" />
          <button
            className="danger-outline"
            onClick={() => {
              setSecret("");
              setPhase("input");
              setCodeInput("");
            }}
          >
            Wipe from screen
          </button>
        </div>
      </section>
    );
  }

  const busy = phase !== "input" && phase !== "error";
  return (
    <section className="card">
      <h2>Receive a secret</h2>
      <p className="muted">Enter the code the sender gave you.</p>
      <input
        type="text"
        autoFocus
        placeholder="XXXX-XXXX-word-word-word-word-word"
        value={codeInput}
        onChange={(e) => setCodeInput(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && codeInput && !busy) void retrieve(codeInput);
        }}
        disabled={busy}
      />
      {error && <p className="danger">{error}</p>}
      <button
        className="primary"
        disabled={!codeInput || busy}
        onClick={() => void retrieve(codeInput)}
      >
        {phase === "deriving" && "Deriving keys…"}
        {phase === "connecting" && "Connecting…"}
        {phase === "live" && "Receiving directly from sender…"}
        {phase === "claiming" && "Retrieving…"}
        {phase === "waiting" && "Waiting for the sender to come online…"}
        {(phase === "input" || phase === "error") && "Retrieve secret"}
      </button>
      {phase === "waiting" && (
        <p className="muted">
          Nothing is parked under this code and the sender isn't online. Leave this
          tab open — the transfer starts automatically when they arrive.
        </p>
      )}
    </section>
  );
}
