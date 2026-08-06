import { useMemo, useState } from "react";
import { DEFAULT_TTL_SECONDS, MAX_SECRET_BYTES } from "@secret-share/protocol";
import {
  CodeFormatError,
  deriveKeys,
  encryptSecret,
  parseCode,
  utf8,
  type ShareCode,
} from "@secret-share/crypto";
import { GrantRejectedError, parkDrop } from "../lib/drop.js";
import { useTenant } from "../lib/tenant.js";

type Phase = "compose" | "sending" | "done" | "failed";

/**
 * The guest side of "request a secret": an outsider opens a one-time link an
 * employee sent them, types the secret, and it's encrypted in this browser
 * before upload. The grant token authorizes exactly one drop; the employee
 * kept the claim code, so nothing needs to travel back.
 */
export function Give({ params }: { params: { grant: string; code: string } | null }) {
  const tenant = useTenant();
  const [phase, setPhase] = useState<Phase>("compose");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState("");
  const [fatal, setFatal] = useState(false);

  const code = useMemo<ShareCode | null>(() => {
    if (!params) return null;
    try {
      return parseCode(params.code);
    } catch (e) {
      return e instanceof CodeFormatError ? null : null;
    }
  }, [params]);

  const name = tenant?.name ?? "The requester";
  const bytes = new TextEncoder().encode(secret).length;
  const tooBig = bytes > MAX_SECRET_BYTES;

  if (!params || !code) {
    return (
      <section className="card">
        <h2>This link isn't complete</h2>
        <p className="muted">
          This request link is incomplete or damaged. Ask the person who sent it
          for a new one.
        </p>
      </section>
    );
  }

  async function send() {
    if (!params || !code) return;
    setPhase("sending");
    setError("");
    try {
      const keys = await deriveKeys(code, tenant?.tenantId);
      const blob = await encryptSecret(keys, utf8(secret));
      await parkDrop(keys, blob, DEFAULT_TTL_SECONDS, { grant: params.grant });
      setSecret("");
      setPhase("done");
    } catch (e) {
      if (e instanceof GrantRejectedError) {
        setFatal(true);
        setError(
          e.reason === "used"
            ? `This request link was already used — each link works exactly once. Ask ${name} for a fresh one.`
            : e.reason === "expired"
              ? `This request link has expired. Ask ${name} for a fresh one.`
              : `Something went wrong with this link. Ask ${name} to create a new request.`,
        );
      } else {
        setError("Could not send right now — check your connection and try again.");
      }
      setPhase("failed");
    }
  }

  if (phase === "done") {
    return (
      <section className="card">
        <h2>Sent</h2>
        <p className="status status-delivered">
          {name} will retrieve it with the code they kept. You can close this page
          — nothing is stored here.
        </p>
      </section>
    );
  }

  return (
    <section className="card">
      <h2>{name} asked you to send them a secret</h2>
      <p className="muted">
        Type or paste it below. It's encrypted in this browser before anything is
        uploaded; {name} retrieves it once and then it's gone. No account needed.
      </p>
      <textarea
        autoFocus
        rows={8}
        placeholder="Paste the password, key, or other secret here..."
        value={secret}
        onChange={(e) => setSecret(e.target.value)}
        disabled={phase === "sending" || fatal}
      />
      <div className="row">
        <span className={tooBig ? "danger" : "muted"}>
          {bytes.toLocaleString()} / {MAX_SECRET_BYTES.toLocaleString()} bytes
        </span>
      </div>
      {error && <p className="danger">{error}</p>}
      <button
        className="primary"
        disabled={!secret || tooBig || phase === "sending" || fatal}
        onClick={() => void send()}
      >
        {phase === "sending" ? "Encrypting & sending…" : "Encrypt & send"}
      </button>
    </section>
  );
}
