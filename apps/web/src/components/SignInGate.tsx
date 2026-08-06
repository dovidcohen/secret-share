import { useState } from "react";
import { consumeAuthError, loginUrl } from "../lib/auth.js";
import { useTenant } from "../lib/tenant.js";

/** Shown in place of a gated composer when the visitor has no session. */
export function SignInGate({ title = "Sign in to send" }: { title?: string }) {
  const tenant = useTenant();
  const [authError] = useState(consumeAuthError);
  if (!tenant) return null;

  return (
    <section className="card">
      <h2>{title}</h2>
      <p className="muted">
        Sending a secret on {tenant.productName} requires a {tenant.name} account.{" "}
        <strong>Receiving a secret never requires sign-in.</strong>
      </p>
      {authError && <p className="danger">{authError}</p>}
      <button className="primary" onClick={() => location.assign(loginUrl())}>
        Sign in with {tenant.idpLabel}
      </button>
    </section>
  );
}
