import { useEffect, useState } from "react";
import { useSession } from "../lib/session.js";
import { useTenant } from "../lib/tenant.js";
import { prepareLogo } from "../lib/image.js";
import { CopyButton } from "../components/CopyButton.js";
import { SignInGate } from "../components/SignInGate.js";

interface AdminTenant {
  displayName: string;
  productName?: string;
  theme: { primaryColor?: string; footerText?: string; logoVersion: number };
  oidc: { issuer: string; clientId: string };
}

interface UsageDay {
  day: string;
  kind: string;
  count: number;
}

interface BillingSummary {
  plan: "trial" | "team" | "business" | "partner";
  status: "trialing" | "active" | "past_due" | "canceled";
  trialEndsAt: number | null;
  currentPeriodEnd: number | null;
  cancelAtPeriodEnd: boolean;
  canManage: boolean;
  canUpgrade: boolean;
  sendingBlocked: "trial_expired" | "canceled" | null;
}

const PLAN_LABELS: Record<BillingSummary["plan"], string> = {
  trial: "Free trial",
  team: "Team",
  business: "Business",
  partner: "Design partner",
};

/**
 * Deliberately minimal tenant self-service: branding and a usage readout.
 * Identity-provider wiring and hostnames are provisioning-script territory.
 */
export function Admin() {
  const tenant = useTenant();
  const { state } = useSession();
  const [config, setConfig] = useState<AdminTenant | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [usage, setUsage] = useState<UsageDay[] | null>(null);
  const [billing, setBilling] = useState<BillingSummary | null>(null);
  const [yearly, setYearly] = useState(false);
  const [billingNotice, setBillingNotice] = useState("");
  const [color, setColor] = useState("#2563eb");
  const [footerText, setFooterText] = useState("");
  const [productName, setProductName] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const authed = state.status === "authed";

  useEffect(() => {
    if (!authed) return;
    void (async () => {
      const res = await fetch("/api/admin/tenant");
      if (res.status === 403) {
        setForbidden(true);
        return;
      }
      if (!res.ok) return;
      const data = (await res.json()) as AdminTenant;
      setConfig(data);
      setColor(data.theme.primaryColor ?? "#2563eb");
      setFooterText(data.theme.footerText ?? "");
      setProductName(data.productName ?? data.displayName);
      const usageRes = await fetch("/api/admin/usage");
      if (usageRes.ok) {
        setUsage(((await usageRes.json()) as { days: UsageDay[] }).days);
      }
      const billingRes = await fetch("/api/admin/billing");
      if (billingRes.ok) {
        setBilling((await billingRes.json()) as BillingSummary);
      }
    })();
  }, [authed]);

  // Returning from a paid Checkout beats the webhook home: Stripe redirects
  // immediately, the subscription lands seconds later. Poll until it does so
  // the admin never sees stale "upgrade" buttons after paying.
  useEffect(() => {
    if (!authed) return;
    if (new URLSearchParams(location.search).get("billing") !== "success") return;
    history.replaceState(null, "", "/admin");
    setBillingNotice("Payment received — activating your subscription…");
    let tries = 0;
    const timer = setInterval(() => {
      void (async () => {
        tries += 1;
        const res = await fetch("/api/admin/billing");
        if (res.ok) {
          const b = (await res.json()) as BillingSummary;
          if (b.status === "active" && !b.canUpgrade) {
            clearInterval(timer);
            setBilling(b);
            setBillingNotice("Subscription active — you're all set.");
            return;
          }
        }
        if (tries >= 20) {
          clearInterval(timer);
          setBillingNotice(
            "Payment received. Activation is taking longer than usual — " +
              "refresh in a minute or two; if the plan still looks wrong, contact support.",
          );
        }
      })();
    }, 3000);
    return () => clearInterval(timer);
  }, [authed]);

  if (!tenant) return null;
  if (state.status === "anon") return <SignInGate title="Sign in to manage this tenant" />;
  if (forbidden) {
    return (
      <section className="card">
        <h2>Admin access required</h2>
        <p className="muted">
          Your account doesn't have the admin role for {tenant.name}.
        </p>
      </section>
    );
  }
  if (!config) {
    return (
      <section className="card">
        <h2>Admin</h2>
        <p className="muted">Loading…</p>
      </section>
    );
  }

  async function saveBranding() {
    setBusy(true);
    setNotice("");
    try {
      const res = await fetch("/api/admin/tenant", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          productName,
          theme: { primaryColor: color, footerText: footerText || null },
        }),
      });
      setNotice(res.ok ? "Saved. Changes appear for visitors within a few minutes." : "Save failed — try again.");
    } finally {
      setBusy(false);
    }
  }

  async function uploadLogo(file: File) {
    setBusy(true);
    setNotice("");
    try {
      const blob = await prepareLogo(file);
      const res = await fetch("/api/admin/tenant/logo", {
        method: "PUT",
        headers: { "Content-Type": "image/png" },
        body: blob,
      });
      setNotice(res.ok ? "Logo updated. It appears for visitors within a few minutes." : "Upload failed — try again.");
    } catch (e) {
      setNotice(e instanceof Error ? e.message : "Upload failed.");
    } finally {
      setBusy(false);
    }
  }

  const totals = new Map<string, number>();
  for (const row of usage ?? []) {
    totals.set(row.kind, (totals.get(row.kind) ?? 0) + row.count);
  }

  async function billingRedirect(path: string, body?: unknown) {
    setBusy(true);
    setBillingNotice("");
    try {
      const res = await fetch(path, {
        method: "POST",
        ...(body !== undefined
          ? { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
          : {}),
      });
      const data = (await res.json().catch(() => null)) as { url?: string } | null;
      if (res.ok && data?.url) {
        location.assign(data.url);
      } else {
        setBillingNotice(
          `Billing is temporarily unavailable (${res.status}) — try again or contact support.`,
        );
        setBusy(false);
      }
    } catch {
      setBillingNotice("Billing is temporarily unavailable — try again or contact support.");
      setBusy(false);
    }
  }

  const trialDaysLeft = billing?.trialEndsAt
    ? Math.max(0, Math.ceil((billing.trialEndsAt - Date.now()) / 86_400_000))
    : null;

  return (
    <>
      <section className="card">
        <h2>Branding</h2>
        {tenant.logoUrl && (
          <p>
            <img className="brand-logo" src={tenant.logoUrl} alt="Current logo" height={28} />
          </p>
        )}
        <label className="muted">
          Replace logo (PNG/JPEG/WebP; resized automatically){" "}
          <input
            type="file"
            accept="image/png,image/jpeg,image/webp"
            disabled={busy}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void uploadLogo(file);
            }}
          />
        </label>
        <label className="muted">
          Product name{" "}
          <input
            type="text"
            value={productName}
            maxLength={80}
            onChange={(e) => setProductName(e.target.value)}
          />
        </label>
        <label className="muted">
          Accent color{" "}
          <input
            type="color"
            value={color}
            onChange={(e) => {
              setColor(e.target.value);
              // Live preview; visitors only see it after Save.
              document.documentElement.style.setProperty("--accent", e.target.value);
            }}
          />
        </label>
        <p className="muted">
          Pick a color with enough contrast on white — it's used for buttons and
          links in light and dark mode.
        </p>
        <label className="muted">
          Footer line{" "}
          <input
            type="text"
            value={footerText}
            maxLength={200}
            placeholder="For FordMed staff and vendors."
            onChange={(e) => setFooterText(e.target.value)}
          />
        </label>
        {notice && <p className="muted">{notice}</p>}
        <button className="primary" disabled={busy} onClick={() => void saveBranding()}>
          Save branding
        </button>
      </section>

      <section className="card">
        <h2>Single sign-on</h2>
        <p className="muted">To change these, contact platform support.</p>
        <div className="code-display">
          <code className="small">Issuer: {config.oidc.issuer}</code>
          <CopyButton text={config.oidc.issuer} label="Copy" />
        </div>
        <div className="code-display">
          <code className="small">Client ID: {config.oidc.clientId}</code>
          <CopyButton text={config.oidc.clientId} label="Copy" />
        </div>
        <div className="code-display">
          <code className="small">Redirect URI: {location.origin}/auth/callback</code>
          <CopyButton text={`${location.origin}/auth/callback`} label="Copy" />
        </div>
        {state.status === "authed" && (
          <>
            <div className="code-display">
              <code className="small">Your subject ID: {state.session.sub}</code>
              <CopyButton text={state.session.sub} label="Copy" />
            </div>
            <p className="muted">
              Ask platform support to pin admin rights to this subject ID —
              unlike an email address, it can't be renamed or reassigned.
            </p>
          </>
        )}
        <p className="muted">
          Emergency cutoff: signs out every user of this tenant, including you.
          Takes effect everywhere within a few minutes.
        </p>
        <button
          className="danger-outline"
          disabled={busy}
          onClick={() => {
            void (async () => {
              setBusy(true);
              try {
                const res = await fetch("/api/admin/tenant/revoke-sessions", {
                  method: "POST",
                });
                if (res.ok) {
                  location.assign("/");
                } else {
                  setNotice("Revoke failed — try again.");
                }
              } finally {
                setBusy(false);
              }
            })();
          }}
        >
          Revoke all sessions
        </button>
      </section>

      {billing && (
        <section className="card">
          <h2>Plan &amp; billing</h2>
          <p className="muted">
            Current plan: <strong>{PLAN_LABELS[billing.plan]}</strong>
            {billing.status === "trialing" && trialDaysLeft !== null && (
              <> — {trialDaysLeft > 0 ? `${trialDaysLeft} day${trialDaysLeft === 1 ? "" : "s"} left in the trial` : "trial ended"}</>
            )}
            {billing.status === "past_due" && <> — payment past due (update your card)</>}
            {billing.status === "canceled" && <> — subscription canceled</>}
            {billing.status === "active" && billing.cancelAtPeriodEnd && (
              <>
                {" "}— cancels{" "}
                {billing.currentPeriodEnd
                  ? `on ${new Date(billing.currentPeriodEnd).toLocaleDateString()}`
                  : "at the end of the billing period"}
              </>
            )}
          </p>
          {billing.status === "active" && billing.cancelAtPeriodEnd && (
            <p className="muted">
              Your team keeps full access until then. Changed your mind? Renew
              under "Manage billing".
            </p>
          )}
          {billing.sendingBlocked && (
            <p className="muted">
              <strong>Sending is paused for your whole team.</strong> Recipients can
              still open secrets that were already sent. Subscribe below to
              reactivate sending.
            </p>
          )}
          {billing.canUpgrade && (
            <>
              <label className="muted">
                <input
                  type="checkbox"
                  checked={yearly}
                  onChange={(e) => setYearly(e.target.checked)}
                />{" "}
                Bill yearly — two months free
              </label>
              <p>
                <button
                  className="primary"
                  disabled={busy}
                  onClick={() =>
                    void billingRedirect("/api/admin/billing/checkout", {
                      plan: "team",
                      interval: yearly ? "yearly" : "monthly",
                    })
                  }
                >
                  Team — {yearly ? "$490/yr" : "$49/mo"}
                </button>{" "}
                <button
                  className="primary"
                  disabled={busy}
                  onClick={() =>
                    void billingRedirect("/api/admin/billing/checkout", {
                      plan: "business",
                      interval: yearly ? "yearly" : "monthly",
                    })
                  }
                >
                  Business — {yearly ? "$990/yr" : "$99/mo"}
                </button>
              </p>
              <p className="muted">
                Team: branded portal on your subdomain with your own single
                sign-on. Business: adds a custom domain (like{" "}
                <code>secrets.yourcompany.com</code>) and priority support.
              </p>
            </>
          )}
          {billing.canManage && (
            <button
              disabled={busy}
              onClick={() => void billingRedirect("/api/admin/billing/portal")}
            >
              Manage billing (invoices, card, cancel)
            </button>
          )}
          {billingNotice && <p className="muted">{billingNotice}</p>}
          {billing.plan === "partner" && (
            <p className="muted">
              Design-partner tenant — no subscription needed. Contact platform
              support to change plans.
            </p>
          )}
        </section>
      )}

      <section className="card">
        <h2>Usage (last 30 days)</h2>
        {usage === null ? (
          <p className="muted">Loading…</p>
        ) : totals.size === 0 ? (
          <p className="muted">No activity recorded yet.</p>
        ) : (
          <p className="muted">
            Secrets sent: {totals.get("drop_created") ?? 0}
            {" · "}Secrets retrieved: {totals.get("drop_claimed") ?? 0}
            {" · "}Guest requests: {totals.get("grant_minted") ?? 0}
            {" · "}Sign-ins: {totals.get("login") ?? 0}
          </p>
        )}
      </section>
    </>
  );
}
