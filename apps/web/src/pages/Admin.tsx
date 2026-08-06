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
    })();
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
