import { useState, type ReactNode } from "react";
import { Send } from "./pages/Send.js";
import { Receive } from "./pages/Receive.js";
import { Optical } from "./pages/Optical.js";
import { Faq } from "./pages/Faq.js";
import { Give } from "./pages/Give.js";
import { Request } from "./pages/Request.js";
import { Admin } from "./pages/Admin.js";
import { IdentityBar } from "./components/IdentityBar.js";
import { parseGiveFragment } from "./lib/grant.js";
import { useTenant, type TenantConfig } from "./lib/tenant.js";

type Mode = "send" | "receive" | "qr" | "faq" | "give" | "request" | "admin";

interface Route {
  mode: Mode;
  code: string;
  give: { grant: string; code: string } | null;
}

function initialRoute(tenant: TenantConfig | null): Route {
  // Tenant-only pages; on the public host these paths fall through to Send.
  // ("/request" before "/r": startsWith would shadow it otherwise.)
  if (tenant) {
    if (location.pathname.startsWith("/give")) {
      // Same discipline as /r: take the fragment into memory and scrub it
      // before anything else runs — the grant+code must not persist in
      // (possibly synced) browser history.
      const fragment = location.hash.slice(1);
      if (fragment.length > 0) {
        history.replaceState(null, "", "/give");
      }
      return { mode: "give", code: "", give: parseGiveFragment(fragment) };
    }
    if (location.pathname.startsWith("/request")) {
      return { mode: "request", code: "", give: null };
    }
    if (location.pathname.startsWith("/admin")) {
      return { mode: "admin", code: "", give: null };
    }
  }
  if (location.pathname.startsWith("/qr")) {
    // The optical mode is public-site-only in v1.
    return { mode: tenant ? "send" : "qr", code: "", give: null };
  }
  const code = location.hash.slice(1);
  if (location.pathname.startsWith("/r") || code.length > 0) {
    // Take the code into memory and scrub it from the address bar so the full
    // share code doesn't persist in (possibly synced) browser history.
    if (code.length > 0) {
      history.replaceState(null, "", "/r");
    }
    return { mode: "receive", code: decodeURIComponent(code), give: null };
  }
  return { mode: "send", code: "", give: null };
}

function Brand({ tenant }: { tenant: TenantConfig | null }) {
  return (
    <h1>
      {tenant?.logoUrl ? (
        <img className="brand-logo" src={tenant.logoUrl} alt="" height={28} />
      ) : (
        <span className="logo">⧉</span>
      )}{" "}
      {tenant ? tenant.productName : "Secret Share"}
    </h1>
  );
}

function TenantFooter({ tenant }: { tenant: TenantConfig }) {
  return (
    <footer>
      <p className="muted">
        Keys are derived from the share code in your browser; the code never reaches
        the server. Secrets are read-once and expire automatically.
      </p>
      <p className="muted">
        {tenant.footerText && <>{tenant.footerText} </>}
        Powered by Secret Share — zero-knowledge: {tenant.name} and the platform
        only ever see ciphertext.
      </p>
    </footer>
  );
}

export function App() {
  const tenant = useTenant();
  const [route] = useState(() => initialRoute(tenant));
  const [mode, setMode] = useState<Mode>(route.mode);

  const tab = (m: Mode, label: ReactNode) => (
    <button className={mode === m ? "tab active" : "tab"} onClick={() => setMode(m)}>
      {label}
    </button>
  );

  // The guest page stands alone: no tabs — a visitor with a one-time link
  // shouldn't wander into sign-in-gated parts of a company's tool.
  if (tenant && mode === "give") {
    return (
      <main>
        <header>
          <Brand tenant={tenant} />
        </header>
        <Give params={route.give} />
        <TenantFooter tenant={tenant} />
      </main>
    );
  }

  return (
    <main>
      <header>
        <Brand tenant={tenant} />
        {tenant && <IdentityBar onAdmin={() => setMode("admin")} />}
        <p className="tagline">
          Pass a secret to exactly one person. End-to-end encrypted, direct when
          possible, gone after one read.
        </p>
        <nav>
          {tab("send", "Send")}
          {tab("receive", "Receive")}
          {tenant ? tab("request", "Request a secret") : tab("qr", "QR Transfer")}
          {tab("faq", "How it works")}
        </nav>
      </header>
      {mode === "send" && <Send />}
      {mode === "receive" && <Receive initialCode={route.code} />}
      {mode === "qr" && !tenant && <Optical />}
      {mode === "request" && tenant && <Request />}
      {mode === "admin" && tenant && <Admin />}
      {mode === "faq" && <Faq />}
      {tenant ? (
        <TenantFooter tenant={tenant} />
      ) : (
        <footer>
          <p className="muted">
            Keys are derived from the share code in your browser; the code never reaches
            the server. Secrets are read-once and expire automatically.
          </p>
          <p className="muted footer-links">
            <a href="/guides/cli">
              CLI: <code>npx shareasecret</code>
            </a>
            {" · "}
            <a href="/guides/send-ssh-key-securely">Send an SSH key securely</a>
            {" · "}
            <a href="/guides/share-password-one-time-link">One-time password links</a>
            {" · "}
            <a href="/guides/send-api-key-securely">Send API keys</a>
            {" · "}
            <a href="/compare/secret-sharing-tools">Compare tools</a>
            {" · "}
            <a href="/blog">Engineering blog</a>
            {" · "}
            <a href="/business">For teams: your brand + SSO</a>
          </p>
        </footer>
      )}
    </main>
  );
}
