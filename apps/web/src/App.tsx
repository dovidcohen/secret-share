import { useState } from "react";
import { Send } from "./pages/Send.js";
import { Receive } from "./pages/Receive.js";
import { Optical } from "./pages/Optical.js";
import { Faq } from "./pages/Faq.js";

function initialRoute(): { mode: "send" | "receive" | "qr"; code: string } {
  if (location.pathname.startsWith("/qr")) {
    return { mode: "qr", code: "" };
  }
  const code = location.hash.slice(1);
  if (location.pathname.startsWith("/r") || code.length > 0) {
    // Take the code into memory and scrub it from the address bar so the full
    // share code doesn't persist in (possibly synced) browser history.
    if (code.length > 0) {
      history.replaceState(null, "", "/r");
    }
    return { mode: "receive", code: decodeURIComponent(code) };
  }
  return { mode: "send", code: "" };
}

export function App() {
  const [route] = useState(initialRoute);
  const [mode, setMode] = useState<"send" | "receive" | "qr" | "faq">(route.mode);

  return (
    <main>
      <header>
        <h1>
          <span className="logo">⧉</span> Secret Share
        </h1>
        <p className="tagline">
          Pass a secret to exactly one person. End-to-end encrypted, direct when
          possible, gone after one read.
        </p>
        <nav>
          <button className={mode === "send" ? "tab active" : "tab"} onClick={() => setMode("send")}>
            Send
          </button>
          <button
            className={mode === "receive" ? "tab active" : "tab"}
            onClick={() => setMode("receive")}
          >
            Receive
          </button>
          <button className={mode === "qr" ? "tab active" : "tab"} onClick={() => setMode("qr")}>
            QR Transfer
          </button>
          <button className={mode === "faq" ? "tab active" : "tab"} onClick={() => setMode("faq")}>
            How it works
          </button>
        </nav>
      </header>
      {mode === "send" && <Send />}
      {mode === "receive" && <Receive initialCode={route.code} />}
      {mode === "qr" && <Optical />}
      {mode === "faq" && <Faq />}
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
        </p>
      </footer>
    </main>
  );
}
