import { useState } from "react";
import { Send } from "./pages/Send.js";
import { Receive } from "./pages/Receive.js";
import { Faq } from "./pages/Faq.js";

function initialRoute(): { mode: "send" | "receive"; code: string } {
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
  const [mode, setMode] = useState<"send" | "receive" | "faq">(route.mode);

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
          <button className={mode === "faq" ? "tab active" : "tab"} onClick={() => setMode("faq")}>
            How it works
          </button>
        </nav>
      </header>
      {mode === "send" && <Send />}
      {mode === "receive" && <Receive initialCode={route.code} />}
      {mode === "faq" && <Faq />}
      <footer>
        <p className="muted">
          Keys are derived from the share code in your browser; the code never reaches
          the server. Secrets are read-once and expire automatically.
        </p>
      </footer>
    </main>
  );
}
