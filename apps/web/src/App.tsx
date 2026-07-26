import { useState } from "react";
import { Send } from "./pages/Send.js";
import { Receive } from "./pages/Receive.js";

function initialRoute(): { mode: "send" | "receive"; code: string } {
  const code = location.hash.slice(1);
  if (location.pathname.startsWith("/r") || code.length > 0) {
    return { mode: "receive", code: decodeURIComponent(code) };
  }
  return { mode: "send", code: "" };
}

export function App() {
  const [route] = useState(initialRoute);
  const [mode, setMode] = useState(route.mode);

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
        </nav>
      </header>
      {mode === "send" ? <Send /> : <Receive initialCode={route.code} />}
      <footer>
        <p className="muted">
          Keys are derived from the share code in your browser; the code never reaches
          the server. Secrets are read-once and expire automatically.
        </p>
      </footer>
    </main>
  );
}
