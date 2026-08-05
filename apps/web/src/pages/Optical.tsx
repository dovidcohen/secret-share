import { useState } from "react";
import { OpticalSender } from "../components/OpticalSender.js";
import { OpticalReceiver } from "../components/OpticalReceiver.js";

/**
 * Air-gapped transfer: data crosses as animated QR codes, screen to camera.
 * ?loopback renders sender and receiver together and wires them canvas-to-
 * canvas so e2e tests can run the whole optical path without a camera.
 */
export function Optical() {
  const [loopback] = useState(() => new URLSearchParams(location.search).has("loopback"));
  const [dir, setDir] = useState<"send" | "receive">("send");

  if (loopback) {
    return (
      <>
        <section className="card" data-testid="optical-send">
          <OpticalSender loopback />
        </section>
        <section className="card" style={{ marginTop: "1rem" }} data-testid="optical-receive">
          <OpticalReceiver loopback />
        </section>
      </>
    );
  }

  return (
    <section className="card">
      <div className="row">
        <nav>
          <button className={dir === "send" ? "tab active" : "tab"} onClick={() => setDir("send")}>
            Send
          </button>
          <button
            className={dir === "receive" ? "tab active" : "tab"}
            onClick={() => setDir("receive")}
          >
            Receive
          </button>
        </nav>
      </div>
      {dir === "send" ? <OpticalSender loopback={false} /> : <OpticalReceiver loopback={false} />}
      <p className="muted">
        No network, no server: the payload travels as light between two devices in the
        same room. Anyone who can see the sender's screen could also capture it — use
        the Encrypted option when the room itself isn't trusted.
      </p>
    </section>
  );
}
