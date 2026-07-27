// Verifies round-two hardening against production:
// localhost origin rejected, HSTS on API responses, TURN tokens single-use.
import { randomBytes } from "node:crypto";

const BASE = "https://shareasecret.io";
let failures = 0;
const check = (label, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${detail ? `: ${detail}` : ""}`);
};

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const id = Array.from(randomBytes(8), (b) => alphabet[b % 32]).join("");

// 1. localhost origin must be rejected in production (undici won't send
// Upgrade headers from fetch, so shell out to curl)
{
  const { execFileSync } = await import("node:child_process");
  const out = execFileSync("curl", [
    "-s", "-o", process.platform === "win32" ? "NUL" : "/dev/null", "-w", "%{http_code}",
    "-H", "Upgrade: websocket",
    "-H", "Connection: Upgrade",
    "-H", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
    "-H", "Sec-WebSocket-Version: 13",
    "-H", "Origin: http://localhost:5173",
    `${BASE}/ws/${id}?role=sender`,
  ]).toString();
  check("localhost origin rejected", out === "403", `status ${out}`);
}

// 2. HSTS present on an API response
{
  const res = await fetch(`${BASE}/api/drops/${id}/claim`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ claimTag: "A".repeat(43) }),
  });
  check("HSTS on API response", res.headers.get("strict-transport-security") === "max-age=31536000");
}

// 3. token from a real session mints once, then is refused (single-use)
{
  const ws = new WebSocket(`wss://shareasecret.io/ws/${id}?role=sender`);
  const token = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("no joined")), 8000);
    ws.addEventListener("message", (e) => {
      const m = JSON.parse(e.data);
      if (m.t === "joined") {
        clearTimeout(timer);
        resolve(m.turnToken);
      }
    });
    ws.addEventListener("error", () => reject(new Error("ws error")));
  });
  check("joined carries token", typeof token === "string" && token.length === 22);

  const mint = (t) =>
    fetch(`${BASE}/api/turn`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mailboxId: id, turnToken: t }),
    });
  const first = await mint(token);
  check("first mint succeeds", first.status === 200, `status ${first.status}`);
  const second = await mint(token);
  check("second mint refused (single-use)", second.status === 403, `status ${second.status}`);
  ws.close();
}

console.log(failures === 0 ? "\nPROD HARDENING CHECKS PASSED" : `\n${failures} CHECKS FAILED`);
process.exit(failures === 0 ? 0 : 1);
