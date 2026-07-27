// Production smoke test: security headers + one full drop round-trip.
// Usage: node workers/api/test/prod-smoke.mjs [base-url]
import { createHash, randomBytes } from "node:crypto";

const BASE = process.argv[2] ?? "https://shareasecret.io";
let failures = 0;
const check = (label, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${detail ? `: ${detail}` : ""}`);
};

// 1. SPA + security headers
{
  const res = await fetch(BASE + "/");
  check("SPA responds 200", res.status === 200, `status ${res.status}`);
  check("CSP header", (res.headers.get("content-security-policy") ?? "").includes("default-src 'self'"));
  check("Referrer-Policy", res.headers.get("referrer-policy") === "no-referrer");
  check("nosniff", res.headers.get("x-content-type-options") === "nosniff");
  const html = await res.text();
  check("serves the app", html.includes("Secret Share") || html.includes("/assets/"));
}

// 2. Drop round-trip (ciphertext-shaped random payload, exercises DO + storage)
{
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const id = Array.from(randomBytes(8), (b) => alphabet[b % 32]).join("");
  const claim = randomBytes(32).toString("base64url");
  const sender = randomBytes(32).toString("base64url");
  const h = (t) => createHash("sha256").update(Buffer.from(t, "base64url")).digest("base64url");
  const ciphertext = randomBytes(256).toString("base64url");

  const create = await fetch(`${BASE}/api/drops/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ claimTagHash: h(claim), senderTagHash: h(sender), ciphertext, ttlSeconds: 300 }),
  });
  check("create drop", create.status === 201, `status ${create.status}`);
  check("no-store on API", create.headers.get("cache-control") === "no-store");

  const claimRes = await fetch(`${BASE}/api/drops/${id}/claim`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ claimTag: claim }),
  });
  check("claim drop", claimRes.status === 200, `status ${claimRes.status}`);
  const body = await claimRes.json();
  check("ciphertext intact", body.ciphertext === ciphertext);

  const again = await fetch(`${BASE}/api/drops/${id}/claim`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ claimTag: claim }),
  });
  check("read-once enforced", again.status === 410, `status ${again.status}`);
}

// 3. www variant
{
  const res = await fetch("https://www.shareasecret.io/", { redirect: "manual" });
  check("www responds", res.status === 200 || (res.status >= 301 && res.status <= 308), `status ${res.status}`);
}

console.log(failures === 0 ? "\nPROD SMOKE PASSED" : `\n${failures} SMOKE CHECKS FAILED`);
process.exit(failures === 0 ? 0 : 1);
