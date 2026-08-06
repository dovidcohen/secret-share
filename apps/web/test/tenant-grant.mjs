// White-label tenant e2e (Playwright + Chromium) against `wrangler dev`:
//   A) anonymous Send on a tenant host shows the SSO gate (no composer)
//   B) employee mints a guest-request link; guest sends without an account;
//      the waiting employee receives it; the link is one-time
//   C) the public host is untouched: no /auth/me call, stock branding
//
// Self-contained: seeds the local KV registry, spawns its own wrangler dev on
// :8788 (dev session cookies are unprefixed + non-Secure so plain http works),
// and forges the employee session with the .dev.vars SESSION_SECRET —
// deliberately reimplementing the cookie codec as an independent check.
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const API_DIR = fileURLToPath(new URL("../../../workers/api", import.meta.url));
const BASE = "http://127.0.0.1:8788";
const TENANT_HOST_HEADER = { "x-dev-tenant-host": "acme.shareasecret.io" };
const DEV_SECRET = "dev-session-secret";
const SECRET_TEXT = "vendor-supplied API key: sk-test-12345";

let failures = 0;
const check = (label, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${detail ? `: ${detail}` : ""}`);
};

// ---------- seed the local KV tenant registry ----------

const NPX = process.platform === "win32" ? "npx.cmd" : "npx";
const seedDir = mkdtempSync(path.join(tmpdir(), "ss-seed-"));
let seedCount = 0;
function kvPutLocal(key, value) {
  // Values go via --path: inline JSON args get mangled by the Windows shell.
  const file = path.join(seedDir, `seed-${seedCount++}.json`);
  writeFileSync(file, value);
  execFileSync(
    NPX,
    ["wrangler", "kv", "key", "put", key, "--path", file, "--binding", "TENANTS", "--local"],
    { cwd: API_DIR, stdio: "pipe", shell: process.platform === "win32" },
  );
}

const now = Date.now();
kvPutLocal(
  "tenant:acme",
  JSON.stringify({
    v: 1,
    tenantId: "acme",
    displayName: "Acme Corp",
    productName: "Acme Secrets",
    hostnames: ["acme.shareasecret.io"],
    theme: { logoVersion: 0, primaryColor: "#0e7490", footerText: "For Acme staff and vendors." },
    oidc: {
      issuer: "https://login.microsoftonline.com/dead-beef/v2.0",
      clientId: "e2e-client",
      clientAuth: "pkce_public",
      scopes: "openid profile email",
      idpLabel: "Acme (Microsoft)",
      allowedEmailDomains: [],
      allowedGroups: [],
    },
    adminEmails: ["admin@acme.test"],
    features: { guestGrants: true, liveSend: true },
    createdAt: now,
    updatedAt: now,
  }),
);
kvPutLocal("host:acme.shareasecret.io", JSON.stringify({ tenantId: "acme" }));
rmSync(seedDir, { recursive: true, force: true });
console.log("seeded local tenant registry");

// ---------- forge the employee session (independent codec implementation) ----------

async function forgeSessionCookie(tenantId, email) {
  const enc = new TextEncoder();
  const ikm = await crypto.subtle.importKey("raw", enc.encode(DEV_SECRET), "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode(tenantId), info: enc.encode("ss/session/v1") },
    ikm,
    256,
  );
  const key = await crypto.subtle.importKey("raw", bits, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const t = Math.floor(Date.now() / 1000);
  const body = enc.encode(
    JSON.stringify({ v: 1, tid: tenantId, sub: "e2e-sub", email, adm: false, iat: t, exp: t + 28800 }),
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, body));
  const b64u = (b) => Buffer.from(b).toString("base64url");
  return `${b64u(body)}.${b64u(mac)}`;
}

// ---------- wrangler dev ----------

const dev = spawn(NPX, ["wrangler", "dev", "--port", "8788"], {
  cwd: API_DIR,
  stdio: "ignore",
  shell: process.platform === "win32",
});
function killDev() {
  if (process.platform === "win32") {
    try {
      execFileSync("taskkill", ["/pid", String(dev.pid), "/T", "/F"], { stdio: "ignore" });
    } catch {}
  } else {
    dev.kill("SIGTERM");
  }
}
process.on("exit", killDev);

for (let i = 0; i < 90; i++) {
  try {
    const res = await fetch(`${BASE}/`);
    if (res.ok) break;
  } catch {}
  await new Promise((r) => setTimeout(r, 1000));
  if (i === 89) {
    console.error("wrangler dev never became ready");
    process.exit(1);
  }
}
console.log("wrangler dev ready on :8788");

// ---------- scenarios ----------

const browser = await chromium.launch();

// A) anonymous visitor on the tenant host: gated Send, tenant branding
{
  const ctx = await browser.newContext({ extraHTTPHeaders: TENANT_HOST_HEADER });
  const page = await ctx.newPage();
  await page.goto(BASE + "/");
  await page.locator("h1", { hasText: "Acme Secrets" }).waitFor({ timeout: 15_000 });
  check("A: tenant branding in header", true);
  const gate = page.locator("button.primary", { hasText: "Sign in with Acme (Microsoft)" });
  await gate.waitFor({ timeout: 15_000 });
  check("A: send is gated behind SSO", (await page.locator("textarea").count()) === 0);
  await ctx.close();
}

// B) the guest-request loop
{
  const employeeCtx = await browser.newContext({ extraHTTPHeaders: TENANT_HOST_HEADER });
  await employeeCtx.addCookies([
    {
      name: "ss_session",
      value: await forgeSessionCookie("acme", "employee@acme.test"),
      url: BASE,
    },
  ]);
  const employee = await employeeCtx.newPage();
  await employee.goto(BASE + "/request");
  await employee.locator("button.primary", { hasText: "Create request link" }).click();
  await employee.locator("h2", { hasText: "Send this link to them" }).waitFor({ timeout: 30_000 });

  const link = (await employee.locator(".code-display code").nth(0).textContent()).trim();
  const claimCode = (await employee.locator(".code-display code").nth(1).textContent()).trim();
  check("B: request link minted", link.includes("/give#g="), link.slice(0, 60));
  check(
    "B: claim code shown once to the employee",
    /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}(-[a-z]+){5}$/.test(claimCode),
    claimCode,
  );

  await employee.locator("button.primary", { hasText: "Wait for it here" }).click();
  await employee.locator("h2", { hasText: "Waiting for their secret" }).waitFor({ timeout: 10_000 });

  // Guest: no cookie, no account — just the link.
  const guestCtx = await browser.newContext({ extraHTTPHeaders: TENANT_HOST_HEADER });
  const guest = await guestCtx.newPage();
  await guest.goto(link);
  check("B: fragment scrubbed from guest address bar", !(await guest.evaluate(() => location.hash)));
  await guest.locator("h2", { hasText: "asked you to send them a secret" }).waitFor({ timeout: 15_000 });
  await guest.fill("textarea", SECRET_TEXT);
  await guest.locator("button.primary", { hasText: "Encrypt & send" }).click();
  await guest.locator("h2", { hasText: "Sent" }).waitFor({ timeout: 30_000 });
  check("B: guest sent without an account", true);

  // The waiting employee should pick it up via the claim poll.
  await employee.locator("pre.secret").waitFor({ timeout: 30_000 });
  const received = await employee.locator("pre.secret").textContent();
  check("B: employee received the exact secret", received === SECRET_TEXT);

  // One-time: a second guest with the same link is refused.
  const guest2 = await guestCtx.newPage();
  await guest2.goto(link);
  await guest2.fill("textarea", "second attempt");
  await guest2.locator("button.primary", { hasText: "Encrypt & send" }).click();
  await guest2.locator("p.danger", { hasText: "already used" }).waitFor({ timeout: 30_000 });
  check("B: request link is strictly one-time", true);

  await guestCtx.close();
  await employeeCtx.close();
}

// C) public host regression: no auth traffic, stock branding, composer open
{
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const authCalls = [];
  page.on("request", (req) => {
    if (req.url().includes("/auth/")) authCalls.push(req.url());
  });
  await page.goto(BASE + "/");
  await page.locator("textarea").waitFor({ timeout: 15_000 });
  const h1 = await page.locator("h1").textContent();
  check("C: public branding untouched", h1.includes("Secret Share"), h1);
  check("C: composer open without sign-in", true);
  await page.waitForTimeout(1500);
  check("C: zero /auth requests on the public host", authCalls.length === 0, authCalls.join(","));
  await ctx.close();
}

await browser.close();
killDev();

console.log(failures === 0 ? "\nALL TENANT E2E CHECKS PASSED" : `\n${failures} TENANT E2E CHECKS FAILED`);
process.exit(failures === 0 ? 0 : 1);
