// End-to-end verification through real browsers (Playwright + Chromium) against
// the production-shaped server: `pnpm build` + `wrangler dev` on :8787.
//
// A) live P2P transfer while both tabs are open (drop deleted afterwards)
// B) async: sender closes tab, receiver claims the parked drop (read-once)
// C) WebRTC blocked -> receiver falls back to the drop after the live timeout
import { chromium } from "playwright";

const BASE = "http://127.0.0.1:8787";
const SSH_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBFakE2eTZORGNZuFAKE0FakeKEYd25vdCByZWFsIGtleSBkYXRhCg==
-----END OPENSSH PRIVATE KEY-----`;

let failures = 0;
const check = (label, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${detail ? `: ${detail}` : ""}`);
};

async function share(page) {
  await page.goto(BASE + "/");
  await page.fill("textarea", SSH_KEY);
  await page.click("button.primary");
  const codeEl = page.locator(".code-display code").first();
  await codeEl.waitFor({ timeout: 30_000 });
  return (await codeEl.textContent()).trim();
}

async function expectSecret(page, expectedVia) {
  await page.locator("pre.secret").waitFor({ timeout: 45_000 });
  const secret = await page.locator("pre.secret").textContent();
  const status = await page.locator(".status").textContent();
  return { secretOk: secret === SSH_KEY, status, viaOk: status.includes(expectedVia) };
}

const browser = await chromium.launch();

// --- Scenario A: live transfer, both tabs open ---
{
  const ctx = await browser.newContext();
  const pageA = await ctx.newPage();
  const code = await share(pageA);
  check("A: share code produced", /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}(-[a-z]+){5}$/.test(code), code);

  const pageB = await ctx.newPage();
  await pageB.goto(`${BASE}/r#${code}`);
  const got = await expectSecret(pageB, "Transferred directly");
  check("A: receiver got exact secret", got.secretOk);
  check("A: transfer was live (P2P)", got.viaOk, got.status);

  await pageA
    .locator(".status", { hasText: "Delivered directly" })
    .waitFor({ timeout: 10_000 })
    .then(() => check("A: sender shows delivered + server copy deleted", true))
    .catch(() => check("A: sender shows delivered + server copy deleted", false));

  // Third party with the same code must NOT get the secret again.
  const pageC = await ctx.newPage();
  await pageC.goto(`${BASE}/r#${code}`);
  await pageC
    .locator("p.danger", { hasText: "already retrieved" })
    .waitFor({ timeout: 30_000 })
    .then(() => check("A: second receive attempt is refused (read-once)", true))
    .catch(async () => {
      check("A: second receive attempt is refused (read-once)", false, await pageC.content().then((c) => c.slice(0, 0)));
    });
  await ctx.close();
}

// --- Scenario B: async — sender parks, closes tab, receiver claims ---
{
  const ctx = await browser.newContext();
  const pageA = await ctx.newPage();
  const code = await share(pageA);
  await pageA.close(); // sender goes away entirely

  const pageB = await ctx.newPage();
  await pageB.goto(`${BASE}/r#${code}`);
  const got = await expectSecret(pageB, "Retrieved and destroyed");
  check("B: receiver got exact secret from parked drop", got.secretOk);
  check("B: async path used", got.viaOk, got.status);

  const pageB2 = await ctx.newPage();
  await pageB2.goto(`${BASE}/r#${code}`);
  await pageB2
    .locator("p.danger", { hasText: "already retrieved" })
    .waitFor({ timeout: 30_000 })
    .then(() => check("B: re-claim refused (read-once)", true))
    .catch(() => check("B: re-claim refused (read-once)", false));
  await ctx.close();
}

await browser.close();

// --- Scenario C: WebRTC blocked -> automatic fallback to the parked drop ---
{
  const blocked = await chromium.launch({
    args: ["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"],
  });
  const ctx = await blocked.newContext();
  const pageA = await ctx.newPage();
  const code = await share(pageA);

  const pageB = await ctx.newPage();
  await pageB.goto(`${BASE}/r#${code}`);
  const t0 = Date.now();
  const got = await expectSecret(pageB, "Retrieved and destroyed");
  const secs = Math.round((Date.now() - t0) / 1000);
  check("C: receiver still got the secret (fallback)", got.secretOk, `${secs}s`);
  check("C: fell back to the parked drop", got.viaOk, got.status);
  await blocked.close();
}

// --- Scenario D: direct-only mode — nothing uploaded, live transfer still works ---
{
  const b2 = await chromium.launch();
  const ctx = await b2.newContext();
  const pageA = await ctx.newPage();
  await pageA.goto(BASE + "/");
  await pageA.fill("textarea", SSH_KEY);
  await pageA.check("input[type=checkbox]");
  await pageA.click("button.primary");
  const codeEl = pageA.locator(".code-display code").first();
  await codeEl.waitFor({ timeout: 30_000 });
  const code = (await codeEl.textContent()).trim();

  // Nothing parked server-side: a claim on this mailbox must 404 (not 403/410).
  const mailboxId = code.split("-").slice(0, 2).join("").toUpperCase();
  const probe = await fetch(`${BASE}/api/drops/${mailboxId}/claim`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ claimTag: "A".repeat(43) }),
  });
  check("D: nothing stored on server (claim 404)", probe.status === 404, `status ${probe.status}`);

  const pageB = await ctx.newPage();
  await pageB.goto(`${BASE}/r#${code}`);
  const got = await expectSecret(pageB, "Transferred directly");
  check("D: receiver got exact secret", got.secretOk);
  check("D: transfer was live", got.viaOk, got.status);
  await pageA
    .locator(".status", { hasText: "Nothing ever touched the server" })
    .waitFor({ timeout: 10_000 })
    .then(() => check("D: sender confirms zero-upload delivery", true))
    .catch(() => check("D: sender confirms zero-upload delivery", false));
  await b2.close();
}

console.log(failures === 0 ? "\nALL E2E CHECKS PASSED" : `\n${failures} E2E CHECKS FAILED`);
process.exit(failures === 0 ? 0 : 1);
