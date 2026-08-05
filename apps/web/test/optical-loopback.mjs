// Optical (QR) transfer e2e — no camera required. `?loopback` renders sender
// and receiver on one page and wires them canvas-to-canvas, so this exercises
// the REAL path: fountain encode → QR render → zxing-wasm decode → fountain
// decode → container open (plaintext and ECDH-encrypted).
//
// Self-contained: serves the built SPA via `vite preview`. Run `pnpm build` first.
//   node test/optical-loopback.mjs
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";
import { chromium } from "playwright";

const webDir = fileURLToPath(new URL("..", import.meta.url));
const PORT = 4174;
const BASE = `http://127.0.0.1:${PORT}`;

if (!existsSync(new URL("../dist/index.html", import.meta.url))) {
  console.error("dist/ missing — run `pnpm build` first");
  process.exit(1);
}

let failures = 0;
const check = (label, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${detail ? `: ${detail}` : ""}`);
};

// --- serve built SPA: run vite's JS entry directly (no shell) so kill() works ---
// vite's package exports hide bin/, so walk from the resolved main entry
const viteMain = createRequire(new URL("../package.json", import.meta.url)).resolve("vite"); // .../vite/dist/node/index.js
const viteBin = path.join(path.dirname(viteMain), "..", "..", "bin", "vite.js");
const server = spawn(
  process.execPath,
  [viteBin, "preview", "--host", "127.0.0.1", "--port", String(PORT), "--strictPort"],
  { cwd: webDir, stdio: "ignore" },
);
const serverGone = new Promise((r) => server.on("exit", r));
let up = false;
for (let i = 0; i < 150 && !up; i++) {
  try {
    up = (await fetch(BASE + "/")).ok;
  } catch {
    await new Promise((r) => setTimeout(r, 200));
  }
}
if (!up) {
  console.error("vite preview never came up");
  server.kill();
  process.exit(1);
}
process.on("exit", () => server.kill());

const browser = await chromium.launch();

async function openLoopback(ctx) {
  const page = await ctx.newPage();
  await page.goto(`${BASE}/?loopback`);
  await page.click("nav button:has-text('QR Transfer')");
  await page.locator("[data-testid=optical-send]").waitFor({ timeout: 10_000 });
  return page;
}

// --- Scenario A: plaintext text transfer ---
{
  const ctx = await browser.newContext();
  const page = await openLoopback(ctx);
  const SECRET = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlFAKEbnNzaC1rZXk\n-----END-----";

  const send = page.locator("[data-testid=optical-send]");
  const recv = page.locator("[data-testid=optical-receive]");

  await recv.locator("button.primary", { hasText: "Start camera" }).click();
  await send.locator("textarea").fill(SECRET);
  await send.locator("button.primary", { hasText: "Start streaming" }).click();

  await recv.locator("pre.secret").waitFor({ timeout: 30_000 });
  const got = await recv.locator("pre.secret").textContent();
  check("A: plaintext text arrives byte-identical", got === SECRET);
  check(
    "A: integrity note shown",
    (await recv.textContent()).includes("Integrity verified"),
  );
  await ctx.close();
}

// --- Scenario B: encrypted binary file transfer + matching safety numbers ---
{
  const ctx = await browser.newContext();
  const page = await openLoopback(ctx);
  const send = page.locator("[data-testid=optical-send]");
  const recv = page.locator("[data-testid=optical-receive]");

  // binary payload with high bytes — catches any charset mangling in the QR
  // path; big enough that the transfer outlives the mid-stream assertions
  const fileBytes = Buffer.alloc(60_000);
  for (let i = 0; i < fileBytes.length; i++) fileBytes[i] = (i * 7 + 250) & 0xff;

  // 1. receiver shows its pairing (public key) QR
  await recv.locator("button", { hasText: "Receive encrypted" }).click();
  await recv.locator("#optical-receiver-key").waitFor({ timeout: 10_000 });

  // 2. sender attaches the file, enables encryption, scans the pairing code
  await send.locator("input[type=file]").setInputFiles({
    name: "blob.bin",
    mimeType: "application/octet-stream",
    buffer: fileBytes,
  });
  await send.locator("input[type=checkbox]").check();
  await send.locator("button.primary", { hasText: "Scan receiver" }).click();

  // 3. pairing pauses on the safety number; the sender must confirm to stream
  await send.locator("h2", { hasText: "Paired" }).waitFor({ timeout: 30_000 });
  const senderSafety = (await send.locator(".safety-number").textContent({ timeout: 10_000 })).trim();
  check("B: sender derived a safety number", /^[0-9A-Z]{8}$/.test(senderSafety), senderSafety);
  await send.locator("button.primary", { hasText: "Start streaming" }).click();
  await send.locator("canvas#optical-sender-canvas").waitFor({ timeout: 30_000 });

  // 4. receiver starts scanning — the safety number must appear DURING the
  // transfer (block 0 carries the sender key and frame 0 is re-emitted), so
  // both parties can compare before the payload finishes landing
  await recv.locator("button.primary", { hasText: "start camera" }).click();
  const liveSafety = (await recv.locator(".safety-number").textContent({ timeout: 60_000 })).trim();
  const midTransfer = await recv.locator("h2", { hasText: "Scanning" }).isVisible();
  check("B: receiver shows the safety number mid-transfer", midTransfer && liveSafety === senderSafety, `${liveSafety} (scanning=${midTransfer})`);
  await recv.locator("h2", { hasText: "Received" }).waitFor({ timeout: 120_000 });
  const recvSafety = (await recv.locator(".safety-number").textContent()).trim();
  check("B: safety numbers match on both screens", recvSafety === senderSafety, `${senderSafety} vs ${recvSafety}`);

  // 5. saved file is byte-identical
  const downloadP = page.waitForEvent("download", { timeout: 15_000 });
  await recv.locator("a[download] button").click();
  try {
    const download = await downloadP;
    const path = await download.path();
    const { readFileSync } = await import("node:fs");
    const gotBytes = readFileSync(path);
    check("B: encrypted file arrives byte-identical", gotBytes.equals(fileBytes), `${gotBytes.length} bytes`);
    check("B: filename preserved", download.suggestedFilename() === "blob.bin", download.suggestedFilename());
  } catch (e) {
    check("B: encrypted file arrives byte-identical", false, String(e));
  }
  await ctx.close();
}

// --- Scenario C: an unpaired receiver is warned and refused (key hygiene) ---
{
  const ctx = await browser.newContext();
  const page = await openLoopback(ctx);
  const send = page.locator("[data-testid=optical-send]");
  const recv = page.locator("[data-testid=optical-receive]");

  // receiver shows a key, sender pairs against it and streams...
  await recv.locator("button", { hasText: "Receive encrypted" }).click();
  await recv.locator("#optical-receiver-key").waitFor({ timeout: 10_000 });
  await send.locator("textarea").fill("for the paired receiver only");
  await send.locator("input[type=checkbox]").check();
  await send.locator("button.primary", { hasText: "Scan receiver" }).click();
  await send.locator("h2", { hasText: "Paired" }).waitFor({ timeout: 30_000 });
  await send.locator("button.primary", { hasText: "Start streaming" }).click();
  await send.locator("canvas#optical-sender-canvas").waitFor({ timeout: 30_000 });

  // ...but the receiver abandons the pairing (Back wipes the ephemeral key)
  // and scans as a plaintext receiver — it must be warned and then refused.
  await recv.locator("button", { hasText: "Back" }).click();
  await recv.locator("button.primary", { hasText: "Start camera" }).click();
  const warned = await recv
    .locator("p.danger", { hasText: "encrypted" })
    .waitFor({ timeout: 60_000 })
    .then(() => true)
    .catch(() => false);
  check("C: unpaired receiver sees the encrypted-stream warning", warned);
  const refused = await recv
    .locator("p.danger", { hasText: "Receive encrypted" })
    .waitFor({ timeout: 120_000 })
    .then(() => true)
    .catch(() => false);
  check("C: completion without a pairing key is refused", refused);
  await ctx.close();
}

await browser.close();
server.kill();
await Promise.race([serverGone, new Promise((r) => setTimeout(r, 3000))]);

console.log(failures === 0 ? "\nALL OPTICAL E2E CHECKS PASSED" : `\n${failures} OPTICAL E2E CHECKS FAILED`);
process.exit(failures === 0 ? 0 : 1);
