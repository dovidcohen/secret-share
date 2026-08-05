// Deployed smoke test for the optical (QR) transfer — catches the class of
// failure the loopback e2e structurally can't: production headers and real
// camera policy. Runs against the live site (or SMOKE_BASE).
//
//   node test/live-smoke.mjs
//   SMOKE_BASE=https://staging.example node test/live-smoke.mjs
import { chromium } from "playwright";

const BASE = process.env.SMOKE_BASE ?? "https://shareasecret.io";

let failures = 0;
const check = (label, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${detail ? `: ${detail}` : ""}`);
};

// --- 1. headers: the camera must not be blocked by policy ---
const bust = `?smoke=${process.pid}${Math.trunc(performance.now())}`;
const res = await fetch(`${BASE}/qr${bust}`, { headers: { "Cache-Control": "no-cache" } });
check("app shell responds", res.ok, `HTTP ${res.status}`);
const policy = res.headers.get("permissions-policy") ?? "";
check("Permissions-Policy allows same-origin camera", policy.includes("camera=(self)"), policy);

// --- 2. asset chain: shell -> main bundle -> decode worker -> wasm ---
const html = await res.text();
const mainJs = html.match(/assets\/main-[\w-]+\.js/)?.[0];
check("shell references main bundle", !!mainJs, mainJs);
let wasmOk = false;
if (mainJs) {
  const js = await (await fetch(`${BASE}/${mainJs}`)).text();
  const workerJs = js.match(/assets\/qr-decode\.worker-[\w-]+\.js/)?.[0];
  check("main bundle references decode worker", !!workerJs, workerJs);
  if (workerJs) {
    const worker = await (await fetch(`${BASE}/${workerJs}`)).text();
    const wasm = worker.match(/assets\/zxing_reader-[\w-]+\.wasm/)?.[0];
    if (wasm) {
      const head = await fetch(`${BASE}/${wasm}`, { method: "HEAD" });
      wasmOk = head.ok;
      check("zxing wasm served same-origin", wasmOk, `${wasm} -> HTTP ${head.status}`);
    } else {
      check("zxing wasm served same-origin", false, "no wasm reference in worker");
    }
  }
}

// --- 3. real getUserMedia against the deployed policy (fake device) ---
const browser = await chromium.launch({
  args: ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream"],
});
const ctx = await browser.newContext({ permissions: ["camera"] });
const page = await ctx.newPage();
await page.goto(`${BASE}/qr`);
await page.click("section nav button:has-text('Receive')");
await page.click("button.primary:has-text('Start camera')");
const cameraLive = await page
  .locator("text=Looking for a stream")
  .waitFor({ timeout: 20_000 })
  .then(() => true)
  .catch(() => false);
check("camera pipeline starts on the deployed site", cameraLive);
if (!cameraLive) {
  const err = await page.locator("p.danger").textContent().catch(() => "(no error shown)");
  console.log(`      page error: ${err}`);
}
await browser.close();

console.log(failures === 0 ? "\nALL LIVE SMOKE CHECKS PASSED" : `\n${failures} LIVE SMOKE CHECKS FAILED`);
process.exit(failures === 0 ? 0 : 1);
