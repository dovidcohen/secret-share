// Mobile-friendliness check: iPhone-sized viewport screenshots + overflow audit.
import { chromium, devices } from "playwright";

const BASE = "http://127.0.0.1:8787";
const SSH_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBFakE2eTZORGNZuFAKE0FakeKEYd25vdCByZWFsIGtleSBkYXRhCg==
-----END OPENSSH PRIVATE KEY-----`;

const browser = await chromium.launch();
const ctx = await browser.newContext({ ...devices["iPhone 13"] });

async function audit(page, name) {
  const overflow = await page.evaluate(() => {
    const bad = [];
    const docW = document.documentElement.clientWidth;
    for (const el of document.querySelectorAll("*")) {
      const r = el.getBoundingClientRect();
      if (r.width > 0 && (r.right > docW + 1 || r.left < -1)) {
        bad.push(`${el.tagName}.${el.className}`.slice(0, 60));
      }
    }
    return {
      horizontalScroll: document.documentElement.scrollWidth > docW,
      overflowing: [...new Set(bad)].slice(0, 5),
    };
  });
  const smallInputs = await page.evaluate(() =>
    [...document.querySelectorAll("input, textarea, select")].map((el) => ({
      tag: el.tagName,
      fontPx: parseFloat(getComputedStyle(el).fontSize),
    })),
  );
  const tapTargets = await page.evaluate(() =>
    [...document.querySelectorAll("button")].map((b) => {
      const r = b.getBoundingClientRect();
      return { text: (b.textContent ?? "").trim().slice(0, 20), w: Math.round(r.width), h: Math.round(r.height) };
    }),
  );
  await page.screenshot({ path: `apps/web/test/shot-${name}.png`, fullPage: true });
  console.log(`--- ${name} ---`);
  console.log("horizontal scroll:", overflow.horizontalScroll, overflow.overflowing.length ? overflow.overflowing : "");
  console.log("input font sizes (iOS zooms if <16px):", JSON.stringify(smallInputs));
  console.log("tap targets (<44px height is small):", JSON.stringify(tapTargets.filter((t) => t.h > 0 && t.h < 44)));
}

// Send page (compose)
const pageA = await ctx.newPage();
await pageA.goto(BASE + "/");
await audit(pageA, "send-compose");

// Send page (code display)
await pageA.fill("textarea", SSH_KEY);
await pageA.click("button.primary");
await pageA.locator(".code-display code").first().waitFor({ timeout: 30_000 });
await audit(pageA, "send-ready");
const code = (await pageA.locator(".code-display code").first().textContent()).trim();

// Receive page (done state, secret shown)
const pageB = await ctx.newPage();
await pageB.goto(`${BASE}/r#${code}`);
await pageB.locator("pre.secret").waitFor({ timeout: 45_000 });
await audit(pageB, "receive-done");

await browser.close();
console.log("done");
