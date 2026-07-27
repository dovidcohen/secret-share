// Renders the 1200x630 Open Graph card to public/og.png.
import { chromium } from "playwright";

const html = `<!doctype html><html><head><style>
  * { margin: 0; box-sizing: border-box; }
  body {
    width: 1200px; height: 630px;
    font-family: system-ui, "Segoe UI", sans-serif;
    background: linear-gradient(135deg, #0f1115 0%, #16213e 60%, #1d3a8f 100%);
    color: #fff; display: flex; flex-direction: column;
    justify-content: center; padding: 0 90px;
  }
  .logo { font-size: 108px; color: #5b8cff; line-height: 1; margin-bottom: 24px; }
  h1 { font-size: 76px; letter-spacing: -1px; }
  p { font-size: 34px; color: #b8c2d8; margin-top: 22px; line-height: 1.4; }
  .badges { margin-top: 40px; display: flex; gap: 18px; }
  .badge {
    border: 2px solid #5b8cff; color: #cfe0ff; border-radius: 999px;
    padding: 10px 26px; font-size: 26px;
  }
  .domain { position: absolute; bottom: 44px; right: 90px; font-size: 30px; color: #8fa3c8; }
</style></head><body>
  <div class="logo">&#x29c9;</div>
  <h1>Secret Share</h1>
  <p>Pass a password, SSH key, or API token to exactly one person.</p>
  <div class="badges">
    <div class="badge">End-to-end encrypted</div>
    <div class="badge">Browser-to-browser</div>
    <div class="badge">Gone after one read</div>
  </div>
  <div class="domain">shareasecret.io</div>
</body></html>`;

const b = await chromium.launch();
const p = await b.newPage({ viewport: { width: 1200, height: 630 } });
await p.setContent(html);
await p.screenshot({ path: "apps/web/public/og.png" });
await b.close();
console.log("wrote apps/web/public/og.png");
