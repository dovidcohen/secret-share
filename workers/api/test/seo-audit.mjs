// Production SEO audit: verifies each page exposes what crawlers need.
const BASE = "https://shareasecret.io";
let warn = 0;
const ok = (b) => (b ? "PASS" : ((warn++), "WARN"));

const PAGES = [
  "/",
  "/guides/send-ssh-key-securely",
  "/guides/share-password-one-time-link",
  "/guides/send-api-key-securely",
  "/guides/cli",
  "/compare/secret-sharing-tools",
  "/blog",
  "/blog/park-first-secret-sharing",
];

async function head(url, opts) {
  const r = await fetch(url, opts);
  const body = await r.text();
  return { status: r.status, headers: r.headers, body };
}

for (const p of PAGES) {
  const { status, body } = await head(BASE + p);
  const has = (re) => re.test(body);
  const title = (body.match(/<title>([^<]*)<\/title>/) || [])[1] || "";
  const desc = (body.match(/<meta\s+name="description"\s+content="([^"]*)"/) || [])[1] || "";
  const canon = (body.match(/rel="canonical" href="([^"]*)"/) || [])[1] || "";
  console.log(`\n${p}  [${status}]`);
  console.log(`  ${ok(status === 200)} 200`);
  console.log(`  ${ok(title.length > 10 && title.length < 65)} title (${title.length}c): ${title.slice(0, 60)}`);
  console.log(`  ${ok(desc.length > 50 && desc.length < 170)} description (${desc.length}c)`);
  console.log(`  ${ok(canon === BASE + p || (p === "/" && canon === BASE + "/"))} canonical: ${canon}`);
  console.log(`  ${ok(has(/application\/ld\+json/))} JSON-LD structured data`);
  console.log(`  ${ok(has(/og:image/) && has(/og:title/))} Open Graph (title+image)`);
  console.log(`  ${ok(has(/<h1[ >]/))} has H1`);
}

// robots + sitemap + og image
const robots = await head(BASE + "/robots.txt");
console.log(`\n/robots.txt [${robots.status}]`);
console.log(`  ${ok(robots.status === 200)} 200`);
console.log(`  ${ok(/Sitemap: https:\/\/shareasecret\.io\/sitemap\.xml/.test(robots.body))} references sitemap`);
console.log(`  ${ok(!/Disallow: \/\s*$/m.test(robots.body))} does not block the whole site`);

const sm = await head(BASE + "/sitemap.xml");
const locs = [...sm.body.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
console.log(`\n/sitemap.xml [${sm.status}]`);
console.log(`  ${ok(sm.status === 200)} 200`);
console.log(`  ${ok(locs.length === PAGES.length)} lists ${locs.length} URLs (expect ${PAGES.length})`);
console.log(`  ${ok(PAGES.every((p) => locs.includes(BASE + (p === "/" ? "/" : p))))} all pages present in sitemap`);

const og = await head(BASE + "/og.png");
console.log(`\n/og.png [${og.status}]`);
console.log(`  ${ok(og.status === 200)} 200`);
console.log(`  ${ok((og.headers.get("content-type") || "").includes("image/png"))} content-type png`);

// Googlebot must not be blocked by security headers etc.
const gb = await fetch(BASE + "/guides/send-ssh-key-securely", {
  headers: { "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" },
});
console.log(`\nGooglebot fetch [${gb.status}]`);
console.log(`  ${ok(gb.status === 200)} served 200 to Googlebot UA`);
console.log(`  ${ok((gb.headers.get("x-robots-tag") || "") === "")} no blocking X-Robots-Tag`);

console.log(warn === 0 ? "\nALL SEO CHECKS PASSED" : `\n${warn} WARNINGS — review above`);
process.exit(0);
