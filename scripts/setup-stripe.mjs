#!/usr/bin/env node
// One-time Stripe bootstrap for the white-label plans. Idempotent: prices are
// keyed by lookup_key, so re-running finds the existing objects instead of
// duplicating them. Requires STRIPE_SECRET_KEY in the environment (use the
// test-mode key first; run again with the live key when ready).
//
//   STRIPE_SECRET_KEY=sk_... node scripts/setup-stripe.mjs
//   STRIPE_SECRET_KEY=sk_... node scripts/setup-stripe.mjs --create-webhook
//
// --create-webhook registers https://shareasecret.io/api/billing/webhook and
// prints the signing secret ONCE — put it straight into
// `wrangler secret put STRIPE_WEBHOOK_SECRET`.

const KEY = process.env.STRIPE_SECRET_KEY;
if (!KEY) {
  console.error("error: set STRIPE_SECRET_KEY (sk_test_... or sk_live_...)");
  process.exit(1);
}

const WEBHOOK_URL = "https://shareasecret.io/api/billing/webhook";
// "Software as a service (SaaS) — business use". Required by Managed Payments
// (on by default on newer accounts): Stripe is merchant of record and needs
// the tax category to calculate/remit sales tax.
const TAX_CODE = "txcd_10103000";
const WEBHOOK_EVENTS = [
  "checkout.session.completed",
  "customer.subscription.created",
  "customer.subscription.updated",
  "customer.subscription.deleted",
];

/** [envVar, lookupKey, productName, unitAmount (cents), interval] */
const PLANS = [
  ["STRIPE_PRICE_TEAM_MONTHLY", "team_monthly", "Secret Share Team", 4900, "month"],
  ["STRIPE_PRICE_TEAM_YEARLY", "team_yearly", "Secret Share Team", 49000, "year"],
  ["STRIPE_PRICE_BUSINESS_MONTHLY", "business_monthly", "Secret Share Business", 9900, "month"],
  ["STRIPE_PRICE_BUSINESS_YEARLY", "business_yearly", "Secret Share Business", 99000, "year"],
];

async function stripe(method, path, params) {
  const res = await fetch(`https://api.stripe.com/v1/${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${KEY}`,
      ...(params ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
    },
    body: params ? new URLSearchParams(params).toString() : undefined,
  });
  const body = await res.json();
  if (!res.ok) {
    console.error(`error: Stripe ${method} ${path} -> ${res.status}`);
    console.error(JSON.stringify(body.error ?? body, null, 2));
    process.exit(1);
  }
  return body;
}

async function findPrice(lookupKey) {
  const res = await stripe(
    "GET",
    `prices?lookup_keys[]=${encodeURIComponent(lookupKey)}&limit=1`,
  );
  return res.data[0] ?? null;
}

const products = new Map(); // name -> product id
async function productIdFor(name) {
  if (products.has(name)) return products.get(name);
  const search = await stripe(
    "GET",
    `products/search?query=${encodeURIComponent(`name:'${name}' AND active:'true'`)}`,
  );
  const existing = search.data[0];
  const product =
    existing ??
    (await stripe("POST", "products", {
      name,
      tax_code: TAX_CODE,
      "metadata[app]": "secret-share",
    }));
  products.set(name, product.id);
  return product.id;
}

/** Products created before the tax-code requirement surfaced get repaired. */
const taxChecked = new Set();
async function ensureTaxCode(productId) {
  if (taxChecked.has(productId)) return;
  taxChecked.add(productId);
  const product = await stripe("GET", `products/${productId}`);
  if (product.tax_code !== TAX_CODE) {
    await stripe("POST", `products/${productId}`, { tax_code: TAX_CODE });
    console.log(`+ set tax_code ${TAX_CODE} on product ${productId}`);
  }
}

const vars = {};
for (const [envVar, lookupKey, productName, amount, interval] of PLANS) {
  let price = await findPrice(lookupKey);
  if (!price) {
    price = await stripe("POST", "prices", {
      lookup_key: lookupKey,
      product: await productIdFor(productName),
      currency: "usd",
      unit_amount: String(amount),
      "recurring[interval]": interval,
      "metadata[app]": "secret-share",
    });
    console.log(`+ created ${lookupKey} -> ${price.id} ($${amount / 100}/${interval})`);
  } else {
    console.log(`= found ${lookupKey} -> ${price.id}`);
  }
  await ensureTaxCode(typeof price.product === "string" ? price.product : price.product.id);
  vars[envVar] = price.id;
}

if (process.argv.includes("--create-webhook")) {
  const hooks = await stripe("GET", "webhook_endpoints?limit=100");
  const existing = hooks.data.find((h) => h.url === WEBHOOK_URL);
  if (existing) {
    console.log(`= webhook already registered (${existing.id}); its secret is only`);
    console.log(`  shown at creation — roll it in the dashboard if you've lost it.`);
  } else {
    const params = { url: WEBHOOK_URL, "metadata[app]": "secret-share" };
    WEBHOOK_EVENTS.forEach((e, i) => (params[`enabled_events[${i}]`] = e));
    const hook = await stripe("POST", "webhook_endpoints", params);
    console.log(`+ webhook ${hook.id} -> ${WEBHOOK_URL}`);
    console.log(`\n  Signing secret (shown once):\n    ${hook.secret}\n`);
  }
}

const mode = KEY.startsWith("sk_live") ? "LIVE" : "TEST";
console.log(`\nDone (${mode} mode). Finish the wiring:\n`);
console.log(`  1. Paste into the "vars" block of workers/api/wrangler.jsonc:\n`);
for (const [k, v] of Object.entries(vars)) console.log(`       "${k}": "${v}",`);
console.log(`\n  2. Secrets (cd workers/api):`);
console.log(`       npx wrangler secret put STRIPE_SECRET_KEY`);
console.log(`       npx wrangler secret put STRIPE_WEBHOOK_SECRET`);
if (!process.argv.includes("--create-webhook")) {
  console.log(`     (no webhook yet — re-run with --create-webhook, or add`);
  console.log(`      ${WEBHOOK_URL} in the Stripe dashboard)`);
}
console.log(`\n  3. Deploy: pnpm build && pnpm --filter @secret-share/api deploy`);
console.log(`  4. Enable the Customer Portal once in the dashboard:`);
console.log(`       https://dashboard.stripe.com/settings/billing/portal`);
