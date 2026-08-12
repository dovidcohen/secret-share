import { loadTenant, saveTenant } from "./tenant/registry.js";
import type { TenantConfig } from "./tenant/schema.js";

/**
 * Stripe subscription billing for white-label tenants.
 *
 * Plans: Team ($49/mo, $490/yr) and Business ($99/mo, $990/yr), flat per org.
 * Trials are 14 days, card-free (tenants are provisioned manually), so the
 * trial clock lives here (billing.trialEndsAt), not in Stripe. Stripe becomes
 * the source of truth the moment a checkout completes; its webhooks are the
 * ONLY writer of post-checkout state, keyed by the tenantId we stamp into
 * subscription metadata at checkout time.
 *
 * No Stripe SDK: the two API calls we make (checkout + portal sessions) are
 * plain form-encoded POSTs, and webhook verification is one HMAC — a
 * dependency would be all risk, no lift. With STRIPE_* secrets unset every
 * entry point 404s and entitlement passes, so the platform runs unchanged
 * until payments are switched on.
 */

const WEBHOOK_TOLERANCE_S = 300;

export type Plan = "team" | "business";
export type Interval = "monthly" | "yearly";

function json(status: number, body: unknown): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

// ---------- entitlement ----------

export type Entitlement = { ok: true } | { ok: false; reason: "trial_expired" | "canceled" };

/**
 * May this tenant's members SEND secrets? Claiming is never gated — a secret
 * already sent must stay receivable regardless of the sender org's invoice.
 * Tenants with no billing block (legacy/design partners) are fully entitled;
 * past_due keeps working while Stripe's dunning retries run — a lapsed card
 * only blocks once the subscription is actually canceled.
 */
export function entitlement(tenant: TenantConfig, now = Date.now()): Entitlement {
  const billing = tenant.billing;
  if (!billing) return { ok: true };
  if (billing.status === "canceled") return { ok: false, reason: "canceled" };
  if (
    billing.status === "trialing" &&
    billing.trialEndsAt !== undefined &&
    now > billing.trialEndsAt
  ) {
    return { ok: false, reason: "trial_expired" };
  }
  return { ok: true };
}

export function entitlementDenied(reason: "trial_expired" | "canceled"): Response {
  // 402 so clients can distinguish "org's plan lapsed" from auth failures.
  return json(402, { error: "PLAN_INACTIVE", reason });
}

// ---------- Stripe REST helpers ----------

function priceIdFor(plan: Plan, interval: Interval, env: Env): string | undefined {
  const table: Record<`${Plan}_${Interval}`, string | undefined> = {
    team_monthly: env.STRIPE_PRICE_TEAM_MONTHLY,
    team_yearly: env.STRIPE_PRICE_TEAM_YEARLY,
    business_monthly: env.STRIPE_PRICE_BUSINESS_MONTHLY,
    business_yearly: env.STRIPE_PRICE_BUSINESS_YEARLY,
  };
  return table[`${plan}_${interval}`];
}

/** Reverse of priceIdFor: which plan does a subscription's price belong to? */
function planForPrice(priceId: string, env: Env): Plan | null {
  if (priceId === env.STRIPE_PRICE_TEAM_MONTHLY || priceId === env.STRIPE_PRICE_TEAM_YEARLY) {
    return "team";
  }
  if (
    priceId === env.STRIPE_PRICE_BUSINESS_MONTHLY ||
    priceId === env.STRIPE_PRICE_BUSINESS_YEARLY
  ) {
    return "business";
  }
  return null;
}

async function stripePost(
  path: string,
  params: Record<string, string>,
  env: Env,
): Promise<Record<string, unknown> | null> {
  const res = await fetch(`https://api.stripe.com/v1/${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(params).toString(),
  });
  if (!res.ok) {
    console.error(`Stripe ${path} failed: ${res.status} ${await res.text()}`);
    return null;
  }
  return (await res.json()) as Record<string, unknown>;
}

/**
 * Hosted Checkout for an upgrade, requested by a signed-in tenant admin. The
 * tenantId is stamped into the SUBSCRIPTION's metadata (not just the session)
 * so every later lifecycle webhook can find its tenant without an index.
 */
export async function createCheckoutSession(
  tenant: TenantConfig,
  plan: Plan,
  interval: Interval,
  origin: string,
  adminEmail: string,
  env: Env,
): Promise<string | null> {
  const price = priceIdFor(plan, interval, env);
  if (!price) return null;
  const params: Record<string, string> = {
    mode: "subscription",
    "line_items[0][price]": price,
    "line_items[0][quantity]": "1",
    success_url: `${origin}/admin?billing=success`,
    cancel_url: `${origin}/admin?billing=canceled`,
    client_reference_id: tenant.tenantId,
    "metadata[tenantId]": tenant.tenantId,
    "subscription_data[metadata][tenantId]": tenant.tenantId,
    allow_promotion_codes: "true",
  };
  // Returning customer keeps one Stripe customer per tenant; first checkout
  // pre-fills the admin's email instead.
  if (tenant.billing?.stripeCustomerId) params.customer = tenant.billing.stripeCustomerId;
  else params.customer_email = adminEmail;
  const session = await stripePost("checkout/sessions", params, env);
  return typeof session?.url === "string" ? session.url : null;
}

/** Stripe Customer Portal: self-serve card updates, plan switches, cancellation. */
export async function createPortalSession(
  tenant: TenantConfig,
  origin: string,
  env: Env,
): Promise<string | null> {
  const customer = tenant.billing?.stripeCustomerId;
  if (!customer) return null;
  const session = await stripePost(
    "billing_portal/sessions",
    { customer, return_url: `${origin}/admin` },
    env,
  );
  return typeof session?.url === "string" ? session.url : null;
}

// ---------- webhook ----------

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Verifies `Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>]` over the RAW body.
 * Multiple v1 entries appear during signing-secret rotation; any match passes.
 */
export async function verifyStripeSignature(
  body: string,
  header: string | null,
  secret: string,
  now = Date.now(),
): Promise<boolean> {
  if (!header) return false;
  let timestamp = "";
  const signatures: string[] = [];
  for (const part of header.split(",")) {
    const [k, v] = part.split("=", 2);
    if (k?.trim() === "t" && v) timestamp = v;
    if (k?.trim() === "v1" && v) signatures.push(v);
  }
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(now / 1000 - ts) > WEBHOOK_TOLERANCE_S) return false;
  if (signatures.length === 0) return false;
  const expected = await hmacHex(secret, `${timestamp}.${body}`);
  return signatures.some((sig) => timingSafeEqual(sig, expected));
}

interface StripeSubscription {
  id?: string;
  status?: string;
  customer?: string;
  metadata?: { tenantId?: string };
  items?: { data?: Array<{ price?: { id?: string }; current_period_end?: number }> };
  current_period_end?: number;
  cancel_at_period_end?: boolean;
  /** Some API versions express period-end cancellation as a timestamp instead. */
  cancel_at?: number | null;
}

/**
 * Stripe does not guarantee webhook ordering — a renew and a cancel fired
 * seconds apart can arrive swapped, and the stale event would win. So events
 * are only a poke: the state we WRITE is re-read from the API. Falls back to
 * the event payload when the key is unset (tests) or the fetch fails.
 */
async function fetchSubscription(id: string, env: Env): Promise<StripeSubscription | null> {
  if (!env.STRIPE_SECRET_KEY) return null;
  const res = await fetch(`https://api.stripe.com/v1/subscriptions/${id}`, {
    headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` },
  });
  if (!res.ok) {
    console.error(`Stripe subscription refetch failed: ${res.status} ${await res.text()}`);
    return null;
  }
  return (await res.json()) as StripeSubscription;
}

function mapStatus(stripeStatus: string): "active" | "past_due" | "canceled" {
  switch (stripeStatus) {
    case "past_due":
    case "unpaid":
      return "past_due";
    case "canceled":
    case "incomplete_expired":
      return "canceled";
    default:
      // active, trialing (Stripe-side), incomplete (first payment pending):
      // treat as active — Stripe cancels or marks past_due if payment fails.
      return "active";
  }
}

async function applySubscription(sub: StripeSubscription, env: Env): Promise<void> {
  const tenantId = sub.metadata?.tenantId;
  if (!tenantId || !sub.id) return; // not one of ours (or a manual dashboard sub)
  // Canceled subscriptions remain fetchable, so this covers deletions too.
  sub = (await fetchSubscription(sub.id, env)) ?? sub;
  const tenant = await loadTenant(tenantId, env, { fresh: true });
  if (!tenant) {
    console.error(`Stripe webhook for unknown tenant "${tenantId}"`);
    return;
  }
  const item = sub.items?.data?.[0];
  const plan = item?.price?.id ? planForPrice(item.price.id, env) : null;
  const periodEndS = item?.current_period_end ?? sub.current_period_end;
  tenant.billing = {
    // Keep the recorded plan if the price is unrecognized (e.g. a bespoke deal
    // created in the dashboard) rather than silently downgrading.
    plan: plan ?? tenant.billing?.plan ?? "team",
    status: mapStatus(sub.status ?? "active"),
    stripeCustomerId: typeof sub.customer === "string" ? sub.customer : tenant.billing?.stripeCustomerId,
    stripeSubscriptionId: sub.id,
    ...(periodEndS ? { currentPeriodEnd: periodEndS * 1000 } : {}),
    // Omitted when false so a portal "renew" cleanly clears it.
    ...(sub.cancel_at_period_end || sub.cancel_at ? { cancelAtPeriodEnd: true } : {}),
  };
  await saveTenant(tenant, env);
}

/**
 * POST /api/billing/webhook — any host, no session (Stripe calls it); the
 * signature over the raw body is the authentication.
 */
export async function handleStripeWebhook(request: Request, env: Env): Promise<Response> {
  if (!env.STRIPE_WEBHOOK_SECRET) return json(404, { error: "NOT_FOUND" });
  const body = await request.text();
  const valid = await verifyStripeSignature(
    body,
    request.headers.get("Stripe-Signature"),
    env.STRIPE_WEBHOOK_SECRET,
  );
  if (!valid) return json(400, { error: "BAD_SIGNATURE" });

  let event: { type?: string; data?: { object?: unknown } };
  try {
    event = JSON.parse(body) as typeof event;
  } catch {
    return json(400, { error: "BAD_REQUEST" });
  }

  switch (event.type) {
    case "checkout.session.completed": {
      // Records the customer id immediately so the portal works even before
      // the subscription.* events land; plan/status settle via those events.
      const session = event.data?.object as
        | { metadata?: { tenantId?: string }; customer?: string; subscription?: string }
        | undefined;
      const tenantId = session?.metadata?.tenantId;
      if (tenantId) {
        const tenant = await loadTenant(tenantId, env, { fresh: true });
        if (tenant) {
          tenant.billing = {
            plan: tenant.billing?.plan ?? "team",
            ...tenant.billing,
            status: "active",
            ...(typeof session?.customer === "string"
              ? { stripeCustomerId: session.customer }
              : {}),
            ...(typeof session?.subscription === "string"
              ? { stripeSubscriptionId: session.subscription }
              : {}),
          };
          await saveTenant(tenant, env);
        }
      }
      break;
    }
    case "customer.subscription.created":
    case "customer.subscription.updated":
    case "customer.subscription.deleted":
      await applySubscription((event.data?.object ?? {}) as StripeSubscription, env);
      break;
    default:
      break; // acknowledged, ignored
  }
  return json(200, { received: true });
}

// ---------- admin surface ----------

/** What the /admin billing card shows; no Stripe ids leak to the browser. */
export function billingSummary(tenant: TenantConfig, env: Env): Record<string, unknown> {
  const ent = entitlement(tenant);
  return {
    plan: tenant.billing?.plan ?? "partner",
    status: tenant.billing?.status ?? "active",
    trialEndsAt: tenant.billing?.trialEndsAt ?? null,
    currentPeriodEnd: tenant.billing?.currentPeriodEnd ?? null,
    cancelAtPeriodEnd: tenant.billing?.cancelAtPeriodEnd ?? false,
    canManage: Boolean(tenant.billing?.stripeCustomerId && env.STRIPE_SECRET_KEY),
    canUpgrade: canStartCheckout(tenant) && Boolean(env.STRIPE_SECRET_KEY),
    sendingBlocked: ent.ok ? null : ent.reason,
  };
}

/** Upgrades make sense only for tenants not already on a live subscription. */
function canStartCheckout(tenant: TenantConfig): boolean {
  const b = tenant.billing;
  if (!b) return false; // legacy/partner: upgrades are an operator conversation
  if (b.plan === "partner") return false;
  return b.status !== "active" || !b.stripeSubscriptionId;
}
