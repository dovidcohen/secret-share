import { z } from "zod";

/**
 * Tenant registry entry, stored in KV as `tenant:<tenantId>` and looked up via
 * `host:<hostname>` -> {tenantId}. Written by scripts/provision-tenant.mjs and
 * (a safe subset) by PUT /api/admin/tenant; the Worker only ever reads it.
 *
 * OIDC client secrets are NOT here — they live in per-tenant Worker secrets
 * named OIDC_CLIENT_SECRET_<TENANTID>, so a KV read never exposes credentials.
 */
export const TenantConfigSchema = z.object({
  v: z.literal(1),
  tenantId: z.string().regex(/^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/),
  displayName: z.string().min(1).max(80),
  /** Product name shown as the header H1; defaults to displayName when empty. */
  productName: z.string().max(80).optional(),
  hostnames: z.array(z.string()).min(1),
  theme: z
    .object({
      primaryColor: z
        .string()
        .regex(/^#[0-9a-f]{6}$/i)
        .optional(),
      /** Cache-buster for /api/tenant/logo; bumped on every logo upload. */
      logoVersion: z.number().int().default(0),
      /** One footer line shown to recipients, e.g. "For FordMed staff and vendors." */
      footerText: z.string().max(200).optional(),
    })
    .default({ logoVersion: 0 }),
  /**
   * Session lifetime. The deprovisioning window for an IdP-side disable is
   * min(this, a session-epoch bump), so security-sensitive tenants should
   * tighten it. (The session EPOCH itself lives in the per-tenant DO, not
   * here — a config read-modify-write must never be able to resurrect it.)
   */
  sessionTtlSeconds: z
    .number()
    .int()
    .min(900)
    .max(28_800)
    .default(28_800),
  oidc: z.object({
    issuer: z.url().refine((u) => u.startsWith("https://"), "issuer must be https"),
    clientId: z.string().min(1),
    /** "secret": confidential client (Worker secret) + PKCE. "pkce_public": PKCE only. */
    clientAuth: z.enum(["secret", "pkce_public"]).default("secret"),
    scopes: z.string().default("openid profile email"),
    /** Label on the sign-in button, e.g. "FordMed (Microsoft)". */
    idpLabel: z.string().max(80).optional(),
    /** [] = any account the IdP authenticates. */
    allowedEmailDomains: z.array(z.string()).default([]),
    /** Matched against the `groups` OR `roles` id_token claim (Entra: prefer app roles). */
    allowedGroups: z.array(z.string()).default([]),
  }),
  /**
   * Bootstrap-only once adminSubjects is populated: email matching grants
   * admin ONLY while adminSubjects is empty. Pin subjects via
   * `provision-tenant.mjs set-admin-subject` after the first login — OIDC
   * `sub` is immutable where emails/UPNs can be renamed or reassigned.
   */
  adminEmails: z.array(z.email()).min(1),
  adminSubjects: z.array(z.string().min(1)).default([]),
  features: z
    .object({
      guestGrants: z.boolean().default(true),
      liveSend: z.boolean().default(true),
    })
    .default({ guestGrants: true, liveSend: true }),
  /**
   * Subscription state, written by the Stripe webhook and the provisioning
   * script — never by tenant admins. Absent on legacy/design-partner tenants,
   * which stay fully entitled (see entitlement() in billing.ts).
   */
  billing: z
    .object({
      plan: z.enum(["trial", "team", "business", "partner"]),
      status: z.enum(["trialing", "active", "past_due", "canceled"]),
      /** Epoch ms; sender actions are blocked once this passes (trials only). */
      trialEndsAt: z.number().optional(),
      stripeCustomerId: z.string().optional(),
      stripeSubscriptionId: z.string().optional(),
      /** Epoch ms of the current paid period's end (informational). */
      currentPeriodEnd: z.number().optional(),
      /** Portal cancel = end-of-period: still active (and entitled) until
       * currentPeriodEnd, then the deletion webhook flips status to canceled. */
      cancelAtPeriodEnd: z.boolean().optional(),
    })
    .optional(),
  createdAt: z.number(),
  updatedAt: z.number(),
});

export type TenantConfig = z.infer<typeof TenantConfigSchema>;

/** Branding block injected into the SPA — the only tenant data anonymous visitors see. */
export function brandingFor(tenant: TenantConfig): {
  tenantId: string;
  name: string;
  productName: string;
  logoUrl: string | null;
  primaryColor: string | null;
  footerText: string | null;
  idpLabel: string;
} {
  return {
    tenantId: tenant.tenantId,
    name: tenant.displayName,
    productName: tenant.productName || tenant.displayName,
    logoUrl:
      tenant.theme.logoVersion > 0
        ? `/api/tenant/logo?v=${tenant.theme.logoVersion}`
        : null,
    primaryColor: tenant.theme.primaryColor ?? null,
    footerText: tenant.theme.footerText ?? null,
    idpLabel: tenant.oidc.idpLabel || tenant.displayName,
  };
}
