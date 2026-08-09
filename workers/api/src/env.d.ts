import type { MailboxDO } from "./mailbox.js";
import type { UsageDO } from "./usagedo.js";

interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

declare global {
  interface Env {
    MAILBOX: DurableObjectNamespace<MailboxDO>;
    ASSETS: Fetcher;
    /** Tenant registry: host:<hostname>, tenant:<id>, logo:<id>, plus OIDC caches. */
    TENANTS: KVNamespace;
    /** Per-tenant state DO: usage counters + the session epoch (revocation). */
    USAGE: DurableObjectNamespace<UsageDO>;
    /** HMAC root for session cookies (secret). Per-tenant OIDC client secrets are
     * separate Worker secrets named OIDC_CLIENT_SECRET_<TENANTID>. */
    SESSION_SECRET?: string;
    /** Bearer secret for GET /api/stats (public product counters). Unset -> 404. */
    STATS_TOKEN?: string;
    /** "dev" via .dev.vars under `wrangler dev`; unset in production. */
    ENVIRONMENT?: string;
    /** Workers rate-limiting bindings; optional so local dev works without them. */
    CREATE_LIMITER?: RateLimiter;
    TURN_LIMITER?: RateLimiter;
    /** Cloudflare Realtime TURN key (secrets); absent -> STUN-only operation. */
    TURN_KEY_ID?: string;
    TURN_KEY_API_TOKEN?: string;
    /** Usage alerting (cron): analytics token + account id secrets, email binding. */
    CF_ANALYTICS_TOKEN?: string;
    CF_ACCOUNT_ID?: string;
    ALERT_EMAIL: SendEmail;
    USAGE_ALERT_THRESHOLD?: string;
    ALERT_FROM: string;
    /** Alert recipient — a secret, so the address stays out of the public repo. */
    ALERT_TO?: string;
  }
}

export {};
