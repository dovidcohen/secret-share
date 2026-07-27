import type { MailboxDO } from "./mailbox.js";

interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

declare global {
  interface Env {
    MAILBOX: DurableObjectNamespace<MailboxDO>;
    ASSETS: Fetcher;
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
    ALERT_TO: string;
  }
}

export {};
