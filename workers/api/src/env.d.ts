import type { MailboxDO } from "./mailbox.js";

interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

declare global {
  interface Env {
    MAILBOX: DurableObjectNamespace<MailboxDO>;
    ASSETS: Fetcher;
    /** Workers rate-limiting binding; optional so local dev works without it. */
    CREATE_LIMITER?: RateLimiter;
    /** Cloudflare Realtime TURN key (secrets); absent -> STUN-only operation. */
    TURN_KEY_ID?: string;
    TURN_KEY_API_TOKEN?: string;
  }
}

export {};
