import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.jsonc" },
        // Tests run like `wrangler dev`: unknown hosts (e.g. https://x/) fall
        // back to the public tenant instead of the production 404.
        miniflare: {
          bindings: {
            ENVIRONMENT: "dev",
            SESSION_SECRET: "test-session-secret",
            STATS_TOKEN: "test-stats-token",
            STRIPE_WEBHOOK_SECRET: "whsec_test",
            STRIPE_PRICE_TEAM_MONTHLY: "price_team_m",
            STRIPE_PRICE_TEAM_YEARLY: "price_team_y",
            STRIPE_PRICE_BUSINESS_MONTHLY: "price_biz_m",
            STRIPE_PRICE_BUSINESS_YEARLY: "price_biz_y",
          },
        },
        // Windows: per-test isolated storage hits EBUSY unlinking the DO's
        // SQLite file. Tests use unique mailbox ids instead of isolation.
        isolatedStorage: false,
        singleWorker: true,
      },
    },
  },
});
