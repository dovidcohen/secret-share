import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.jsonc" },
        // Windows: per-test isolated storage hits EBUSY unlinking the DO's
        // SQLite file. Tests use unique mailbox ids instead of isolation.
        isolatedStorage: false,
        singleWorker: true,
      },
    },
  },
});
