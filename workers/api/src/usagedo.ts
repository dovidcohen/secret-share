import { DurableObject } from "cloudflare:workers";

/**
 * Per-tenant usage counters for the admin page and future billing. One
 * instance per tenant (`usage:<tenantId>`), incremented fire-and-forget via
 * ctx.waitUntil from the Worker — a metering failure must never surface on
 * the user path.
 */

export type UsageKind =
  | "drop_created"
  | "drop_claimed"
  | "grant_minted"
  | "login";

const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
/** Rows older than this are swept opportunistically on writes. */
const RETENTION_DAYS = 400;

export class UsageDO extends DurableObject<Env> {
  private initialized = false;

  private init(): void {
    if (this.initialized) return;
    this.ctx.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS events (
        day TEXT NOT NULL,
        kind TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (day, kind)
      )`,
    );
    this.initialized = true;
  }

  override async fetch(request: Request): Promise<Response> {
    this.init();
    const url = new URL(request.url);
    if (url.pathname === "/internal/increment" && request.method === "POST") {
      const body = (await request.json().catch(() => null)) as { kind?: string } | null;
      if (!body?.kind) return Response.json({ error: "BAD_REQUEST" }, { status: 400 });
      const day = new Date().toISOString().slice(0, 10);
      this.ctx.storage.sql.exec(
        `INSERT INTO events (day, kind, count) VALUES (?, ?, 1)
         ON CONFLICT(day, kind) DO UPDATE SET count = count + 1`,
        day,
        body.kind,
      );
      this.sweep(day);
      return new Response(null, { status: 204 });
    }
    if (url.pathname === "/internal/read" && request.method === "GET") {
      const to = normalizeDay(url.searchParams.get("to")) ?? today();
      const from = normalizeDay(url.searchParams.get("from")) ?? daysAgo(30);
      const rows = this.ctx.storage.sql
        .exec<{ day: string; kind: string; count: number }>(
          `SELECT day, kind, count FROM events WHERE day >= ? AND day <= ? ORDER BY day, kind`,
          from,
          to,
        )
        .toArray();
      return Response.json({ days: rows }, { headers: { "Cache-Control": "no-store" } });
    }
    return Response.json({ error: "NOT_FOUND" }, { status: 404 });
  }

  private sweep(currentDay: string): void {
    const cutoff = new Date(
      new Date(`${currentDay}T00:00:00Z`).getTime() - RETENTION_DAYS * 86_400_000,
    )
      .toISOString()
      .slice(0, 10);
    this.ctx.storage.sql.exec(`DELETE FROM events WHERE day < ?`, cutoff);
  }
}

function normalizeDay(raw: string | null): string | null {
  return raw && DAY_RE.test(raw) ? raw : null;
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

function daysAgo(n: number): string {
  return new Date(Date.now() - n * 86_400_000).toISOString().slice(0, 10);
}

/** Fire-and-forget increment; swallows every failure by design. */
export function recordUsage(
  env: Env,
  ctx: ExecutionContext,
  tenantId: string,
  kind: UsageKind,
): void {
  if (!env.USAGE) return;
  try {
    const stub = env.USAGE.get(env.USAGE.idFromName(`usage:${tenantId}`));
    ctx.waitUntil(
      stub
        .fetch("https://usage/internal/increment", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ kind }),
        })
        .catch(() => {}),
    );
  } catch {
    // metering must never break the user path
  }
}
