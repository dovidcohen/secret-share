import { EmailMessage } from "cloudflare:email";
import { PUBLIC_USAGE_ID } from "./usagedo.js";
import { stubFetch } from "./stubfetch.js";

/**
 * Free-plan Workers get 100k requests/day; past that, requests fail until
 * midnight UTC. This cron handler sums today's invocations via the GraphQL
 * analytics API and emails an alert once the threshold is crossed, so there is
 * time to flip on Workers Paid before users see errors.
 */
export async function checkUsage(env: Env): Promise<void> {
  // ALERT_TO is a secret (recipient address kept out of the public repo).
  if (!env.CF_ANALYTICS_TOKEN || !env.CF_ACCOUNT_ID || !env.ALERT_TO) return; // not configured

  const today = new Date().toISOString().slice(0, 10);
  const res = await fetch("https://api.cloudflare.com/client/v4/graphql", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}`,
      "Content-Type": "application/json",
    },
    // Values are inlined (both are our own config/clock, not user input) to
    // avoid GraphQL scalar-name mismatches in variable declarations.
    body: JSON.stringify({
      query: `{
        viewer {
          accounts(filter: { accountTag: "${env.CF_ACCOUNT_ID}" }) {
            workersInvocationsAdaptive(limit: 1000, filter: { date: "${today}" }) {
              sum { requests }
            }
          }
        }
      }`,
    }),
  });
  if (!res.ok) {
    const detail = (await res.text()).slice(0, 300);
    console.log(`usage-alert: analytics query failed (${res.status}): ${detail}`);
    return;
  }

  interface GqlResponse {
    data?: {
      viewer?: {
        accounts?: Array<{
          workersInvocationsAdaptive?: Array<{ sum?: { requests?: number } }>;
        }>;
      };
    };
    errors?: Array<{ message?: string }>;
  }
  const body = (await res.json()) as GqlResponse;
  if (body.errors?.length) {
    console.log(`usage-alert: graphql error: ${body.errors[0]?.message ?? "unknown"}`);
    return;
  }
  const buckets = body.data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive ?? [];
  const requests = buckets.reduce((n, b) => n + (b.sum?.requests ?? 0), 0);
  const threshold = Number(env.USAGE_ALERT_THRESHOLD ?? "80000");
  console.log(`usage-alert: ${requests} requests today (threshold ${threshold})`);
  if (requests < threshold) return;

  const pct = Math.round((requests / 100_000) * 100);
  const subject = `shareasecret.io at ${pct}% of the free daily request limit (${requests.toLocaleString()})`;
  const raw = [
    `From: Secret Share Alerts <${env.ALERT_FROM}>`,
    `To: ${env.ALERT_TO}`,
    `Subject: ${subject}`,
    `Message-ID: <usage-${today}-${Math.floor(requests / 10000)}@shareasecret.io>`,
    "Content-Type: text/plain; charset=utf-8",
    "",
    `Workers requests today (UTC ${today}): ${requests.toLocaleString()} of 100,000 free-plan requests.`,
    "",
    "Past the cap, requests fail until midnight UTC. To lift it, enable Workers Paid ($5/mo):",
    "https://dash.cloudflare.com/?to=/:account/workers/plans",
    "",
    "This alert fires from the Worker's 6-hourly usage cron while usage stays above the threshold.",
  ].join("\r\n");

  await env.ALERT_EMAIL.send(new EmailMessage(env.ALERT_FROM, env.ALERT_TO, raw));
}

export interface PublicDigest {
  yesterday: string;
  sentYesterday: number;
  claimedYesterday: number;
  sentWeek: number;
  claimedWeek: number;
}

const DAY_MS = 86_400_000;
const isoDay = (t: number) => new Date(t).toISOString().slice(0, 10);

/**
 * Public product activity for the digest: yesterday, plus a rolling 7-day
 * window. `now` is injectable for tests. Counts come from the public UsageDO,
 * so they exclude bots and asset traffic — a send is a real send.
 */
export async function computePublicDigest(
  env: Env,
  now: number = Date.now(),
): Promise<PublicDigest> {
  const yesterday = isoDay(now - DAY_MS);
  const from = isoDay(now - 7 * DAY_MS);
  const to = isoDay(now);
  const stub = env.USAGE.get(env.USAGE.idFromName(`usage:${PUBLIC_USAGE_ID}`));
  const res = await stubFetch(
    stub,
    `https://usage/internal/read?from=${from}&to=${to}`,
  );
  const days = res.ok
    ? ((await res.json()) as { days: { day: string; kind: string; count: number }[] }).days
    : [];
  const dayKind = (d: string, k: string) =>
    days.filter((r) => r.day === d && r.kind === k).reduce((n, r) => n + r.count, 0);
  const weekKind = (k: string) =>
    days.filter((r) => r.kind === k).reduce((n, r) => n + r.count, 0);
  return {
    yesterday,
    sentYesterday: dayKind(yesterday, "drop_created"),
    claimedYesterday: dayKind(yesterday, "drop_claimed"),
    sentWeek: weekKind("drop_created"),
    claimedWeek: weekKind("drop_claimed"),
  };
}

/**
 * Daily email digest of real public-product usage. Stays silent when the
 * product has been fully dormant for the whole window, so a quiet inbox never
 * gets a daily "0 sends" — the digest resumes the day real activity returns.
 */
export async function sendDailyDigest(env: Env): Promise<void> {
  if (!env.ALERT_TO) return; // not configured

  const d = await computePublicDigest(env);
  if (d.sentWeek === 0 && d.claimedWeek === 0) {
    console.log("daily-digest: dormant week, skipping email");
    return;
  }

  const s = (n: number) => (n === 1 ? "" : "s");
  const subject = `shareasecret.io: ${d.sentYesterday} send${s(d.sentYesterday)} yesterday (${d.sentWeek} this week)`;
  const raw = [
    `From: Secret Share Alerts <${env.ALERT_FROM}>`,
    `To: ${env.ALERT_TO}`,
    `Subject: ${subject}`,
    `Message-ID: <digest-${d.yesterday}@shareasecret.io>`,
    "Content-Type: text/plain; charset=utf-8",
    "",
    `Public product activity (real sends/claims — bots and page loads excluded).`,
    "",
    `Yesterday (${d.yesterday}):`,
    `  Secrets sent:      ${d.sentYesterday}`,
    `  Secrets retrieved: ${d.claimedYesterday}`,
    "",
    `Last 7 days:`,
    `  Secrets sent:      ${d.sentWeek}`,
    `  Secrets retrieved: ${d.claimedWeek}`,
    "",
    "Counts started 2026-08-09 and are not retroactive. This digest is silent",
    "on weeks with no activity at all.",
  ].join("\r\n");

  await env.ALERT_EMAIL.send(new EmailMessage(env.ALERT_FROM, env.ALERT_TO, raw));
  console.log(`daily-digest: sent (${d.sentYesterday} yesterday, ${d.sentWeek} week)`);
}
