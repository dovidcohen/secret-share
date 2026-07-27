import { EmailMessage } from "cloudflare:email";

/**
 * Free-plan Workers get 100k requests/day; past that, requests fail until
 * midnight UTC. This cron handler sums today's invocations via the GraphQL
 * analytics API and emails an alert once the threshold is crossed, so there is
 * time to flip on Workers Paid before users see errors.
 */
export async function checkUsage(env: Env): Promise<void> {
  if (!env.CF_ANALYTICS_TOKEN || !env.CF_ACCOUNT_ID) return; // not configured

  const today = new Date().toISOString().slice(0, 10);
  const res = await fetch("https://api.cloudflare.com/client/v4/graphql", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      query: `query($account: String!, $date: Date!) {
        viewer {
          accounts(filter: { accountTag: $account }) {
            workersInvocationsAdaptive(limit: 1000, filter: { date: $date }) {
              sum { requests }
            }
          }
        }
      }`,
      variables: { account: env.CF_ACCOUNT_ID, date: today },
    }),
  });
  if (!res.ok) {
    console.log(`usage-alert: analytics query failed (${res.status})`);
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
  }
  const body = (await res.json()) as GqlResponse;
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
