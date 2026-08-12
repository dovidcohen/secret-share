import { CreateGrantResponseSchema } from "@secret-share/protocol";
import { PlanInactiveError, SessionExpiredError } from "./drop.js";

/**
 * Guest-send ("request a secret") link plumbing. Both the share code and the
 * grant token travel in the URL FRAGMENT — never a path or query — so neither
 * appears in any server or proxy log. Fragment-query encoding keeps parsing
 * unambiguous (codes contain dashes, tokens are opaque).
 *
 *   https://secrets.example.com/give#g=<grant>&c=XKQ2-M7PT-word-word-word-word-word
 */

export function packGiveFragment(grant: string, code: string): string {
  const params = new URLSearchParams();
  params.set("g", grant);
  params.set("c", code);
  return params.toString();
}

export function parseGiveFragment(
  fragment: string,
): { grant: string; code: string } | null {
  const params = new URLSearchParams(fragment);
  const grant = params.get("g");
  const code = params.get("c");
  return grant && code ? { grant, code } : null;
}

/** 40-bit mailbox collision (or a lingering grant there) — regenerate and retry. */
export class GrantMintConflictError extends Error {
  override name = "GrantMintConflictError";
}

export async function mintGrant(
  mailboxId: string,
): Promise<{ grant: string; expiresAt: number }> {
  const res = await fetch("/api/grants", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mailboxId }),
  });
  if (res.status === 401) throw new SessionExpiredError();
  if (res.status === 402) throw new PlanInactiveError();
  if (res.status === 409) throw new GrantMintConflictError();
  if (!res.ok) throw new Error(`Could not create the request link (${res.status})`);
  return CreateGrantResponseSchema.parse(await res.json());
}
