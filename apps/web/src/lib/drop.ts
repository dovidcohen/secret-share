import {
  ClaimResponseSchema,
  CreateDropResponseSchema,
} from "@secret-share/protocol";
import { fromB64url, tagHash, toB64url, type DerivedKeys } from "@secret-share/crypto";

export class DropExistsError extends Error {
  override name = "DropExistsError";
}
export class DropGoneError extends Error {
  override name = "DropGoneError";
}
export class DropNotFoundError extends Error {
  override name = "DropNotFoundError";
}
export class BadTagError extends Error {
  override name = "BadTagError";
  constructor(public attemptsLeft: number) {
    super(`Wrong code, ${attemptsLeft} attempts left`);
  }
}
/** Tenant host said 401: the SSO session lapsed mid-flow. */
export class SessionExpiredError extends Error {
  override name = "SessionExpiredError";
}
/** Tenant host said 402: the org's trial or subscription has lapsed. */
export class PlanInactiveError extends Error {
  override name = "PlanInactiveError";
}
/** A guest-send grant was refused; `reason` drives the copy on the /give page. */
export class GrantRejectedError extends Error {
  override name = "GrantRejectedError";
  constructor(public reason: "used" | "expired" | "invalid") {
    super(`Grant rejected: ${reason}`);
  }
}

const JSON_HEADERS = { "Content-Type": "application/json" };

/** Parks the encrypted blob; returns expiresAt (epoch ms). */
export async function parkDrop(
  keys: DerivedKeys,
  blob: Uint8Array,
  ttlSeconds: number,
  opts: { grant?: string } = {},
): Promise<number> {
  const [claimTagHash, senderTagHash] = await Promise.all([
    tagHash(keys.claimTag),
    tagHash(keys.senderTag),
  ]);
  const res = await fetch(`/api/drops/${keys.mailboxId}`, {
    method: "PUT",
    // The grant rides a header, never the URL — URLs end up in logs.
    headers: opts.grant ? { ...JSON_HEADERS, "X-Guest-Grant": opts.grant } : JSON_HEADERS,
    body: JSON.stringify({
      claimTagHash,
      senderTagHash,
      ciphertext: toB64url(blob),
      ttlSeconds,
    }),
  });
  if (res.status === 401) throw new SessionExpiredError();
  if (res.status === 402) throw new PlanInactiveError();
  if (res.status === 403) {
    const body = (await res.json().catch(() => null)) as { error?: string } | null;
    throw new GrantRejectedError(
      body?.error === "GRANT_USED"
        ? "used"
        : body?.error === "GRANT_EXPIRED"
          ? "expired"
          : "invalid",
    );
  }
  if (res.status === 409) throw new DropExistsError();
  if (!res.ok) throw new Error(`Create failed (${res.status})`);
  return CreateDropResponseSchema.parse(await res.json()).expiresAt;
}

/** Claims (and thereby destroys) the drop; returns the encrypted blob bytes. */
export async function claimDrop(keys: DerivedKeys): Promise<Uint8Array> {
  const res = await fetch(`/api/drops/${keys.mailboxId}/claim`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ claimTag: keys.claimTag }),
  });
  if (res.status === 410) throw new DropGoneError();
  if (res.status === 404) throw new DropNotFoundError();
  if (res.status === 403) {
    const body = (await res.json()) as { attemptsLeft?: number };
    throw new BadTagError(body.attemptsLeft ?? 0);
  }
  if (!res.ok) throw new Error(`Claim failed (${res.status})`);
  return fromB64url(ClaimResponseSchema.parse(await res.json()).ciphertext);
}

/** Sender-side burn: proves knowledge of the sender tag, wipes the drop. */
export async function revokeDrop(keys: DerivedKeys): Promise<void> {
  const res = await fetch(`/api/drops/${keys.mailboxId}`, {
    method: "DELETE",
    headers: JSON_HEADERS,
    body: JSON.stringify({ senderTag: keys.senderTag }),
  });
  if (!res.ok && res.status !== 404 && res.status !== 410) {
    throw new Error(`Revoke failed (${res.status})`);
  }
}
