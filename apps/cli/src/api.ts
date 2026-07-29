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

const JSON_HEADERS = { "Content-Type": "application/json" };

/** Parks the encrypted blob; returns expiresAt (epoch ms). */
export async function parkDrop(
  server: string,
  keys: DerivedKeys,
  blob: Uint8Array,
  ttlSeconds: number,
): Promise<number> {
  const [claimTagHash, senderTagHash] = await Promise.all([
    tagHash(keys.claimTag),
    tagHash(keys.senderTag),
  ]);
  const res = await fetch(`${server}/api/drops/${keys.mailboxId}`, {
    method: "PUT",
    headers: JSON_HEADERS,
    body: JSON.stringify({
      claimTagHash,
      senderTagHash,
      ciphertext: toB64url(blob),
      ttlSeconds,
    }),
  });
  if (res.status === 409) throw new DropExistsError();
  if (!res.ok) throw new Error(`Create failed (${res.status})`);
  return CreateDropResponseSchema.parse(await res.json()).expiresAt;
}

/** Claims (and thereby destroys) the drop; returns the encrypted blob bytes. */
export async function claimDrop(
  server: string,
  keys: DerivedKeys,
): Promise<Uint8Array> {
  const res = await fetch(`${server}/api/drops/${keys.mailboxId}/claim`, {
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
export async function revokeDrop(
  server: string,
  keys: DerivedKeys,
): Promise<void> {
  const res = await fetch(`${server}/api/drops/${keys.mailboxId}`, {
    method: "DELETE",
    headers: JSON_HEADERS,
    body: JSON.stringify({ senderTag: keys.senderTag }),
  });
  if (!res.ok && res.status !== 404 && res.status !== 410) {
    throw new Error(`Revoke failed (${res.status})`);
  }
}
