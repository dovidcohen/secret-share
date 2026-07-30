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

const REQUEST_TIMEOUT_MS = 15_000;
/** Claim responses carry ciphertext (<=19k b64 chars); everything else is tiny. */
const MAX_RESPONSE_BYTES = 64 * 1024;

/** fetch with a deadline — a stalled server must not hang the CLI forever. */
function apiFetch(url: string, init: RequestInit): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
}

/** Reads and parses a JSON body, aborting past the size cap instead of buffering it. */
async function boundedJson(res: Response, maxBytes = MAX_RESPONSE_BYTES): Promise<unknown> {
  const reader = res.body?.getReader();
  if (!reader) return {};
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`server response exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  const body = Buffer.concat(chunks).toString("utf8");
  return body.length === 0 ? {} : JSON.parse(body);
}

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
  const res = await apiFetch(`${server}/api/drops/${keys.mailboxId}`, {
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
  return CreateDropResponseSchema.parse(await boundedJson(res, 4 * 1024)).expiresAt;
}

/** Claims (and thereby destroys) the drop; returns the encrypted blob bytes. */
export async function claimDrop(
  server: string,
  keys: DerivedKeys,
): Promise<Uint8Array> {
  const res = await apiFetch(`${server}/api/drops/${keys.mailboxId}/claim`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ claimTag: keys.claimTag }),
  });
  if (res.status === 410) throw new DropGoneError();
  if (res.status === 404) throw new DropNotFoundError();
  if (res.status === 403) {
    const body = (await boundedJson(res, 4 * 1024)) as { attemptsLeft?: number };
    throw new BadTagError(body.attemptsLeft ?? 0);
  }
  if (!res.ok) throw new Error(`Claim failed (${res.status})`);
  return fromB64url(ClaimResponseSchema.parse(await boundedJson(res)).ciphertext);
}

/** Sender-side burn: proves knowledge of the sender tag, wipes the drop. */
export async function revokeDrop(
  server: string,
  keys: DerivedKeys,
): Promise<void> {
  const res = await apiFetch(`${server}/api/drops/${keys.mailboxId}`, {
    method: "DELETE",
    headers: JSON_HEADERS,
    body: JSON.stringify({ senderTag: keys.senderTag }),
  });
  if (!res.ok && res.status !== 404 && res.status !== 410) {
    throw new Error(`Revoke failed (${res.status})`);
  }
}
