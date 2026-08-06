import type { ShareCode } from "./code.js";
import { concatBytes, fromB64url, toB64url, utf8 } from "./encoding.js";

/**
 * Protocol constants — changing any of these is a breaking protocol version bump
 * (existing drops and codes would stop decrypting).
 */
export const ARGON2_PARAMS = {
  memoryKiB: 65_536, // 64 MiB
  iterations: 3,
  parallelism: 1, // no threads -> no SharedArrayBuffer -> no COOP/COEP headers
  hashLength: 32,
} as const;

const V = "secret-share/v1";

export interface DerivedKeys {
  mailboxId: string;
  /**
   * Optional derivation context (e.g. a tenant id on white-label hosts).
   * Binds every derived key and the blob AAD to the namespace the code was
   * minted in, so ciphertext can't be transplanted across namespaces.
   * Undefined reproduces the original public derivation byte-for-byte.
   */
  context?: string;
  /** AES-256-GCM key for the parked (async) blob. */
  kBlob: CryptoKey;
  /** Root key material for live-session key derivation (mixed with per-session salts). */
  sessionIkm: Uint8Array;
  /** Presented to the server to claim the drop; server stores only its SHA-256. */
  claimTag: string;
  /** Authorizes sender revoke; server stores only its SHA-256. */
  senderTag: string;
}

export interface SessionKeys {
  /** AES-256-GCM key for DataChannel frames. */
  kFrame: CryptoKey;
  /** HMAC-SHA256 key for the key-confirmation exchange. */
  kConfirm: CryptoKey;
}

export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  bytes: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", ikm as BufferSource, "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: info as BufferSource },
    key,
    bytes * 8,
  );
  return new Uint8Array(bits);
}

function hkdfBits(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  bytes: number,
): Promise<Uint8Array> {
  return hkdfSha256(ikm, salt, utf8(info), bytes);
}

async function aesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

let argon2idImpl:
  | ((opts: {
      password: string;
      salt: Uint8Array;
      parallelism: number;
      iterations: number;
      memorySize: number;
      hashLength: number;
      outputType: "binary";
    }) => Promise<Uint8Array>)
  | undefined;

/**
 * hash-wasm is lazy-loaded so the WASM chunk doesn't weigh down the landing page;
 * the first deriveKeys() call pays the fetch.
 */
async function argon2id(password: string, salt: Uint8Array): Promise<Uint8Array> {
  if (!argon2idImpl) {
    const mod = await import("hash-wasm");
    argon2idImpl = mod.argon2id;
  }
  return argon2idImpl({
    password,
    salt,
    parallelism: ARGON2_PARAMS.parallelism,
    iterations: ARGON2_PARAMS.iterations,
    memorySize: ARGON2_PARAMS.memoryKiB,
    hashLength: ARGON2_PARAMS.hashLength,
    outputType: "binary",
  });
}

/** "tenant:XKQ2M7PT" under a context, plain "XKQ2M7PT" without — the shared binding string. */
export function boundMailboxId(mailboxId: string, context?: string): string {
  return context ? `${context}:${mailboxId}` : mailboxId;
}

/**
 * code -> Argon2id (salted by mailbox id, so brute force is per-mailbox) -> HKDF fan-out.
 * The words are the password; the server-visible mailbox id contributes no key entropy.
 * A context (tenant id) prefixes both salts, keeping namespaces cryptographically disjoint.
 */
export async function deriveKeys(code: ShareCode, context?: string): Promise<DerivedKeys> {
  const bound = boundMailboxId(code.mailboxId, context);
  const ikm = await argon2id(code.words.join(" "), utf8(`${V}/${bound}`));
  const salt = utf8(bound);
  const [blobRaw, sessionIkm, claimRaw, senderRaw] = await Promise.all([
    hkdfBits(ikm, salt, `${V}/blob`, 32),
    hkdfBits(ikm, salt, `${V}/session`, 32),
    hkdfBits(ikm, salt, `${V}/claim`, 32),
    hkdfBits(ikm, salt, `${V}/sender`, 32),
  ]);
  return {
    mailboxId: code.mailboxId,
    context,
    kBlob: await aesKey(blobRaw),
    sessionIkm,
    claimTag: toB64url(claimRaw),
    senderTag: toB64url(senderRaw),
  };
}

/**
 * Live-session keys: both peers' random salts are mixed in so a reused code
 * never reuses frame IVs and each session confirms independently.
 */
export async function deriveSessionKeys(
  keys: Pick<DerivedKeys, "sessionIkm">,
  senderSalt: Uint8Array,
  receiverSalt: Uint8Array,
): Promise<SessionKeys> {
  const salt = concatBytes(senderSalt, receiverSalt);
  const [frameRaw, confirmRaw] = await Promise.all([
    hkdfBits(keys.sessionIkm, salt, `${V}/frame-key`, 32),
    hkdfBits(keys.sessionIkm, salt, `${V}/confirm-key`, 32),
  ]);
  return {
    kFrame: await aesKey(frameRaw),
    kConfirm: await crypto.subtle.importKey(
      "raw",
      confirmRaw as BufferSource,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"],
    ),
  };
}

/** MAC over the handshake transcript; exchanged before any secret bytes flow. */
export async function confirmationMac(
  session: SessionKeys,
  mailboxId: string,
  senderSalt: Uint8Array,
  receiverSalt: Uint8Array,
  role: "sender" | "receiver",
  context?: string,
): Promise<Uint8Array> {
  const transcript = concatBytes(
    utf8(`${V}/confirm/${role}/${boundMailboxId(mailboxId, context)}/`),
    senderSalt,
    receiverSalt,
  );
  const mac = await crypto.subtle.sign("HMAC", session.kConfirm, transcript as BufferSource);
  return new Uint8Array(mac);
}

/** SHA-256 of a tag's raw bytes, base64url — what the server stores at create time. */
export async function tagHash(tagB64url: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", fromB64url(tagB64url) as BufferSource);
  return toB64url(new Uint8Array(digest));
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}
