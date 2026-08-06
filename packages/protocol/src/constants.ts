export const PROTOCOL_VERSION = 1;

/** Maximum secret plaintext size in bytes. */
export const MAX_SECRET_BYTES = 10_240;

/** Base64url ciphertext upper bound: version byte + IV + plaintext + GCM tag, with slack. */
export const MAX_CIPHERTEXT_B64_CHARS = 19_000;

export const MIN_TTL_SECONDS = 60;
export const DEFAULT_TTL_SECONDS = 86_400; // 24h
export const MAX_TTL_SECONDS = 604_800; // 7d

/** Failed claim-tag presentations before the drop is burned. */
export const MAX_CLAIM_ATTEMPTS = 5;

/** Failed guest-grant token presentations before the grant is burned. */
export const MAX_GRANT_ATTEMPTS = 5;

/** Guest-send grant lifetime bounds (tenant "request a secret" links). */
export const DEFAULT_GRANT_TTL_SECONDS = 86_400; // 24h
export const MAX_GRANT_TTL_SECONDS = 604_800; // 7d

/** Crockford base32, 8 chars = 40 bits (no I, L, O, U). */
export const MAILBOX_ID_REGEX = /^[0-9A-HJKMNP-TV-Z]{8}$/;

/** Receiver gives up on the live path this long after peer-joined without an open DataChannel. */
export const LIVE_TIMEOUT_MS = 10_000;

/** WebSocket close code: replaced by a newer socket with the same role. */
export const WS_CLOSE_REPLACED = 4001;

export const WS_PING = '{"t":"ping"}';
export const WS_PONG = '{"t":"pong"}';

export type ErrorCode =
  | "ROOM_FULL"
  | "BAD_MESSAGE"
  | "RATE_LIMITED"
  | "BURNED"
  | "DROP_EXISTS"
  | "NOT_FOUND"
  | "GONE"
  | "BAD_TAG"
  | "TOO_LARGE"
  | "AUTH_REQUIRED"
  | "BAD_GRANT"
  | "GRANT_EXISTS"
  | "GRANT_USED"
  | "GRANT_EXPIRED";
