import { z } from "zod";
import {
  DEFAULT_TTL_SECONDS,
  MAILBOX_ID_REGEX,
  MAX_CIPHERTEXT_B64_CHARS,
  MAX_TTL_SECONDS,
  MIN_TTL_SECONDS,
} from "./constants.js";

const b64url = (len: number) =>
  z
    .string()
    .length(len)
    .regex(/^[A-Za-z0-9_-]+$/);

/** 32 bytes base64url-unpadded = 43 chars. */
export const TagSchema = b64url(43);

export const MailboxIdSchema = z.string().regex(MAILBOX_ID_REGEX);

/** Body of PUT /api/drops/:mailboxId — the mailbox id travels in the path. */
export const CreateDropRequestSchema = z.object({
  claimTagHash: TagSchema,
  senderTagHash: TagSchema,
  ciphertext: z
    .string()
    .min(1)
    .max(MAX_CIPHERTEXT_B64_CHARS)
    .regex(/^[A-Za-z0-9_-]+$/),
  ttlSeconds: z
    .number()
    .int()
    .min(MIN_TTL_SECONDS)
    .max(MAX_TTL_SECONDS)
    .default(DEFAULT_TTL_SECONDS),
});
export type CreateDropRequest = z.infer<typeof CreateDropRequestSchema>;

export const CreateDropResponseSchema = z.object({
  expiresAt: z.number(), // epoch ms
});
export type CreateDropResponse = z.infer<typeof CreateDropResponseSchema>;

export const ClaimRequestSchema = z.object({
  claimTag: TagSchema,
});
export type ClaimRequest = z.infer<typeof ClaimRequestSchema>;

export const ClaimResponseSchema = z.object({
  ciphertext: z.string(),
});
export type ClaimResponse = z.infer<typeof ClaimResponseSchema>;

export const RevokeRequestSchema = z.object({
  senderTag: TagSchema,
});
export type RevokeRequest = z.infer<typeof RevokeRequestSchema>;

export const ApiErrorSchema = z.object({
  error: z.string(),
  attemptsLeft: z.number().int().optional(),
});
export type ApiError = z.infer<typeof ApiErrorSchema>;

/** POST /api/turn — requires a turnToken issued on the signaling socket. */
export const TurnRequestSchema = z.object({
  mailboxId: MailboxIdSchema,
  turnToken: z
    .string()
    .length(22)
    .regex(/^[A-Za-z0-9_-]+$/),
});
export type TurnRequest = z.infer<typeof TurnRequestSchema>;

/** TURN response — short-lived ICE servers (404 when TURN is not configured). */
export const IceServerSchema = z.object({
  urls: z.union([z.string(), z.array(z.string())]),
  username: z.string().optional(),
  credential: z.string().optional(),
});
export const TurnResponseSchema = z.object({
  iceServers: z.array(IceServerSchema),
});
export type TurnResponse = z.infer<typeof TurnResponseSchema>;
