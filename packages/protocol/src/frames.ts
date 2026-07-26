import { z } from "zod";
import { RoleSchema } from "./ws.js";

/** DataChannel frame layout: [1 byte type][payload]. */
export const FRAME_TYPE = {
  /** JSON HelloPayload, plaintext (carries no secrets). */
  HELLO: 0x01,
  /** 32-byte key-confirmation HMAC. */
  CONFIRM: 0x02,
  /** [2B chunkIdx BE][2B chunkTotal BE][encrypted frame]. */
  SECRET: 0x03,
  /** Encrypted frame whose plaintext is SHA-256 of the received secret. */
  ACK: 0x04,
  BYE: 0x05,
} as const;
export type FrameType = (typeof FRAME_TYPE)[keyof typeof FRAME_TYPE];

/** Chunk plaintext size — keeps DataChannel messages well under the 16KiB interop limit. */
export const SECRET_CHUNK_BYTES = 8_192;

export const HelloPayloadSchema = z.object({
  v: z.literal(1),
  role: RoleSchema,
  /** 16 random bytes, base64url-unpadded (22 chars); salts the session keys/IVs. */
  sessionSalt: z
    .string()
    .length(22)
    .regex(/^[A-Za-z0-9_-]+$/),
});
export type HelloPayload = z.infer<typeof HelloPayloadSchema>;
