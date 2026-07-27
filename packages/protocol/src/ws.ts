import { z } from "zod";
import { TagSchema } from "./rest.js";

export const RoleSchema = z.enum(["sender", "receiver"]);
export type Role = z.infer<typeof RoleSchema>;

export const SignalPayloadSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("offer"), sdp: z.string().max(20_000) }),
  z.object({ kind: z.literal("answer"), sdp: z.string().max(20_000) }),
  z.object({
    kind: z.literal("ice"),
    candidate: z.string().max(2_000),
    sdpMid: z.string().max(64).nullable(),
    sdpMLineIndex: z.number().int().min(0).max(255).nullable(),
  }),
]);
export type SignalPayload = z.infer<typeof SignalPayloadSchema>;

/**
 * The client's role travels as a query param on the upgrade request
 * (GET /ws/:mailboxId?role=sender) so the server can tag the socket at
 * accept time; there is no separate join message.
 */
// client -> server
export const ClientMessageSchema = z.discriminatedUnion("t", [
  z.object({ t: z.literal("signal"), payload: SignalPayloadSchema }),
  // Live transfer confirmed -> delete the parked drop. Destructive, so it must
  // prove knowledge of the sender tag; the socket's role alone is spoofable by
  // anyone who learns the mailbox id.
  z.object({ t: z.literal("delivered"), senderTag: TagSchema }),
]);
export type ClientMessage = z.infer<typeof ClientMessageSchema>;

// server -> client
export const ServerMessageSchema = z.discriminatedUnion("t", [
  z.object({
    t: z.literal("joined"),
    role: RoleSchema,
    peerPresent: z.boolean(),
    dropAvailable: z.boolean(),
    /** Capability for POST /api/turn — TURN minting is tied to a live session. */
    turnToken: z.string().length(22).regex(/^[A-Za-z0-9_-]+$/),
  }),
  z.object({ t: z.literal("peer-joined") }),
  z.object({ t: z.literal("peer-left") }),
  z.object({ t: z.literal("signal"), payload: SignalPayloadSchema }),
  z.object({ t: z.literal("delivered-ok") }),
  z.object({
    t: z.literal("error"),
    code: z.enum(["BAD_MESSAGE", "RATE_LIMITED", "NOT_ALLOWED"]),
  }),
]);
export type ServerMessage = z.infer<typeof ServerMessageSchema>;
