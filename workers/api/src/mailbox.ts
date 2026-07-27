import { DurableObject } from "cloudflare:workers";
import {
  ClientMessageSchema,
  CreateDropRequestSchema,
  ClaimRequestSchema,
  MAX_CLAIM_ATTEMPTS,
  RevokeRequestSchema,
  RoleSchema,
  WS_CLOSE_REPLACED,
  WS_PING,
  WS_PONG,
  type Role,
  type ServerMessage,
  type SignalPayload,
} from "@secret-share/protocol";

interface DropRecord {
  ciphertext: string;
  claimTagHash: string;
  senderTagHash: string;
  createdAt: number;
  expiresAt: number;
}

interface SocketState {
  role: Role;
}

const MAX_WS_MESSAGE_BYTES = 24_000;
const WS_MESSAGES_PER_10S = 100;

function json(status: number, body: unknown): Response {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}

function fromB64url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "="));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toB64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256B64url(tagB64url: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", fromB64url(tagB64url));
  return toB64url(new Uint8Array(digest));
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/**
 * One instance per mailbox id. Owns the encrypted drop (SQLite storage, so
 * read-once is transactional), the claim attempt counter, the TTL alarm, and
 * the WebSocket signaling room — everything about a mailbox is serialized here.
 */
export class MailboxDO extends DurableObject<Env> {
  /** In-memory per-socket rate buckets; reset on hibernation wake, which is fine. */
  private buckets = new Map<WebSocket, { count: number; resetAt: number }>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Keepalives answered without waking the DO from hibernation.
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair(WS_PING, WS_PONG),
    );
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;

    if (pathname.startsWith("/ws/")) {
      return this.handleUpgrade(request, url);
    }
    if (pathname === "/internal/turn-verify" && request.method === "POST") {
      return this.handleTurnVerify(request);
    }
    if (pathname.endsWith("/claim") && request.method === "POST") {
      return this.handleClaim(request);
    }
    if (request.method === "PUT") {
      return this.handleCreate(request);
    }
    if (request.method === "DELETE") {
      return this.handleRevoke(request);
    }
    return json(404, { error: "NOT_FOUND" });
  }

  // ---------- async drop (REST) ----------

  private async handleCreate(request: Request): Promise<Response> {
    const body = CreateDropRequestSchema.safeParse(
      await request.json().catch(() => null),
    );
    if (!body.success) return json(400, { error: "BAD_REQUEST" });

    const [drop, tombstone] = await Promise.all([
      this.ctx.storage.get<DropRecord>("drop"),
      this.ctx.storage.get<boolean>("tombstone"),
    ]);
    if (drop || tombstone) return json(409, { error: "DROP_EXISTS" });

    const now = Date.now();
    const record: DropRecord = {
      ciphertext: body.data.ciphertext,
      claimTagHash: body.data.claimTagHash,
      senderTagHash: body.data.senderTagHash,
      createdAt: now,
      expiresAt: now + body.data.ttlSeconds * 1000,
    };
    await this.ctx.storage.put("drop", record);
    await this.ctx.storage.setAlarm(record.expiresAt);
    return json(201, { expiresAt: record.expiresAt });
  }

  private async handleClaim(request: Request): Promise<Response> {
    const body = ClaimRequestSchema.safeParse(
      await request.json().catch(() => null),
    );
    if (!body.success) return json(400, { error: "BAD_REQUEST" });

    if (await this.ctx.storage.get<boolean>("tombstone")) {
      return json(410, { error: "GONE" });
    }
    const drop = await this.ctx.storage.get<DropRecord>("drop");
    if (!drop) return json(404, { error: "NOT_FOUND" });
    if (drop.expiresAt <= Date.now()) {
      await this.burnDrop();
      return json(410, { error: "GONE" });
    }

    const presented = await sha256B64url(body.data.claimTag);
    const ok = constantTimeEqual(
      fromB64url(presented),
      fromB64url(drop.claimTagHash),
    );
    if (!ok) {
      const failed = ((await this.ctx.storage.get<number>("failedClaims")) ?? 0) + 1;
      if (failed >= MAX_CLAIM_ATTEMPTS) {
        await this.burnDrop();
        return json(410, { error: "GONE" });
      }
      await this.ctx.storage.put("failedClaims", failed);
      return json(403, {
        error: "BAD_TAG",
        attemptsLeft: MAX_CLAIM_ATTEMPTS - failed,
      });
    }

    // Read-once: delete before responding; the DO serializes concurrent claims.
    await this.burnDrop();
    return json(200, { ciphertext: drop.ciphertext });
  }

  private async handleRevoke(request: Request): Promise<Response> {
    const body = RevokeRequestSchema.safeParse(
      await request.json().catch(() => null),
    );
    if (!body.success) return json(400, { error: "BAD_REQUEST" });

    const drop = await this.ctx.storage.get<DropRecord>("drop");
    if (!drop) {
      return (await this.ctx.storage.get<boolean>("tombstone"))
        ? json(410, { error: "GONE" })
        : json(404, { error: "NOT_FOUND" });
    }
    const presented = await sha256B64url(body.data.senderTag);
    if (!constantTimeEqual(fromB64url(presented), fromB64url(drop.senderTagHash))) {
      return json(403, { error: "BAD_TAG" });
    }
    await this.burnDrop();
    return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  }

  /**
   * Removes the ciphertext but leaves a tombstone so later claims read as
   * 410 GONE (indistinguishable from expiry); the alarm sweeps the tombstone.
   */
  private async burnDrop(): Promise<void> {
    await this.ctx.storage.delete("drop");
    await this.ctx.storage.delete("failedClaims");
    await this.ctx.storage.put("tombstone", true);
    if ((await this.ctx.storage.getAlarm()) === null) {
      this.ctx.storage.setAlarm(Date.now() + 24 * 3600 * 1000);
    }
  }

  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.deleteAlarm();
  }

  // ---------- live signaling (WebSocket) ----------

  private async handleUpgrade(request: Request, url: URL): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return json(426, { error: "UPGRADE_REQUIRED" });
    }
    // Browsers always send Origin on WS upgrades; reject cross-site pages
    // driving our signaling. Absent Origin (non-browser clients) is allowed —
    // this is CSRF-style protection, not authentication.
    const origin = request.headers.get("Origin");
    if (origin) {
      let originHost: string | null = null;
      try {
        originHost = new URL(origin).hostname;
      } catch {
        return json(403, { error: "BAD_ORIGIN" });
      }
      // Host comparison (not full origin): `wrangler dev` rewrites both the
      // request URL and the Origin header to the route host over http.
      const sameHost = originHost === url.hostname;
      // localhost is only trusted under `wrangler dev` — in production a
      // malicious local process must not get a pass.
      const isLocalDev =
        this.env.ENVIRONMENT === "dev" &&
        (originHost === "localhost" || originHost === "127.0.0.1");
      if (!sameHost && !isLocalDev) return json(403, { error: "BAD_ORIGIN" });
    }
    const role = RoleSchema.safeParse(url.searchParams.get("role"));
    if (!role.success) return json(400, { error: "BAD_REQUEST" });

    // At most one socket per role: newest wins, the older one is told why.
    for (const ws of this.ctx.getWebSockets(role.data)) {
      ws.close(WS_CLOSE_REPLACED, "replaced by a newer connection");
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server, [role.data]);
    server.serializeAttachment({ role: role.data } satisfies SocketState);

    const peerRole: Role = role.data === "sender" ? "receiver" : "sender";
    const drop = await this.ctx.storage.get<DropRecord>("drop");
    this.send(server, {
      t: "joined",
      role: role.data,
      peerPresent: this.ctx.getWebSockets(peerRole).length > 0,
      dropAvailable: !!drop && drop.expiresAt > Date.now(),
      turnToken: await this.issueTurnToken(),
    });
    // Fresh token per peer-joined: a parked sender's original token is long
    // expired by the time a receiver finally shows up.
    for (const peer of this.ctx.getWebSockets(peerRole)) {
      this.send(peer, { t: "peer-joined", turnToken: await this.issueTurnToken() });
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  private static readonly TURN_TOKEN_TTL_MS = 10 * 60 * 1000;
  private static readonly TURN_TOKEN_MAX_OUTSTANDING = 8;

  /**
   * TURN capability tokens: minting relay credentials requires an open
   * signaling session, so /api/turn can't be farmed as a free generic TURN
   * service. Short-lived, single-use, and capped per mailbox.
   */
  private async issueTurnToken(): Promise<string> {
    const now = Date.now();
    const tokens = Object.fromEntries(
      Object.entries(
        (await this.ctx.storage.get<Record<string, number>>("turnTokens")) ?? {},
      )
        .filter(([, exp]) => exp > now)
        .sort(([, a], [, b]) => b - a)
        .slice(0, MailboxDO.TURN_TOKEN_MAX_OUTSTANDING - 1),
    );
    const raw = new Uint8Array(16);
    crypto.getRandomValues(raw);
    const token = toB64url(raw);
    tokens[token] = now + MailboxDO.TURN_TOKEN_TTL_MS;
    await this.ctx.storage.put("turnTokens", tokens);
    return token;
  }

  private async handleTurnVerify(request: Request): Promise<Response> {
    const body = (await request.json().catch(() => null)) as { token?: string } | null;
    if (!body?.token) return json(400, { error: "BAD_REQUEST" });
    const tokens =
      (await this.ctx.storage.get<Record<string, number>>("turnTokens")) ?? {};
    const exp = tokens[body.token];
    if (!exp || exp <= Date.now()) return json(403, { error: "BAD_TOKEN" });
    // Single-use: a captured token can't be replayed to mint more credentials.
    delete tokens[body.token];
    await this.ctx.storage.put("turnTokens", tokens);
    return new Response(null, { status: 204 });
  }

  override async webSocketMessage(
    ws: WebSocket,
    message: string | ArrayBuffer,
  ): Promise<void> {
    if (typeof message !== "string" || message.length > MAX_WS_MESSAGE_BYTES) {
      this.send(ws, { t: "error", code: "BAD_MESSAGE" });
      return;
    }
    if (!this.allowMessage(ws)) {
      this.send(ws, { t: "error", code: "RATE_LIMITED" });
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(message);
    } catch {
      this.send(ws, { t: "error", code: "BAD_MESSAGE" });
      return;
    }
    const msg = ClientMessageSchema.safeParse(parsed);
    if (!msg.success) {
      this.send(ws, { t: "error", code: "BAD_MESSAGE" });
      return;
    }

    const state = ws.deserializeAttachment() as SocketState;
    switch (msg.data.t) {
      case "signal":
        this.relaySignal(state.role, msg.data.payload);
        break;
      case "delivered": {
        // Destructive: requires the sender tag, not just a socket claiming the
        // sender role (roles are unauthenticated by design).
        if (state.role !== "sender") {
          this.send(ws, { t: "error", code: "NOT_ALLOWED" });
          return;
        }
        const drop = await this.ctx.storage.get<DropRecord>("drop");
        if (drop) {
          const presented = await sha256B64url(msg.data.senderTag);
          if (!constantTimeEqual(fromB64url(presented), fromB64url(drop.senderTagHash))) {
            this.send(ws, { t: "error", code: "NOT_ALLOWED" });
            return;
          }
          await this.burnDrop();
        }
        this.send(ws, { t: "delivered-ok" });
        break;
      }
    }
  }

  override async webSocketClose(ws: WebSocket): Promise<void> {
    this.buckets.delete(ws);
    this.notifyPeerLeft(ws);
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    this.buckets.delete(ws);
    this.notifyPeerLeft(ws);
  }

  private notifyPeerLeft(ws: WebSocket): void {
    const state = ws.deserializeAttachment() as SocketState | null;
    if (!state) return;
    const peerRole: Role = state.role === "sender" ? "receiver" : "sender";
    this.broadcast(peerRole, { t: "peer-left" });
  }

  private relaySignal(from: Role, payload: SignalPayload): void {
    const to: Role = from === "sender" ? "receiver" : "sender";
    this.broadcast(to, { t: "signal", payload });
  }

  private broadcast(role: Role, msg: ServerMessage): void {
    for (const ws of this.ctx.getWebSockets(role)) this.send(ws, msg);
  }

  private send(ws: WebSocket, msg: ServerMessage): void {
    try {
      ws.send(JSON.stringify(msg));
    } catch {
      // socket already closing; peer-left will follow via webSocketClose
    }
  }

  private allowMessage(ws: WebSocket): boolean {
    const now = Date.now();
    const bucket = this.buckets.get(ws);
    if (!bucket || bucket.resetAt <= now) {
      this.buckets.set(ws, { count: 1, resetAt: now + 10_000 });
      return true;
    }
    bucket.count += 1;
    return bucket.count <= WS_MESSAGES_PER_10S;
  }
}
