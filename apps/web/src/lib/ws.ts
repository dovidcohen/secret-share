import {
  ServerMessageSchema,
  WS_PING,
  type ClientMessage,
  type Role,
  type ServerMessage,
} from "@secret-share/protocol";

const PING_INTERVAL_MS = 30_000;

/** Thin typed wrapper over the signaling WebSocket with fan-out subscriptions. */
export class Signaling {
  private handlers = new Set<(msg: ServerMessage) => void>();
  private closeHandlers = new Set<(code: number) => void>();
  private pingTimer: ReturnType<typeof setInterval> | undefined;

  private constructor(private ws: WebSocket) {
    ws.addEventListener("message", (e) => {
      if (typeof e.data !== "string" || e.data === '{"t":"pong"}') return;
      const parsed = ServerMessageSchema.safeParse(JSON.parse(e.data));
      if (!parsed.success) return;
      for (const h of [...this.handlers]) h(parsed.data);
    });
    ws.addEventListener("close", (e) => {
      this.stopPing();
      for (const h of [...this.closeHandlers]) h(e.code);
    });
    this.pingTimer = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send(WS_PING);
    }, PING_INTERVAL_MS);
  }

  static connect(mailboxId: string, role: Role): Promise<Signaling> {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws/${mailboxId}?role=${role}`);
    return new Promise((resolve, reject) => {
      ws.addEventListener("open", () => resolve(new Signaling(ws)), { once: true });
      ws.addEventListener("error", () => reject(new Error("Signaling connection failed")), {
        once: true,
      });
    });
  }

  /** Subscribe to server messages; returns an unsubscribe function. */
  on(handler: (msg: ServerMessage) => void): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  onClose(handler: (code: number) => void): () => void {
    this.closeHandlers.add(handler);
    return () => this.closeHandlers.delete(handler);
  }

  /** Resolves with the first message matching the predicate, or null on timeout/close. */
  next(
    predicate: (msg: ServerMessage) => boolean,
    timeoutMs: number,
  ): Promise<ServerMessage | null> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        cleanup();
        resolve(null);
      }, timeoutMs);
      const offMsg = this.on((msg) => {
        if (!predicate(msg)) return;
        cleanup();
        resolve(msg);
      });
      const offClose = this.onClose(() => {
        cleanup();
        resolve(null);
      });
      const cleanup = () => {
        clearTimeout(timer);
        offMsg();
        offClose();
      };
    });
  }

  send(msg: ClientMessage): void {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(msg));
  }

  close(): void {
    this.stopPing();
    this.ws.close();
  }

  private stopPing(): void {
    if (this.pingTimer !== undefined) clearInterval(this.pingTimer);
    this.pingTimer = undefined;
  }
}
