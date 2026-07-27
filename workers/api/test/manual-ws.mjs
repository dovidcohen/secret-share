// M3 manual verification of WebSocket signaling against `wrangler dev`.
// Uses Node's built-in WebSocket (Node >= 22).
import { createHash, randomBytes } from "node:crypto";

const HTTP = "http://127.0.0.1:8787";
const WS = "ws://127.0.0.1:8787";
let failures = 0;

function check(label, ok, detail = "") {
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${detail ? `: ${detail}` : ""}`);
}

function randomMailboxId() {
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  return Array.from(randomBytes(8), (b) => alphabet[b % 32]).join("");
}

class Client {
  constructor(mailboxId, role) {
    this.messages = [];
    this.closed = null;
    this.waiters = [];
    this.ws = new WebSocket(`${WS}/ws/${mailboxId}?role=${role}`);
    this.ws.addEventListener("message", (e) => {
      this.messages.push(JSON.parse(e.data));
      this.waiters.forEach((w) => w());
    });
    this.ws.addEventListener("close", (e) => {
      this.closed = { code: e.code, reason: e.reason };
      this.waiters.forEach((w) => w());
    });
  }
  async next(predicate, timeoutMs = 5000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const found = this.messages.find(predicate);
      if (found) return found;
      if (this.closed) return null;
      if (Date.now() > deadline) return null;
      await new Promise((r) => {
        this.waiters.push(r);
        setTimeout(r, 100);
      });
    }
  }
  async waitClosed(timeoutMs = 5000) {
    const deadline = Date.now() + timeoutMs;
    while (!this.closed && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    return this.closed;
  }
  send(obj) {
    this.ws.send(JSON.stringify(obj));
  }
}

const open = (c) => new Promise((res, rej) => {
  c.ws.addEventListener("open", res);
  c.ws.addEventListener("error", rej);
});

// --- scenario 1: presence + relay ---
{
  const id = randomMailboxId();
  const sender = new Client(id, "sender");
  await open(sender);
  const j1 = await sender.next((m) => m.t === "joined");
  check("sender joined alone", j1 && j1.peerPresent === false && j1.dropAvailable === false, JSON.stringify(j1));

  const receiver = new Client(id, "receiver");
  await open(receiver);
  const j2 = await receiver.next((m) => m.t === "joined");
  check("receiver sees sender", j2 && j2.peerPresent === true, JSON.stringify(j2));
  check("sender notified of peer", !!(await sender.next((m) => m.t === "peer-joined")));

  sender.send({ t: "signal", payload: { kind: "offer", sdp: "v=0 fake-offer" } });
  const offer = await receiver.next((m) => m.t === "signal");
  check("offer relayed to receiver", offer?.payload?.sdp === "v=0 fake-offer");

  receiver.send({ t: "signal", payload: { kind: "answer", sdp: "v=0 fake-answer" } });
  const answer = await sender.next((m) => m.t === "signal");
  check("answer relayed to sender", answer?.payload?.sdp === "v=0 fake-answer");

  receiver.send({ t: "signal", payload: { kind: "ice", candidate: "candidate:1 1 udp 1 1.2.3.4 5 typ host", sdpMid: "0", sdpMLineIndex: 0 } });
  const ice = await sender.next((m) => m.t === "signal" && m.payload.kind === "ice");
  check("ice relayed to sender", !!ice);

  sender.send({ t: "nonsense" });
  const err = await sender.next((m) => m.t === "error");
  check("bad message rejected", err?.code === "BAD_MESSAGE");

  // duplicate role: newest wins
  const sender2 = new Client(id, "sender");
  await open(sender2);
  const closed = await sender.waitClosed();
  check("old sender closed 4001", closed?.code === 4001, JSON.stringify(closed));
  check("new sender joined with peer", (await sender2.next((m) => m.t === "joined"))?.peerPresent === true);

  // peer-left on receiver close
  receiver.ws.close();
  check("sender told peer-left", !!(await sender2.next((m) => m.t === "peer-left")));
  sender2.ws.close();
}

// --- scenario 2: dropAvailable + delivered burns the drop ---
{
  const id = randomMailboxId();
  const claimTag = randomBytes(32).toString("base64url");
  const senderTag = randomBytes(32).toString("base64url");
  const h = (t) => createHash("sha256").update(Buffer.from(t, "base64url")).digest("base64url");
  const create = await fetch(`${HTTP}/api/drops/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ claimTagHash: h(claimTag), senderTagHash: h(senderTag), ciphertext: "AQIDBAUG", ttlSeconds: 3600 }),
  });
  check("drop created", create.status === 201);

  const receiver = new Client(id, "receiver");
  await open(receiver);
  const j = await receiver.next((m) => m.t === "joined");
  check("receiver sees dropAvailable", j?.dropAvailable === true, JSON.stringify(j));
  check("joined carries a turnToken", typeof j?.turnToken === "string" && j.turnToken.length === 22);

  // receiver may not delete the drop, even with the right tag
  receiver.send({ t: "delivered", senderTag });
  const notAllowed = await receiver.next((m) => m.t === "error");
  check("receiver cannot send delivered", notAllowed?.code === "NOT_ALLOWED");

  const sender = new Client(id, "sender");
  await open(sender);
  await sender.next((m) => m.t === "joined");

  // sender role without knowledge of the sender tag is refused
  sender.send({ t: "delivered", senderTag: randomBytes(32).toString("base64url") });
  const badTag = await sender.next((m) => m.t === "error");
  check("delivered with wrong tag refused", badTag?.code === "NOT_ALLOWED");

  sender.send({ t: "delivered", senderTag });
  check("delivered acked", !!(await sender.next((m) => m.t === "delivered-ok")));

  const claim = await fetch(`${HTTP}/api/drops/${id}/claim`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ claimTag }),
  });
  check("drop gone after delivered", claim.status === 410, `status ${claim.status}`);
  receiver.ws.close();
  sender.ws.close();
}

// --- scenario 3: ping/pong auto-response ---
{
  const id = randomMailboxId();
  const c = new Client(id, "sender");
  await open(c);
  await c.next((m) => m.t === "joined");
  c.ws.send('{"t":"ping"}');
  check("ping answered with pong", !!(await c.next((m) => m.t === "pong")));
  c.ws.close();
}

await new Promise((r) => setTimeout(r, 200));
console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECKS FAILED`);
process.exit(failures === 0 ? 0 : 1);
