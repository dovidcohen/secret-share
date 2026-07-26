// M2 manual verification against a running `wrangler dev` (http://127.0.0.1:8787).
// Exercises: create -> claim -> re-claim 410; bad tags -> burn; short TTL -> 410.
import { createHash, randomBytes } from "node:crypto";

const BASE = "http://127.0.0.1:8787";
let failures = 0;

function makeTags() {
  const claimTag = randomBytes(32).toString("base64url");
  const senderTag = randomBytes(32).toString("base64url");
  const h = (t) => createHash("sha256").update(Buffer.from(t, "base64url")).digest("base64url");
  return { claimTag, senderTag, claimTagHash: h(claimTag), senderTagHash: h(senderTag) };
}

function randomMailboxId() {
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  return Array.from(randomBytes(8), (b) => alphabet[b % 32]).join("");
}

async function req(method, path, body) {
  const res = await fetch(BASE + path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

function check(label, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}: got ${JSON.stringify(actual)}${ok ? "" : ` expected ${JSON.stringify(expected)}`}`);
}

// --- scenario 1: happy path + read-once ---
{
  const id = randomMailboxId();
  const t = makeTags();
  const create = await req("PUT", `/api/drops/${id}`, {
    claimTagHash: t.claimTagHash, senderTagHash: t.senderTagHash, ciphertext: "AQIDBAUG", ttlSeconds: 3600,
  });
  check("create", create.status, 201);
  const dup = await req("PUT", `/api/drops/${id}`, {
    claimTagHash: t.claimTagHash, senderTagHash: t.senderTagHash, ciphertext: "AQIDBAUG", ttlSeconds: 3600,
  });
  check("duplicate create", dup.status, 409);
  const claim = await req("POST", `/api/drops/${id}/claim`, { claimTag: t.claimTag });
  check("claim status", claim.status, 200);
  check("claim ciphertext", claim.body.ciphertext, "AQIDBAUG");
  const again = await req("POST", `/api/drops/${id}/claim`, { claimTag: t.claimTag });
  check("re-claim is GONE", again.status, 410);
}

// --- scenario 2: attempt limiting burns the drop ---
{
  const id = randomMailboxId();
  const t = makeTags();
  await req("PUT", `/api/drops/${id}`, {
    claimTagHash: t.claimTagHash, senderTagHash: t.senderTagHash, ciphertext: "AQIDBAUG", ttlSeconds: 3600,
  });
  for (let i = 1; i <= 4; i++) {
    const bad = await req("POST", `/api/drops/${id}/claim`, { claimTag: randomBytes(32).toString("base64url") });
    check(`bad tag #${i} status`, bad.status, 403);
    check(`bad tag #${i} attemptsLeft`, bad.body.attemptsLeft, 5 - i);
  }
  const fifth = await req("POST", `/api/drops/${id}/claim`, { claimTag: randomBytes(32).toString("base64url") });
  check("5th bad tag burns", fifth.status, 410);
  const rightTooLate = await req("POST", `/api/drops/${id}/claim`, { claimTag: t.claimTag });
  check("correct tag after burn", rightTooLate.status, 410);
}

// --- scenario 3: sender revoke ---
{
  const id = randomMailboxId();
  const t = makeTags();
  await req("PUT", `/api/drops/${id}`, {
    claimTagHash: t.claimTagHash, senderTagHash: t.senderTagHash, ciphertext: "AQIDBAUG", ttlSeconds: 3600,
  });
  const badRevoke = await req("DELETE", `/api/drops/${id}`, { senderTag: randomBytes(32).toString("base64url") });
  check("revoke with wrong tag", badRevoke.status, 403);
  const revoke = await req("DELETE", `/api/drops/${id}`, { senderTag: t.senderTag });
  check("revoke", revoke.status, 204);
  const claim = await req("POST", `/api/drops/${id}/claim`, { claimTag: t.claimTag });
  check("claim after revoke", claim.status, 410);
}

// --- scenario 4: TTL expiry via alarm ---
{
  const id = randomMailboxId();
  const t = makeTags();
  await req("PUT", `/api/drops/${id}`, {
    claimTagHash: t.claimTagHash, senderTagHash: t.senderTagHash, ciphertext: "AQIDBAUG", ttlSeconds: 60,
  });
  console.log("waiting 75s for the TTL alarm...");
  await new Promise((r) => setTimeout(r, 75_000));
  const claim = await req("POST", `/api/drops/${id}/claim`, { claimTag: t.claimTag });
  const ok = claim.status === 410 || claim.status === 404; // alarm swept (404) or tombstoned (410)
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"} claim after expiry: got ${claim.status} (410 or 404 accepted)`);
}

// --- scenario 5: validation ---
{
  const bad = await req("PUT", `/api/drops/lowercase!`, {});
  check("invalid mailbox id", bad.status, 404);
  const id = randomMailboxId();
  const t = makeTags();
  const badBody = await req("PUT", `/api/drops/${id}`, { claimTagHash: "short", senderTagHash: t.senderTagHash, ciphertext: "AQ" });
  check("invalid body", badBody.status, 400);
}

console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECKS FAILED`);
process.exit(failures === 0 ? 0 : 1);
