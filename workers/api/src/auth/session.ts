/**
 * Stateless HMAC-signed cookies. IdP-agnostic on purpose: a future SAML
 * assertion consumer would mint exactly the same session, so nothing
 * downstream of login knows or cares which protocol authenticated the user.
 *
 * Token format: base64url(payloadJson) + "." + base64url(HMAC-SHA256(payload)).
 * The MAC key is HKDF-derived from the global SESSION_SECRET per tenant, so
 * tenants can be rotated independently later and a forged tid never verifies.
 */

export const SESSION_TTL_S = 8 * 3600;
const TXN_TTL_S = 600;

/**
 * __Host- enforces Secure + Path=/ + no Domain in production. Browsers refuse
 * Secure cookies over plain http, so `wrangler dev` (http://127.0.0.1) uses
 * unprefixed names — same codec, same checks.
 */
function sessionCookieName(env: Env): string {
  return env.ENVIRONMENT === "dev" ? "ss_session" : "__Host-ss_session";
}
function txnCookieName(env: Env): string {
  return env.ENVIRONMENT === "dev" ? "ss_txn" : "__Host-ss_txn";
}

export interface SessionPayload {
  v: 1;
  tid: string;
  sub: string;
  email: string;
  name?: string;
  /** Admin at login time; admin endpoints re-check against live config. */
  adm: boolean;
  /** Tenant sessionVersion at mint time; a config bump revokes all sessions. */
  sv: number;
  iat: number;
  exp: number;
}

/** OIDC transaction state parked between /auth/login and /auth/callback. */
export interface TxnPayload {
  v: 1;
  tid: string;
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
  exp: number;
}

const enc = new TextEncoder();

function toB64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "="));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomToken(bytes = 16): string {
  const raw = new Uint8Array(bytes);
  crypto.getRandomValues(raw);
  return toB64url(raw);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

async function macKey(secret: string, tenantId: string, info: string): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey("raw", enc.encode(secret), "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: enc.encode(tenantId),
      info: enc.encode(info),
    },
    ikm,
    256,
  );
  return crypto.subtle.importKey("raw", bits, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
    "verify",
  ]);
}

async function sign(payload: unknown, secret: string, tenantId: string, info: string): Promise<string> {
  const body = enc.encode(JSON.stringify(payload));
  const key = await macKey(secret, tenantId, info);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, body));
  return `${toB64url(body)}.${toB64url(mac)}`;
}

async function verify<T extends { exp: number; tid: string }>(
  token: string,
  secret: string,
  tenantId: string,
  info: string,
): Promise<T | null> {
  const dot = token.indexOf(".");
  if (dot < 0) return null;
  let body: Uint8Array;
  let mac: Uint8Array;
  try {
    body = fromB64url(token.slice(0, dot));
    mac = fromB64url(token.slice(dot + 1));
  } catch {
    return null;
  }
  const key = await macKey(secret, tenantId, info);
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, body as BufferSource));
  if (!constantTimeEqual(expected, mac)) return null;
  let payload: T;
  try {
    payload = JSON.parse(new TextDecoder().decode(body)) as T;
  } catch {
    return null;
  }
  if (payload.tid !== tenantId) return null;
  if (payload.exp * 1000 <= Date.now()) return null;
  return payload;
}

function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return rest.join("=");
  }
  return null;
}

function cookieAttrs(maxAge: number, env: Env): string {
  // SameSite=Lax survives the top-level redirect back from the IdP while
  // keeping cross-site POST/PUT cookieless (CSRF-safe for the API).
  const secure = env.ENVIRONMENT === "dev" ? "" : " Secure;";
  return `Path=/;${secure} HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}

// ---------- session cookie ----------

export async function mintSessionCookie(
  payload: Omit<SessionPayload, "v" | "iat" | "exp">,
  env: Env,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const full: SessionPayload = { v: 1, ...payload, iat: now, exp: now + SESSION_TTL_S };
  const token = await sign(full, requireSecret(env), payload.tid, "ss/session/v1");
  return `${sessionCookieName(env)}=${token}; ${cookieAttrs(SESSION_TTL_S, env)}`;
}

export async function readSession(
  request: Request,
  tenantId: string,
  env: Env,
): Promise<SessionPayload | null> {
  if (!env.SESSION_SECRET) return null;
  const token = readCookie(request, sessionCookieName(env));
  if (!token) return null;
  return verify<SessionPayload>(token, env.SESSION_SECRET, tenantId, "ss/session/v1");
}

/**
 * The gate every protected request goes through: signature-valid AND minted
 * under the tenant's CURRENT sessionVersion. Bumping the version (emergency
 * revoke, authorization-policy edits) cuts off outstanding sessions without
 * waiting out the cookie TTL.
 */
export async function readValidSession(
  request: Request,
  tenant: { tenantId: string; sessionVersion: number },
  env: Env,
): Promise<SessionPayload | null> {
  const session = await readSession(request, tenant.tenantId, env);
  if (!session || session.sv !== tenant.sessionVersion) return null;
  return session;
}

export function clearSessionCookie(env: Env): string {
  return `${sessionCookieName(env)}=; ${cookieAttrs(0, env)}`;
}

// ---------- login transaction cookie ----------

export async function mintTxnCookie(
  payload: Omit<TxnPayload, "v" | "exp">,
  env: Env,
): Promise<string> {
  const full: TxnPayload = {
    v: 1,
    ...payload,
    exp: Math.floor(Date.now() / 1000) + TXN_TTL_S,
  };
  const token = await sign(full, requireSecret(env), payload.tid, "ss/txn/v1");
  return `${txnCookieName(env)}=${token}; ${cookieAttrs(TXN_TTL_S, env)}`;
}

export async function readTxn(
  request: Request,
  tenantId: string,
  env: Env,
): Promise<TxnPayload | null> {
  if (!env.SESSION_SECRET) return null;
  const token = readCookie(request, txnCookieName(env));
  if (!token) return null;
  return verify<TxnPayload>(token, env.SESSION_SECRET, tenantId, "ss/txn/v1");
}

export function clearTxnCookie(env: Env): string {
  return `${txnCookieName(env)}=; ${cookieAttrs(0, env)}`;
}

function requireSecret(env: Env): string {
  if (!env.SESSION_SECRET) throw new Error("SESSION_SECRET is not configured");
  return env.SESSION_SECRET;
}
