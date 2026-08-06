import type { TenantConfig } from "../tenant/schema.js";

/**
 * Minimal OIDC relying party: authorization code + PKCE + RS256 id_token
 * validation, all WebCrypto. Hand-rolled deliberately — the flow surface here
 * is ~small and this codebase's ethos is auditable crypto plumbing over
 * dependencies. RS256 only for v1 (Entra, Okta, Google all default to it).
 */

export interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
}

export interface IdTokenClaims {
  iss: string;
  aud: string | string[];
  sub: string;
  exp: number;
  iat: number;
  nbf?: number;
  nonce?: string;
  email?: string;
  preferred_username?: string;
  name?: string;
  groups?: string[];
  roles?: string[];
}

const CLOCK_SKEW_S = 300;
const DISCOVERY_KV_TTL_S = 3600;

function sha256Hex(s: string): Promise<string> {
  return crypto.subtle
    .digest("SHA-256", new TextEncoder().encode(s))
    .then((d) =>
      Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, "0")).join(""),
    );
}

function fromB64url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "="));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toB64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** PKCE S256 challenge for a base64url verifier string. */
export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return toB64url(new Uint8Array(digest));
}

export class OidcError extends Error {
  constructor(public code: string, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
  }
}

export async function discover(issuer: string, env: Env): Promise<DiscoveryDocument> {
  const kvKey = `disc:${await sha256Hex(issuer)}`;
  const cached = await env.TENANTS.get(kvKey, {
    type: "json",
    cacheTtl: DISCOVERY_KV_TTL_S,
  }).catch(() => null);
  if (cached) return cached as DiscoveryDocument;

  const url = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const res = await fetch(url);
  if (!res.ok) throw new OidcError("DISCOVERY_FAILED", `${res.status} from ${url}`);
  const doc = (await res.json()) as DiscoveryDocument;
  // Entra's v2.0 issuer contains the directory tenant id; an exact match here
  // is what stops a look-alike issuer from serving us its own keys.
  if (doc.issuer !== issuer) {
    throw new OidcError("ISSUER_MISMATCH", `${doc.issuer} != ${issuer}`);
  }
  if (!doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
    throw new OidcError("DISCOVERY_INCOMPLETE");
  }
  await env.TENANTS.put(kvKey, JSON.stringify(doc), {
    expirationTtl: 24 * 3600,
  }).catch(() => {});
  return doc;
}

interface Jwk {
  kty: string;
  kid?: string;
  use?: string;
  n?: string;
  e?: string;
}

async function fetchJwks(
  jwksUri: string,
  kid: string | undefined,
  env: Env,
): Promise<Jwk[]> {
  const kvKey = `jwks:${await sha256Hex(jwksUri)}`;
  const cached = (await env.TENANTS.get(kvKey, { type: "json", cacheTtl: 3600 }).catch(
    () => null,
  )) as { keys?: Jwk[] } | null;
  if (cached?.keys?.some((k) => !kid || k.kid === kid)) return cached.keys;

  // kid miss (key rotation) or empty cache: hit the IdP directly.
  const res = await fetch(jwksUri);
  if (!res.ok) throw new OidcError("JWKS_FETCH_FAILED", `${res.status}`);
  const jwks = (await res.json()) as { keys?: Jwk[] };
  if (!Array.isArray(jwks.keys)) throw new OidcError("JWKS_MALFORMED");
  await env.TENANTS.put(kvKey, JSON.stringify(jwks), {
    expirationTtl: 24 * 3600,
  }).catch(() => {});
  return jwks.keys;
}

/** Splits, verifies RS256 signature against the issuer's JWKS, checks core claims. */
export async function validateIdToken(
  jwt: string,
  opts: { issuer: string; clientId: string; nonce: string; jwksUri: string },
  env: Env,
): Promise<IdTokenClaims> {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new OidcError("BAD_TOKEN", "not a JWS");
  const [h, p, s] = parts as [string, string, string];

  let header: { alg?: string; kid?: string };
  let claims: IdTokenClaims;
  try {
    header = JSON.parse(new TextDecoder().decode(fromB64url(h)));
    claims = JSON.parse(new TextDecoder().decode(fromB64url(p)));
  } catch {
    throw new OidcError("BAD_TOKEN", "undecodable");
  }
  if (header.alg !== "RS256") throw new OidcError("BAD_ALG", header.alg);

  const keys = await fetchJwks(opts.jwksUri, header.kid, env);
  const jwk = keys.find(
    (k) => k.kty === "RSA" && (!header.kid || k.kid === header.kid),
  );
  if (!jwk) throw new OidcError("NO_MATCHING_KEY", header.kid);

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", n: jwk.n, e: jwk.e },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    fromB64url(s) as BufferSource,
    new TextEncoder().encode(`${h}.${p}`),
  );
  if (!valid) throw new OidcError("BAD_SIGNATURE");

  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== opts.issuer) throw new OidcError("BAD_ISS", claims.iss);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(opts.clientId)) throw new OidcError("BAD_AUD");
  if (typeof claims.exp !== "number" || claims.exp + CLOCK_SKEW_S <= now) {
    throw new OidcError("EXPIRED");
  }
  if (typeof claims.iat === "number" && claims.iat - CLOCK_SKEW_S > now) {
    throw new OidcError("ISSUED_IN_FUTURE");
  }
  if (typeof claims.nbf === "number" && claims.nbf - CLOCK_SKEW_S > now) {
    throw new OidcError("NOT_YET_VALID");
  }
  if (claims.nonce !== opts.nonce) throw new OidcError("BAD_NONCE");
  return claims;
}

/**
 * The one seam for client-secret storage: today a per-tenant Worker secret,
 * later envelope-encrypted KV behind this same function.
 */
export function getClientSecret(env: Env, tenant: TenantConfig): string | null {
  const name = `OIDC_CLIENT_SECRET_${tenant.tenantId.toUpperCase().replace(/-/g, "_")}`;
  const value = (env as unknown as Record<string, unknown>)[name];
  return typeof value === "string" && value.length > 0 ? value : null;
}

export async function exchangeCode(
  doc: DiscoveryDocument,
  tenant: TenantConfig,
  env: Env,
  params: { code: string; redirectUri: string; verifier: string },
): Promise<{ id_token?: string }> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    redirect_uri: params.redirectUri,
    client_id: tenant.oidc.clientId,
    code_verifier: params.verifier,
  });
  if (tenant.oidc.clientAuth === "secret") {
    const secret = getClientSecret(env, tenant);
    if (!secret) throw new OidcError("CLIENT_SECRET_MISSING", tenant.tenantId);
    body.set("client_secret", secret);
  }
  const res = await fetch(doc.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new OidcError("TOKEN_EXCHANGE_FAILED", `${res.status} ${detail.slice(0, 200)}`);
  }
  return (await res.json()) as { id_token?: string };
}
