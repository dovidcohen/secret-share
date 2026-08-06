import type { TenantConfig } from "../tenant/schema.js";
import {
  discover,
  exchangeCode,
  pkceChallenge,
  validateIdToken,
  OidcError,
  type IdTokenClaims,
} from "./oidc.js";
import {
  clearSessionCookie,
  clearTxnCookie,
  mintSessionCookie,
  mintTxnCookie,
  randomToken,
  readSession,
  readTxn,
} from "./session.js";

/**
 * /auth/* endpoints — only reachable on tenant hosts (the router 404s them on
 * the apex, which stays account-free). Failures land on /?auth_error=<code>;
 * the SPA turns that into copy.
 */
export async function handleAuth(
  request: Request,
  url: URL,
  tenant: TenantConfig,
  env: Env,
): Promise<Response> {
  const { pathname } = url;
  if (pathname === "/auth/login" && request.method === "GET") {
    return login(url, tenant, env);
  }
  if (pathname === "/auth/callback" && request.method === "GET") {
    return callback(request, url, tenant, env);
  }
  if (pathname === "/auth/logout" && request.method === "POST") {
    return withNoStore(
      new Response(null, {
        status: 204,
        headers: { "Set-Cookie": clearSessionCookie(env) },
      }),
    );
  }
  if (pathname === "/auth/me" && request.method === "GET") {
    return me(request, tenant, env);
  }
  return withNoStore(Response.json({ error: "NOT_FOUND" }, { status: 404 }));
}

function withNoStore(res: Response): Response {
  res.headers.set("Cache-Control", "no-store");
  return res;
}

/** return_to must stay a same-site path — never a full URL, never a fragment. */
function sanitizeReturnTo(raw: string | null): string {
  if (!raw || !raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) {
    return "/";
  }
  return raw.split("#")[0] as string;
}

function authFailure(url: URL, code: string, env: Env): Response {
  const res = new Response(null, {
    status: 302,
    headers: {
      Location: `${url.origin}/?auth_error=${encodeURIComponent(code)}`,
      "Set-Cookie": clearTxnCookie(env),
    },
  });
  return withNoStore(res);
}

async function login(url: URL, tenant: TenantConfig, env: Env): Promise<Response> {
  let doc;
  try {
    doc = await discover(tenant.oidc.issuer, env);
  } catch (e) {
    console.error("OIDC discovery failed", e);
    return authFailure(url, "IDP_UNREACHABLE", env);
  }

  const state = randomToken(16);
  const nonce = randomToken(16);
  const verifier = randomToken(32);
  const returnTo = sanitizeReturnTo(url.searchParams.get("return_to"));

  const authorize = new URL(doc.authorization_endpoint);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("client_id", tenant.oidc.clientId);
  authorize.searchParams.set("redirect_uri", `${url.origin}/auth/callback`);
  authorize.searchParams.set("scope", tenant.oidc.scopes);
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("nonce", nonce);
  authorize.searchParams.set("code_challenge", await pkceChallenge(verifier));
  authorize.searchParams.set("code_challenge_method", "S256");

  const txnCookie = await mintTxnCookie(
    { tid: tenant.tenantId, state, nonce, verifier, returnTo },
    env,
  );
  return withNoStore(
    new Response(null, {
      status: 302,
      headers: { Location: authorize.toString(), "Set-Cookie": txnCookie },
    }),
  );
}

async function callback(
  request: Request,
  url: URL,
  tenant: TenantConfig,
  env: Env,
): Promise<Response> {
  const txn = await readTxn(request, tenant.tenantId, env);
  if (!txn) return authFailure(url, "LOGIN_EXPIRED", env);

  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");
  if (!code || !state || state !== txn.state) return authFailure(url, "BAD_STATE", env);

  let claims: IdTokenClaims;
  try {
    const doc = await discover(tenant.oidc.issuer, env);
    const tokens = await exchangeCode(doc, tenant, env, {
      code,
      redirectUri: `${url.origin}/auth/callback`,
      verifier: txn.verifier,
    });
    if (!tokens.id_token) throw new OidcError("NO_ID_TOKEN");
    claims = await validateIdToken(
      tokens.id_token,
      {
        issuer: tenant.oidc.issuer,
        clientId: tenant.oidc.clientId,
        nonce: txn.nonce,
        jwksUri: doc.jwks_uri,
      },
      env,
    );
  } catch (e) {
    console.error("OIDC callback failed", e);
    return authFailure(url, e instanceof OidcError ? e.code : "AUTH_FAILED", env);
  }

  const email = (claims.email ?? claims.preferred_username ?? "").toLowerCase();
  if (!email || !email.includes("@")) return authFailure(url, "NO_EMAIL_CLAIM", env);

  const { allowedEmailDomains, allowedGroups } = tenant.oidc;
  if (allowedEmailDomains.length > 0) {
    const domain = email.slice(email.lastIndexOf("@") + 1);
    if (!allowedEmailDomains.some((d) => d.toLowerCase() === domain)) {
      return authFailure(url, "DOMAIN_NOT_ALLOWED", env);
    }
  }
  if (allowedGroups.length > 0) {
    // Entra: `groups` (object ids) or `roles` (app roles — preferred, since the
    // groups claim is omitted entirely for users in >200 groups).
    const memberships = [...(claims.groups ?? []), ...(claims.roles ?? [])];
    if (!allowedGroups.some((g) => memberships.includes(g))) {
      return authFailure(url, "GROUP_NOT_ALLOWED", env);
    }
  }

  const sessionCookie = await mintSessionCookie(
    {
      tid: tenant.tenantId,
      sub: claims.sub,
      email,
      name: claims.name,
      adm: tenant.adminEmails.some((a) => a.toLowerCase() === email),
    },
    env,
  );
  const res = new Response(null, {
    status: 302,
    headers: { Location: `${url.origin}${txn.returnTo}` },
  });
  res.headers.append("Set-Cookie", sessionCookie);
  res.headers.append("Set-Cookie", clearTxnCookie(env));
  return withNoStore(res);
}

async function me(request: Request, tenant: TenantConfig, env: Env): Promise<Response> {
  const session = await readSession(request, tenant.tenantId, env);
  if (!session) {
    return withNoStore(Response.json({ error: "AUTH_REQUIRED" }, { status: 401 }));
  }
  return withNoStore(
    Response.json({
      email: session.email,
      name: session.name ?? null,
      tenantId: session.tid,
      isAdmin: session.adm,
      exp: session.exp,
    }),
  );
}
