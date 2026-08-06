export interface Session {
  email: string;
  name: string | null;
  tenantId: string;
  isAdmin: boolean;
  /** Cookie expiry, epoch seconds. */
  exp: number;
}

export async function fetchSession(): Promise<Session | null> {
  try {
    const res = await fetch("/auth/me");
    if (!res.ok) return null;
    return (await res.json()) as Session;
  } catch {
    return null;
  }
}

/**
 * Where to send the browser to sign in. return_to is the current PATH only —
 * never location.hash, which is where share codes live.
 */
export function loginUrl(returnTo: string = location.pathname): string {
  return `/auth/login?return_to=${encodeURIComponent(returnTo)}`;
}

export async function logout(): Promise<void> {
  try {
    await fetch("/auth/logout", { method: "POST" });
  } catch {
    // cookie may survive a network blip; the UI resets regardless
  }
}

/**
 * Reads and scrubs ?auth_error=<code> left by a failed /auth/callback,
 * translated to user-facing copy.
 */
export function consumeAuthError(): string | null {
  const params = new URLSearchParams(location.search);
  const code = params.get("auth_error");
  if (!code) return null;
  params.delete("auth_error");
  const query = params.toString();
  history.replaceState(null, "", location.pathname + (query ? `?${query}` : ""));
  return authErrorMessage(code);
}

function authErrorMessage(code: string): string {
  switch (code) {
    case "DOMAIN_NOT_ALLOWED":
      return "Your account's email domain isn't allowed on this service.";
    case "GROUP_NOT_ALLOWED":
      return "Your account isn't in a group that's allowed to use this service.";
    case "LOGIN_EXPIRED":
      return "The sign-in took too long — please try again.";
    case "IDP_UNREACHABLE":
      return "The sign-in service could not be reached — please try again shortly.";
    default:
      return "Sign-in failed — please try again.";
  }
}
