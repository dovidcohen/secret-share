import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { fetchSession, logout, type Session } from "./auth.js";
import type { TenantConfig } from "./tenant.js";

/**
 * "off" on the public host — the provider never even calls /auth/me there, so
 * shareasecret.io gains zero requests from the tenant feature.
 */
export type SessionState =
  | { status: "off" }
  | { status: "loading" }
  | { status: "anon" }
  | { status: "authed"; session: Session };

interface SessionApi {
  state: SessionState;
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
}

const SessionContext = createContext<SessionApi>({
  state: { status: "off" },
  refresh: async () => {},
  signOut: async () => {},
});

export function SessionProvider({
  tenant,
  children,
}: {
  tenant: TenantConfig | null;
  children: ReactNode;
}) {
  const [state, setState] = useState<SessionState>(
    tenant ? { status: "loading" } : { status: "off" },
  );

  const refresh = useCallback(async () => {
    if (!tenant) return;
    const session = await fetchSession();
    setState(session ? { status: "authed", session } : { status: "anon" });
  }, [tenant]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const signOut = useCallback(async () => {
    await logout();
    setState({ status: "anon" });
  }, []);

  return (
    <SessionContext.Provider value={{ state, refresh, signOut }}>
      {children}
    </SessionContext.Provider>
  );
}

export function useSession(): SessionApi {
  return useContext(SessionContext);
}
