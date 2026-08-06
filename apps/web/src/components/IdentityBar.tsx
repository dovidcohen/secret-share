import { useSession } from "../lib/session.js";

/** Signed-in identity chip in the header; invisible everywhere else. */
export function IdentityBar({ onAdmin }: { onAdmin: () => void }) {
  const { state, signOut } = useSession();
  if (state.status !== "authed") return null;

  return (
    <p className="muted identity-bar">
      {state.session.email}
      {state.session.isAdmin && (
        <>
          {" · "}
          <button className="linklike" onClick={onAdmin}>
            Admin
          </button>
        </>
      )}
      {" · "}
      <button className="linklike" onClick={() => void signOut()}>
        Sign out
      </button>
    </p>
  );
}
