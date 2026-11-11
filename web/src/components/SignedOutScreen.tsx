import { useId, useState, type SubmitEvent } from "react";
import type { SignOutReason } from "../auth.ts";

interface SignedOutScreenProps {
  readonly reason: SignOutReason | null;
  /**
   * Development builds only: signs in with a token issued by the local development API.
   * Throws if the token is malformed. Absent in production builds, where single sign-on
   * (Phase 2) is the only way in.
   */
  readonly onDevSignIn?: ((token: string) => void) | undefined;
}

export function SignedOutScreen({ reason, onDevSignIn }: SignedOutScreenProps) {
  return (
    <div className="signed-out">
      <main className="signed-out-panel">
        <p className="product-name">LightHouse Enterprise</p>
        <h1>Sign in to the console</h1>
        {reason === "session_ended" && (
          <p role="status" className="notice">
            Your session has ended. Sign in again to continue.
          </p>
        )}
        {reason === "user" && (
          <p role="status" className="notice">
            You have signed out.
          </p>
        )}
        {onDevSignIn === undefined ? (
          <p>Sign-in with your organisation&rsquo;s single sign-on is not available in this build yet.</p>
        ) : (
          <DevSignInForm onSignIn={onDevSignIn} />
        )}
      </main>
    </div>
  );
}

function DevSignInForm({ onSignIn }: { onSignIn: (token: string) => void }) {
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const inputId = useId();
  const hintId = useId();
  const errorId = useId();

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      onSignIn(token);
    } catch {
      setError("That is not a valid access token. Copy the whole token from your local API and try again.");
    }
  }

  return (
    <form className="dev-sign-in" onSubmit={handleSubmit} noValidate>
      <label htmlFor={inputId}>Development access token</label>
      <p id={hintId} className="field-hint">
        For local development only. Paste a token issued by your local LightHouse API. It is kept in this tab&rsquo;s
        memory and is gone when you close or reload it.
      </p>
      <input
        id={inputId}
        type="password"
        autoComplete="off"
        spellCheck={false}
        value={token}
        onChange={(event) => {
          setToken(event.target.value);
          setError(null);
        }}
        aria-describedby={error === null ? hintId : `${hintId} ${errorId}`}
        aria-invalid={error !== null}
        required
      />
      {error !== null && (
        <p id={errorId} role="alert" className="field-error">
          {error}
        </p>
      )}
      <button type="submit" className="button button-primary">
        Sign in
      </button>
    </form>
  );
}
