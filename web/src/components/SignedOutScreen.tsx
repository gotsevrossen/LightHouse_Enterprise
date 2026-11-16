import { useId, useState, type SubmitEvent } from "react";
import type { SignOutReason } from "../auth.ts";
import type { SsoStartResult } from "../supabaseAuth.ts";

interface SignedOutScreenProps {
  readonly reason: SignOutReason | null;
  /** True while a single sign-on redirect is being completed. */
  readonly signingIn?: boolean;
  /** Starts single sign-on for the organisation that owns the email domain. */
  readonly onSsoSignIn?: ((emailOrDomain: string) => Promise<SsoStartResult>) | undefined;
  /**
   * Development builds only: signs in with a token issued by the local development API.
   * Throws if the token is malformed. Absent in production builds, where single sign-on
   * (Phase 2) is the only way in.
   */
  readonly onDevSignIn?: ((token: string) => void) | undefined;
}

export function SignedOutScreen({ reason, signingIn = false, onSsoSignIn, onDevSignIn }: SignedOutScreenProps) {
  if (signingIn) {
    return (
      <div className="signed-out">
        <main className="signed-out-panel">
          <p className="product-name">LightHouse Enterprise</p>
          <h1>Signing you in</h1>
          <p role="status" className="notice">
            Finishing single sign-on…
          </p>
        </main>
      </div>
    );
  }
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
        {reason === "sign_in_failed" && (
          <p role="alert" className="notice notice-error">
            Single sign-on did not finish, so you are not signed in. Try again. If it keeps happening, ask your
            administrator to check your access to LightHouse.
          </p>
        )}
        {onSsoSignIn !== undefined && <SsoSignInForm onSignIn={onSsoSignIn} />}
        {onDevSignIn !== undefined && <DevSignInForm onSignIn={onDevSignIn} />}
        {onSsoSignIn === undefined && onDevSignIn === undefined && (
          <p>Single sign-on is not set up in this build of the console. Ask your LightHouse administrator.</p>
        )}
      </main>
    </div>
  );
}

const SSO_ERRORS: Record<Exclude<SsoStartResult["kind"], "redirecting">, string> = {
  invalid_domain: "Enter your work email address, for example name@example.com.",
  no_provider:
    "Single sign-on is not set up for that email domain. Check the address, or ask your administrator which address to use.",
  failed: "The sign-in service could not be reached. Try again in a moment.",
};

function SsoSignInForm({ onSignIn }: { onSignIn: (emailOrDomain: string) => Promise<SsoStartResult> }) {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputId = useId();
  const hintId = useId();
  const errorId = useId();

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    onSignIn(email).then(
      (result) => {
        // On success the tab is already leaving for the identity provider; stay busy.
        if (result.kind !== "redirecting") {
          setBusy(false);
          setError(SSO_ERRORS[result.kind]);
        }
      },
      () => {
        setBusy(false);
        setError(SSO_ERRORS.failed);
      },
    );
  }

  return (
    <form className="dev-sign-in" onSubmit={handleSubmit} noValidate>
      <label htmlFor={inputId}>Work email</label>
      <p id={hintId} className="field-hint">
        You will continue to your organisation&rsquo;s sign-in page and come back here.
      </p>
      <input
        id={inputId}
        type="email"
        inputMode="email"
        autoComplete="username"
        spellCheck={false}
        value={email}
        onChange={(event) => {
          setEmail(event.target.value);
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
      <button type="submit" className="button button-primary" disabled={busy}>
        {busy ? "Opening your sign-in page…" : "Continue with single sign-on"}
      </button>
    </form>
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
