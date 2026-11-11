import { useCallback, useEffect, useState } from "react";
import type { ApiClient, Me } from "./api.ts";
import { useAuthState, type AuthProvider } from "./auth.ts";
import { AlertsQueue } from "./components/AlertsQueue.tsx";
import { AppShell } from "./components/AppShell.tsx";
import { ErrorBoundary } from "./components/ErrorBoundary.tsx";
import { describeError } from "./components/errorText.ts";
import { SignedOutScreen } from "./components/SignedOutScreen.tsx";

interface AppProps {
  readonly auth: AuthProvider;
  readonly api: ApiClient;
  /** Development builds only. See SignedOutScreen. */
  readonly onDevSignIn?: ((token: string) => void) | undefined;
}

export function App({ auth, api, onDevSignIn }: AppProps) {
  const state = useAuthState(auth);
  if (state.status === "signed_out") {
    return <SignedOutScreen reason={state.reason} onDevSignIn={onDevSignIn} />;
  }
  return <Console auth={auth} api={api} />;
}

type MeState =
  | { readonly kind: "loading" }
  | { readonly kind: "error"; readonly error: unknown }
  | { readonly kind: "ready"; readonly me: Me };

function Console({ auth, api }: { auth: AuthProvider; api: ApiClient }) {
  const [meState, setMeState] = useState<MeState>({ kind: "loading" });
  const [reloadCount, setReloadCount] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    api.getMe(controller.signal).then(
      (me) => {
        if (!controller.signal.aborted) setMeState({ kind: "ready", me });
      },
      (error: unknown) => {
        if (!controller.signal.aborted) setMeState({ kind: "error", error });
      },
    );
    return () => {
      controller.abort();
    };
  }, [api, reloadCount]);

  const retry = useCallback(() => {
    setMeState({ kind: "loading" });
    setReloadCount((count) => count + 1);
  }, []);

  const signOut = useCallback(() => {
    void auth.signOut("user");
  }, [auth]);

  return (
    <AppShell me={meState.kind === "ready" ? meState.me : null} onSignOut={signOut}>
      <ErrorBoundary>
        {meState.kind === "loading" && (
          <p role="status" className="notice">
            Loading your account…
          </p>
        )}
        {meState.kind === "error" && (
          <div role="alert" className="notice notice-error">
            <p>{describeError(meState.error, "your account")}</p>
            <button type="button" className="button" onClick={retry}>
              Try again
            </button>
          </div>
        )}
        {meState.kind === "ready" && <AlertsQueue api={api} />}
      </ErrorBoundary>
    </AppShell>
  );
}
