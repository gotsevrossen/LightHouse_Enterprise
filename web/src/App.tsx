import { useCallback, useEffect, useRef, useState } from "react";
import type { Alert, ApiClient, Me, Role } from "./api.ts";
import { useAuthState, type AuthProvider } from "./auth.ts";
import { AlertDetailView } from "./components/AlertDetailView.tsx";
import { AlertsQueue } from "./components/AlertsQueue.tsx";
import { AppShell } from "./components/AppShell.tsx";
import { ChatPanel } from "./components/ChatPanel.tsx";
import { ErrorBoundary } from "./components/ErrorBoundary.tsx";
import { describeError } from "./components/errorText.ts";
import { SignedOutScreen } from "./components/SignedOutScreen.tsx";
import type { SsoStartResult } from "./supabaseAuth.ts";

interface AppProps {
  readonly auth: AuthProvider;
  readonly api: ApiClient;
  /** Starts single sign-on. Absent when Supabase is not configured in this build. */
  readonly onSsoSignIn?: ((emailOrDomain: string) => Promise<SsoStartResult>) | undefined;
  /** Development builds only. See SignedOutScreen. */
  readonly onDevSignIn?: ((token: string) => void) | undefined;
}

export function App({ auth, api, onSsoSignIn, onDevSignIn }: AppProps) {
  const state = useAuthState(auth);
  if (state.status === "signing_in") {
    return <SignedOutScreen reason={null} signingIn />;
  }
  if (state.status === "signed_out") {
    return <SignedOutScreen reason={state.reason} onSsoSignIn={onSsoSignIn} onDevSignIn={onDevSignIn} />;
  }
  return <Console auth={auth} api={api} />;
}

type MeState =
  | { readonly kind: "loading" }
  | { readonly kind: "error"; readonly error: unknown }
  | { readonly kind: "ready"; readonly me: Me };

// Roles that may change an alert's status. This only decides which controls are shown; the
// API checks the role again on every request (CLAUDE.md rule 10).
const STATUS_ROLES: ReadonlySet<Role> = new Set(["analyst", "responder", "admin"]);

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
        {meState.kind === "ready" && <Workspace api={api} me={meState.me} />}
      </ErrorBoundary>
    </AppShell>
  );
}

/** Whether to show chat. Unknown (still loading) and any failure both mean "hidden". */
function useChatAvailable(api: ApiClient): boolean {
  const [available, setAvailable] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    api.getChatStatus(controller.signal).then(
      (status) => {
        if (!controller.signal.aborted) setAvailable(status.available);
      },
      () => {
        if (!controller.signal.aborted) setAvailable(false);
      },
    );
    return () => {
      controller.abort();
    };
  }, [api]);
  return available;
}

function Workspace({ api, me }: { api: ApiClient; me: Me }) {
  // In-app view state rather than a URL route: alert ids stay out of the address bar and
  // history, and there is no router dependency. The queue stays mounted (hidden) while an
  // alert is open, so going back keeps its place.
  const [openAlertId, setOpenAlertId] = useState<string | null>(null);
  const [updated, setUpdated] = useState<Alert | null>(null);
  const returnFocusTo = useRef<string | null>(null);
  const queueRef = useRef<HTMLDivElement>(null);
  const chatAvailable = useChatAvailable(api);

  const open = useCallback((id: string) => {
    returnFocusTo.current = id;
    setOpenAlertId(id);
  }, []);

  const back = useCallback(() => {
    setOpenAlertId(null);
  }, []);

  // Back on the queue, put focus on the alert that was opened, matched by comparing the
  // data attribute (no selector is built from the id).
  useEffect(() => {
    if (openAlertId !== null || returnFocusTo.current === null) return;
    const id = returnFocusTo.current;
    returnFocusTo.current = null;
    const buttons = queueRef.current?.querySelectorAll<HTMLButtonElement>("button[data-alert-id]") ?? [];
    for (const button of buttons) {
      if (button.dataset.alertId === id) {
        button.focus();
        return;
      }
    }
  }, [openAlertId]);

  return (
    <>
      <div ref={queueRef} hidden={openAlertId !== null}>
        <AlertsQueue
          api={api}
          onOpen={open}
          updated={updated}
          beforeList={
            chatAvailable ? (
              <details className="chat-disclosure">
                <summary>Ask LightHouse</summary>
                <ChatPanel
                  api={api}
                  alertId={null}
                  showHeading={false}
                  intro="Ask about your alerts or security in general."
                />
              </details>
            ) : null
          }
        />
      </div>
      {openAlertId !== null && (
        <AlertDetailView
          key={openAlertId}
          api={api}
          alertId={openAlertId}
          canChangeStatus={STATUS_ROLES.has(me.role)}
          chatAvailable={chatAvailable}
          onBack={back}
          onUpdated={setUpdated}
        />
      )}
    </>
  );
}
