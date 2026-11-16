import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createApiClient } from "./api.ts";
import { App } from "./App.tsx";
import { MemoryAuthProvider, type AuthProvider } from "./auth.ts";
import { ErrorBoundary } from "./components/ErrorBoundary.tsx";
import { readPublicConfig, type PublicConfig } from "./config.ts";
import { readSsoCallback } from "./ssoCallback.ts";
import { createSupabaseAuthClient, SupabaseAuthProvider, type SsoStartResult } from "./supabaseAuth.ts";
import "./styles.css";

function ConfigurationError() {
  return (
    <main className="signed-out">
      <div role="alert" className="signed-out-panel notice notice-error">
        <h1>The console is not configured correctly</h1>
        <p>
          A sign-in or API setting in this build is not allowed. Check VITE_API_BASE_URL, VITE_SUPABASE_URL and
          VITE_SUPABASE_PUBLISHABLE_KEY, then rebuild.
        </p>
      </div>
    </main>
  );
}

function start(container: HTMLElement) {
  const root = createRoot(container);

  // Taken first, before any other code runs: a sign-in callback carries the session in the
  // URL fragment, and the address bar and history entry are cleaned straight away so the
  // tokens are not left where Back, a bookmark or a screen share could expose them.
  const callback = readSsoCallback(window.location.href);
  if (callback.kind !== "none") {
    window.history.replaceState(window.history.state, "", callback.cleanUrl);
  }

  let config: PublicConfig;
  try {
    // SECURITY: only public values are read from the build environment. See src/config.ts.
    config = readPublicConfig();
  } catch {
    root.render(<ConfigurationError />);
    return;
  }

  let auth: AuthProvider;
  let onSsoSignIn: ((emailOrDomain: string) => Promise<SsoStartResult>) | undefined;
  let onDevSignIn: ((token: string) => void) | undefined;

  if (config.supabase !== null) {
    const sso = new SupabaseAuthProvider(createSupabaseAuthClient(config.supabase), {
      // Back to this page, without any query or fragment. This address must be on the
      // Supabase project's redirect allow-list.
      redirectTo: `${window.location.origin}${window.location.pathname}`,
    });
    if (callback.kind === "session") {
      void sso.completeSignIn(callback);
    } else if (callback.kind === "error") {
      sso.failSignIn();
    }
    auth = sso;
    onSsoSignIn = (emailOrDomain) => sso.startSignIn(emailOrDomain);
  } else {
    // No single sign-on in this build. Development builds can sign in with a token issued
    // by the local API; production builds show that sign-in is not set up.
    const memory = new MemoryAuthProvider();
    auth = memory;
    onDevSignIn = import.meta.env.DEV
      ? (token: string) => {
          memory.signInWithToken(token);
        }
      : undefined;
  }

  const api = createApiClient({ baseUrl: config.apiBaseUrl, auth });

  root.render(
    <StrictMode>
      <ErrorBoundary>
        <App auth={auth} api={api} onSsoSignIn={onSsoSignIn} onDevSignIn={onDevSignIn} />
      </ErrorBoundary>
    </StrictMode>,
  );
}

const container = document.getElementById("root");
if (container !== null) {
  start(container);
}
