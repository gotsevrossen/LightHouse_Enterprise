import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createApiClient } from "./api.ts";
import { App } from "./App.tsx";
import { MemoryAuthProvider } from "./auth.ts";
import { ErrorBoundary } from "./components/ErrorBoundary.tsx";
import { resolveApiBaseUrl } from "./config.ts";
import "./styles.css";

function ConfigurationError() {
  return (
    <main className="signed-out">
      <div role="alert" className="signed-out-panel notice notice-error">
        <h1>The console is not configured correctly</h1>
        <p>The API address in this build is not allowed. Check VITE_API_BASE_URL and rebuild.</p>
      </div>
    </main>
  );
}

function start(container: HTMLElement) {
  const root = createRoot(container);

  let baseUrl: string;
  try {
    // SECURITY: only public values are read from import.meta.env. See src/config.ts.
    baseUrl = resolveApiBaseUrl(import.meta.env.VITE_API_BASE_URL);
  } catch {
    root.render(<ConfigurationError />);
    return;
  }

  // Phase 2 replaces this with a Supabase Auth (SAML SSO) provider behind the same interface.
  const auth = new MemoryAuthProvider();
  const api = createApiClient({ baseUrl, auth });
  const onDevSignIn = import.meta.env.DEV
    ? (token: string) => {
        auth.signInWithToken(token);
      }
    : undefined;

  root.render(
    <StrictMode>
      <ErrorBoundary>
        <App auth={auth} api={api} onDevSignIn={onDevSignIn} />
      </ErrorBoundary>
    </StrictMode>,
  );
}

const container = document.getElementById("root");
if (container !== null) {
  start(container);
}
