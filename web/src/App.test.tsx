import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { createApiClient } from "./api.ts";
import { App } from "./App.tsx";
import { MemoryAuthProvider } from "./auth.ts";
import { SupabaseAuthProvider, type SsoAuthClient } from "./supabaseAuth.ts";
import { ErrorBoundary } from "./components/ErrorBoundary.tsx";
import {
  bodyText,
  jsonResponse,
  makeAlert,
  makeAlertDetail,
  makeAnalystDetail,
  requestedUrls,
  routedFetch,
  signedInAuth,
  TEST_TENANT_ID,
  TEST_TOKEN,
  TEST_USER_ID,
} from "./test/fixtures.ts";

const ME = { user_id: TEST_USER_ID, tenant_id: TEST_TENANT_ID, role: "responder" };

function setup(options: { auth?: MemoryAuthProvider; routes?: Parameters<typeof routedFetch>[0]; dev?: boolean } = {}) {
  const auth = options.auth ?? signedInAuth();
  const fetch = routedFetch(
    options.routes ?? {
      "/api/me": () => jsonResponse(ME),
      "/api/alerts": () => jsonResponse({ items: [makeAlert()], next_cursor: null }),
    },
  );
  const api = createApiClient({ baseUrl: "/api", auth, fetch });
  const onDevSignIn =
    options.dev === false
      ? undefined
      : (token: string) => {
          auth.signInWithToken(token);
        };
  render(<App auth={auth} api={api} onDevSignIn={onDevSignIn} />);
  return { auth, fetch };
}

describe("App", () => {
  it("shows the signed-out screen and makes no API calls", () => {
    const { fetch } = setup({ auth: new MemoryAuthProvider() });
    expect(screen.getByRole("heading", { name: "Sign in to the console" })).toBeTruthy();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("offers no token sign-in outside development builds", () => {
    setup({ auth: new MemoryAuthProvider(), dev: false });
    expect(screen.queryByLabelText("Development access token")).toBeNull();
    expect(screen.getByText(/Single sign-on is not set up in this build/)).toBeTruthy();
  });

  it("signs in with a development token and shows the shell with tenant and role", async () => {
    const { fetch } = setup({ auth: new MemoryAuthProvider() });

    fireEvent.change(screen.getByLabelText("Development access token"), { target: { value: TEST_TOKEN } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    const banner = screen.getByRole("banner");
    expect(within(banner).getByText("LightHouse Enterprise")).toBeTruthy();
    expect(await within(banner).findByText("Responder")).toBeTruthy();
    expect(within(banner).getByText(TEST_TENANT_ID)).toBeTruthy();
    expect(await screen.findByRole("heading", { level: 1, name: "Alerts" })).toBeTruthy();
    await waitFor(() => {
      expect(requestedUrls(fetch)).toEqual(["/api/me", "/api/alerts?limit=50", "/api/chat/status"]);
    });
  });

  it("rejects a malformed development token with a message", () => {
    const { fetch } = setup({ auth: new MemoryAuthProvider() });
    fireEvent.change(screen.getByLabelText("Development access token"), { target: { value: "not a token" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(screen.getByRole("alert").textContent).toContain("not a valid access token");
    expect(screen.getByLabelText("Development access token").getAttribute("aria-invalid")).toBe("true");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("signs out from the header", async () => {
    const { auth } = setup();
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));

    expect(auth.getState()).toEqual({ status: "signed_out", reason: "user" });
    expect(screen.getByRole("status").textContent).toBe("You have signed out.");
    await expect(auth.getAccessToken()).resolves.toBeNull();
  });

  it("returns to the signed-out screen when the API answers 401", async () => {
    setup({
      routes: {
        "/api/me": () => jsonResponse(ME),
        "/api/alerts": () => jsonResponse({ detail: "expired" }, 401),
      },
    });

    expect(await screen.findByRole("heading", { name: "Sign in to the console" })).toBeTruthy();
    expect(screen.getByRole("status").textContent).toBe("Your session has ended. Sign in again to continue.");
  });

  it("shows an error state, not a white screen, for a corrupt account response", async () => {
    setup({
      routes: {
        "/api/me": () => jsonResponse({ user_id: TEST_USER_ID, tenant_id: TEST_TENANT_ID, role: "superadmin" }),
      },
    });

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("format the console does not recognise");
    expect(within(alert).getByRole("button", { name: "Try again" })).toBeTruthy();
    // The shell, and with it the way out, is still there.
    expect(screen.getByRole("button", { name: "Sign out" })).toBeTruthy();
  });

  it("shows an error state when the API returns HTML instead of JSON", async () => {
    setup({
      routes: {
        "/api/me": () => new Response("<!doctype html><title>Gateway</title>", { status: 200 }),
      },
    });
    expect((await screen.findByRole("alert")).textContent).toContain("format the console does not recognise");
  });
});

function workspace(role: string, options: { chat?: boolean } = {}) {
  let status = "new";
  return setup({
    routes: {
      "/api/me": () => jsonResponse({ ...ME, role }),
      "/api/alerts": () => jsonResponse({ items: [makeAlert({ status })], next_cursor: null }),
      "/api/alerts/alert-1": (_url, init) => {
        if (init?.method === "PATCH") {
          status = (JSON.parse(bodyText(init)) as { status: string }).status;
        }
        const body = role === "viewer" ? makeAlertDetail({ status }) : makeAnalystDetail({ status });
        return jsonResponse(body);
      },
      "/api/chat/status": () => jsonResponse({ available: options.chat ?? false }),
    },
  });
}

async function openFirstAlert() {
  fireEvent.click(await screen.findByRole("button", { name: "Suspicious sign-in from an unfamiliar location" }));
  return screen.findByRole("heading", { level: 1, name: "Suspicious sign-in from an unfamiliar location" });
}

describe("App workspace", () => {
  it("opens an alert from the queue and returns to it with focus on the same alert", async () => {
    workspace("analyst");
    await openFirstAlert();
    expect(screen.getByRole("button", { name: "Back to alerts" })).toBeTruthy();
    // The queue is kept but hidden while the alert is open.
    expect(screen.queryByRole("heading", { level: 1, name: "Alerts" })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Back to alerts" }));
    const title = await screen.findByRole("button", { name: "Suspicious sign-in from an unfamiliar location" });
    expect(document.activeElement).toBe(title);
  });

  it("shows viewers no status control and no analyst view", async () => {
    workspace("viewer");
    await openFirstAlert();
    expect(screen.getByText("What happened")).toBeTruthy();
    expect(screen.queryByLabelText("Change status")).toBeNull();
    expect(screen.queryByText("Analyst view")).toBeNull();
  });

  it.each(["analyst", "responder", "admin"])("offers %s the status control and the analyst view", async (role) => {
    workspace(role);
    await openFirstAlert();
    expect(screen.getByLabelText("Change status")).toBeTruthy();
    expect(screen.getByText("Analyst view")).toBeTruthy();
  });

  it("carries a confirmed status change back to the queue", async () => {
    workspace("analyst");
    await openFirstAlert();
    fireEvent.change(screen.getByLabelText("Change status"), { target: { value: "resolved" } });
    fireEvent.click(screen.getByRole("button", { name: "Save status" }));
    expect(await screen.findByText("Status saved as Resolved.")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Back to alerts" }));
    const list = await screen.findByRole("list");
    expect(list.textContent).toContain("Status: Resolved.");
  });

  it("hides every chat panel when chat is unavailable", async () => {
    workspace("analyst", { chat: false });
    await screen.findByRole("list");
    expect(screen.queryByText("Ask LightHouse")).toBeNull();
    await openFirstAlert();
    expect(screen.queryByText("Ask LightHouse")).toBeNull();
  });

  it("offers a general chat on the queue and an alert-scoped one on the detail when available", async () => {
    workspace("viewer", { chat: true });
    const summary = await screen.findByText("Ask LightHouse", { selector: "summary" });
    expect(summary.closest("details")?.open).toBe(false);
    await openFirstAlert();
    expect(screen.getByRole("heading", { name: "Ask LightHouse" })).toBeTruthy();
  });
});

function pendingSsoClient(): SsoAuthClient {
  return {
    signInWithSSO: () => Promise.resolve({ data: null, error: { code: "sso_provider_not_found" } }),
    setSession: () => new Promise(() => undefined),
    getSession: () => Promise.resolve({ data: { session: null }, error: null }),
    signOut: () => Promise.resolve({ error: null }),
    onAuthStateChange: () => ({ data: { subscription: { unsubscribe: () => undefined } } }),
  };
}

describe("App single sign-on", () => {
  function renderSso(auth: SupabaseAuthProvider) {
    const fetch = routedFetch({});
    const api = createApiClient({ baseUrl: "/api", auth, fetch });
    render(<App auth={auth} api={api} onSsoSignIn={(value) => auth.startSignIn(value)} />);
    return fetch;
  }

  it("asks for a work email and explains a domain without single sign-on", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const auth = new SupabaseAuthProvider(pendingSsoClient(), { redirectTo: "https://console.example.test/", navigate: vi.fn() });
    const fetch = renderSso(auth);

    expect(screen.queryByLabelText("Development access token")).toBeNull();
    fireEvent.change(screen.getByLabelText("Work email"), { target: { value: "person@example.test" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue with single sign-on" }));

    expect((await screen.findByRole("alert")).textContent).toContain("Single sign-on is not set up for that email domain");
    expect(fetch).not.toHaveBeenCalled();
    expect(setItem).not.toHaveBeenCalled();
  });

  it("rejects something that is not an email address", async () => {
    const auth = new SupabaseAuthProvider(pendingSsoClient(), { redirectTo: "https://console.example.test/", navigate: vi.fn() });
    renderSso(auth);
    fireEvent.change(screen.getByLabelText("Work email"), { target: { value: "not an email" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue with single sign-on" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Enter your work email address");
  });

  it("shows progress while a callback is completed, and a fixed message if it failed", () => {
    const auth = new SupabaseAuthProvider(pendingSsoClient(), { redirectTo: "https://console.example.test/", navigate: vi.fn() });
    void auth.completeSignIn({ accessToken: "a.b.c", refreshToken: "r" });
    const fetch = renderSso(auth);
    expect(screen.getByRole("heading", { name: "Signing you in" })).toBeTruthy();
    expect(fetch).not.toHaveBeenCalled();

    auth.failSignIn();
    return waitFor(() => {
      expect(screen.getByRole("alert").textContent).toContain("Single sign-on did not finish");
    });
  });
});

describe("ErrorBoundary", () => {
  it("replaces a crashed subtree with an error notice", () => {
    // React reports caught render errors to console.error; silence it for this test only.
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    function Broken(): never {
      throw new Error("render failure");
    }
    render(
      <ErrorBoundary>
        <Broken />
      </ErrorBoundary>,
    );

    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("This part of the console stopped working");
    expect(alert.textContent).not.toContain("render failure");
    expect(within(alert).getByRole("button", { name: "Reload page" })).toBeTruthy();
  });
});
