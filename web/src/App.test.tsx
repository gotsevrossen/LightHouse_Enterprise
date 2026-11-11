import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { createApiClient } from "./api.ts";
import { App } from "./App.tsx";
import { MemoryAuthProvider } from "./auth.ts";
import { ErrorBoundary } from "./components/ErrorBoundary.tsx";
import {
  jsonResponse,
  makeAlert,
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
    expect(screen.getByText(/single sign-on is not available in this build yet/)).toBeTruthy();
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
    expect(requestedUrls(fetch)).toEqual(["/api/me", "/api/alerts?limit=50"]);
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
