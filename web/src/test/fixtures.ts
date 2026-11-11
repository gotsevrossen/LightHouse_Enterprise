// Synthetic test data only. No real tenant ids, users or customer alerts.
import { vi, type Mock } from "vitest";
import type { Alert } from "../api.ts";
import { MemoryAuthProvider } from "../auth.ts";

export const TEST_TOKEN = "test-token.abc123";
export const TEST_TENANT_ID = "00000000-0000-4000-8000-00000000000a";
export const TEST_USER_ID = "00000000-0000-4000-8000-0000000000b1";

export function makeAlert(overrides: Partial<Record<keyof Alert, unknown>> = {}): Record<string, unknown> {
  return {
    id: "alert-1",
    source: "Example XDR",
    title: "Suspicious sign-in from an unfamiliar location",
    severity: "high",
    source_severity: "medium",
    status: "new",
    summary: "A user signed in from a country they have not used before.",
    recommended_action: "Confirm with the user that the sign-in was theirs.",
    needs_human_review: false,
    created_at: "2026-11-01T09:30:00Z",
    ...overrides,
  };
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export function signedInAuth(): MemoryAuthProvider {
  const auth = new MemoryAuthProvider();
  auth.signInWithToken(TEST_TOKEN);
  return auth;
}

type Route = (url: URL) => Response | Promise<Response>;

function inputToString(input: RequestInfo | URL): string {
  return typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
}

/** The URL string passed to each call of a fetch mock, in order. */
export function requestedUrls(fetchMock: Mock<typeof fetch>): string[] {
  return fetchMock.mock.calls.map(([input]) => inputToString(input));
}

/**
 * A fetch stand-in that routes by pathname. Unknown paths fail the test loudly instead of
 * silently returning something.
 */
export function routedFetch(routes: Record<string, Route>) {
  return vi.fn<typeof fetch>((input) => {
    const url = new URL(inputToString(input), "http://console.test");
    const route = routes[url.pathname];
    if (route === undefined) {
      return Promise.reject(new Error(`Unexpected request to ${url.pathname}`));
    }
    return Promise.resolve(route(url));
  });
}

export function headerOf(init: RequestInit | undefined, name: string): string | null {
  return new Headers(init?.headers).get(name);
}
