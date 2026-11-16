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

type Route = (url: URL, init: RequestInit | undefined) => Response | Promise<Response>;

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
  return vi.fn<typeof fetch>((input, init) => {
    const url = new URL(inputToString(input), "http://console.test");
    const route = routes[url.pathname];
    if (route === undefined) {
      return Promise.reject(new Error(`Unexpected request to ${url.pathname}`));
    }
    return Promise.resolve(route(url, init));
  });
}

/** A request's body as text (the client always sends JSON strings). */
export function bodyText(init: RequestInit | undefined): string {
  return typeof init?.body === "string" ? init.body : "";
}

export function headerOf(init: RequestInit | undefined, name: string): string | null {
  return new Headers(init?.headers).get(name);
}

/** The fields `GET /api/alerts/{id}` adds for everyone. */
export function makeAlertDetail(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ...makeAlert(),
    source_alert_id: "src-0001",
    updated_at: "2026-11-01T09:35:00Z",
    category: "Initial access",
    occurred_at: "2026-11-01T09:28:00Z",
    confidence: 0.85,
    review_reason: null,
    triaged_at: "2026-11-01T09:31:00Z",
    ...overrides,
  };
}

/** The analyst shape: the viewer shape plus evidence and reasoning. */
export function makeAnalystDetail(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return makeAlertDetail({
    evidence: { user_principal: "user@example.test", country: "Elsewhere", sign_in_count: 3, mfa: false, ip_addresses: ["192.0.2.10", "192.0.2.11"], device: null },
    reasoning: "The sign-in came from a country this user has not used before.",
    ...overrides,
  });
}

/** A stream that delivers `chunks` (strings are UTF-8 encoded) and then closes. */
export function streamOf(chunks: readonly (string | Uint8Array)[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let index = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      const chunk = chunks[index];
      index += 1;
      if (chunk === undefined) {
        controller.close();
        return;
      }
      controller.enqueue(typeof chunk === "string" ? encoder.encode(chunk) : chunk);
    },
  });
}

/** NDJSON text for a list of events, one per line. */
export function ndjson(events: readonly unknown[]): string {
  return events.map((event) => `${JSON.stringify(event)}\n`).join("");
}

export function ndjsonResponse(body: ReadableStream<Uint8Array> | string, status = 200): Response {
  return new Response(typeof body === "string" ? streamOf([body]) : body, {
    status,
    headers: { "Content-Type": "application/x-ndjson" },
  });
}
