import { describe, expect, it, vi } from "vitest";
import { ApiError, createApiClient, parseAlertPage, parseMe } from "./api.ts";
import { MemoryAuthProvider } from "./auth.ts";
import {
  headerOf,
  jsonResponse,
  makeAlert,
  requestedUrls,
  routedFetch,
  signedInAuth,
  TEST_TENANT_ID,
  TEST_TOKEN,
  TEST_USER_ID,
} from "./test/fixtures.ts";

const ME = { user_id: TEST_USER_ID, tenant_id: TEST_TENANT_ID, role: "analyst" };

async function expectApiError(promise: Promise<unknown>, kind: ApiError["kind"]): Promise<ApiError> {
  const error: unknown = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(ApiError);
  expect((error as ApiError).kind).toBe(kind);
  return error as ApiError;
}

describe("createApiClient", () => {
  it("attaches the bearer token and calls only our API", async () => {
    const fetch = routedFetch({ "/api/me": () => jsonResponse(ME) });
    const api = createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch });

    await expect(api.getMe()).resolves.toEqual(ME);

    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(url).toBe("/api/me");
    expect(headerOf(init, "Authorization")).toBe(`Bearer ${TEST_TOKEN}`);
    expect(init?.credentials).toBe("omit");
    expect(init?.redirect).toBe("error");
  });

  it("does not send a request when signed out", async () => {
    const fetch = routedFetch({ "/api/me": () => jsonResponse(ME) });
    const api = createApiClient({ baseUrl: "/api", auth: new MemoryAuthProvider(), fetch });

    await expectApiError(api.getMe(), "signed_out");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("signs the user out on 401", async () => {
    const auth = signedInAuth();
    const api = createApiClient({
      baseUrl: "/api",
      auth,
      fetch: routedFetch({ "/api/me": () => jsonResponse({ detail: "expired" }, 401) }),
    });

    await expectApiError(api.getMe(), "unauthorized");
    expect(auth.getState()).toEqual({ status: "signed_out", reason: "session_ended" });
    await expect(auth.getAccessToken()).resolves.toBeNull();
  });

  it("does not end a newer session when an older request gets 401", async () => {
    const auth = signedInAuth();
    const api = createApiClient({
      baseUrl: "/api",
      auth,
      fetch: routedFetch({
        "/api/me": () => {
          // The user signs in again while the old request is in flight.
          auth.signInWithToken("newer-token");
          return jsonResponse({}, 401);
        },
      }),
    });

    await expectApiError(api.getMe(), "unauthorized");
    expect(auth.getState().status).toBe("signed_in");
    await expect(auth.getAccessToken()).resolves.toBe("newer-token");
  });

  it("maps 403, server errors and network failures to typed errors", async () => {
    const auth = signedInAuth();
    const forbidden = createApiClient({ baseUrl: "/api", auth, fetch: routedFetch({ "/api/me": () => jsonResponse({}, 403) }) });
    await expectApiError(forbidden.getMe(), "forbidden");

    const broken = createApiClient({ baseUrl: "/api", auth, fetch: routedFetch({ "/api/me": () => jsonResponse({}, 503) }) });
    const httpError = await expectApiError(broken.getMe(), "http");
    expect(httpError.status).toBe(503);

    const offline = createApiClient({
      baseUrl: "/api",
      auth,
      fetch: vi.fn<typeof fetch>(() => Promise.reject(new TypeError("Failed to fetch"))),
    });
    await expectApiError(offline.getMe(), "network");
    expect(auth.getState().status).toBe("signed_in");
  });

  it("treats a body that is not JSON as an invalid response", async () => {
    const api = createApiClient({
      baseUrl: "/api",
      auth: signedInAuth(),
      fetch: routedFetch({ "/api/me": () => new Response("<html>proxy error</html>", { status: 200 }) }),
    });
    await expectApiError(api.getMe(), "invalid_response");
  });

  it("never puts the token in an error message", async () => {
    const api = createApiClient({
      baseUrl: "/api",
      auth: signedInAuth(),
      fetch: routedFetch({ "/api/me": () => jsonResponse({ role: "root" }) }),
    });
    const error = await expectApiError(api.getMe(), "invalid_response");
    expect(error.message).not.toContain(TEST_TOKEN);
    expect(String(error)).not.toContain(TEST_TOKEN);
  });

  it("encodes limit and cursor as query parameters", async () => {
    const fetch = routedFetch({ "/api/alerts": () => jsonResponse({ items: [], next_cursor: null }) });
    const api = createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch });

    await api.listAlerts({ limit: 25, cursor: "abc&role=admin" });

    const parsed = new URL(requestedUrls(fetch)[0] ?? "", "http://console.test");
    expect(parsed.pathname).toBe("/api/alerts");
    expect(parsed.searchParams.get("limit")).toBe("25");
    expect(parsed.searchParams.get("cursor")).toBe("abc&role=admin");
    expect(parsed.searchParams.has("role")).toBe(false);
  });

  it("rejects an out-of-range limit before sending anything", async () => {
    const fetch = routedFetch({});
    const api = createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch });
    await expect(api.listAlerts({ limit: 0 })).rejects.toBeInstanceOf(RangeError);
    await expect(api.listAlerts({ limit: 1.5 })).rejects.toBeInstanceOf(RangeError);
    await expect(api.listAlerts({ limit: 201 })).rejects.toBeInstanceOf(RangeError);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("parseMe", () => {
  it("accepts every server role", () => {
    for (const role of ["viewer", "analyst", "responder", "admin"]) {
      expect(parseMe({ ...ME, role }).role).toBe(role);
    }
  });

  it.each([
    ["null", null],
    ["an array", [ME]],
    ["an unknown role", { ...ME, role: "owner" }],
    ["a missing tenant", { user_id: TEST_USER_ID, role: "admin" }],
    ["an empty user id", { ...ME, user_id: "" }],
    ["a numeric tenant", { ...ME, tenant_id: 42 }],
  ])("rejects %s", (_label, body) => {
    expect(() => parseMe(body)).toThrow(ApiError);
  });

  it("drops unexpected extra fields", () => {
    expect(parseMe({ ...ME, is_superuser: true })).toEqual(ME);
  });
});

describe("parseAlertPage", () => {
  it("accepts a valid page", () => {
    const page = parseAlertPage({ items: [makeAlert()], next_cursor: "next" });
    expect(page.items).toHaveLength(1);
    expect(page.next_cursor).toBe("next");
  });

  it("accepts null summary and recommended action", () => {
    const page = parseAlertPage({
      items: [makeAlert({ summary: null, recommended_action: null })],
      next_cursor: null,
    });
    expect(page.items[0]?.summary).toBeNull();
  });

  it.each([
    ["items that is not an array", { items: "nope", next_cursor: null }],
    ["a missing cursor", { items: [] }],
    ["an empty-string cursor", { items: [], next_cursor: "" }],
    ["an unknown severity", { items: [makeAlert({ severity: "severe" })], next_cursor: null }],
    ["an unknown source severity", { items: [makeAlert({ source_severity: 3 })], next_cursor: null }],
    ["a missing title", { items: [makeAlert({ title: undefined })], next_cursor: null }],
    ["a non-boolean review flag", { items: [makeAlert({ needs_human_review: "false" })], next_cursor: null }],
    ["an unparseable date", { items: [makeAlert({ created_at: "yesterday-ish" })], next_cursor: null }],
    ["an alert that is null", { items: [null], next_cursor: null }],
  ])("rejects %s", (_label, body) => {
    expect(() => parseAlertPage(body)).toThrow(ApiError);
  });
});
