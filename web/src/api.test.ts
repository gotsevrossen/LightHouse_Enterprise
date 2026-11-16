import { describe, expect, it, vi } from "vitest";
import {
  ApiError,
  buildChatBody,
  CHAT_MAX_HISTORY_CONTENT_LENGTH,
  CHAT_MAX_HISTORY_MESSAGES,
  createApiClient,
  parseAlertDetail,
  parseAlertPage,
  parseChatStatus,
  parseMe,
  type ChatMessage,
} from "./api.ts";
import { MemoryAuthProvider } from "./auth.ts";
import {
  bodyText,
  headerOf,
  jsonResponse,
  makeAlert,
  makeAlertDetail,
  makeAnalystDetail,
  ndjson,
  ndjsonResponse,
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

const ALERT_ID = "11111111-2222-4333-8444-555555555555";

describe("parseAlertDetail", () => {
  it("reads the viewer shape, without an analyst section", () => {
    const detail = parseAlertDetail(makeAlertDetail());
    expect(detail.analyst).toBeNull();
    expect(detail.category).toBe("Initial access");
    expect(detail.confidence).toBe(0.85);
    expect(detail.triaged_at).toBe("2026-11-01T09:31:00Z");
  });

  it("reads the analyst shape with evidence entries in order", () => {
    const detail = parseAlertDetail(makeAnalystDetail());
    expect(detail.analyst?.reasoning).toBe("The sign-in came from a country this user has not used before.");
    expect(detail.analyst?.evidence).toEqual([
      { key: "user_principal", value: "user@example.test" },
      { key: "country", value: "Elsewhere" },
      { key: "sign_in_count", value: 3 },
      { key: "mfa", value: false },
      { key: "ip_addresses", value: ["192.0.2.10", "192.0.2.11"] },
      { key: "device", value: null },
    ]);
  });

  it("accepts the nullable triage fields as null, and empty evidence", () => {
    const detail = parseAlertDetail(
      makeAnalystDetail({
        category: null,
        occurred_at: null,
        confidence: null,
        review_reason: "refusal",
        triaged_at: null,
        evidence: {},
        reasoning: null,
      }),
    );
    expect(detail.analyst).toEqual({ evidence: [], reasoning: null });
    expect(detail.review_reason).toBe("refusal");
  });

  it("drops unexpected fields, at the top level and nowhere else", () => {
    const detail = parseAlertDetail({ ...makeAlertDetail(), tenant_id: TEST_TENANT_ID, is_admin: true });
    expect(Object.keys(detail)).not.toContain("tenant_id");
    expect(Object.keys(detail)).not.toContain("is_admin");
    expect(Object.keys(detail)).not.toContain("source_alert_id");
  });

  it("keeps a __proto__ evidence key as data without touching any prototype", () => {
    const body = JSON.parse(
      JSON.stringify(makeAnalystDetail()).replace('"user_principal"', '"__proto__"'),
    ) as unknown;
    const detail = parseAlertDetail(body);
    const entry = detail.analyst?.evidence.find((item) => item.key === "__proto__");
    expect(entry?.value).toBe("user@example.test");
    expect(Object.getPrototypeOf(detail.analyst?.evidence[0])).toBe(Object.prototype);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it.each([
    ["a confidence above 1", makeAlertDetail({ confidence: 1.5 })],
    ["a negative confidence", makeAlertDetail({ confidence: -0.1 })],
    ["a confidence given as text", makeAlertDetail({ confidence: "high" })],
    ["a numeric category", makeAlertDetail({ category: 7 })],
    ["an unparseable occurred_at", makeAlertDetail({ occurred_at: "soon" })],
    ["a numeric review reason", makeAlertDetail({ review_reason: 3 })],
    ["evidence without reasoning", makeAlertDetail({ evidence: {} })],
    ["reasoning without evidence", makeAlertDetail({ reasoning: "x" })],
    ["evidence that is a list", makeAnalystDetail({ evidence: [["k", "v"]] })],
    ["nested evidence", makeAnalystDetail({ evidence: { process: { name: "x" } } })],
    ["an evidence list with a number in it", makeAnalystDetail({ evidence: { ips: ["192.0.2.1", 5] } })],
    ["numeric reasoning", makeAnalystDetail({ reasoning: 42 })],
    ["a missing base field", makeAlertDetail({ needs_human_review: undefined })],
  ])("rejects %s", (_label, body) => {
    expect(() => parseAlertDetail(body)).toThrow(ApiError);
  });
});

describe("parseChatStatus", () => {
  it("reads the flag and nothing else", () => {
    expect(parseChatStatus({ available: true, model: "x" })).toEqual({ available: true });
  });

  it.each([[null], [{}], [{ available: "yes" }]])("rejects %j", (body) => {
    expect(() => parseChatStatus(body)).toThrow(ApiError);
  });
});

describe("alert detail and status requests", () => {
  it("fetches one alert by id", async () => {
    const fetch = routedFetch({ [`/api/alerts/${ALERT_ID}`]: () => jsonResponse(makeAnalystDetail({ id: ALERT_ID })) });
    const api = createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch });
    const detail = await api.getAlert(ALERT_ID);
    expect(detail.id).toBe(ALERT_ID);
    expect(fetch.mock.calls[0]?.[1]?.method).toBe("GET");
  });

  it("refuses ids that would change the request path", async () => {
    const fetch = routedFetch({});
    const api = createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch });
    for (const id of ["..", ".", "a/b", "a?x=1", "", "a#b", "%2e%2e"]) {
      await expect(api.getAlert(id)).rejects.toBeInstanceOf(RangeError);
      await expect(api.updateAlertStatus(id, "resolved")).rejects.toBeInstanceOf(RangeError);
    }
    expect(fetch).not.toHaveBeenCalled();
  });

  it("maps 404 to not_found", async () => {
    const api = createApiClient({
      baseUrl: "/api",
      auth: signedInAuth(),
      fetch: routedFetch({ [`/api/alerts/${ALERT_ID}`]: () => jsonResponse({ detail: "not found" }, 404) }),
    });
    await expectApiError(api.getAlert(ALERT_ID), "not_found");
  });

  it("sends a status change as JSON with PATCH and returns the server's copy", async () => {
    const fetch = routedFetch({
      [`/api/alerts/${ALERT_ID}`]: (_url, init) => {
        const body = JSON.parse(bodyText(init)) as { status: string };
        return jsonResponse(makeAnalystDetail({ id: ALERT_ID, status: body.status }));
      },
    });
    const api = createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch });

    const updated = await api.updateAlertStatus(ALERT_ID, "investigating");

    expect(updated.status).toBe("investigating");
    const init = fetch.mock.calls[0]?.[1];
    expect(init?.method).toBe("PATCH");
    expect(init?.body).toBe(JSON.stringify({ status: "investigating" }));
    expect(headerOf(init, "Content-Type")).toBe("application/json");
    expect(headerOf(init, "Authorization")).toBe(`Bearer ${TEST_TOKEN}`);
    expect(init?.redirect).toBe("error");
    expect(init?.credentials).toBe("omit");
  });

  it("refuses an unknown status before sending", async () => {
    const fetch = routedFetch({});
    const api = createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch });
    await expect(api.updateAlertStatus(ALERT_ID, "deleted" as never)).rejects.toBeInstanceOf(RangeError);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("maps a 403 on a status change to forbidden and keeps the session", async () => {
    const auth = signedInAuth();
    const api = createApiClient({
      baseUrl: "/api",
      auth,
      fetch: routedFetch({ [`/api/alerts/${ALERT_ID}`]: () => jsonResponse({ detail: "forbidden" }, 403) }),
    });
    await expectApiError(api.updateAlertStatus(ALERT_ID, "resolved"), "forbidden");
    expect(auth.getState().status).toBe("signed_in");
  });

  it("rejects a malformed PATCH response", async () => {
    const api = createApiClient({
      baseUrl: "/api",
      auth: signedInAuth(),
      fetch: routedFetch({ [`/api/alerts/${ALERT_ID}`]: () => jsonResponse({ ok: true }) }),
    });
    await expectApiError(api.updateAlertStatus(ALERT_ID, "resolved"), "invalid_response");
  });
});

describe("buildChatBody", () => {
  it("trims the question and passes the alert id", () => {
    expect(buildChatBody({ question: "  Why?  ", alertId: ALERT_ID, history: [] })).toEqual({
      question: "Why?",
      alert_id: ALERT_ID,
      history: [],
    });
  });

  it("rejects an empty or oversized question, and a bad alert id", () => {
    expect(() => buildChatBody({ question: "   ", alertId: null, history: [] })).toThrow(RangeError);
    expect(() => buildChatBody({ question: "q".repeat(2_001), alertId: null, history: [] })).toThrow(RangeError);
    expect(() => buildChatBody({ question: "q", alertId: "../me", history: [] })).toThrow(RangeError);
  });

  it("keeps the newest messages within the server's limits", () => {
    const history: ChatMessage[] = [];
    for (let i = 0; i < 8; i += 1) {
      history.push({ role: "user", content: `question ${String(i)}` });
      history.push({ role: "assistant", content: i === 7 ? "x".repeat(5_000) : `answer ${String(i)}` });
    }
    const body = buildChatBody({ question: "next", alertId: null, history });
    expect(body.history).toHaveLength(CHAT_MAX_HISTORY_MESSAGES);
    expect(body.history[0]).toEqual({ role: "user", content: "question 3" });
    expect(body.history.at(-1)?.content).toHaveLength(CHAT_MAX_HISTORY_CONTENT_LENGTH);
    expect(body.history.every((message) => message.content.length <= CHAT_MAX_HISTORY_CONTENT_LENGTH)).toBe(true);
  });

  it("never starts the history with an answer, and never splits a surrogate pair", () => {
    const history: ChatMessage[] = [
      { role: "assistant", content: "orphan" },
      { role: "user", content: "q" },
      { role: "assistant", content: `${"a".repeat(CHAT_MAX_HISTORY_CONTENT_LENGTH - 1)}😀` },
    ];
    const body = buildChatBody({ question: "next", alertId: null, history });
    expect(body.history[0]?.role).toBe("user");
    const last = body.history.at(-1)?.content ?? "";
    expect(last).toHaveLength(CHAT_MAX_HISTORY_CONTENT_LENGTH - 1);
    // No lone high surrogate left at the end.
    expect(/[\uD800-\uDBFF]$/.test(last)).toBe(false);
  });
});

describe("chat requests", () => {
  it("reads chat status", async () => {
    const fetch = routedFetch({ "/api/chat/status": () => jsonResponse({ available: false }) });
    const api = createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch });
    await expect(api.getChatStatus()).resolves.toEqual({ available: false });
  });

  it("posts the question and streams the answer", async () => {
    const fetch = routedFetch({
      "/api/chat/stream": () =>
        ndjsonResponse(ndjson([{ type: "start" }, { type: "delta", text: "Yes." }, { type: "done" }])),
    });
    const api = createApiClient({ baseUrl: "/api", auth: signedInAuth(), fetch });
    const deltas: string[] = [];

    const outcome = await api.streamChat({ question: "Is this bad?", alertId: ALERT_ID, history: [] }, (text) =>
      deltas.push(text),
    );

    expect(outcome).toEqual({ kind: "done" });
    expect(deltas).toEqual(["Yes."]);
    const init = fetch.mock.calls[0]?.[1];
    expect(init?.method).toBe("POST");
    expect(JSON.parse(bodyText(init))).toEqual({ question: "Is this bad?", alert_id: ALERT_ID, history: [] });
    expect(headerOf(init, "Accept")).toBe("application/x-ndjson");
    expect(init?.redirect).toBe("error");
  });

  it.each([
    [429, "rate_limited"],
    [503, "unavailable"],
    [413, "too_long"],
  ])("turns HTTP %i before the stream into the %s outcome", async (status, code) => {
    const api = createApiClient({
      baseUrl: "/api",
      auth: signedInAuth(),
      fetch: routedFetch({ "/api/chat/stream": () => jsonResponse({ detail: "limit" }, status) }),
    });
    await expect(api.streamChat({ question: "q", alertId: null, history: [] }, () => undefined)).resolves.toEqual({
      kind: "error",
      code,
    });
  });

  it("treats a response that is not NDJSON as a protocol error", async () => {
    const api = createApiClient({
      baseUrl: "/api",
      auth: signedInAuth(),
      fetch: routedFetch({ "/api/chat/stream": () => jsonResponse({ answer: "<b>hi</b>" }) }),
    });
    await expect(api.streamChat({ question: "q", alertId: null, history: [] }, () => undefined)).resolves.toEqual({
      kind: "error",
      code: "protocol",
    });
  });

  it("signs out on 401 and rejects on 403", async () => {
    const auth = signedInAuth();
    const unauthorized = createApiClient({
      baseUrl: "/api",
      auth,
      fetch: routedFetch({ "/api/chat/stream": () => jsonResponse({}, 401) }),
    });
    await expectApiError(unauthorized.streamChat({ question: "q", alertId: null, history: [] }, () => undefined), "unauthorized");
    expect(auth.getState().status).toBe("signed_out");

    const forbidden = createApiClient({
      baseUrl: "/api",
      auth: signedInAuth(),
      fetch: routedFetch({ "/api/chat/stream": () => jsonResponse({}, 403) }),
    });
    await expectApiError(forbidden.streamChat({ question: "q", alertId: null, history: [] }, () => undefined), "forbidden");
  });
});
