import type { AuthProvider } from "./auth.ts";

// Typed client for our own API. The console talks to nothing else: not Claude, not the
// database. Every response is checked against the shapes below before the UI sees it, so a
// corrupt or unexpected payload becomes an error state instead of a crash or, worse, a
// half-rendered queue that looks complete.

export const ROLES = ["viewer", "analyst", "responder", "admin"] as const;
export type Role = (typeof ROLES)[number];

export const SEVERITIES = ["info", "low", "medium", "high", "critical", "unknown"] as const;
export type Severity = (typeof SEVERITIES)[number];

export interface Me {
  readonly user_id: string;
  readonly tenant_id: string;
  readonly role: Role;
}

/**
 * One alert as the API returns it. Every string field except `id` and `created_at`
 * originates in a customer system and is attacker-controlled: render it as text only.
 */
export interface Alert {
  readonly id: string;
  readonly source: string;
  readonly title: string;
  readonly severity: Severity;
  readonly source_severity: Severity;
  readonly status: string;
  readonly summary: string | null;
  readonly recommended_action: string | null;
  readonly needs_human_review: boolean;
  readonly created_at: string;
}

export const ALERT_STATUSES = ["new", "triaged", "investigating", "resolved", "dismissed"] as const;
export type AlertStatus = (typeof ALERT_STATUSES)[number];

export function isAlertStatus(value: unknown): value is AlertStatus {
  return isOneOf(ALERT_STATUSES, value);
}

/** One evidence value: what the connectors produce (flat scalars or a short list of strings). */
export type EvidenceValue = string | number | boolean | null | readonly string[];

/**
 * Evidence as an ordered list of entries, not an object. Keys come from the response, and
 * copying a key such as "__proto__" onto a plain object would change its prototype instead
 * of adding a property.
 */
export interface EvidenceEntry {
  readonly key: string;
  readonly value: EvidenceValue;
}

/** Only present for analyst and above; the API leaves both fields out for viewers. */
export interface AnalystDetail {
  readonly evidence: readonly EvidenceEntry[];
  readonly reasoning: string | null;
}

/**
 * `GET /api/alerts/{id}`. `category`, `review_reason` and everything in `analyst` are
 * attacker-controlled (evidence) or model output about attacker-controlled text
 * (reasoning). Render as text only.
 */
export interface AlertDetail extends Alert {
  readonly category: string | null;
  readonly occurred_at: string | null;
  readonly confidence: number | null;
  readonly review_reason: string | null;
  readonly triaged_at: string | null;
  readonly analyst: AnalystDetail | null;
}

export interface ChatStatus {
  readonly available: boolean;
}

export const CHAT_MAX_QUESTION_LENGTH = 2_000;
export const CHAT_MAX_HISTORY_MESSAGES = 10;
export const CHAT_MAX_HISTORY_CONTENT_LENGTH = 4_000;

export interface ChatMessage {
  readonly role: "user" | "assistant";
  readonly content: string;
}

export interface ChatRequest {
  readonly question: string;
  readonly alertId: string | null;
  readonly history: readonly ChatMessage[];
}

export const CHAT_SERVER_ERROR_CODES = [
  "budget_exceeded",
  "rate_limited",
  "declined",
  "unavailable",
  "too_long",
  "internal",
] as const;
export type ChatServerErrorCode = (typeof CHAT_SERVER_ERROR_CODES)[number];
/** Server codes, plus "protocol" (the stream broke the format) and "network". */
export type ChatErrorCode = ChatServerErrorCode | "protocol" | "network";

export type ChatOutcome = { readonly kind: "done" } | { readonly kind: "error"; readonly code: ChatErrorCode };

export interface AlertPage {
  readonly items: readonly Alert[];
  readonly next_cursor: string | null;
}

export interface ListAlertsParams {
  readonly limit?: number;
  readonly cursor?: string | null;
}

export interface ApiClient {
  getMe(signal?: AbortSignal): Promise<Me>;
  listAlerts(params?: ListAlertsParams, signal?: AbortSignal): Promise<AlertPage>;
  getAlert(id: string, signal?: AbortSignal): Promise<AlertDetail>;
  updateAlertStatus(id: string, status: AlertStatus, signal?: AbortSignal): Promise<AlertDetail>;
  getChatStatus(signal?: AbortSignal): Promise<ChatStatus>;
  /**
   * Asks a question and streams the answer. `onDelta` receives each piece of answer text in
   * order. Resolves with how the answer ended; a broken stream resolves as an error outcome
   * rather than rejecting. Rejects with ApiError for auth failures before the stream
   * starts, and with the abort reason when `signal` aborts.
   */
  streamChat(request: ChatRequest, onDelta: (text: string) => void, signal?: AbortSignal): Promise<ChatOutcome>;
}

export type ApiErrorKind =
  | "signed_out"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "http"
  | "network"
  | "invalid_response";

// Fixed messages only. Errors never carry the token, the URL with its query, or any part of
// the response body.
const ERROR_MESSAGES: Record<ApiErrorKind, string> = {
  signed_out: "Not signed in.",
  unauthorized: "The session is no longer valid.",
  forbidden: "This account is not allowed to do that.",
  not_found: "The API could not find that item.",
  http: "The API returned an error.",
  network: "The API could not be reached.",
  invalid_response: "The API returned a response in an unexpected format.",
};

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | null;

  constructor(kind: ApiErrorKind, status: number | null = null) {
    super(ERROR_MESSAGES[kind]);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
  }
}

export const MAX_ALERTS_LIMIT = 200;
const MAX_CURSOR_LENGTH = 2_048;

export interface ApiClientOptions {
  /** Already checked by resolveApiBaseUrl: "" (site root), a path, or an https origin. */
  readonly baseUrl: string;
  readonly auth: AuthProvider;
  readonly fetch?: typeof fetch;
}

// Alert ids are server-issued UUIDs. Anything else is refused before it reaches a URL path:
// in particular "." and "..", which the URL parser would resolve to another API route.
const ALERT_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

function alertPath(id: string): `/${string}` {
  if (!ALERT_ID_PATTERN.test(id)) {
    throw new RangeError("Not a valid alert id.");
  }
  return `/alerts/${encodeURIComponent(id)}`;
}

type Method = "GET" | "PATCH" | "POST";

export function createApiClient(options: ApiClientOptions): ApiClient {
  const { baseUrl, auth } = options;
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);

  /** Sends one request and maps auth and HTTP failures. Returns only a 2xx response. */
  async function send(
    method: Method,
    path: `/${string}`,
    query: URLSearchParams | null,
    body: unknown,
    accept: string,
    signal: AbortSignal | undefined,
    passStatuses: readonly number[] = [],
  ): Promise<Response> {
    const token = await auth.getAccessToken();
    if (token === null) {
      throw new ApiError("signed_out");
    }

    const search = query?.toString() ?? "";
    const url = search === "" ? `${baseUrl}${path}` : `${baseUrl}${path}?${search}`;
    const headers: Record<string, string> = { Accept: accept, Authorization: `Bearer ${token}` };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    let response: Response;
    try {
      response = await fetchImpl(url, {
        method,
        headers,
        body: body === undefined ? null : JSON.stringify(body),
        // Auth is the bearer header only; cookies are never sent, so there is no ambient
        // credential for another site to ride on.
        credentials: "omit",
        cache: "no-store",
        // The API never redirects. Refusing redirects keeps requests on the origin we chose.
        redirect: "error",
        signal: signal ?? null,
      });
    } catch (error) {
      if (signal?.aborted === true) {
        throw error;
      }
      throw new ApiError("network");
    }

    if (response.status === 401) {
      // Only end the session that was rejected; a newer sign-in made while this request was
      // in flight is left alone.
      if ((await auth.getAccessToken()) === token) {
        await auth.signOut("session_ended");
      }
      throw new ApiError("unauthorized", 401);
    }
    if (passStatuses.includes(response.status)) {
      return response;
    }
    if (response.status === 403) {
      throw new ApiError("forbidden", 403);
    }
    if (response.status === 404) {
      throw new ApiError("not_found", 404);
    }
    if (!response.ok) {
      throw new ApiError("http", response.status);
    }
    return response;
  }

  async function readJson(response: Response, signal: AbortSignal | undefined): Promise<unknown> {
    try {
      return (await response.json()) as unknown;
    } catch (error) {
      if (signal?.aborted === true) {
        throw error;
      }
      throw new ApiError("invalid_response", response.status);
    }
  }

  async function getJson(
    path: `/${string}`,
    query: URLSearchParams | null,
    signal: AbortSignal | undefined,
  ): Promise<unknown> {
    return readJson(await send("GET", path, query, undefined, "application/json", signal), signal);
  }

  return {
    async getMe(signal) {
      return parseMe(await getJson("/me", null, signal));
    },

    async listAlerts(params = {}, signal) {
      const query = new URLSearchParams();
      if (params.limit !== undefined) {
        if (!Number.isInteger(params.limit) || params.limit < 1 || params.limit > MAX_ALERTS_LIMIT) {
          throw new RangeError(`limit must be an integer from 1 to ${MAX_ALERTS_LIMIT}.`);
        }
        query.set("limit", String(params.limit));
      }
      if (params.cursor !== undefined && params.cursor !== null) {
        if (params.cursor === "" || params.cursor.length > MAX_CURSOR_LENGTH) {
          throw new RangeError("cursor is empty or too long.");
        }
        query.set("cursor", params.cursor);
      }
      return parseAlertPage(await getJson("/alerts", query, signal));
    },

    async getAlert(id, signal) {
      return parseAlertDetail(await getJson(alertPath(id), null, signal));
    },

    async updateAlertStatus(id, status, signal) {
      const path = alertPath(id);
      if (!isOneOf(ALERT_STATUSES, status)) {
        throw new RangeError("Not a valid alert status.");
      }
      const response = await send("PATCH", path, null, { status }, "application/json", signal);
      return parseAlertDetail(await readJson(response, signal));
    },

    async getChatStatus(signal) {
      return parseChatStatus(await getJson("/chat/status", null, signal));
    },

    async streamChat(request, onDelta, signal) {
      const body = buildChatBody(request);
      // Limits applied before the stream starts come back as plain HTTP statuses. They are
      // passed through so the person sees the same message as for an in-stream error.
      const response = await send("POST", "/chat/stream", null, body, "application/x-ndjson", signal, [
        ...Object.keys(CHAT_STATUS_CODES).map(Number),
      ]);
      const preStreamCode = CHAT_STATUS_CODES[response.status];
      if (preStreamCode !== undefined) {
        await response.body?.cancel().catch(() => undefined);
        return { kind: "error", code: preStreamCode };
      }
      const contentType = (response.headers.get("Content-Type") ?? "").split(";")[0]?.trim().toLowerCase();
      if (contentType !== "application/x-ndjson" || response.body === null) {
        await response.body?.cancel().catch(() => undefined);
        return { kind: "error", code: "protocol" };
      }
      return readChatStream(response.body, onDelta, signal);
    },
  };
}

const CHAT_STATUS_CODES: Partial<Record<number, ChatServerErrorCode>> = {
  413: "too_long",
  429: "rate_limited",
  503: "unavailable",
};

/**
 * Builds the request body within the server's limits, so a long conversation degrades to
 * "the oldest turns are forgotten" instead of a rejected request.
 */
export function buildChatBody(request: ChatRequest): {
  question: string;
  alert_id: string | null;
  history: ChatMessage[];
} {
  const question = request.question.trim();
  // String length counts UTF-16 units, which is never fewer than the code points the server
  // counts, so this check is conservative.
  if (question === "" || question.length > CHAT_MAX_QUESTION_LENGTH) {
    throw new RangeError(`The question must be 1 to ${CHAT_MAX_QUESTION_LENGTH} characters.`);
  }
  if (request.alertId !== null && !ALERT_ID_PATTERN.test(request.alertId)) {
    throw new RangeError("Not a valid alert id.");
  }
  let history = request.history
    .filter((message) => message.content.trim() !== "")
    .map((message) => ({
      role: message.role,
      content: truncateUnits(message.content, CHAT_MAX_HISTORY_CONTENT_LENGTH),
    }));
  history = history.slice(Math.max(0, history.length - CHAT_MAX_HISTORY_MESSAGES));
  // Never start the history with an answer whose question was cut off.
  if (history[0]?.role === "assistant") {
    history = history.slice(1);
  }
  return { question, alert_id: request.alertId, history };
}

// Cuts to at most `max` UTF-16 units without splitting a surrogate pair, which would make
// the request body invalid UTF-8.
function truncateUnits(value: string, max: number): string {
  if (value.length <= max) return value;
  let end = max;
  const last = value.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  return value.slice(0, end);
}

// ---------------------------------------------------------------------------------------
// The chat stream. One JSON object per line: start, then deltas, then one terminal event.
// The body is untrusted input like any response, and a stream can also stop half-way. Every
// way it can go wrong ends in an error outcome with a fixed message, never a thrown parse
// error and never a half-answer that looks complete.

/** Longest single line accepted. Deltas are small; a huge line is a broken or hostile stream. */
export const CHAT_MAX_LINE_LENGTH = 16_384;
/** Longest answer accepted, in characters. */
export const CHAT_MAX_ANSWER_LENGTH = 32_000;

const CHAT_EVENT_TYPES = new Set(["start", "delta", "done", "error"]);

export async function readChatStream(
  body: ReadableStream<Uint8Array>,
  onDelta: (text: string) => void,
  signal?: AbortSignal,
): Promise<ChatOutcome> {
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let buffer = "";
  let started = false;
  let answerLength = 0;

  const stop = async (outcome: ChatOutcome): Promise<ChatOutcome> => {
    await reader.cancel().catch(() => undefined);
    return outcome;
  };

  const onAbort = () => {
    void reader.cancel().catch(() => undefined);
  };
  signal?.addEventListener("abort", onAbort, { once: true });

  // Handles one complete line. Returns an outcome to stop, or null to keep reading.
  const handleLine = (rawLine: string): ChatOutcome | null => {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (line.trim() === "") return null;
    let event: unknown;
    try {
      event = JSON.parse(line);
    } catch {
      return { kind: "error", code: "protocol" };
    }
    if (!isRecord(event) || typeof event.type !== "string" || !CHAT_EVENT_TYPES.has(event.type)) {
      return { kind: "error", code: "protocol" };
    }
    if (!started) {
      if (event.type !== "start") return { kind: "error", code: "protocol" };
      started = true;
      return null;
    }
    switch (event.type) {
      case "start":
        return { kind: "error", code: "protocol" };
      case "delta": {
        if (typeof event.text !== "string") return { kind: "error", code: "protocol" };
        answerLength += event.text.length;
        if (answerLength > CHAT_MAX_ANSWER_LENGTH) return { kind: "error", code: "protocol" };
        if (event.text !== "") onDelta(event.text);
        return null;
      }
      case "done":
        return { kind: "done" };
      default: {
        const code = event.code;
        return { kind: "error", code: isOneOf(CHAT_SERVER_ERROR_CODES, code) ? code : "internal" };
      }
    }
  };

  try {
    for (;;) {
      if (isAborted(signal)) {
        await reader.cancel().catch(() => undefined);
        throw abortReason(signal);
      }
      let chunk: ReadableStreamReadResult<Uint8Array>;
      try {
        chunk = await reader.read();
      } catch {
        if (isAborted(signal)) throw abortReason(signal);
        return await stop({ kind: "error", code: "network" });
      }
      if (isAborted(signal)) {
        await reader.cancel().catch(() => undefined);
        throw abortReason(signal);
      }
      if (chunk.done) {
        let tail: string;
        try {
          tail = buffer + decoder.decode();
        } catch {
          return { kind: "error", code: "protocol" };
        }
        // A final line without a newline still counts; a stream that ends without a
        // terminal event is incomplete, whatever came before it.
        const outcome = handleLine(tail);
        return outcome ?? { kind: "error", code: "protocol" };
      }
      try {
        buffer += decoder.decode(chunk.value, { stream: true });
      } catch {
        return await stop({ kind: "error", code: "protocol" });
      }
      let newline = buffer.indexOf("\n");
      while (newline !== -1) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (line.length > CHAT_MAX_LINE_LENGTH) return await stop({ kind: "error", code: "protocol" });
        const outcome = handleLine(line);
        if (outcome !== null) return await stop(outcome);
        newline = buffer.indexOf("\n");
      }
      if (buffer.length > CHAT_MAX_LINE_LENGTH) {
        return await stop({ kind: "error", code: "protocol" });
      }
    }
  } finally {
    signal?.removeEventListener("abort", onAbort);
  }
}

// A function, not an inline check: the flag changes while awaits are pending, which inline
// narrowing would not account for.
function isAborted(signal: AbortSignal | undefined): signal is AbortSignal {
  return signal?.aborted === true;
}

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException("Aborted", "AbortError");
}

// ---------------------------------------------------------------------------------------
// Response validation. Each parser copies only the known fields into a fresh object, so
// unexpected extra properties never reach the UI.

function invalid(): never {
  throw new ApiError("invalid_response");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isStringOrNull(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isOneOf<T extends string>(allowed: readonly T[], value: unknown): value is T {
  return typeof value === "string" && (allowed as readonly string[]).includes(value);
}

function isTimestamp(value: unknown): value is string {
  return isNonEmptyString(value) && !Number.isNaN(Date.parse(value));
}

export function parseMe(value: unknown): Me {
  if (!isRecord(value)) invalid();
  const { user_id, tenant_id, role } = value;
  if (!isNonEmptyString(user_id) || !isNonEmptyString(tenant_id) || !isOneOf(ROLES, role)) {
    invalid();
  }
  return { user_id, tenant_id, role };
}

export function parseAlert(value: unknown): Alert {
  if (!isRecord(value)) invalid();
  const {
    id,
    source,
    title,
    severity,
    source_severity,
    status,
    summary,
    recommended_action,
    needs_human_review,
    created_at,
  } = value;
  if (
    !isNonEmptyString(id) ||
    typeof source !== "string" ||
    typeof title !== "string" ||
    !isOneOf(SEVERITIES, severity) ||
    !isOneOf(SEVERITIES, source_severity) ||
    typeof status !== "string" ||
    !isStringOrNull(summary) ||
    !isStringOrNull(recommended_action) ||
    typeof needs_human_review !== "boolean" ||
    !isTimestamp(created_at)
  ) {
    invalid();
  }
  return {
    id,
    source,
    title,
    severity,
    source_severity,
    status,
    summary,
    recommended_action,
    needs_human_review,
    created_at,
  };
}

export function parseAlertPage(value: unknown): AlertPage {
  if (!isRecord(value)) invalid();
  const { items, next_cursor } = value;
  if (!Array.isArray(items) || !(next_cursor === null || isNonEmptyString(next_cursor))) {
    invalid();
  }
  // One malformed alert fails the whole page: a queue silently missing an item is worse
  // than a visible error.
  return { items: items.map(parseAlert), next_cursor };
}

function isNullableTimestamp(value: unknown): value is string | null {
  return value === null || isTimestamp(value);
}

function parseEvidenceValue(value: unknown): EvidenceValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalid();
    return value;
  }
  if (Array.isArray(value)) {
    if (!value.every((item): item is string => typeof item === "string")) invalid();
    return [...value];
  }
  return invalid();
}

function parseEvidence(value: unknown): EvidenceEntry[] {
  if (!isRecord(value)) invalid();
  return Object.keys(value).map((key) => ({ key, value: parseEvidenceValue(value[key]) }));
}

export function parseAlertDetail(value: unknown): AlertDetail {
  const base = parseAlert(value);
  if (!isRecord(value)) invalid();
  const { category, occurred_at, confidence, review_reason, triaged_at } = value;
  if (
    !isStringOrNull(category) ||
    !isNullableTimestamp(occurred_at) ||
    !(confidence === null || (typeof confidence === "number" && confidence >= 0 && confidence <= 1)) ||
    !isStringOrNull(review_reason) ||
    !isNullableTimestamp(triaged_at)
  ) {
    invalid();
  }

  // The API sends both analyst fields or neither (viewers). One without the other is a
  // response the console does not understand, not a partial view to guess at.
  const hasEvidence = Object.hasOwn(value, "evidence");
  const hasReasoning = Object.hasOwn(value, "reasoning");
  let analyst: AnalystDetail | null = null;
  if (hasEvidence || hasReasoning) {
    if (!hasEvidence || !hasReasoning || !isStringOrNull(value.reasoning)) invalid();
    analyst = { evidence: parseEvidence(value.evidence), reasoning: value.reasoning };
  }

  return { ...base, category, occurred_at, confidence, review_reason, triaged_at, analyst };
}

export function parseChatStatus(value: unknown): ChatStatus {
  if (!isRecord(value) || typeof value.available !== "boolean") invalid();
  return { available: value.available };
}
