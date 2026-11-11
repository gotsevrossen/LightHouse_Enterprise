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
}

export type ApiErrorKind =
  | "signed_out"
  | "unauthorized"
  | "forbidden"
  | "http"
  | "network"
  | "invalid_response";

// Fixed messages only. Errors never carry the token, the URL with its query, or any part of
// the response body.
const ERROR_MESSAGES: Record<ApiErrorKind, string> = {
  signed_out: "Not signed in.",
  unauthorized: "The session is no longer valid.",
  forbidden: "This account is not allowed to do that.",
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

export function createApiClient(options: ApiClientOptions): ApiClient {
  const { baseUrl, auth } = options;
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);

  async function getJson(
    path: `/${string}`,
    query: URLSearchParams | null,
    signal: AbortSignal | undefined,
  ): Promise<unknown> {
    const token = await auth.getAccessToken();
    if (token === null) {
      throw new ApiError("signed_out");
    }

    const search = query?.toString() ?? "";
    const url = search === "" ? `${baseUrl}${path}` : `${baseUrl}${path}?${search}`;

    let response: Response;
    try {
      response = await fetchImpl(url, {
        method: "GET",
        headers: { Accept: "application/json", Authorization: `Bearer ${token}` },
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
    if (response.status === 403) {
      throw new ApiError("forbidden", 403);
    }
    if (!response.ok) {
      throw new ApiError("http", response.status);
    }

    try {
      return (await response.json()) as unknown;
    } catch (error) {
      if (signal?.aborted === true) {
        throw error;
      }
      throw new ApiError("invalid_response", response.status);
    }
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
  };
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
