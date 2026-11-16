// SECURITY: values read from import.meta.env are compiled into the JavaScript bundle and are
// public. Only public values may be read here: the API base URL, and (from Phase 2) the
// Supabase project URL and Supabase publishable key. Never the Anthropic API key, the
// Supabase secret / service_role key, a database password or a connector credential. The
// console never calls Claude and never talks to the database; it talks only to our API.

const DEFAULT_API_BASE_URL = "/api";
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Normalises and checks the API base URL.
 *
 * The API client attaches the user's bearer token to every request made under this base, so
 * a mistyped or hostile value would send sessions to someone else. Accept only a
 * same-origin path, an https URL, or plain http to a loopback address for development.
 */
export function resolveApiBaseUrl(raw: string | undefined): string {
  const value = (raw ?? "").trim();
  if (value === "") {
    return DEFAULT_API_BASE_URL;
  }

  if (value.startsWith("/")) {
    // "//host" and "/\host" are protocol-relative to browsers and would leave our origin.
    if (value.startsWith("//") || value.includes("\\")) {
      throw new Error("VITE_API_BASE_URL must be a path on this site or an https URL.");
    }
    return stripTrailingSlash(value);
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("VITE_API_BASE_URL is not a valid URL.");
  }

  const secure = url.protocol === "https:";
  const loopback = url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
  if (!secure && !loopback) {
    throw new Error("VITE_API_BASE_URL must use https (plain http only for localhost).");
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    throw new Error("VITE_API_BASE_URL must not contain credentials, a query or a fragment.");
  }
  return stripTrailingSlash(`${url.origin}${url.pathname}`);
}

// Paths are appended as `${base}/me`, so a base of "/" must become "" (never "//me", which a
// browser reads as the host "me").
function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

export interface SupabaseConfig {
  /** The project origin, for example https://<ref>.supabase.co, with no trailing slash. */
  readonly url: string;
  /** The project's publishable key. Public by design; it identifies the project only. */
  readonly publishableKey: string;
}

// Publishable keys look like `sb_publishable_<random>`. Secret keys (`sb_secret_<random>`)
// and the legacy service_role JWT bypass row-level security; one of those in a VITE_
// variable would be published to every visitor, so anything that is not plainly a
// publishable key stops the console at start-up instead of shipping.
const PUBLISHABLE_KEY_PATTERN = /^sb_publishable_[A-Za-z0-9_-]{8,256}$/;

/**
 * Checks the Supabase settings used for single sign-on.
 *
 * Returns null when neither value is set (single sign-on is not configured in this build).
 * Throws when only one is set, or either is not acceptable: a half-configured or mistyped
 * sign-in would otherwise fail in confusing ways, or hand the sign-in flow to another host.
 */
export function resolveSupabaseConfig(rawUrl: string | undefined, rawKey: string | undefined): SupabaseConfig | null {
  const urlValue = (rawUrl ?? "").trim();
  const keyValue = (rawKey ?? "").trim();
  if (urlValue === "" && keyValue === "") {
    return null;
  }
  if (urlValue === "" || keyValue === "") {
    throw new Error("Set both VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY, or neither.");
  }

  let url: URL;
  try {
    url = new URL(urlValue);
  } catch {
    throw new Error("VITE_SUPABASE_URL is not a valid URL.");
  }
  const secure = url.protocol === "https:";
  const loopback = url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
  if (!secure && !loopback) {
    throw new Error("VITE_SUPABASE_URL must use https (plain http only for localhost).");
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "" || url.pathname !== "/") {
    throw new Error("VITE_SUPABASE_URL must be the project origin only, with no path, query or credentials.");
  }

  if (keyValue.startsWith("sb_secret_")) {
    throw new Error("VITE_SUPABASE_PUBLISHABLE_KEY holds a secret key. Never put a secret key in the console.");
  }
  if (!PUBLISHABLE_KEY_PATTERN.test(keyValue)) {
    throw new Error("VITE_SUPABASE_PUBLISHABLE_KEY must be a Supabase publishable key (sb_publishable_…).");
  }
  return { url: url.origin, publishableKey: keyValue };
}

export interface PublicConfig {
  readonly apiBaseUrl: string;
  readonly supabase: SupabaseConfig | null;
}

/**
 * Reads and checks every VITE_ value the console uses. This is the only place in the
 * console that reads them (a test enforces it), so the set of values compiled into the
 * public bundle is visible in one function.
 */
export function readPublicConfig(env: ImportMetaEnv = import.meta.env): PublicConfig {
  return {
    apiBaseUrl: resolveApiBaseUrl(env.VITE_API_BASE_URL),
    supabase: resolveSupabaseConfig(env.VITE_SUPABASE_URL, env.VITE_SUPABASE_PUBLISHABLE_KEY),
  };
}
