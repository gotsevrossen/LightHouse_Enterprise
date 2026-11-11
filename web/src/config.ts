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
