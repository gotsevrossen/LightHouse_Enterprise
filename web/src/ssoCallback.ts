import { isWellFormedToken } from "./auth.ts";

// Reads the single sign-on redirect that Supabase Auth sends back to the console.
//
// The console uses the implicit flow: after the identity provider signs the person in,
// Supabase redirects to the console with the session in the URL fragment
// (`#access_token=…&refresh_token=…&expires_at=…&token_type=bearer`). The fragment never
// reaches a server or a Referer header. The PKCE flow would need its code verifier to
// survive the redirect in web storage, which the console does not use (see auth.ts).
//
// Threats handled here:
// - tokens lingering in the address bar or history: the caller replaces the URL with the
//   cleaned one before anything else runs, so Back cannot bring the tokens back;
// - crafted callback URLs: only the expected parameters are read, each is checked, and a
//   repeated parameter or an expired session is refused rather than guessed at;
// - provider error text: `error_description` comes from outside and is never shown; the
//   person sees one fixed message.
//
// Not handled here, and worth knowing: someone who holds a valid session for this
// Supabase project could send a person a link carrying that session, signing them in as
// the sender (login CSRF). Without storage there is nowhere to keep a "this tab started a
// sign-in" marker across the redirect. The console shows the tenant and role in the header
// so a person can see whose console they are in.

/** Fragment parameters that mark the URL as a sign-in callback. */
const FRAGMENT_MARKERS = ["access_token", "refresh_token", "error", "error_code", "error_description"] as const;
/** Query parameters an auth redirect may carry. Removed from the URL; never used. */
const QUERY_AUTH_KEYS = ["code", "error", "error_code", "error_description"] as const;

// Supabase refresh tokens are short opaque strings. Generous bound, strict alphabet.
const REFRESH_TOKEN_PATTERN = /^[A-Za-z0-9_-]{1,1024}$/;
const DIGITS = /^\d{1,12}$/;

export type SsoCallback =
  | { readonly kind: "none" }
  | { readonly kind: "error"; readonly cleanUrl: string }
  | { readonly kind: "session"; readonly cleanUrl: string; readonly accessToken: string; readonly refreshToken: string };

const SESSION_KEYS = ["access_token", "refresh_token", "token_type", "expires_at", "expires_in"] as const;

/**
 * Inspects `href`. Returns `none` when it is not a sign-in callback (the URL is left
 * alone); otherwise the URL to replace it with and either the session or an error.
 */
export function readSsoCallback(href: string, nowSeconds: number = Date.now() / 1000): SsoCallback {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return { kind: "none" };
  }
  const fragment = new URLSearchParams(url.hash.startsWith("#") ? url.hash.slice(1) : url.hash);
  const query = url.searchParams;
  const isCallback =
    FRAGMENT_MARKERS.some((key) => fragment.has(key)) || QUERY_AUTH_KEYS.some((key) => query.has(key));
  if (!isCallback) {
    return { kind: "none" };
  }

  // A PKCE code is never expected (the console uses the implicit flow), so it is treated
  // like an error rather than exchanged.
  const reportedError =
    ["error", "error_code", "error_description"].some((key) => fragment.has(key) || query.has(key)) ||
    query.has("code");

  // The whole fragment goes, along with any auth parameters in the query. Other query
  // parameters are kept (the console has none of its own today).
  for (const key of QUERY_AUTH_KEYS) query.delete(key);
  const search = query.toString();
  const cleanUrl = `${url.pathname}${search === "" ? "" : `?${search}`}`;
  const failed: SsoCallback = { kind: "error", cleanUrl };

  if (reportedError) {
    return failed;
  }

  // A repeated parameter is ambiguous (which one would the library use?), so it is refused.
  if (SESSION_KEYS.some((key) => fragment.getAll(key).length > 1)) {
    return failed;
  }
  const accessToken = fragment.get("access_token");
  const refreshToken = fragment.get("refresh_token");
  const tokenType = fragment.get("token_type");
  const expiresAt = fragment.get("expires_at");
  const expiresIn = fragment.get("expires_in");

  if (
    accessToken === null ||
    !isWellFormedToken(accessToken) ||
    accessToken.split(".").length !== 3 ||
    refreshToken === null ||
    !REFRESH_TOKEN_PATTERN.test(refreshToken) ||
    tokenType?.toLowerCase() !== "bearer"
  ) {
    return failed;
  }

  // An expired session in the URL is stale (an old link, or history). Supabase would
  // quietly use the refresh token to revive it; the console refuses instead.
  if (expiresAt !== null) {
    if (!DIGITS.test(expiresAt) || Number(expiresAt) <= nowSeconds) return failed;
  } else if (expiresIn === null || !DIGITS.test(expiresIn) || Number(expiresIn) <= 0) {
    return failed;
  }

  return { kind: "session", cleanUrl, accessToken, refreshToken };
}
