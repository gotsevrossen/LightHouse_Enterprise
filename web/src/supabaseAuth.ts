import { createClient } from "@supabase/supabase-js";
import { isWellFormedToken, type AuthProvider, type AuthState, type SignOutReason } from "./auth.ts";
import type { SupabaseConfig } from "./config.ts";

// Single sign-on with Supabase Auth (SAML through each organisation's identity provider).
//
// Security decisions:
// - Sessions live in memory only. The client is created with `persistSession: false` and
//   no storage, so nothing is written to localStorage, sessionStorage, IndexedDB or a
//   cookie. A reload signs the person out; signing in again through single sign-on is quick.
// - The client never reads the URL itself (`detectSessionInUrl: false`). The callback is
//   parsed by ssoCallback.ts, which accepts only the expected parameters and has the URL
//   cleaned before the session is used.
// - The console talks to Supabase for sign-in only. Data comes from our API, which checks
//   the access token on every request; the publishable key grants nothing by itself.

/**
 * The part of the Supabase Auth client the console uses. Declared narrowly so tests can
 * stand in for it, and so a reader can see every call the console makes to Supabase.
 */
export interface SsoAuthClient {
  signInWithSSO(params: {
    domain: string;
    options: { redirectTo: string; skipBrowserRedirect: boolean };
  }): Promise<{ data: { url: string } | null; error: { code?: string | undefined } | null }>;
  setSession(session: {
    access_token: string;
    refresh_token: string;
  }): Promise<{ data: { session: { access_token: string } | null }; error: unknown }>;
  getSession(): Promise<{ data: { session: { access_token: string } | null }; error: unknown }>;
  signOut(options: { scope: "local" }): Promise<{ error: unknown }>;
  onAuthStateChange(callback: (event: string, session: { access_token: string } | null) => void): {
    data: { subscription: { unsubscribe(): void } };
  };
}

export function createSupabaseAuthClient(config: SupabaseConfig): SsoAuthClient {
  const client = createClient(config.url, config.publishableKey, {
    auth: {
      // The implicit flow returns the session in the URL fragment. PKCE would need its code
      // verifier to survive the redirect in web storage, which the console does not use.
      flowType: "implicit",
      persistSession: false,
      autoRefreshToken: true,
      detectSessionInUrl: false,
    },
  });
  return client.auth;
}

export type SsoStartResult =
  | { readonly kind: "redirecting" }
  | { readonly kind: "invalid_domain" }
  | { readonly kind: "no_provider" }
  | { readonly kind: "failed" };

// A DNS name: labels of letters, digits and inner hyphens, a dot-separated TLD of letters
// (or punycode). Matched after lower-casing.
const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

/** Takes a work email address or a bare domain; returns the lower-cased domain or null. */
export function ssoDomainFrom(input: string): string | null {
  const trimmed = input.trim().toLowerCase();
  const at = trimmed.lastIndexOf("@");
  const domain = at === -1 ? trimmed : trimmed.slice(at + 1);
  return DOMAIN_PATTERN.test(domain) ? domain : null;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

// The identity provider's address comes back from Supabase. Only a real web address is
// followed, never javascript:, data: or anything else a navigation would execute.
function isNavigableSignInUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname));
  } catch {
    return false;
  }
}

interface SupabaseAuthProviderOptions {
  /** Where the identity provider sends the person back to: the console's own address. */
  readonly redirectTo: string;
  /** Navigates the tab. Defaults to window.location.assign. */
  readonly navigate?: (url: string) => void;
}

const SIGNED_IN: AuthState = { status: "signed_in" };
const SIGNING_IN: AuthState = { status: "signing_in" };

export class SupabaseAuthProvider implements AuthProvider {
  readonly #client: SsoAuthClient;
  readonly #redirectTo: string;
  readonly #navigate: (url: string) => void;
  #state: AuthState = { status: "signed_out", reason: null };
  readonly #listeners = new Set<() => void>();

  constructor(client: SsoAuthClient, options: SupabaseAuthProviderOptions) {
    this.#client = client;
    this.#redirectTo = options.redirectTo;
    this.#navigate =
      options.navigate ??
      ((url: string) => {
        window.location.assign(url);
      });
    // Supabase reports a session that ended on its side (for example, a refresh token that
    // was revoked). Sign-in itself is driven by completeSignIn, never by this event alone.
    this.#client.onAuthStateChange((event, session) => {
      if (event === "SIGNED_OUT" || (event === "TOKEN_REFRESHED" && session === null)) {
        if (this.#state.status === "signed_in") {
          this.#setState({ status: "signed_out", reason: "session_ended" });
        }
      }
    });
  }

  getState(): AuthState {
    return this.#state;
  }

  subscribe(listener: () => void): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  async getAccessToken(): Promise<string | null> {
    if (this.#state.status !== "signed_in") {
      return null;
    }
    let token: string | undefined;
    try {
      // Returns the in-memory session, refreshing it first if it has expired.
      const { data } = await this.#client.getSession();
      token = data.session?.access_token;
    } catch {
      return null;
    }
    return token !== undefined && isWellFormedToken(token) ? token : null;
  }

  /** Starts single sign-on for the organisation that owns `domain`. */
  async startSignIn(emailOrDomain: string): Promise<SsoStartResult> {
    const domain = ssoDomainFrom(emailOrDomain);
    if (domain === null) {
      return { kind: "invalid_domain" };
    }
    let result: Awaited<ReturnType<SsoAuthClient["signInWithSSO"]>>;
    try {
      result = await this.#client.signInWithSSO({
        domain,
        // The console checks the address before following it, so the library must not
        // navigate on its own.
        options: { redirectTo: this.#redirectTo, skipBrowserRedirect: true },
      });
    } catch {
      return { kind: "failed" };
    }
    if (result.error !== null || result.data === null) {
      return result.error?.code === "sso_provider_not_found" ? { kind: "no_provider" } : { kind: "failed" };
    }
    // The library passes the response body through unchecked, so the type is a hope.
    const url: unknown = result.data.url;
    if (typeof url !== "string" || !isNavigableSignInUrl(url)) {
      return { kind: "failed" };
    }
    this.#navigate(url);
    return { kind: "redirecting" };
  }

  /**
   * Finishes sign-in with the session from a callback URL that ssoCallback.ts has already
   * checked and removed from the address bar. Supabase checks the access token with its
   * server before the session is accepted.
   */
  async completeSignIn(session: { accessToken: string; refreshToken: string }): Promise<void> {
    this.#setState(SIGNING_IN);
    let ok: boolean;
    try {
      const { data, error } = await this.#client.setSession({
        access_token: session.accessToken,
        refresh_token: session.refreshToken,
      });
      ok = error === null && data.session !== null;
    } catch {
      ok = false;
    }
    this.#setState(ok ? SIGNED_IN : { status: "signed_out", reason: "sign_in_failed" });
  }

  /** Records a callback that carried an error or could not be read. */
  failSignIn(): void {
    this.#setState({ status: "signed_out", reason: "sign_in_failed" });
  }

  async signOut(reason: SignOutReason): Promise<void> {
    const wasSignedIn = this.#state.status !== "signed_out";
    // Local state first: the console must leave the signed-in view even if Supabase
    // cannot be reached to revoke the session.
    if (wasSignedIn) {
      this.#setState({ status: "signed_out", reason });
    }
    try {
      // "local" revokes this session's refresh token on the server and clears it here,
      // leaving the person's sessions on other devices alone.
      await this.#client.signOut({ scope: "local" });
    } catch {
      // Nothing more to do: the in-memory session is gone with the state change above.
    }
  }

  #setState(next: AuthState): void {
    this.#state = next;
    for (const listener of this.#listeners) {
      listener();
    }
  }
}
