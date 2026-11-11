import { useCallback, useSyncExternalStore } from "react";

export type SignOutReason = "user" | "session_ended";

export type AuthState =
  | { readonly status: "signed_in" }
  | { readonly status: "signed_out"; readonly reason: SignOutReason | null };

/**
 * What the console needs from a sign-in system. Phase 2 implements this with Supabase Auth
 * (SAML single sign-on); until then MemoryAuthProvider stands in for development.
 *
 * Implementations must keep tokens in memory only. Never write a token to localStorage,
 * sessionStorage, IndexedDB or a readable cookie: any script injection or shared machine
 * would then be able to lift a session into a security console.
 */
export interface AuthProvider {
  /** Current state. Must return the same object until the state changes. */
  getState(): AuthState;
  /** Calls `listener` after every state change. Returns an unsubscribe function. */
  subscribe(listener: () => void): () => void;
  /** The bearer token for API calls, or null when signed out. */
  getAccessToken(): Promise<string | null>;
  signOut(reason: SignOutReason): Promise<void>;
}

// RFC 6750 b64token. Rejecting anything else also stops header injection through a pasted
// value with line breaks in it.
const TOKEN_PATTERN = /^[A-Za-z0-9\-._~+/]+=*$/;
export const MAX_TOKEN_LENGTH = 16_384;

export function isWellFormedToken(token: string): boolean {
  return token.length > 0 && token.length <= MAX_TOKEN_LENGTH && TOKEN_PATTERN.test(token);
}

const SIGNED_IN: AuthState = { status: "signed_in" };

/**
 * Development-only provider: holds one token in memory and forgets it when the tab closes.
 * The token is one issued by the local development API; this class never creates one.
 */
export class MemoryAuthProvider implements AuthProvider {
  #token: string | null = null;
  #state: AuthState = { status: "signed_out", reason: null };
  readonly #listeners = new Set<() => void>();

  getState(): AuthState {
    return this.#state;
  }

  subscribe(listener: () => void): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  getAccessToken(): Promise<string | null> {
    return Promise.resolve(this.#token);
  }

  /** Throws if the value is not a well-formed bearer token. */
  signInWithToken(raw: string): void {
    const token = raw.trim();
    if (!isWellFormedToken(token)) {
      throw new Error("That is not a valid access token.");
    }
    this.#token = token;
    this.#setState(SIGNED_IN);
  }

  signOut(reason: SignOutReason): Promise<void> {
    this.#token = null;
    if (this.#state.status === "signed_in") {
      this.#setState({ status: "signed_out", reason });
    }
    return Promise.resolve();
  }

  #setState(next: AuthState): void {
    this.#state = next;
    for (const listener of this.#listeners) {
      listener();
    }
  }
}

export function useAuthState(auth: AuthProvider): AuthState {
  const subscribe = useCallback((listener: () => void) => auth.subscribe(listener), [auth]);
  const getSnapshot = useCallback(() => auth.getState(), [auth]);
  return useSyncExternalStore(subscribe, getSnapshot);
}
