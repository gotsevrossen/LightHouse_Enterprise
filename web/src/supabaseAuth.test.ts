import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { createApiClient } from "./api.ts";
import { createSupabaseAuthClient, ssoDomainFrom, SupabaseAuthProvider, type SsoAuthClient } from "./supabaseAuth.ts";
import { bodyText, headerOf, jsonResponse } from "./test/fixtures.ts";
import { makeJwtShapedToken } from "./test/tokens.ts";

const REDIRECT = "https://console.example.test/";
const SUPABASE = { url: "https://project.example.test", publishableKey: "sb_publishable_test-placeholder-key" };

function freshToken(sub = "test-user"): string {
  return makeJwtShapedToken({ sub, exp: Math.floor(Date.now() / 1000) + 3600, aud: "authenticated" });
}

type Listener = (event: string, session: { access_token: string } | null) => void;

/** A stand-in for the Supabase Auth client. Mocks are separate values so tests can assert on them. */
function fakeClient(overrides: Partial<SsoAuthClient> = {}) {
  const state: { session: { access_token: string } | null; listener: Listener | null } = { session: null, listener: null };
  const signInWithSSO = vi.fn<SsoAuthClient["signInWithSSO"]>(() =>
    Promise.resolve({ data: { url: "https://idp.example.test/saml/start" }, error: null }),
  );
  const setSession = vi.fn<SsoAuthClient["setSession"]>((session) => {
    state.session = { access_token: session.access_token };
    return Promise.resolve({ data: { session: state.session }, error: null });
  });
  const signOut = vi.fn<SsoAuthClient["signOut"]>(() => {
    state.session = null;
    return Promise.resolve({ error: null });
  });
  const client: SsoAuthClient = {
    signInWithSSO,
    setSession,
    getSession: () => Promise.resolve({ data: { session: state.session }, error: null }),
    signOut,
    onAuthStateChange: (callback) => {
      state.listener = callback;
      return { data: { subscription: { unsubscribe: () => undefined } } };
    },
    ...overrides,
  };
  return {
    client,
    state,
    signInWithSSO,
    setSession,
    signOut,
    emit: (event: string, session: { access_token: string } | null) => {
      state.listener?.(event, session);
    },
  };
}

describe("ssoDomainFrom", () => {
  it("takes the domain from an email address or a bare domain", () => {
    expect(ssoDomainFrom("  Person@Example.TEST ")).toBe("example.test");
    expect(ssoDomainFrom("corp.example.test")).toBe("corp.example.test");
    expect(ssoDomainFrom("a@b@corp.example.test")).toBe("corp.example.test");
  });

  it.each(["", "person", "person@", "@localhost", "exa mple.test", "example.test/path", "-bad.example.test", "javascript:alert(1)"])(
    "rejects %j",
    (value) => {
      expect(ssoDomainFrom(value)).toBeNull();
    },
  );
});

describe("SupabaseAuthProvider", () => {
  it("starts single sign-on for the email's domain and follows only the returned https address", async () => {
    const fake = fakeClient();
    const navigate = vi.fn();
    const auth = new SupabaseAuthProvider(fake.client, { redirectTo: REDIRECT, navigate });

    await expect(auth.startSignIn("person@Example.test")).resolves.toEqual({ kind: "redirecting" });

    expect(fake.signInWithSSO).toHaveBeenCalledWith({
      domain: "example.test",
      options: { redirectTo: REDIRECT, skipBrowserRedirect: true },
    });
    expect(navigate).toHaveBeenCalledWith("https://idp.example.test/saml/start");
  });

  it.each(["javascript:alert(1)", "data:text/html,<script>1</script>", "http://idp.example.test/", "not a url"])(
    "refuses to navigate to %j",
    async (url) => {
      const navigate = vi.fn();
      const auth = new SupabaseAuthProvider(
        fakeClient({ signInWithSSO: () => Promise.resolve({ data: { url }, error: null }) }).client,
        { redirectTo: REDIRECT, navigate },
      );
      await expect(auth.startSignIn("person@example.test")).resolves.toEqual({ kind: "failed" });
      expect(navigate).not.toHaveBeenCalled();
    },
  );

  it("reports a domain without single sign-on, an invalid domain and a failure separately", async () => {
    const noProvider = new SupabaseAuthProvider(
      fakeClient({ signInWithSSO: () => Promise.resolve({ data: null, error: { code: "sso_provider_not_found" } }) }).client,
      { redirectTo: REDIRECT, navigate: vi.fn() },
    );
    await expect(noProvider.startSignIn("person@example.test")).resolves.toEqual({ kind: "no_provider" });

    const fake = fakeClient();
    const auth = new SupabaseAuthProvider(fake.client, { redirectTo: REDIRECT, navigate: vi.fn() });
    await expect(auth.startSignIn("not an email")).resolves.toEqual({ kind: "invalid_domain" });
    expect(fake.signInWithSSO).not.toHaveBeenCalled();

    const throwing = new SupabaseAuthProvider(
      fakeClient({ signInWithSSO: () => Promise.reject(new TypeError("offline")) }).client,
      { redirectTo: REDIRECT, navigate: vi.fn() },
    );
    await expect(throwing.startSignIn("person@example.test")).resolves.toEqual({ kind: "failed" });
  });

  it("completes sign-in from a checked callback and hands out the access token", async () => {
    const fake = fakeClient();
    const auth = new SupabaseAuthProvider(fake.client, { redirectTo: REDIRECT, navigate: vi.fn() });
    const states: string[] = [];
    auth.subscribe(() => states.push(auth.getState().status));
    const token = freshToken();

    await expect(auth.getAccessToken()).resolves.toBeNull();
    await auth.completeSignIn({ accessToken: token, refreshToken: "refresh-1" });

    expect(states).toEqual(["signing_in", "signed_in"]);
    expect(fake.setSession).toHaveBeenCalledWith({ access_token: token, refresh_token: "refresh-1" });
    await expect(auth.getAccessToken()).resolves.toBe(token);
  });

  it("ends signed out with a reason when Supabase rejects the session", async () => {
    const auth = new SupabaseAuthProvider(
      fakeClient({ setSession: () => Promise.resolve({ data: { session: null }, error: new Error("invalid JWT") }) }).client,
      { redirectTo: REDIRECT, navigate: vi.fn() },
    );
    await auth.completeSignIn({ accessToken: freshToken(), refreshToken: "refresh-1" });
    expect(auth.getState()).toEqual({ status: "signed_out", reason: "sign_in_failed" });
    await expect(auth.getAccessToken()).resolves.toBeNull();
  });

  it("signs out locally first, then revokes this session only", async () => {
    const fake = fakeClient();
    const auth = new SupabaseAuthProvider(fake.client, { redirectTo: REDIRECT, navigate: vi.fn() });
    await auth.completeSignIn({ accessToken: freshToken(), refreshToken: "refresh-1" });

    await auth.signOut("user");

    expect(auth.getState()).toEqual({ status: "signed_out", reason: "user" });
    expect(fake.signOut).toHaveBeenCalledWith({ scope: "local" });
    await expect(auth.getAccessToken()).resolves.toBeNull();
  });

  it("still leaves the console when revoking fails", async () => {
    const fake = fakeClient({ signOut: () => Promise.reject(new TypeError("offline")) });
    const auth = new SupabaseAuthProvider(fake.client, { redirectTo: REDIRECT, navigate: vi.fn() });
    await auth.completeSignIn({ accessToken: freshToken(), refreshToken: "refresh-1" });
    await auth.signOut("session_ended");
    expect(auth.getState()).toEqual({ status: "signed_out", reason: "session_ended" });
  });

  it("follows Supabase when it ends the session, but never signs in on an event alone", async () => {
    const fake = fakeClient();
    const auth = new SupabaseAuthProvider(fake.client, { redirectTo: REDIRECT, navigate: vi.fn() });

    fake.emit("SIGNED_IN", { access_token: freshToken() });
    expect(auth.getState().status).toBe("signed_out");

    await auth.completeSignIn({ accessToken: freshToken(), refreshToken: "refresh-1" });
    fake.emit("SIGNED_OUT", null);
    expect(auth.getState()).toEqual({ status: "signed_out", reason: "session_ended" });
  });

  it("does not hand out a malformed token", async () => {
    const fake = fakeClient();
    const auth = new SupabaseAuthProvider(fake.client, { redirectTo: REDIRECT, navigate: vi.fn() });
    await auth.completeSignIn({ accessToken: freshToken(), refreshToken: "refresh-1" });
    fake.state.session = { access_token: "bad token\r\nX-Injected: 1" };
    await expect(auth.getAccessToken()).resolves.toBeNull();
  });
});

describe("the real Supabase client, as the console configures it", () => {
  let fetchMock: Mock<typeof fetch>;
  const user = {
    id: "00000000-0000-4000-8000-0000000000b1",
    aud: "authenticated",
    role: "authenticated",
    email: "person@example.test",
    app_metadata: {},
    user_metadata: {},
    created_at: "2026-11-01T00:00:00Z",
  };

  beforeEach(() => {
    fetchMock = vi.fn<typeof fetch>((input) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/auth/v1/user") return Promise.resolve(jsonResponse(user));
      if (url.pathname === "/auth/v1/logout") return Promise.resolve(new Response(null, { status: 204 }));
      if (url.pathname === "/auth/v1/sso") return Promise.resolve(jsonResponse({ url: "https://idp.example.test/saml/start" }));
      return Promise.reject(new Error(`Unexpected request to ${url.pathname}`));
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  function requestTo(path: string): [string, RequestInit | undefined] | undefined {
    for (const [input, init] of fetchMock.mock.calls) {
      const url = input instanceof Request ? input.url : String(input);
      if (new URL(url).pathname === path) return [url, init];
    }
    return undefined;
  }

  it("keeps the session in memory only and never touches web storage or cookies", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const getItem = vi.spyOn(Storage.prototype, "getItem");
    const auth = new SupabaseAuthProvider(createSupabaseAuthClient(SUPABASE), { redirectTo: REDIRECT, navigate: vi.fn() });
    const token = freshToken();

    await auth.completeSignIn({ accessToken: token, refreshToken: "refresh-1" });
    expect(auth.getState().status).toBe("signed_in");
    await expect(auth.getAccessToken()).resolves.toBe(token);

    // The session was checked with Supabase, with the token in a header, never the URL.
    const [userUrl, userInit] = requestTo("/auth/v1/user") ?? [];
    expect(userUrl).toBeDefined();
    expect(userUrl).not.toContain(token);
    expect(headerOf(userInit, "Authorization")).toBe(`Bearer ${token}`);

    await auth.signOut("user");
    const [logoutUrl] = requestTo("/auth/v1/logout") ?? [];
    expect(new URL(logoutUrl ?? "http://x.test").searchParams.get("scope")).toBe("local");
    await expect(auth.getAccessToken()).resolves.toBeNull();

    expect(setItem).not.toHaveBeenCalled();
    expect(getItem).not.toHaveBeenCalled();
    // eslint-disable-next-line no-restricted-syntax -- reading only, to prove nothing was stored
    expect(window.localStorage.length + window.sessionStorage.length).toBe(0);
    expect(document.cookie).toBe("");
  });

  it("starts single sign-on without a PKCE verifier and without navigating by itself", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const navigate = vi.fn();
    // jsdom does not allow spying on location.assign; an unchanged address shows the
    // library did not navigate on its own.
    const before = window.location.href;
    const auth = new SupabaseAuthProvider(createSupabaseAuthClient(SUPABASE), { redirectTo: REDIRECT, navigate });

    await expect(auth.startSignIn("person@example.test")).resolves.toEqual({ kind: "redirecting" });

    const [, init] = requestTo("/auth/v1/sso") ?? [];
    const body = JSON.parse(bodyText(init)) as Record<string, unknown>;
    expect(body.domain).toBe("example.test");
    expect(body.redirect_to).toBe(REDIRECT);
    expect(body.code_challenge ?? null).toBeNull();
    expect(navigate).toHaveBeenCalledWith("https://idp.example.test/saml/start");
    expect(window.location.href).toBe(before);
    expect(setItem).not.toHaveBeenCalled();
  });

  it("does not read a session from the page URL by itself", async () => {
    const token = freshToken();
    window.history.replaceState(null, "", `/#access_token=${token}&refresh_token=r&expires_in=3600&token_type=bearer`);
    try {
      const auth = new SupabaseAuthProvider(createSupabaseAuthClient(SUPABASE), { redirectTo: REDIRECT, navigate: vi.fn() });
      // Give the client's start-up a chance to run.
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(auth.getState().status).toBe("signed_out");
      expect(requestTo("/auth/v1/user")).toBeUndefined();
    } finally {
      window.history.replaceState(null, "", "/");
    }
  });

  it("works as the API client's token source", async () => {
    const auth = new SupabaseAuthProvider(createSupabaseAuthClient(SUPABASE), { redirectTo: REDIRECT, navigate: vi.fn() });
    const token = freshToken();
    await auth.completeSignIn({ accessToken: token, refreshToken: "refresh-1" });
    const apiFetch = vi.fn<typeof fetch>(() =>
      Promise.resolve(jsonResponse({ user_id: user.id, tenant_id: "00000000-0000-4000-8000-00000000000a", role: "viewer" })),
    );
    const api = createApiClient({ baseUrl: "/api", auth, fetch: apiFetch });
    await api.getMe();
    expect(headerOf(apiFetch.mock.calls[0]?.[1], "Authorization")).toBe(`Bearer ${token}`);
  });
});
