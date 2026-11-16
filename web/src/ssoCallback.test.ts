import { describe, expect, it } from "vitest";
import { readSsoCallback } from "./ssoCallback.ts";
import { makeJwtShapedToken } from "./test/tokens.ts";

const NOW = 1_800_000_000;
const ORIGIN = "https://console.example.test";

function fragment(values: Record<string, string>): string {
  return new URLSearchParams(values).toString();
}

function sessionFragment(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    access_token: makeJwtShapedToken({ sub: "test-user", exp: NOW + 3600 }),
    refresh_token: "r3fresh-T0ken_x",
    expires_in: "3600",
    expires_at: String(NOW + 3600),
    token_type: "bearer",
    ...overrides,
  };
}

describe("readSsoCallback", () => {
  it("leaves an ordinary URL alone", () => {
    expect(readSsoCallback(`${ORIGIN}/`, NOW)).toEqual({ kind: "none" });
    expect(readSsoCallback(`${ORIGIN}/?view=x#section`, NOW)).toEqual({ kind: "none" });
  });

  it("reads a session and cleans the whole fragment from the URL", () => {
    const values = sessionFragment();
    const result = readSsoCallback(`${ORIGIN}/console/#${fragment(values)}`, NOW);
    expect(result).toEqual({
      kind: "session",
      cleanUrl: "/console/",
      accessToken: values.access_token,
      refreshToken: values.refresh_token,
    });
  });

  it("ignores unexpected parameters, and they do not survive in the URL", () => {
    const values = sessionFragment({ provider_token: "upstream-token", next: "https://evil.example.test", type: "sso" });
    const result = readSsoCallback(`${ORIGIN}/?keep=1&error_description=x#${fragment(values)}`, NOW);
    // An error in the query wins: the callback fails closed.
    expect(result.kind).toBe("error");
    expect(result.kind !== "none" && result.cleanUrl).toBe("/?keep=1");

    const ok = readSsoCallback(`${ORIGIN}/?keep=1#${fragment(values)}`, NOW);
    expect(ok.kind).toBe("session");
    expect(ok.kind === "session" && ok.cleanUrl).toBe("/?keep=1");
    expect(JSON.stringify(ok)).not.toContain("upstream-token");
    expect(JSON.stringify(ok)).not.toContain("evil.example.test");
  });

  it("turns a provider error into a fixed failure, without its text", () => {
    const result = readSsoCallback(
      `${ORIGIN}/#${fragment({ error: "access_denied", error_description: "<script>alert(1)</script> Call 555-0100 for help" })}`,
      NOW,
    );
    expect(result).toEqual({ kind: "error", cleanUrl: "/" });
  });

  it("refuses a PKCE code, which this console never asks for", () => {
    expect(readSsoCallback(`${ORIGIN}/?code=abc123`, NOW)).toEqual({ kind: "error", cleanUrl: "/" });
  });

  it.each([
    ["no refresh token", sessionFragment({ refresh_token: "" })],
    ["an access token that is not JWT-shaped", sessionFragment({ access_token: "opaque" })],
    ["an access token with a line break", sessionFragment({ access_token: "a.b.c\r\nX: y" })],
    ["a refresh token with odd characters", sessionFragment({ refresh_token: "abc def" })],
    ["a token type other than bearer", sessionFragment({ token_type: "mac" })],
    ["an expired session", sessionFragment({ expires_at: String(NOW - 1) })],
    ["a non-numeric expiry", sessionFragment({ expires_at: "soon" })],
  ])("refuses %s", (_label, values) => {
    expect(readSsoCallback(`${ORIGIN}/#${fragment(values)}`, NOW).kind).toBe("error");
  });

  it("refuses a missing expiry", () => {
    const values = sessionFragment();
    const without = Object.fromEntries(Object.entries(values).filter(([key]) => !key.startsWith("expires_")));
    expect(readSsoCallback(`${ORIGIN}/#${fragment(without)}`, NOW).kind).toBe("error");
  });

  it("accepts expires_in alone", () => {
    const values = sessionFragment();
    const withoutAt = Object.fromEntries(Object.entries(values).filter(([key]) => key !== "expires_at"));
    expect(readSsoCallback(`${ORIGIN}/#${fragment(withoutAt)}`, NOW).kind).toBe("session");
  });

  it("refuses a repeated token parameter", () => {
    const values = sessionFragment();
    const doubled = `${fragment(values)}&access_token=${makeJwtShapedToken({ sub: "someone-else" })}`;
    expect(readSsoCallback(`${ORIGIN}/#${doubled}`, NOW).kind).toBe("error");
  });
});
