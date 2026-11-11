import { describe, expect, it, vi } from "vitest";
import { isWellFormedToken, MAX_TOKEN_LENGTH, MemoryAuthProvider } from "./auth.ts";
import { TEST_TOKEN } from "./test/fixtures.ts";
import { makeJwtShapedToken } from "./test/tokens.ts";

describe("MemoryAuthProvider", () => {
  it("starts signed out with no token", async () => {
    const auth = new MemoryAuthProvider();
    expect(auth.getState()).toEqual({ status: "signed_out", reason: null });
    await expect(auth.getAccessToken()).resolves.toBeNull();
  });

  it("signs in, notifies listeners and signs out", async () => {
    const auth = new MemoryAuthProvider();
    const listener = vi.fn();
    const unsubscribe = auth.subscribe(listener);

    auth.signInWithToken(`  ${TEST_TOKEN}  `);
    expect(auth.getState().status).toBe("signed_in");
    await expect(auth.getAccessToken()).resolves.toBe(TEST_TOKEN);

    await auth.signOut("user");
    expect(auth.getState()).toEqual({ status: "signed_out", reason: "user" });
    await expect(auth.getAccessToken()).resolves.toBeNull();
    expect(listener).toHaveBeenCalledTimes(2);

    unsubscribe();
    auth.signInWithToken(TEST_TOKEN);
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it("returns a stable state object between changes", () => {
    const auth = new MemoryAuthProvider();
    expect(auth.getState()).toBe(auth.getState());
  });

  it("rejects malformed tokens and stays signed out", () => {
    const auth = new MemoryAuthProvider();
    expect(() => {
      auth.signInWithToken("");
    }).toThrow();
    expect(() => {
      auth.signInWithToken("abc\r\nX-Injected: 1");
    }).toThrow();
    expect(auth.getState().status).toBe("signed_out");
  });

  it("does not touch web storage", () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const auth = new MemoryAuthProvider();
    auth.signInWithToken(TEST_TOKEN);
    expect(setItem).not.toHaveBeenCalled();
    // eslint-disable-next-line no-restricted-syntax -- reading only, to prove nothing was stored
    expect(window.localStorage.length + window.sessionStorage.length).toBe(0);
  });
});

describe("isWellFormedToken", () => {
  it("accepts JWT-shaped tokens", () => {
    const token = makeJwtShapedToken();
    expect(token.split(".")).toHaveLength(3);
    expect(isWellFormedToken(token)).toBe(true);
  });

  it("rejects whitespace, control characters and oversized values", () => {
    expect(isWellFormedToken("has space")).toBe(false);
    expect(isWellFormedToken("line\nbreak")).toBe(false);
    expect(isWellFormedToken("a".repeat(MAX_TOKEN_LENGTH + 1))).toBe(false);
  });
});
