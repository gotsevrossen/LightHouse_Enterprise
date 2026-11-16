import { describe, expect, it } from "vitest";
import { readPublicConfig, resolveApiBaseUrl, resolveSupabaseConfig } from "./config.ts";
import { makeJwtShapedToken } from "./test/tokens.ts";

// Key-shaped values are assembled at run time so the secret scanner never sees a literal.
const PUBLISHABLE = ["sb", "publishable", "test0placeholder0value"].join("_");
const SECRET = ["sb", "secret", "test0placeholder0value0000"].join("_");

describe("resolveApiBaseUrl", () => {
  it("defaults to /api on the same origin", () => {
    expect(resolveApiBaseUrl(undefined)).toBe("/api");
    expect(resolveApiBaseUrl("  ")).toBe("/api");
  });

  it("accepts paths and strips trailing slashes", () => {
    expect(resolveApiBaseUrl("/api/")).toBe("/api");
    expect(resolveApiBaseUrl("/v1/api")).toBe("/v1/api");
    // "/" must not become "//me", which a browser treats as the host "me".
    expect(resolveApiBaseUrl("/")).toBe("");
  });

  it("accepts https and loopback http", () => {
    expect(resolveApiBaseUrl("https://api.example.test/api/")).toBe("https://api.example.test/api");
    expect(resolveApiBaseUrl("http://127.0.0.1:8000/api")).toBe("http://127.0.0.1:8000/api");
    expect(resolveApiBaseUrl("http://localhost:8000")).toBe("http://localhost:8000");
  });

  it.each([
    ["protocol-relative URL", "//evil.example.test/api"],
    ["backslash trick", "/\\evil.example.test"],
    ["plain http to a remote host", "http://api.example.test/api"],
    ["javascript URL", "javascript:alert(1)"],
    ["embedded credentials", "https://user:pass@api.example.test/api"],
    ["query string", "https://api.example.test/api?x=1"],
    ["not a URL", "api.example.test"],
  ])("rejects a %s", (_label, value) => {
    expect(() => resolveApiBaseUrl(value)).toThrow();
  });
});

describe("resolveSupabaseConfig", () => {
  it("is off when neither value is set", () => {
    expect(resolveSupabaseConfig(undefined, undefined)).toBeNull();
    expect(resolveSupabaseConfig(" ", "")).toBeNull();
  });

  it("accepts an https project origin and a publishable key", () => {
    expect(resolveSupabaseConfig("https://abc123.supabase.co/", ` ${PUBLISHABLE} `)).toEqual({
      url: "https://abc123.supabase.co",
      publishableKey: PUBLISHABLE,
    });
    expect(resolveSupabaseConfig("http://127.0.0.1:54321", PUBLISHABLE)?.url).toBe("http://127.0.0.1:54321");
  });

  it("refuses half a configuration", () => {
    expect(() => resolveSupabaseConfig("https://abc123.supabase.co", undefined)).toThrow();
    expect(() => resolveSupabaseConfig(undefined, PUBLISHABLE)).toThrow();
  });

  it.each([
    ["plain http to a remote host", "http://abc123.supabase.co"],
    ["a path", "https://abc123.supabase.co/auth/v1"],
    ["a query", "https://abc123.supabase.co/?x=1"],
    ["credentials", "https://user:pass@abc123.supabase.co"],
    ["a javascript URL", "javascript:alert(1)"],
    ["not a URL", "abc123.supabase.co"],
  ])("refuses a URL with %s", (_label, url) => {
    expect(() => resolveSupabaseConfig(url, PUBLISHABLE)).toThrow();
  });

  it("refuses a secret key, with a message saying so", () => {
    expect(() => resolveSupabaseConfig("https://abc123.supabase.co", SECRET)).toThrow(/secret key/);
  });

  it("refuses a legacy JWT key, which could be the service_role key", () => {
    const legacy = makeJwtShapedToken({ role: "service_role" });
    expect(() => resolveSupabaseConfig("https://abc123.supabase.co", legacy)).toThrow();
  });

  it("refuses anything else in the key", () => {
    expect(() => resolveSupabaseConfig("https://abc123.supabase.co", "sb_publishable_has space")).toThrow();
    expect(() => resolveSupabaseConfig("https://abc123.supabase.co", "anything")).toThrow();
  });
});

describe("readPublicConfig", () => {
  it("reads the three public values", () => {
    expect(
      readPublicConfig({
        VITE_API_BASE_URL: "/api/",
        VITE_SUPABASE_URL: "https://abc123.supabase.co",
        VITE_SUPABASE_PUBLISHABLE_KEY: PUBLISHABLE,
      } as ImportMetaEnv),
    ).toEqual({ apiBaseUrl: "/api", supabase: { url: "https://abc123.supabase.co", publishableKey: PUBLISHABLE } });
  });

  it("throws for a bad value, so the console stops at start-up", () => {
    expect(() =>
      readPublicConfig({ VITE_SUPABASE_URL: "https://abc123.supabase.co", VITE_SUPABASE_PUBLISHABLE_KEY: SECRET } as ImportMetaEnv),
    ).toThrow();
  });
});
