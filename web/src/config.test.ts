import { describe, expect, it } from "vitest";
import { resolveApiBaseUrl } from "./config.ts";

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
