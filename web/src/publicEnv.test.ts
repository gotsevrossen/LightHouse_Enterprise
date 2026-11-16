import { describe, expect, it } from "vitest";

// Every VITE_ value is compiled into the public bundle. This test fails if any source file
// reads an environment value other than the three public ones (and Vite's DEV flag), so a
// secret cannot be wired into the console by accident.

const ALLOWED = new Set(["VITE_API_BASE_URL", "VITE_SUPABASE_URL", "VITE_SUPABASE_PUBLISHABLE_KEY"]);
const ALLOWED_BUILT_INS = new Set(["DEV"]);

// Raw source text of every module under src, test files excluded (they may mention names
// in order to test them).
const sources = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}"], {
  query: "?raw",
  import: "default",
  eager: true,
});

describe("public configuration", () => {
  it("finds the source files", () => {
    expect(Object.keys(sources)).toEqual(expect.arrayContaining(["./config.ts", "./main.tsx"]));
  });

  it("reads no VITE_ variable other than the three public ones", () => {
    const found = new Set<string>();
    for (const text of Object.values(sources)) {
      for (const match of text.matchAll(/VITE_[A-Z0-9_]+/g)) {
        found.add(match[0]);
      }
    }
    for (const name of found) {
      expect(ALLOWED.has(name), `${name} is not an allowed public variable`).toBe(true);
    }
  });

  it("reads import.meta.env only for allowed names, and only in config.ts and main.tsx", () => {
    for (const [file, text] of Object.entries(sources)) {
      for (const match of text.matchAll(/import\.meta\.env(?:\.([A-Za-z0-9_]+)|\s*\[|\b)/g)) {
        const name = match[1];
        if (file === "./config.ts" && name === undefined) {
          // readPublicConfig takes the whole env object and reads the allowed names from it.
          continue;
        }
        expect(name === undefined ? `${file}: dynamic access` : file).not.toMatch(/dynamic access/);
        expect(["./config.ts", "./main.tsx"], `${file} reads the environment`).toContain(file);
        expect(ALLOWED.has(name ?? "") || ALLOWED_BUILT_INS.has(name ?? ""), `${file} reads ${name ?? "?"}`).toBe(true);
      }
    }
  });

  it("declares only the public variables in env.d.ts", () => {
    const declared = [...(sources["./env.d.ts"] ?? "").matchAll(/readonly (VITE_[A-Z0-9_]+)/g)].map((match) => match[1]);
    expect(new Set(declared)).toEqual(ALLOWED);
  });
});
