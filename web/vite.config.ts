import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

// The development API runs as one local process. The console only ever calls our own API
// under /api; in production that is the same origin, in development Vite forwards it here.
const DEV_API_TARGET = "http://127.0.0.1:8000";

const apiProxy = {
  "/api": { target: DEV_API_TARGET, changeOrigin: false },
};

/**
 * Adds a Content-Security-Policy meta tag to the production index.html.
 *
 * Alert text comes from customer systems and is attacker-controlled. React already renders
 * it as text; this policy is the second layer, so that if markup ever slips through it
 * cannot load or run script from anywhere. Only applied to builds because the dev server
 * injects inline scripts for hot reload. The static host should also send the same policy
 * as a header, plus `frame-ancestors 'none'`, which a meta tag cannot carry.
 */
function contentSecurityPolicy(): Plugin {
  let connectSrc = "'self'";
  return {
    name: "lighthouse-csp",
    apply: "build",
    configResolved(config) {
      // src/config.ts validates this value fully at runtime; here we only need its origin.
      const raw: unknown = config.env.VITE_API_BASE_URL;
      const origin = typeof raw === "string" ? /^(https?:\/\/[^/?#\s]+)/i.exec(raw.trim())?.[1] : undefined;
      if (origin !== undefined) {
        connectSrc = `'self' ${origin.toLowerCase()}`;
      }
    },
    transformIndexHtml() {
      const policy = [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self'",
        "font-src 'self'",
        `connect-src ${connectSrc}`,
        "manifest-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "object-src 'none'",
      ].join("; ");
      return [
        {
          tag: "meta",
          attrs: { "http-equiv": "Content-Security-Policy", content: policy },
          injectTo: "head-prepend",
        },
      ];
    },
  };
}

export default defineConfig({
  plugins: [react(), contentSecurityPolicy()],
  server: {
    host: "127.0.0.1",
    strictPort: true,
    proxy: apiProxy,
  },
  preview: {
    host: "127.0.0.1",
    strictPort: true,
    proxy: apiProxy,
  },
  build: {
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test/setup.ts"],
    restoreMocks: true,
    unstubGlobals: true,
  },
});
