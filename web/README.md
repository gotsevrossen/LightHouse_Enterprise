# LightHouse Enterprise web console

The browser console for LightHouse Enterprise: React 19, TypeScript (strict), Vite. This is
the Phase 0 scaffold: an app shell, a signed-out screen and the alerts queue. The full
console is built in Phase 2.

The console talks only to the LightHouse API under `/api`. It never calls Claude, never
talks to the database, and holds no secrets. See `CLAUDE.md` at the repository root for the
security rules.

## Commands

Run from this directory. Node `^22.22.2 || ^24.15.0 || >=26` (the lockfile was written by
npm 11 and installs cleanly with npm 10).

```sh
npm ci            # install exactly what package-lock.json says
npm run dev       # dev server on http://127.0.0.1:5173, /api proxied to http://127.0.0.1:8000
npm run lint      # ESLint (typescript-eslint strict, type-checked), zero warnings allowed
npm run build     # tsc -b type-check, then vite build into dist/
npm test          # vitest, runs once and exits
npm run preview   # serve dist/ locally (same /api proxy)
```

The CI check is:

```sh
npm ci && npm run lint && npm run build && npm test
```

## Configuration

Copy `.env.example` to `.env.local` if you need to override anything. Every `VITE_`
variable is compiled into the public bundle, so only public values belong there: the API
base URL, and from Phase 2 the Supabase project URL and publishable key.

| Variable | Default | Notes |
| --- | --- | --- |
| `VITE_API_BASE_URL` | `/api` | A same-origin path, an `https://` URL, or `http://` to localhost only. Anything else stops the console at start-up, because the bearer token is sent to this address. |

## Signing in during development

Until single sign-on lands in Phase 2, development builds (`npm run dev`) show a
"Development access token" field. Paste a token issued by your local API. It is kept in
memory only and is gone when the tab is closed or reloaded. Production builds do not show
this field.

Auth sits behind the `AuthProvider` interface in `src/auth.ts`. Phase 2 adds a Supabase
Auth implementation of the same interface; nothing else needs to change. Tokens must never
be written to `localStorage`, `sessionStorage` or a readable cookie (ESLint blocks web
storage).

## Layout

```
src/
  main.tsx                 Entry: reads public config, wires auth and the API client
  App.tsx                  Signed-out screen or the console (shell + alerts queue)
  api.ts                   Typed API client and response validation
  auth.ts                  AuthProvider interface, in-memory dev provider, useAuthState
  config.ts                API base URL validation (the only place env is read)
  styles.css               Design tokens (CSS variables) and all styles
  components/
    AppShell.tsx           Header with product name, tenant, role and sign-out
    SignedOutScreen.tsx    Signed-out screen and the development token form
    AlertsQueue.tsx        Alerts list with loading, empty and error states
    SeverityLabel.tsx      Severity as text, a rank meter and colour
    ErrorBoundary.tsx      Fallback so a render error never leaves a blank page
    errorText.ts           Plain-English error messages
  test/                    Test setup and synthetic fixtures
```

## Known advisories

- **GHSA-g3hv-75wg-m249 (minimatch, moderate, denial of service).** It reaches us only
  through dev-only lint tooling (`eslint` 10, `typescript-eslint` 8.72), which matches our
  own glob patterns and never ships in the bundle. There is no patched minimatch 10.x, and
  ESLint 10 does not support minimatch 11. npm's only fix is downgrading to `eslint` 9.
  Decision: accepted, versions left as they are. Revisit when ESLint supports a patched
  minimatch. `npm audit` reports this one advisory as 10 findings, one per dependent
  package.

## Test tokens

Tests never contain a JWT-shaped string literal, because the secret scanner flags them.
Use `makeJwtShapedToken()` from `src/test/tokens.ts`, which builds an unsigned token at run
time.

## Rules that apply to every change here

- Alert content comes from customer systems and is attacker-controlled. Render it as text
  only: no `dangerouslySetInnerHTML`, no building URLs, HTML, styles or class names from
  it. ESLint enforces the first.
- Validate every API response in `api.ts` before the UI sees it. A bad payload must show
  an error state, not a blank page or a partial list.
- Severity is always shown as a text label, never by colour alone.
- Hiding a control is not access control; the API enforces roles.
- No `console` logging (ESLint enforces it). Never log tokens or customer data.
- Production builds carry a Content-Security-Policy meta tag (see `vite.config.ts`). The
  static host should send the same policy as a header and add `frame-ancestors 'none'`.
