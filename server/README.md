# LightHouse Enterprise server

FastAPI control plane: authentication, tenant-scoped reads of alerts, the audit log,
(Phase 1) alert ingestion with Claude triage, and (Phase 2) alert status changes and the
streamed "Ask LightHouse" chat.

## Commands

Run from `server/`. Python 3.12 and [uv](https://docs.astral.sh/uv/) are required.

```sh
uv sync --frozen                 # install exactly what uv.lock pins (dev tools included)
uv run ruff check .              # lint
uv run ruff format --check .     # formatting
uv run pyright                   # type check (strict)
uv run pytest                    # tests, against a real PostgreSQL 16
```

All in one line, as CI runs it (CI also runs `uv lock --check` first):

```sh
uv sync --frozen && uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest
```

### Test database

The tests need a real PostgreSQL 16 and apply every file in `../supabase/migrations/` in
order. Either:

- set `LH_TEST_DATABASE_URL` to a **superuser** URL of an empty, throwaway server (CI uses
  a `postgres:16` service container). The suite creates its own database, the
  `lh_api_test` login role and, if missing, the Supabase API roles `anon`,
  `authenticated` and `service_role`, then drops the database at the end; or
- leave it unset and have the PostgreSQL 16 server binaries installed
  (`/usr/lib/postgresql/16/bin` by default, override with `LH_TEST_PG_BIN`). The suite
  starts a private cluster on a unix socket in a temp directory and removes it afterwards.
  When run as root it starts Postgres as the `postgres` OS user.

Tests need no network and no keys: JWT signing keys are generated at run time and the
triage tests use the fixture model.

### Run locally

```sh
LH_DATABASE_URL=... LH_JWT_ISSUER=https://<project-ref>.supabase.co/auth/v1 \
LH_JWT_JWKS_URL=https://<project-ref>.supabase.co/auth/v1/.well-known/jwks.json \
uv run uvicorn --factory lighthouse.main:create_app --port 8000
```

### Container

```sh
docker build -t lighthouse-server .
docker run --rm -p 8000:8000 -e LH_DATABASE_URL -e LH_JWT_ISSUER -e LH_JWT_JWKS_URL lighthouse-server
```

The image holds no configuration or secrets; everything arrives as runtime environment
variables from the hosting platform's secret store. It runs as an unprivileged user.

## Configuration

All settings are environment variables with the `LH_` prefix (`src/lighthouse/config.py`).
No `.env` file is read.

| Variable | Required | Meaning |
| --- | --- | --- |
| `LH_DATABASE_URL` | yes | Postgres URL. **Secret** (contains the password). See "Database roles". |
| `LH_JWT_ISSUER` | yes | Expected `iss` of Supabase Auth tokens, e.g. `https://<ref>.supabase.co/auth/v1`. |
| `LH_JWT_AUDIENCE` | no | Expected `aud`. Default `authenticated`. |
| `LH_JWT_JWKS_URL` | one of | HTTPS JWKS endpoint of Supabase Auth (asymmetric signing keys). |
| `LH_JWT_PUBLIC_KEY` | one of | A PEM public key (EC P-256 or RSA >= 2048) instead of JWKS. |
| `LH_JWT_LEEWAY_SECONDS` | no | Clock skew allowed on `exp`/`iat`. Default 30. |
| `LH_DEV` | no | `1` exposes `/docs` and `/openapi.json`. Never on a deployed environment. |
| `LH_DB_POOL_MIN_SIZE`, `LH_DB_POOL_MAX_SIZE` | no | Connection pool bounds (1, 10). |
| `LH_DB_STATEMENT_CACHE_SIZE` | no | Set `0` behind a transaction-mode pooler (Supavisor 6543). |
| `ANTHROPIC_API_KEY` | no | **Secret.** Read by the Anthropic SDK itself, never by our settings. Without it the server starts and serves, and triage stores alerts as needing human review (`model_unavailable`). Separate keys for development and production. |
| `LH_TRIAGE_ENABLED` | no | `false` turns model calls off (`model_disabled`). Default `true`. |
| `LH_TRIAGE_MODEL` | no | Model ID. Default `claude-opus-5-5`. A cheaper model is an owner decision backed by an eval. |
| `LH_TRIAGE_EFFORT` | no | `low`, `medium`, `high`, `xhigh` or `max`. Default `medium`, set explicitly because model defaults differ. |
| `LH_TRIAGE_MAX_TOKENS` | no | Per call, thinking included. Default 16000 (1024-32000). |
| `LH_TRIAGE_TIMEOUT_SECONDS` | no | Per HTTP attempt. Default 120. The SDK retries twice, so one triage can take about 3x this. |
| `LH_TRIAGE_DAILY_TOKEN_BUDGET_PER_TENANT` | no | Tokens (input + output + cache read + cache write) per tenant per UTC day, **triage and chat together**. Default 2000000. `0` means no model calls; there is no unlimited value. |
| `LH_CHAT_ENABLED` | no | `false` turns chat off (`GET /api/chat/status` reports `available: false`). Default `true`. Chat also reports unavailable without an Anthropic credential. |
| `LH_CHAT_MODEL` | no | Model ID for chat. Default `claude-opus-5-5`. |
| `LH_CHAT_EFFORT` | no | `low` ... `max`. Default `low`: chat is interactive (time to first token) and only explains; raising it needs an eval result. |
| `LH_CHAT_MAX_TOKENS` | no | Per answer, thinking included. Default 8000 (1024-32000). A cost ceiling; answers past it end with `too_long`. |
| `LH_CHAT_TIMEOUT_SECONDS` | no | Wall-clock limit for one answer, and the SDK's per-read timeout. Default 90. One SDK retry before the stream starts. |
| `LH_CHAT_REQUESTS_PER_MINUTE_PER_USER` | no | Chat requests per signed-in user per UTC minute, counted in Postgres (holds across replicas). Default 10, at least 1. |

HS256 shared-secret tokens are not accepted: the project must use Supabase's asymmetric
JWT signing keys.

## Triage with Claude

`lighthouse.ai` is the only package that imports the Anthropic SDK; the rest of the server
uses the `TriageModel` interface (`lighthouse/triage.py`), and tests use a fixture model or
a stubbed HTTP transport, so they need no key and make no network calls.

- One request per alert: adaptive thinking, explicit effort, structured output validated
  again in code, server-side refusal fallbacks (`fallbacks: "default"`), and a prompt-cache
  breakpoint on the frozen system prompt. Alert content goes only inside one
  `<untrusted_evidence>` fence in which every angle bracket is escaped.
- Stored severity is never below the source's: in code, in the pipeline SQL, and by the
  `severity >= source_severity` constraint.
- Refusals, cut-off or invalid output, timeouts, rate limits and API errors all store the
  alert as needing human review with a machine-readable `review_reason`; ingestion carries
  on. Outcomes the alert content can provoke are not retried for unchanged content.
- `ingest/pipeline.py` holds no transaction across the model call, skips unchanged alerts
  (content hash), checks the tenant's daily token budget first, and writes one
  `lh.model_usage` row and one audit entry (ids, model, token counts, reason; no alert
  text) per model call.
- The SDK's own `anthropic` logger is pinned to WARNING, because at DEBUG it logs request
  bodies (alert text). `ANTHROPIC_LOG=debug` does not override this.

## Chat with Claude ("Ask LightHouse")

`lighthouse/chat.py` holds the provider-independent `ChatModel` interface;
`lighthouse/ai/chat_model.py` implements it with the SDK's streaming helper
(`client.beta.messages.stream`), and `lighthouse/ai/chat_prompt.py` builds the request.
Fencing and escaping are shared with triage in `lighthouse/ai/fence.py`.

- Everything in the user turn is untrusted and fenced: the alert (`<untrusted_evidence>`),
  the client-supplied history (`<conversation_history>`, one quoted JSON transcript, so
  "assistant" items are never replayed as the model's own turns) and the question
  (`<user_question>`). Nothing from the request reaches the system prompt.
- Alert context only when `alert_id` is given, projected by role: viewers' context has
  title, summary, recommended action, severity, status and category; analyst and above
  also get the evidence and the triage reasoning. Never other alerts, the tenant name or
  the user's identity.
- Before any model call: the per-user rate limit (`lh.chat_rate_limits`, fixed UTC-minute
  windows) and the tenant's daily token budget. No transaction is held while streaming;
  usage (`lh.model_usage`, purpose `chat`) and the `chat.asked` audit entry (alert id,
  model, token counts, outcome; never text) are written after, also when the client
  disconnects mid-answer.
- Adaptive thinking, explicit effort, server-side refusal fallbacks (`fallbacks:
  "default"`), cache breakpoints on the frozen system prompt and on the alert context.
- A refusal after some text has streamed ends with `{"type":"error","code":"declined"}`:
  the console must treat the text shown before it as incomplete. The server never stores
  question or answer text.

## Auth model

- `Authorization: Bearer <Supabase access token>` on every `/api/*` route.
- Tenant and role come only from `app_metadata.tenant_id` and `app_metadata.role`
  (`viewer` < `analyst` < `responder` < `admin`). `user_metadata` is never read, because
  users can edit it. Missing or malformed claims give 401/403, never a default tenant.
- Anonymous Supabase users are refused.
- **Membership check on every request.** After the token is verified, `get_principal`
  reads the caller's row in `lh.memberships` (one query, through `tenant_transaction`, so
  RLS limits it to the token's tenant). No row (removed, or the token names a tenant the
  user does not belong to) is 403 `forbidden`, the same body as any other refusal. A
  database failure during the lookup is 503 `unavailable`, never access. Membership is
  not cached in the process: a cache would reopen the window this check closes.
- **Effective role = the lower of the token's role and the membership row's role.**
  Demotion and removal take effect on the next request; promotion takes effect once the
  person's token is refreshed with the new claim. `/api/me` reports the effective role.
- Roles are checked on the server with `require_role(...)`, against the effective role.
  Routes depend on `get_principal` or `require_role`; the token-only check
  (`_token_principal`) is private, and `tests/test_membership.py` fails if any
  authenticated route reaches it without going through `get_principal`.
- Tests: `members.token(tenant, role=...)` (fixture in `tests/conftest.py`) seeds the
  membership row and returns the matching token; use the raw `tokens` factory only to
  test what a non-member gets.

## Routes

| Route | Auth | Notes |
| --- | --- | --- |
| `GET /healthz` | none | `{"status": "ok"}`, nothing else. |
| `GET /api/me` | viewer | `{user_id, tenant_id, tenant_name, role}` with the effective role (see "Auth model"); 403 if the tenant does not exist or the user is not a member. |
| `GET /api/alerts?limit=&cursor=` | viewer | `{items, next_cursor}`, newest first, keyset cursor, `limit` 1-200. |
| `GET /api/alerts/{id}` | viewer | 404 for another tenant's id, same as a missing id. Analyst and above also get `evidence` and the model's `reasoning`. |
| `PATCH /api/alerts/{id}` | analyst | Body `{"status": "new"\|"triaged"\|"investigating"\|"resolved"\|"dismissed"}`, nothing else (422). Returns the `GET` body for the caller's role. Audited as `alert.status_changed` with `from`/`to`; a no-op writes nothing. |
| `GET /api/chat/status` | viewer | `{"available": bool}`. |
| `POST /api/chat/stream` | viewer | Body `{"question": 1-2000 chars, "alert_id": uuid\|null, "history": [{"role": "user"\|"assistant", "content": <=4000 chars}] (<=10)}`. `application/x-ndjson`: `{"type":"start"}`, `{"type":"delta","text":...}`*, then exactly one of `{"type":"done"}` or `{"type":"error","code":"budget_exceeded"\|"rate_limited"\|"declined"\|"unavailable"\|"too_long"\|"internal"}`. Invalid bodies are 422 and an unknown or other tenant's `alert_id` is 404, before the stream starts. |
| `GET /api/audit?limit=&cursor=` | admin | The tenant's audit trail; each read is itself audited. |

## Database roles and tenant isolation

Migrations live in `../supabase/migrations/`. Tables are in the `lh` schema (not `public`,
so the Supabase Data API never reaches them), and `anon`/`authenticated` have no access.

- Every table has row-level security **enabled and forced**, with policies for the role
  `lh_app` keyed on `current_setting('app.tenant_id')`. An absent, empty or malformed
  setting matches no rows and rejects writes.
- Request handling runs in `tenant_transaction()`: `SET LOCAL ROLE lh_app` and
  `set_config('app.tenant_id', ..., true)` inside one transaction, so nothing carries
  over to the next user of a pooled connection.
- `lh_app` is `NOLOGIN`, `NOBYPASSRLS` and owns nothing. The server checks this at
  startup and refuses to start otherwise (also if any `lh` table lacks forced RLS).
- `lh.audit_log` is append-only: `lh_app` may only `SELECT`/`INSERT`, and a trigger
  rejects `UPDATE`, `DELETE` and `TRUNCATE` for every role.
- `lh.alerts.severity >= source_severity` is a check constraint (severity floor), and a
  trigger stops `source_severity` being lowered.

The connection user only needs to be allowed to `SET ROLE lh_app`. The migration grants
that to the user that runs it. Recommended for production: a dedicated login role with no
other privileges, created once by an operator and granted the role without inheritance, so
that a query that somehow skipped `SET ROLE` fails with "permission denied" instead of
running as a privileged user:

```sql
create role lh_api login password '<set in the dashboard, never in a file>' noinherit;
grant lh_app to lh_api;
```

The tests connect exactly this way (`lh_api_test`).
