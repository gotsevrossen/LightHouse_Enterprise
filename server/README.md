# LightHouse Enterprise server

FastAPI control plane: authentication, tenant-scoped reads of alerts, the audit log, and
(Phase 1) alert ingestion with Claude triage.

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
| `LH_TRIAGE_DAILY_TOKEN_BUDGET_PER_TENANT` | no | Tokens (input + output + cache read + cache write) per tenant per UTC day. Default 2000000. `0` means no model calls; there is no unlimited value. |

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

## Auth model

- `Authorization: Bearer <Supabase access token>` on every `/api/*` route.
- Tenant and role come only from `app_metadata.tenant_id` and `app_metadata.role`
  (`viewer` < `analyst` < `responder` < `admin`). `user_metadata` is never read, because
  users can edit it. Missing or malformed claims give 401/403, never a default tenant.
- Anonymous Supabase users are refused.
- Roles are checked on the server with `require_role(...)`.

## Routes

| Route | Auth | Notes |
| --- | --- | --- |
| `GET /healthz` | none | `{"status": "ok"}`, nothing else. |
| `GET /api/me` | viewer | `{user_id, tenant_id, tenant_name, role}`; 403 if the tenant does not exist. |
| `GET /api/alerts?limit=&cursor=` | viewer | `{items, next_cursor}`, newest first, keyset cursor, `limit` 1-200. |
| `GET /api/alerts/{id}` | viewer | 404 for another tenant's id, same as a missing id. Analyst and above also get `evidence` and the model's `reasoning`. |
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
