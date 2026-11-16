"""Connector runner: one pass over every active connection.

    python -m lighthouse.ingest.run --once

Security boundaries (CLAUDE.md rule 2, "Secrets", "Database conventions"):

- Scheduling is the only cross-tenant step. It runs as `lh_ingest`, which can list
  connection metadata across tenants and nothing else (see the connectors migration).
  It never uses the Supabase `service_role` key or the table owner.
- Everything done *for* a tenant (read the cursor, ingest each alert, store the cursor,
  record the outcome and the audit trail) runs as `lh_app` through `db.tenant_transaction`
  pinned to that connection's tenant, so a bug here cannot write into another tenant.
- Connections are isolated from each other: each runs in its own task under a time
  budget, every failure is caught and recorded on that connection, and a bounded
  semaphore stops one slow tenant from starving the rest.
- The cursor only moves after every alert the connector returned was ingested.
- Logs and audit entries carry ids, counts and fixed error labels, never customer text,
  tokens or response bodies.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import logging
import sys
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Final, Literal, Protocol, cast
from uuid import UUID

import asyncpg
import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from lighthouse.audit import JsonValue, record_audit
from lighthouse.connectors.base import (
    Connector,
    ConnectorAuthError,
    ConnectorCredential,
    ConnectorError,
    ConnectorPermanentError,
    ConnectorTransientError,
    CredentialProvider,
    FetchResult,
    check_credential_ref,
)
from lighthouse.db import Connection, Pool, Record, rls_safety_problems, tenant_transaction
from lighthouse.ingest.schema import NormalizedAlert
from lighthouse.triage import TriageModel

logger = logging.getLogger(__name__)

INGEST_ROLE: Final = "lh_ingest"
AUDIT_ACTOR: Final = "system:connector-runner"
MAX_LAST_ERROR_CHARS: Final = 500
PARTIAL_RUN_NOTE: Final = "partial run: a per-run cap was reached; the rest follows next run"


class RunnerSettings(BaseSettings):
    """Worker configuration, `LH_*` environment variables (no `.env` file is read).

    Kept here rather than in `lighthouse.config.Settings` so the worker does not need
    the API's sign-in settings to start.
    """

    model_config = SettingsConfigDict(env_prefix="LH_", extra="ignore", frozen=True)

    database_url: SecretStr
    db_statement_cache_size: int = Field(default=100, ge=0)
    db_command_timeout_seconds: float = Field(default=30.0, gt=0)
    ingest_max_concurrency: int = Field(default=4, ge=1, le=64)
    # Wall clock for one connection's fetch and ingest. Bookkeeping after it is bounded
    # separately by the database command timeout.
    ingest_connection_budget_seconds: float = Field(default=600.0, gt=0, le=3600)
    ingest_max_connections: int = Field(default=1000, ge=1, le=100_000)


class ConnectionRow(BaseModel):
    """What the scheduling step reads about one connection. Never includes a secret."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    tenant_id: UUID
    kind: str
    external_tenant_id: UUID
    credential_ref: str


class IngestFn(Protocol):
    """`lighthouse.ingest.pipeline.ingest_alert`: upsert, triage and store one alert
    inside the tenant's own transaction."""

    def __call__(
        self, pool: Pool, tenant_id: UUID, alert: NormalizedAlert, model: TriageModel, /
    ) -> Awaitable[object]: ...


type ConnectorFactory = Callable[[ConnectionRow, ConnectorCredential], Connector]


@dataclass(frozen=True, slots=True)
class ConnectionOutcome:
    connection_id: UUID
    tenant_id: UUID
    status: Literal["succeeded", "failed"]
    fetched: int = 0
    ingested: int = 0
    ingest_failures: int = 0
    skipped: int = 0
    pages: int = 0
    truncated: bool = False
    error_kind: str | None = None
    error: str | None = None


# Database -------------------------------------------------------------------------------


async def _init_connection(conn: asyncpg.Connection[Record]) -> None:
    # Same codec as the API pool: audit detail is a jsonb column written from a dict.
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


async def ingest_role_problems(conn: Connection) -> list[str]:
    """Check that `lh_ingest` can do what scheduling needs and nothing more.

    Run at startup alongside `rls_safety_problems`: a worker pointed at a database where
    the scheduling role could read alerts or write anything refuses to start.
    """
    problems: list[str] = []
    role = await conn.fetchrow(
        "select rolsuper, rolbypassrls, rolcanlogin from pg_catalog.pg_roles where rolname = $1",
        INGEST_ROLE,
    )
    if role is None:
        return [f"role {INGEST_ROLE} does not exist"]
    if role["rolsuper"] or role["rolbypassrls"]:
        problems.append(f"role {INGEST_ROLE} can bypass row-level security")
    rows = await conn.fetch(
        """
        select c.relname,
               pg_catalog.pg_get_userbyid(c.relowner) as owner,
               pg_catalog.has_table_privilege($1, c.oid, 'SELECT') as can_select,
               pg_catalog.has_table_privilege($1, c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE')
                 as can_write
          from pg_catalog.pg_class c
          join pg_catalog.pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'lh' and c.relkind in ('r', 'p')
         order by c.relname
        """,
        INGEST_ROLE,
    )
    for row in rows:
        name = cast("str", row["relname"])
        if row["owner"] == INGEST_ROLE:
            problems.append(f"table lh.{name} is owned by {INGEST_ROLE}")
        if row["can_write"]:
            problems.append(f"role {INGEST_ROLE} can write lh.{name}")
        # Table-level SELECT on connections would also expose last_error and anything
        # added later; only the column grants of the migration are expected.
        if row["can_select"]:
            problems.append(f"role {INGEST_ROLE} can read every column of lh.{name}")
    return problems


async def create_worker_pool(settings: RunnerSettings) -> Pool:
    pool = await asyncpg.create_pool(
        dsn=settings.database_url.get_secret_value(),
        min_size=1,
        max_size=settings.ingest_max_concurrency + 1,
        statement_cache_size=settings.db_statement_cache_size,
        command_timeout=settings.db_command_timeout_seconds,
        init=_init_connection,
    )
    try:
        async with pool.acquire() as conn:
            problems = [*await rls_safety_problems(conn), *await ingest_role_problems(conn)]
    except BaseException:
        await pool.close()
        raise
    if problems:
        await pool.close()
        msg = "; ".join(problems)
        raise RuntimeError(msg)
    return pool


async def list_active_connections(pool: Pool, *, limit: int) -> list[ConnectionRow]:
    """The scheduling step, as `lh_ingest`: active connections across all tenants."""
    async with pool.acquire() as conn, conn.transaction():
        # First statement of the transaction, as in tenant_transaction: nothing runs as
        # the connection user, which on Supabase can bypass RLS.
        await conn.execute(f"set local role {INGEST_ROLE}")
        rows = await conn.fetch(
            """
            select id, tenant_id, kind::text as kind, external_tenant_id, credential_ref
              from lh.connections
             where status = 'active'
             order by id
             limit $1
            """,
            limit,
        )
    connections: list[ConnectionRow] = []
    for row in rows:
        try:
            connections.append(ConnectionRow.model_validate(dict(row.items())))
        except ValidationError:
            logger.warning("skipping unreadable connection row", extra={"lh_id": str(row["id"])})
    return connections


async def _read_cursor(conn: Connection, connection_id: UUID) -> str | None:
    value = await conn.fetchval(
        "select cursor from lh.connector_cursors where connection_id = $1", connection_id
    )
    return value if isinstance(value, str) else None


async def _store_cursor(conn: Connection, row: ConnectionRow, cursor: str) -> None:
    # tenant_id is written from the row, and RLS WITH CHECK plus the composite foreign
    # key both refuse it unless it is this transaction's tenant and the connection's own.
    await conn.execute(
        """
        insert into lh.connector_cursors (connection_id, tenant_id, cursor)
        values ($1, $2, $3)
        on conflict (connection_id) do update set cursor = excluded.cursor
        """,
        row.id,
        row.tenant_id,
        cursor,
    )


# One connection -------------------------------------------------------------------------


@dataclass(slots=True)
class _Progress:
    result: FetchResult | None = None
    ingested: int = 0
    ingest_failures: int = 0

    def counts(self) -> dict[str, JsonValue]:
        result = self.result
        return {
            "fetched": len(result.alerts) if result else 0,
            "ingested": self.ingested,
            "ingest_failures": self.ingest_failures,
            "skipped": result.skipped if result else 0,
            "pages": result.pages if result else 0,
            "truncated": result.truncated if result else False,
        }


async def _fetch_and_ingest(  # noqa: PLR0913 - keyword-only dependencies of one run
    row: ConnectionRow,
    cursor: str | None,
    progress: _Progress,
    *,
    pool: Pool,
    credentials: CredentialProvider,
    connector_factory: ConnectorFactory,
    ingest: IngestFn,
    model: TriageModel,
) -> None:
    credential = await credentials.get(check_credential_ref(row.credential_ref))
    # The connection row (written by the consent flow) decides which customer directory
    # this tenant reads. A credential for any other directory is refused before use.
    if credential.entra_tenant_id != row.external_tenant_id:
        msg = "credential does not belong to this connection's directory"
        raise ConnectorPermanentError(msg)
    connector = connector_factory(row, credential)
    progress.result = await connector.fetch(cursor)
    for alert in progress.result.alerts:
        try:
            await ingest(pool, row.tenant_id, alert, model)
        except Exception as exc:  # noqa: BLE001 - one alert must not stop the others
            progress.ingest_failures += 1
            logger.warning(
                "alert ingest failed",
                extra={"lh_connection_id": str(row.id), "lh_error": type(exc).__name__},
            )
        else:
            progress.ingested += 1


def _classify(exc: BaseException) -> ConnectorError:
    if isinstance(exc, ConnectorError):
        return exc
    if isinstance(exc, TimeoutError):
        return ConnectorTransientError("time budget for this connection was exceeded")
    # Only the type name: an exception message can carry customer text or a URL.
    return ConnectorError(f"internal error ({type(exc).__name__})")


async def run_connection(  # noqa: PLR0913 - keyword-only dependencies of one run
    row: ConnectionRow,
    *,
    pool: Pool,
    credentials: CredentialProvider,
    connector_factory: ConnectorFactory,
    ingest: IngestFn,
    model: TriageModel,
    budget_seconds: float,
) -> ConnectionOutcome:
    target = str(row.id)
    async with tenant_transaction(pool, row.tenant_id) as conn:
        cursor = await _read_cursor(conn, row.id)
        await record_audit(
            conn,
            actor=AUDIT_ACTOR,
            action="connector.run.started",
            target=target,
            detail={"kind": row.kind},
        )

    progress = _Progress()
    error: ConnectorError | None = None
    try:
        async with asyncio.timeout(budget_seconds):
            await _fetch_and_ingest(
                row,
                cursor,
                progress,
                pool=pool,
                credentials=credentials,
                connector_factory=connector_factory,
                ingest=ingest,
                model=model,
            )
    except Exception as exc:  # noqa: BLE001 - every failure is recorded on the connection
        error = _classify(exc)
    if error is None and progress.ingest_failures:
        error = ConnectorTransientError(
            f"{progress.ingest_failures} alert(s) could not be ingested; cursor not advanced"
        )

    result = progress.result
    counts = progress.counts()
    async with tenant_transaction(pool, row.tenant_id) as conn:
        if error is None and result is not None:
            if result.next_cursor is not None:
                await _store_cursor(conn, row, result.next_cursor)
            await conn.execute(
                """
                update lh.connections
                   set last_success_at = pg_catalog.now(), last_error = $2
                 where id = $1
                """,
                row.id,
                PARTIAL_RUN_NOTE if result.truncated else None,
            )
            await record_audit(
                conn,
                actor=AUDIT_ACTOR,
                action="connector.run.succeeded",
                target=target,
                detail=counts,
            )
        else:
            failure = error or ConnectorError("run produced no result")
            # Auth and permanent errors need a person (re-consent, fix configuration), so
            # the connection leaves the schedule instead of hammering the source.
            needs_person = isinstance(failure, ConnectorAuthError | ConnectorPermanentError)
            await conn.execute(
                """
                update lh.connections
                   set last_error = $2,
                       status = case when $3 then 'error'::lh.connection_status else status end
                 where id = $1
                """,
                row.id,
                failure.message[:MAX_LAST_ERROR_CHARS],
                needs_person,
            )
            await record_audit(
                conn,
                actor=AUDIT_ACTOR,
                action="connector.run.failed",
                target=target,
                detail={**counts, "error_kind": failure.kind},
            )
            error = failure

    outcome = ConnectionOutcome(
        connection_id=row.id,
        tenant_id=row.tenant_id,
        status="failed" if error else "succeeded",
        fetched=len(result.alerts) if result else 0,
        ingested=progress.ingested,
        ingest_failures=progress.ingest_failures,
        skipped=result.skipped if result else 0,
        pages=result.pages if result else 0,
        truncated=result.truncated if result else False,
        error_kind=error.kind if error else None,
        error=error.message if error else None,
    )
    logger.info(
        "connector run finished",
        extra={
            "lh_connection_id": target,
            "lh_tenant_id": str(row.tenant_id),
            "lh_status": outcome.status,
            "lh_error_kind": outcome.error_kind,
            **{f"lh_{key}": value for key, value in counts.items()},
        },
    )
    return outcome


# A whole pass ---------------------------------------------------------------------------


async def run_once(  # noqa: PLR0913 - keyword-only dependencies of one pass
    pool: Pool,
    *,
    credentials: CredentialProvider,
    connector_factory: ConnectorFactory,
    ingest: IngestFn,
    model: TriageModel,
    max_concurrency: int = 4,
    budget_seconds: float = 600.0,
    max_connections: int = 1000,
) -> list[ConnectionOutcome]:
    if max_concurrency < 1 or budget_seconds <= 0 or max_connections < 1:
        msg = "max_concurrency, budget_seconds and max_connections must be positive"
        raise ValueError(msg)
    connections = await list_active_connections(pool, limit=max_connections)
    semaphore = asyncio.Semaphore(max_concurrency)

    async def guarded(row: ConnectionRow) -> ConnectionOutcome:
        async with semaphore:
            try:
                return await run_connection(
                    row,
                    pool=pool,
                    credentials=credentials,
                    connector_factory=connector_factory,
                    ingest=ingest,
                    model=model,
                    budget_seconds=budget_seconds,
                )
            except Exception as exc:  # noqa: BLE001 - isolation: never take down the pass
                # Reached only if the bookkeeping itself failed (e.g. the database).
                logger.error(  # noqa: TRY400 - no traceback: it may hold customer text
                    "connector run could not be recorded",
                    extra={"lh_connection_id": str(row.id), "lh_error": type(exc).__name__},
                )
                return ConnectionOutcome(
                    connection_id=row.id,
                    tenant_id=row.tenant_id,
                    status="failed",
                    error_kind="internal",
                    error=f"internal error ({type(exc).__name__})",
                )

    return list(await asyncio.gather(*(guarded(row) for row in connections)))


# Command line ---------------------------------------------------------------------------


class _JsonFormatter(logging.Formatter):
    """One JSON object per line; only `lh_*` extras are included, by construction."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key.startswith("lh_"):
                payload[key.removeprefix("lh_")] = value
        return json.dumps(payload, default=str)


def _default_ingest() -> IngestFn:
    # Imported lazily, by name: the pipeline (and through it the model client) is only
    # needed when the runner really runs, tests inject a fake instead, and this module
    # must not fail to import while the pipeline is being built alongside it.
    pipeline = importlib.import_module("lighthouse.ingest.pipeline")
    return cast("IngestFn", pipeline.ingest_alert)


def _default_model() -> TriageModel:
    from lighthouse.ai import build_triage_model  # noqa: PLC0415
    from lighthouse.config import load_settings  # noqa: PLC0415

    return build_triage_model(load_settings())


def _credential_provider() -> CredentialProvider | None:
    # The Supabase Vault-backed provider is the next step once a Supabase project exists
    # to build it against (see connectors/base.py). Until then there is no production
    # credential source, and the runner refuses to start rather than fall back to one.
    return None


async def _main_async(settings: RunnerSettings, credentials: CredentialProvider) -> int:
    from lighthouse.connectors.defender_xdr import DefenderXdrConnector  # noqa: PLC0415
    from lighthouse.connectors.msgraph_auth import GraphTokenProvider  # noqa: PLC0415

    ingest = _default_ingest()
    model = _default_model()
    pool = await create_worker_pool(settings)
    try:
        # trust_env=False: proxies and CA bundles come from code review, not from
        # whatever environment the container happens to inherit.
        async with httpx.AsyncClient(follow_redirects=False, trust_env=False) as http:
            tokens = GraphTokenProvider(http)

            def factory(row: ConnectionRow, credential: ConnectorCredential) -> Connector:
                if row.kind != "defender_xdr":
                    msg = "unsupported connector kind"
                    raise ConnectorPermanentError(msg)
                return DefenderXdrConnector(
                    http=http,
                    tokens=tokens,
                    credential=credential,
                    external_tenant_id=row.external_tenant_id,
                )

            outcomes = await run_once(
                pool,
                credentials=credentials,
                connector_factory=factory,
                ingest=ingest,
                model=model,
                max_concurrency=settings.ingest_max_concurrency,
                budget_seconds=settings.ingest_connection_budget_seconds,
                max_connections=settings.ingest_max_connections,
            )
    finally:
        await pool.close()
    return 1 if any(outcome.status == "failed" for outcome in outcomes) else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m lighthouse.ingest.run")
    parser.add_argument(
        "--once",
        action="store_true",
        help="run every active connection once and exit (scheduling is Supabase Cron's job)",
    )
    args = parser.parse_args(argv)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    # httpx logs every request URL at INFO; those carry customer directory ids.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if not args.once:
        parser.error("only --once is supported")
    credentials = _credential_provider()
    if credentials is None:
        logger.error("no connector credential provider is configured (Vault provider pending)")
        return 2
    settings = RunnerSettings()  # pyright: ignore[reportCallIssue] - from the environment
    return asyncio.run(_main_async(settings, credentials))


if __name__ == "__main__":
    sys.exit(main())
