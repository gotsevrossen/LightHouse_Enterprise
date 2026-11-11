"""Database access for request handling.

Security boundary. Every query made on behalf of a user runs inside `tenant_transaction`,
which switches to the `lh_app` role and sets the tenant for that transaction only. Row-level
security on `lh_app` is what keeps tenants apart; application queries do not need, and are
not trusted, to filter by tenant.
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Final, cast
from uuid import UUID

import asyncpg
from asyncpg.pool import PoolConnectionProxy
from fastapi import Request

from lighthouse.config import Settings

APP_ROLE: Final = "lh_app"
APP_SCHEMA: Final = "lh"

type Record = asyncpg.Record
type Pool = asyncpg.Pool[Record]
type Connection = asyncpg.Connection[Record] | PoolConnectionProxy[Record]


class UnsafeDatabaseConfigError(RuntimeError):
    """The database is configured so that RLS would not isolate tenants."""


async def _init_connection(conn: asyncpg.Connection[Record]) -> None:
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


async def create_pool(settings: Settings) -> Pool:
    pool = await asyncpg.create_pool(
        dsn=settings.database_url.get_secret_value(),
        min_size=settings.db_pool_min_size,
        max_size=settings.db_pool_max_size,
        statement_cache_size=settings.db_statement_cache_size,
        command_timeout=settings.db_command_timeout_seconds,
        init=_init_connection,
    )
    try:
        async with pool.acquire() as conn:
            problems = await rls_safety_problems(conn)
    except BaseException:
        await pool.close()
        raise
    if problems:
        await pool.close()
        raise UnsafeDatabaseConfigError("; ".join(problems))
    return pool


async def rls_safety_problems(conn: Connection) -> list[str]:
    """Check the invariants tenant isolation depends on; return what is wrong.

    Run at startup so a server pointed at a database where `lh_app` could bypass RLS, owns
    a table, or where a table lacks forced RLS, refuses to serve instead of leaking.
    """
    problems: list[str] = []
    role = await conn.fetchrow(
        "select rolsuper, rolbypassrls from pg_catalog.pg_roles where rolname = $1",
        APP_ROLE,
    )
    if role is None:
        problems.append(f"role {APP_ROLE} does not exist")
    elif role["rolsuper"] or role["rolbypassrls"]:
        problems.append(f"role {APP_ROLE} can bypass row-level security")

    rows = await conn.fetch(
        """
        select c.relname,
               c.relrowsecurity,
               c.relforcerowsecurity,
               pg_catalog.pg_get_userbyid(c.relowner) as owner
          from pg_catalog.pg_class c
          join pg_catalog.pg_namespace n on n.oid = c.relnamespace
         where n.nspname = $1
           and c.relkind in ('r', 'p')
         order by c.relname
        """,
        APP_SCHEMA,
    )
    for row in rows:
        name = cast("str", row["relname"])
        if not (row["relrowsecurity"] and row["relforcerowsecurity"]):
            problems.append(f"table {APP_SCHEMA}.{name} does not have forced row-level security")
        if row["owner"] == APP_ROLE:
            problems.append(f"table {APP_SCHEMA}.{name} is owned by {APP_ROLE}")
    return problems


@asynccontextmanager
async def tenant_transaction(pool: Pool, tenant_id: UUID) -> AsyncGenerator[Connection]:
    """A transaction that runs as `lh_app`, scoped to one tenant.

    Both settings are transaction-local (`SET LOCAL`, `set_config(..., true)`), so they end
    with the transaction and a pooled connection never carries one request's tenant into
    the next. The role switch comes first: nothing runs as the connection user, which on
    Supabase can bypass RLS.
    """
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(f"set local role {APP_ROLE}")
        await conn.execute(
            "select pg_catalog.set_config('app.tenant_id', $1, true)",
            str(tenant_id),
        )
        yield conn


def get_pool(request: Request) -> Pool:
    return cast("Pool", request.app.state.pool)
