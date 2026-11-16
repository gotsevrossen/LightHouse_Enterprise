"""The connectors migration, at the SQL level: tenant isolation for connections and
cursors as `lh_app`, the narrow cross-tenant view of `lh_ingest`, and the guards on
credential_ref and last_error. No application code in between."""

from __future__ import annotations

import secrets
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from uuid import UUID, uuid4

import asyncpg
import pytest

from lighthouse.db import rls_safety_problems
from lighthouse.ingest.run import ingest_role_problems
from tests.connector_helpers import create_connection
from tests.helpers import Conn, create_alert, create_tenant

NEW_TABLES = ("connections", "connector_cursors")
OTHER_TABLES = ("tenants", "memberships", "alerts", "audit_log", "connector_cursors")


@asynccontextmanager
async def as_role(conn: Conn, role: str, tenant: UUID | None = None) -> AsyncGenerator[Conn]:
    """A transaction as `role` (with `app.tenant_id` set if given), rolled back on exit."""
    tx = conn.transaction()
    await tx.start()
    try:
        await conn.execute(f"set local role {role}")
        if tenant is not None:
            await conn.execute("select set_config('app.tenant_id', $1, true)", str(tenant))
        yield conn
    finally:
        await tx.rollback()


@pytest.fixture
async def pair(superuser: Conn) -> tuple[UUID, UUID, UUID, UUID]:
    tenant_a = await create_tenant(superuser, "Example Tenant A")
    tenant_b = await create_tenant(superuser, "Example Tenant B")
    conn_a = await create_connection(superuser, tenant_a)
    conn_b = await create_connection(superuser, tenant_b)
    for tenant, connection in ((tenant_a, conn_a), (tenant_b, conn_b)):
        await superuser.execute(
            "insert into lh.connector_cursors (connection_id, tenant_id, cursor) values ($1, $2, $3)",
            connection,
            tenant,
            f"cursor-{tenant}",
        )
    return tenant_a, tenant_b, conn_a, conn_b


_APP_COLUMNS = "id, tenant_id, kind, external_tenant_id, status, last_success_at, last_error"


# lh_app: isolation --------------------------------------------------------------------


async def test_app_sees_only_own_connections_and_cursors(
    superuser: Conn, pair: tuple[UUID, UUID, UUID, UUID]
) -> None:
    tenant_a, tenant_b, conn_a, conn_b = pair
    async with as_role(superuser, "lh_app", tenant_a) as conn:
        rows = await conn.fetch(f"select {_APP_COLUMNS} from lh.connections")  # noqa: S608
        assert {row["id"] for row in rows} == {conn_a}
        assert await conn.fetchval("select count(*) from lh.connections where id = $1", conn_b) == 0
        cursors = await conn.fetch("select connection_id, tenant_id from lh.connector_cursors")
        assert [(row["connection_id"], row["tenant_id"]) for row in cursors] == [(conn_a, tenant_a)]
    async with as_role(superuser, "lh_app", tenant_b) as conn:
        assert await conn.fetchval("select count(*) from lh.connections where id = $1", conn_a) == 0


@pytest.mark.parametrize("tenant", [None, "", "not-a-uuid"])
async def test_app_without_tenant_sees_nothing(
    superuser: Conn, pair: tuple[UUID, UUID, UUID, UUID], tenant: str | None
) -> None:
    del pair
    tx = superuser.transaction()
    await tx.start()
    try:
        await superuser.execute("set local role lh_app")
        if tenant is not None:
            await superuser.execute("select set_config('app.tenant_id', $1, true)", tenant)
        assert await superuser.fetchval("select count(*) from lh.connections") == 0
        assert await superuser.fetchval("select count(*) from lh.connector_cursors") == 0
    finally:
        await tx.rollback()


async def test_app_cannot_read_credential_ref(
    superuser: Conn, pair: tuple[UUID, UUID, UUID, UUID]
) -> None:
    tenant_a, *_ = pair
    for query in ("select credential_ref from lh.connections", "select * from lh.connections"):
        async with as_role(superuser, "lh_app", tenant_a) as conn:
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.fetch(query)


async def test_app_cannot_create_or_delete_connections(
    superuser: Conn, pair: tuple[UUID, UUID, UUID, UUID]
) -> None:
    tenant_a, _, conn_a, _ = pair
    async with as_role(superuser, "lh_app", tenant_a) as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(
                """
                insert into lh.connections (tenant_id, kind, external_tenant_id, credential_ref)
                values ($1, 'defender_xdr', $2, 'vault:x')
                """,
                tenant_a,
                uuid4(),
            )
    async with as_role(superuser, "lh_app", tenant_a) as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("delete from lh.connections where id = $1", conn_a)


@pytest.mark.parametrize(
    "assignment",
    ["credential_ref = 'vault:other'", "tenant_id = gen_random_uuid()", "kind = kind",
     "external_tenant_id = gen_random_uuid()", "created_at = now()"],
)
async def test_app_cannot_update_identity_or_credential(
    superuser: Conn, pair: tuple[UUID, UUID, UUID, UUID], assignment: str
) -> None:
    tenant_a, _, conn_a, _ = pair
    async with as_role(superuser, "lh_app", tenant_a) as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(f"update lh.connections set {assignment} where id = $1", conn_a)  # noqa: S608


async def test_app_updates_run_state_only_in_own_tenant(
    superuser: Conn, pair: tuple[UUID, UUID, UUID, UUID]
) -> None:
    tenant_a, _, conn_a, conn_b = pair
    async with as_role(superuser, "lh_app", tenant_a) as conn:
        own = await conn.execute(
            "update lh.connections set last_error = 'x', status = 'error', "
            "last_success_at = now() where id = $1",
            conn_a,
        )
        other = await conn.execute(
            "update lh.connections set last_error = 'x' where id = $1", conn_b
        )
        assert own == "UPDATE 1"
        assert other == "UPDATE 0"


async def test_cursor_writes_are_pinned_to_tenant(
    superuser: Conn, pair: tuple[UUID, UUID, UUID, UUID]
) -> None:
    tenant_a, tenant_b, conn_a, conn_b = pair
    # Another tenant's cursor: invisible to update.
    async with as_role(superuser, "lh_app", tenant_a) as conn:
        result = await conn.execute(
            "update lh.connector_cursors set cursor = 'hijack' where connection_id = $1", conn_b
        )
        assert result == "UPDATE 0"
    # Writing a row labelled with another tenant: refused by RLS WITH CHECK.
    other_connection = await create_connection(superuser, tenant_b)
    async with as_role(superuser, "lh_app", tenant_a) as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(
                "insert into lh.connector_cursors (connection_id, tenant_id, cursor) "
                "values ($1, $2, 'x')",
                other_connection,
                tenant_b,
            )
    # Labelling another tenant's connection with our own tenant: refused by the
    # composite foreign key, so a cursor can never be detached from its tenant.
    async with as_role(superuser, "lh_app", tenant_a) as conn:
        with pytest.raises(asyncpg.ForeignKeyViolationError):
            await conn.execute(
                "insert into lh.connector_cursors (connection_id, tenant_id, cursor) "
                "values ($1, $2, 'x')",
                other_connection,
                tenant_a,
            )
    # Moving our own cursor into another tenant: refused (the immutability trigger fires
    # before RLS WITH CHECK, which would refuse it too).
    async with as_role(superuser, "lh_app", tenant_a) as conn:
        with pytest.raises((asyncpg.CheckViolationError, asyncpg.InsufficientPrivilegeError)):
            await conn.execute(
                "update lh.connector_cursors set tenant_id = $2 where connection_id = $1",
                conn_a,
                tenant_b,
            )
    # Own cursor: read and write.
    async with as_role(superuser, "lh_app", tenant_a) as conn:
        result = await conn.execute(
            "update lh.connector_cursors set cursor = 'next' where connection_id = $1", conn_a
        )
        assert result == "UPDATE 1"


async def test_app_cannot_delete_cursors(
    superuser: Conn, pair: tuple[UUID, UUID, UUID, UUID]
) -> None:
    tenant_a, _, conn_a, _ = pair
    async with as_role(superuser, "lh_app", tenant_a) as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("delete from lh.connector_cursors where connection_id = $1", conn_a)


# lh_ingest: one narrow cross-tenant view ------------------------------------------------


async def test_ingest_lists_connections_across_tenants(
    superuser: Conn, pair: tuple[UUID, UUID, UUID, UUID]
) -> None:
    _, _, conn_a, conn_b = pair
    async with as_role(superuser, "lh_ingest") as conn:
        rows = await conn.fetch(
            "select id, tenant_id, kind, external_tenant_id, status, credential_ref "
            "from lh.connections"
        )
    ids = {row["id"] for row in rows}
    assert {conn_a, conn_b} <= ids


@pytest.mark.parametrize(
    "query",
    [
        "select last_error from lh.connections",
        "select last_success_at from lh.connections",
        "select * from lh.connections",
        *(f"select * from lh.{table}" for table in OTHER_TABLES),  # noqa: S608
        "select count(*) from lh.alerts",
        "select lh.current_tenant_id()",
    ],
)
async def test_ingest_cannot_read_anything_else(
    superuser: Conn, pair: tuple[UUID, UUID, UUID, UUID], query: str
) -> None:
    tenant_a, *_ = pair
    await create_alert(superuser, tenant_a, title="Secret alert text")
    async with as_role(superuser, "lh_ingest") as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.fetch(query)


@pytest.mark.parametrize(
    "statement",
    [
        "update lh.connections set status = 'disabled'",
        "update lh.connections set credential_ref = 'vault:other'",
        "delete from lh.connections",
        "insert into lh.connections (tenant_id, kind, external_tenant_id, credential_ref) "
        "select tenant_id, kind, gen_random_uuid(), 'vault:x' from lh.connections limit 1",
        "insert into lh.connector_cursors (connection_id, tenant_id, cursor) "
        "select id, tenant_id, 'x' from lh.connections limit 1",
        "insert into lh.audit_log (tenant_id, actor, action) "
        "select tenant_id, 'x', 'x' from lh.connections limit 1",
        "insert into lh.alerts (tenant_id, source, source_alert_id, title, source_severity, "
        "severity) select tenant_id, 'x', 'x', 'x', 'low', 'low' from lh.connections limit 1",
        "truncate lh.connections",
    ],
)
async def test_ingest_cannot_write(
    superuser: Conn, pair: tuple[UUID, UUID, UUID, UUID], statement: str
) -> None:
    del pair
    async with as_role(superuser, "lh_ingest") as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(statement)


async def test_ingest_tenant_setting_does_not_widen_access(
    superuser: Conn, pair: tuple[UUID, UUID, UUID, UUID]
) -> None:
    tenant_a, *_ = pair
    async with as_role(superuser, "lh_ingest", tenant_a) as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.fetch("select * from lh.connector_cursors")


# Roles and startup checks ---------------------------------------------------------------


async def test_roles_cannot_bypass_rls(superuser: Conn) -> None:
    rows = await superuser.fetch(
        "select rolname, rolsuper, rolbypassrls, rolcanlogin from pg_roles "
        "where rolname in ('lh_app', 'lh_ingest')"
    )
    assert {row["rolname"] for row in rows} == {"lh_app", "lh_ingest"}
    for row in rows:
        assert not row["rolsuper"]
        assert not row["rolbypassrls"]
        assert not row["rolcanlogin"]


async def test_new_tables_have_forced_rls_and_no_role_owns_them(superuser: Conn) -> None:
    for table in NEW_TABLES:
        row = await superuser.fetchrow(
            """
            select c.relrowsecurity, c.relforcerowsecurity,
                   pg_get_userbyid(c.relowner) as owner
              from pg_class c join pg_namespace n on n.oid = c.relnamespace
             where n.nspname = 'lh' and c.relname = $1
            """,
            table,
        )
        assert row is not None
        assert row["relrowsecurity"]
        assert row["relforcerowsecurity"]
        assert row["owner"] not in {"lh_app", "lh_ingest"}


async def test_startup_checks_report_no_problems(app_conn: Conn) -> None:
    assert await rls_safety_problems(app_conn) == []
    assert await ingest_role_problems(app_conn) == []


async def test_ingest_check_catches_a_widened_grant(superuser: Conn) -> None:
    tx = superuser.transaction()
    await tx.start()
    try:
        await superuser.execute("grant select on lh.alerts to lh_ingest")
        await superuser.execute("grant update on lh.connections to lh_ingest")
        problems = await ingest_role_problems(superuser)
    finally:
        await tx.rollback()
    assert "role lh_ingest can read every column of lh.alerts" in problems
    assert "role lh_ingest can write lh.connections" in problems


@pytest.mark.parametrize("api_role", ["anon", "authenticated"])
async def test_supabase_api_roles_have_no_access(superuser: Conn, api_role: str) -> None:
    for table in NEW_TABLES:
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"):
            assert not await superuser.fetchval(
                "select has_table_privilege($1, $2, $3)", api_role, f"lh.{table}", privilege
            ), f"{api_role} has {privilege} on lh.{table}"


# Column guards ---------------------------------------------------------------------------


def _pem_like() -> str:
    # Built at run time: never a key-shaped literal in the repository.
    return "-----BEGIN " + "PRIVATE KEY-----\n" + secrets.token_urlsafe(48) + "\n-----END"


def _jwt_like() -> str:
    return "eyJ" + secrets.token_urlsafe(24) + "." + "eyJ" + secrets.token_urlsafe(24) + ".sig"


@pytest.mark.parametrize(
    "make_value",
    [
        _pem_like,
        _jwt_like,
        lambda: secrets.token_urlsafe(32),
        lambda: "vault:" + secrets.token_urlsafe(32),
        lambda: "vault:" + "a" * 65,
        lambda: "vault:Has.Upper~Case",
        lambda: "vault:",
        lambda: "",
        lambda: "vault:x\n",
    ],
    ids=["pem", "jwt", "random-secret", "mixed-case", "too-long", "punctuation", "empty-name",
         "empty", "newline"],
)
async def test_credential_ref_must_be_a_reference(
    superuser: Conn, make_value: object
) -> None:
    assert callable(make_value)
    tenant = await create_tenant(superuser)
    with pytest.raises(asyncpg.CheckViolationError):
        await create_connection(superuser, tenant, credential_ref=str(make_value()))


async def test_credential_ref_accepts_vault_ids(superuser: Conn) -> None:
    tenant = await create_tenant(superuser)
    await create_connection(superuser, tenant, credential_ref=f"vault:{uuid4()}")
    await create_connection(superuser, tenant, credential_ref="vault:defender_prod-01")


async def test_last_error_guards(superuser: Conn) -> None:
    tenant = await create_tenant(superuser)
    connection = await create_connection(superuser, tenant)
    with pytest.raises(asyncpg.CheckViolationError):
        await superuser.execute(
            "update lh.connections set last_error = $2 where id = $1", connection, "x" * 501
        )
    with pytest.raises(asyncpg.CheckViolationError):
        await superuser.execute(
            "update lh.connections set last_error = $2 where id = $1",
            connection,
            "token was " + _jwt_like(),
        )


async def test_identity_columns_immutable_for_every_role(superuser: Conn) -> None:
    tenant = await create_tenant(superuser)
    other = await create_tenant(superuser)
    connection = await create_connection(superuser, tenant)
    for assignment, value in (
        ("tenant_id", other),
        ("external_tenant_id", uuid4()),
    ):
        with pytest.raises(asyncpg.CheckViolationError):
            await superuser.execute(
                f"update lh.connections set {assignment} = $2 where id = $1",  # noqa: S608
                connection,
                value,
            )
    await superuser.execute(
        "insert into lh.connector_cursors (connection_id, tenant_id, cursor) values ($1, $2, 'c')",
        connection,
        tenant,
    )
    with pytest.raises(asyncpg.CheckViolationError):
        await superuser.execute(
            "update lh.connector_cursors set tenant_id = $2 where connection_id = $1",
            connection,
            other,
        )


async def test_unique_connection_per_directory(superuser: Conn) -> None:
    tenant = await create_tenant(superuser)
    directory = uuid4()
    await create_connection(superuser, tenant, directory=directory)
    with pytest.raises(asyncpg.UniqueViolationError):
        await create_connection(superuser, tenant, directory=directory)
    # The same directory under another tenant is a separate connection (a managed
    # service provider may onboard one directory into two of its own tenants).
    await create_connection(superuser, await create_tenant(superuser), directory=directory)


async def test_cursor_length_capped(superuser: Conn) -> None:
    tenant = await create_tenant(superuser)
    connection = await create_connection(superuser, tenant)
    with pytest.raises(asyncpg.CheckViolationError):
        await superuser.execute(
            "insert into lh.connector_cursors (connection_id, tenant_id, cursor) "
            "values ($1, $2, $3)",
            connection,
            tenant,
            "c" * 2049,
        )


async def test_updated_at_maintained(superuser: Conn) -> None:
    tenant = await create_tenant(superuser)
    connection = await create_connection(superuser, tenant)
    before = await superuser.fetchval(
        "select updated_at from lh.connections where id = $1", connection
    )
    await superuser.execute("select pg_sleep(0.01)")
    await superuser.execute(
        "update lh.connections set status = 'disabled' where id = $1", connection
    )
    after = await superuser.fetchval(
        "select updated_at from lh.connections where id = $1", connection
    )
    assert after > before
