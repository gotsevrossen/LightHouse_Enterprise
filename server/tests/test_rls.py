"""Tenant isolation at the SQL level, as the request role `lh_app`.

These tests talk to Postgres directly, with no application code in between, so they show
that the database itself (policies, grants, triggers, constraints) enforces isolation.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from uuid import UUID, uuid4

import asyncpg
import pytest

from lighthouse.auth import Role
from lighthouse.db import rls_safety_problems
from lighthouse.models import AlertStatus
from lighthouse.severity import Severity
from tests.helpers import Conn, create_alert, create_tenant

TENANT_TABLES = ("tenants", "memberships", "alerts", "audit_log")


@asynccontextmanager
async def as_app(conn: Conn, tenant: UUID | str | None) -> AsyncGenerator[Conn]:
    """A transaction as lh_app, with `app.tenant_id` set to `tenant` (unset if None).

    Rolled back on exit so tests do not leak rows into each other.
    """
    tx = conn.transaction()
    await tx.start()
    try:
        await conn.execute("set local role lh_app")
        if tenant is not None:
            await conn.execute("select set_config('app.tenant_id', $1, true)", str(tenant))
        yield conn
    finally:
        await tx.rollback()


async def _seed_pair(superuser: Conn) -> tuple[UUID, UUID, UUID, UUID]:
    tenant_a = await create_tenant(superuser, "Example Tenant A")
    tenant_b = await create_tenant(superuser, "Example Tenant B")
    alert_a = await create_alert(superuser, tenant_a, title="Alert for A")
    alert_b = await create_alert(superuser, tenant_b, title="Alert for B")
    for tenant in (tenant_a, tenant_b):
        await superuser.execute(
            "insert into lh.memberships (tenant_id, user_id, role) values ($1, $2, 'admin')",
            tenant,
            uuid4(),
        )
        await superuser.execute(
            "insert into lh.audit_log (tenant_id, actor, action) values ($1, 'seed', 'seed')",
            tenant,
        )
    return tenant_a, tenant_b, alert_a, alert_b


_INSERT_ALERT = """
    insert into lh.alerts (tenant_id, source, source_alert_id, title, source_severity, severity)
    values ($1, 'fixture', $2, 'Injected', 'low', 'low')
"""


# No tenant: fail closed ------------------------------------------------------------------


@pytest.mark.parametrize(
    "setting",
    [
        None,
        "",
        "not-a-uuid",
        "{00000000-0000-4000-8000-000000000001}",
        " 00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000001' or '1'='1",
    ],
    ids=["unset", "empty", "garbage", "braces", "leading-space", "injection"],
)
async def test_without_valid_tenant_setting_nothing_is_visible(
    superuser: Conn, app_conn: Conn, setting: str | None
) -> None:
    await _seed_pair(superuser)
    async with as_app(app_conn, setting):
        for table in TENANT_TABLES:
            # Not an error, and not a leak: an empty result.
            count = await app_conn.fetchval(f"select count(*) from lh.{table}")  # noqa: S608
            assert count == 0, table


@pytest.mark.parametrize("setting", [None, "", "not-a-uuid"])
async def test_without_valid_tenant_setting_inserts_are_rejected(
    superuser: Conn, app_conn: Conn, setting: str | None
) -> None:
    tenant_a, *_ = await _seed_pair(superuser)
    with pytest.raises(asyncpg.InsufficientPrivilegeError, match="row-level security"):
        async with as_app(app_conn, setting):
            await app_conn.execute(_INSERT_ALERT, tenant_a, f"x-{uuid4()}")
    with pytest.raises(asyncpg.InsufficientPrivilegeError, match="row-level security"):
        async with as_app(app_conn, setting):
            await app_conn.execute(
                "insert into lh.audit_log (tenant_id, actor, action) values ($1, 'a', 'b')",
                tenant_a,
            )


# Tenant A set: cannot touch tenant B -------------------------------------------------------


async def test_tenant_a_reads_only_its_own_rows(superuser: Conn, app_conn: Conn) -> None:
    tenant_a, tenant_b, alert_a, alert_b = await _seed_pair(superuser)
    async with as_app(app_conn, tenant_a):
        ids = {r["id"] for r in await app_conn.fetch("select id from lh.alerts")}
        assert ids == {alert_a}
        # Even asking for B's rows explicitly returns nothing.
        assert await app_conn.fetch("select id from lh.alerts where tenant_id = $1", tenant_b) == []
        assert await app_conn.fetchrow("select id from lh.alerts where id = $1", alert_b) is None
        tenants = {r["id"] for r in await app_conn.fetch("select id from lh.tenants")}
        assert tenants == {tenant_a}
        member_tenants = {
            r["tenant_id"] for r in await app_conn.fetch("select tenant_id from lh.memberships")
        }
        assert member_tenants == {tenant_a}
        audit_tenants = {
            r["tenant_id"] for r in await app_conn.fetch("select tenant_id from lh.audit_log")
        }
        assert audit_tenants == {tenant_a}


async def test_tenant_a_cannot_insert_into_tenant_b(superuser: Conn, app_conn: Conn) -> None:
    tenant_a, tenant_b, *_ = await _seed_pair(superuser)
    with pytest.raises(asyncpg.InsufficientPrivilegeError, match="row-level security"):
        async with as_app(app_conn, tenant_a):
            await app_conn.execute(_INSERT_ALERT, tenant_b, f"x-{uuid4()}")
    with pytest.raises(asyncpg.InsufficientPrivilegeError, match="row-level security"):
        async with as_app(app_conn, tenant_a):
            await app_conn.execute(
                "insert into lh.audit_log (tenant_id, actor, action) values ($1, 'a', 'b')",
                tenant_b,
            )
    # Own tenant works, which shows the rejections above are about the tenant.
    async with as_app(app_conn, tenant_a):
        await app_conn.execute(_INSERT_ALERT, tenant_a, f"x-{uuid4()}")


async def test_tenant_a_cannot_move_a_row_into_tenant_b(superuser: Conn, app_conn: Conn) -> None:
    tenant_a, tenant_b, alert_a, _ = await _seed_pair(superuser)
    # Both the immutability trigger and the policy's WITH CHECK stop this.
    with pytest.raises((asyncpg.InsufficientPrivilegeError, asyncpg.CheckViolationError)):
        async with as_app(app_conn, tenant_a):
            await app_conn.execute(
                "update lh.alerts set tenant_id = $1 where id = $2", tenant_b, alert_a
            )


async def test_update_policy_with_check_alone_blocks_moving_rows(
    superuser: Conn, app_conn: Conn
) -> None:
    """Prove the policy itself holds, independent of the trigger that also blocks it."""
    tenant_a, tenant_b, alert_a, _ = await _seed_pair(superuser)
    # Disable the trigger in one transaction on the superuser connection; lh_app runs on
    # the same connection inside it, and everything is rolled back afterwards.
    tx = superuser.transaction()
    await tx.start()
    try:
        await superuser.execute("alter table lh.alerts disable trigger alerts_before_update")
        await superuser.execute("set local role lh_app")
        await superuser.execute("select set_config('app.tenant_id', $1, true)", str(tenant_a))
        with pytest.raises(asyncpg.InsufficientPrivilegeError, match="row-level security"):
            await superuser.execute(
                "update lh.alerts set tenant_id = $1 where id = $2", tenant_b, alert_a
            )
    finally:
        await tx.rollback()
    owner = await superuser.fetchval("select tenant_id from lh.alerts where id = $1", alert_a)
    assert owner == tenant_a


async def test_tenant_a_cannot_update_tenant_b_rows(superuser: Conn, app_conn: Conn) -> None:
    tenant_a, _, _, alert_b = await _seed_pair(superuser)
    async with as_app(app_conn, tenant_a):
        status = await app_conn.execute(
            "update lh.alerts set title = 'Tampered' where id = $1", alert_b
        )
        assert status == "UPDATE 0"
        # Without any WHERE at all, only A's rows are touched.
        await app_conn.execute("update lh.alerts set title = 'Bulk'")
    title = await superuser.fetchval("select title from lh.alerts where id = $1", alert_b)
    assert title == "Alert for B"


async def test_tenant_a_cannot_delete_tenant_b_rows(superuser: Conn, app_conn: Conn) -> None:
    tenant_a, _, _, alert_b = await _seed_pair(superuser)
    async with as_app(app_conn, tenant_a):
        assert await app_conn.execute("delete from lh.alerts where id = $1", alert_b) == "DELETE 0"
        await app_conn.execute("delete from lh.alerts")
    assert await superuser.fetchval("select count(*) from lh.alerts where id = $1", alert_b) == 1


async def test_tenants_and_memberships_are_read_only_for_lh_app(
    superuser: Conn, app_conn: Conn
) -> None:
    tenant_a, *_ = await _seed_pair(superuser)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with as_app(app_conn, tenant_a):
            await app_conn.execute("insert into lh.tenants (name) values ('Example')")
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with as_app(app_conn, tenant_a):
            await app_conn.execute(
                "insert into lh.memberships (tenant_id, user_id, role) values ($1, $2, 'admin')",
                tenant_a,
                uuid4(),
            )
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with as_app(app_conn, tenant_a):
            await app_conn.execute("update lh.memberships set role = 'admin'")


# audit_log is append-only ----------------------------------------------------------------


async def test_lh_app_can_append_to_own_audit_log(superuser: Conn, app_conn: Conn) -> None:
    tenant_a, *_ = await _seed_pair(superuser)
    async with as_app(app_conn, tenant_a):
        await app_conn.execute(
            "insert into lh.audit_log (tenant_id, actor, action) values ($1, 'a', 'b')",
            tenant_a,
        )


@pytest.mark.parametrize(
    "statement",
    [
        "update lh.audit_log set action = 'rewritten'",
        "delete from lh.audit_log",
        "truncate lh.audit_log",
    ],
)
async def test_lh_app_cannot_change_audit_log(
    superuser: Conn, app_conn: Conn, statement: str
) -> None:
    tenant_a, *_ = await _seed_pair(superuser)
    with pytest.raises(asyncpg.InsufficientPrivilegeError, match="permission denied"):
        async with as_app(app_conn, tenant_a):
            await app_conn.execute(statement)


@pytest.mark.parametrize(
    "statement",
    [
        "update lh.audit_log set action = 'rewritten'",
        "delete from lh.audit_log",
        "truncate lh.audit_log",
    ],
)
async def test_audit_log_trigger_blocks_even_superuser(superuser: Conn, statement: str) -> None:
    await _seed_pair(superuser)
    with pytest.raises(asyncpg.InsufficientPrivilegeError, match="append-only"):
        async with superuser.transaction():
            await superuser.execute(statement)


# Severity floor --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "stored"),
    [("high", "medium"), ("critical", "info"), ("low", "info")],
)
async def test_severity_floor_rejects_lower_severity(
    superuser: Conn, app_conn: Conn, source: str, stored: str
) -> None:
    tenant = await create_tenant(superuser)
    with pytest.raises(asyncpg.CheckViolationError, match="alerts_severity_floor"):
        await create_alert(superuser, tenant, source_severity=source, severity=stored)
    with pytest.raises(asyncpg.CheckViolationError, match="alerts_severity_floor"):
        async with as_app(app_conn, tenant):
            await app_conn.execute(
                """
                insert into lh.alerts
                  (tenant_id, source, source_alert_id, title, source_severity, severity)
                values ($1, 'fixture', $2, 'x', $3, $4)
                """,
                tenant,
                f"x-{uuid4()}",
                source,
                stored,
            )


async def test_severity_floor_holds_on_update(superuser: Conn, app_conn: Conn) -> None:
    tenant = await create_tenant(superuser)
    alert = await create_alert(superuser, tenant, source_severity="high", severity="critical")
    async with as_app(app_conn, tenant):
        await app_conn.execute("update lh.alerts set severity = 'high' where id = $1", alert)
    with pytest.raises(asyncpg.CheckViolationError, match="alerts_severity_floor"):
        async with as_app(app_conn, tenant):
            await app_conn.execute("update lh.alerts set severity = 'low' where id = $1", alert)
    # Lowering the source severity to make room for a lower severity is refused too.
    with pytest.raises(asyncpg.CheckViolationError, match="source_severity may not be lowered"):
        async with as_app(app_conn, tenant):
            await app_conn.execute(
                "update lh.alerts set source_severity = 'low', severity = 'low' where id = $1",
                alert,
            )
    # Raising the source severity above the stored severity violates the floor.
    with pytest.raises(asyncpg.CheckViolationError, match="alerts_severity_floor"):
        await superuser.execute(
            "update lh.alerts set source_severity = 'critical', severity = 'high' where id = $1",
            alert,
        )
    await superuser.execute(
        "update lh.alerts set source_severity = 'critical', severity = 'critical' where id = $1",
        alert,
    )


@pytest.mark.parametrize("column", ["source", "source_alert_id"])
async def test_alert_identity_columns_are_immutable(superuser: Conn, column: str) -> None:
    tenant = await create_tenant(superuser)
    alert = await create_alert(superuser, tenant)
    with pytest.raises(asyncpg.CheckViolationError, match="immutable"):
        await superuser.execute(f"update lh.alerts set {column} = 'changed' where id = $1", alert)  # noqa: S608


async def test_updated_at_is_maintained(superuser: Conn) -> None:
    tenant = await create_tenant(superuser)
    alert = await create_alert(superuser, tenant)
    await superuser.execute("update lh.alerts set updated_at = 'epoch' where id = $1", alert)
    row = await superuser.fetchrow("select created_at, updated_at from lh.alerts where id = $1", alert)
    assert row is not None
    assert row["updated_at"] >= row["created_at"]


# Structural invariants -------------------------------------------------------------------


async def test_rls_safety_invariants_hold(superuser: Conn) -> None:
    assert await rls_safety_problems(superuser) == []


async def test_rls_safety_check_detects_unforced_table(superuser: Conn) -> None:
    tx = superuser.transaction()
    await tx.start()
    try:
        await superuser.execute("create table lh.unprotected_example (tenant_id uuid not null)")
        problems = await rls_safety_problems(superuser)
        assert any("unprotected_example" in p for p in problems)
        await superuser.execute("alter table lh.unprotected_example owner to lh_app")
        await superuser.execute("alter table lh.unprotected_example enable row level security")
        await superuser.execute("alter table lh.unprotected_example force row level security")
        problems = await rls_safety_problems(superuser)
        assert problems == ["table lh.unprotected_example is owned by lh_app"]
    finally:
        await tx.rollback()


async def test_lh_app_role_attributes(superuser: Conn) -> None:
    row = await superuser.fetchrow(
        "select rolsuper, rolbypassrls, rolcanlogin from pg_roles where rolname = 'lh_app'"
    )
    assert row is not None
    assert (row["rolsuper"], row["rolbypassrls"], row["rolcanlogin"]) == (False, False, False)


async def test_every_policy_targets_lh_app_and_uses_current_tenant(superuser: Conn) -> None:
    rows = await superuser.fetch(
        "select tablename, cmd, roles, qual, with_check from pg_policies where schemaname = 'lh'"
    )
    assert rows
    for row in rows:
        assert list(row["roles"]) == ["lh_app"], row
        for expression in (row["qual"], row["with_check"]):
            if expression is not None:
                assert "current_tenant_id()" in expression, row
        if row["cmd"] == "UPDATE":
            assert row["qual"] is not None, row
            assert row["with_check"] is not None, row


async def test_supabase_api_roles_have_no_access(superuser: Conn) -> None:
    # The harness gave anon/authenticated default privileges on everything before the
    # migration ran; the migration must have taken them all back.
    for role in ("anon", "authenticated"):
        assert not await superuser.fetchval("select has_schema_privilege($1, 'lh', 'usage')", role)
        for table in TENANT_TABLES:
            for privilege in ("select", "insert", "update", "delete"):
                assert not await superuser.fetchval(
                    "select has_table_privilege($1, $2, $3)", role, f"lh.{table}", privilege
                ), (role, table, privilege)
        assert not await superuser.fetchval(
            "select has_function_privilege($1, 'lh.current_tenant_id()', 'execute')", role
        )


async def test_lh_app_privileges_on_audit_log(superuser: Conn) -> None:
    def check(privilege: str) -> str:
        return f"select has_table_privilege('lh_app', 'lh.audit_log', '{privilege}')"

    assert await superuser.fetchval(check("select"))
    assert await superuser.fetchval(check("insert"))
    for privilege in ("update", "delete", "truncate"):
        assert not await superuser.fetchval(check(privilege)), privilege


async def test_connection_user_without_set_role_has_no_access(app_conn: Conn) -> None:
    """If request code ever forgot SET ROLE, the API login role must fail closed."""
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.fetch("select * from lh.alerts")


async def test_python_enums_match_database_enums(superuser: Conn) -> None:
    async def labels(type_name: str) -> list[str]:
        return await superuser.fetchval(
            f"select enum_range(null::lh.{type_name})::text[]"  # noqa: S608
        )

    assert await labels("severity") == [s.value for s in Severity]
    assert await labels("member_role") == [r.value for r in Role]
    assert await labels("alert_status") == [s.value for s in AlertStatus]
