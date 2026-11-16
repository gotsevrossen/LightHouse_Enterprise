"""The triage migration: tenant isolation of `lh.model_usage` and of the new alert columns,
append-only usage for the request role, and the backstop constraints.

Every check runs as `lh_app` through the API's login role, which is how request handling
and the ingest pipeline reach the database.
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from uuid import UUID

import asyncpg
import pytest

from lighthouse.triage import ReviewReason
from tests.helpers import Conn, create_alert, create_tenant

_INSERT_USAGE = """
    insert into lh.model_usage (tenant_id, purpose, model, input_tokens, outcome)
    values ($1, 'triage', 'fixture-model', $2, 'completed')
"""


@asynccontextmanager
async def as_app(conn: Conn, tenant: UUID | None) -> AsyncGenerator[Conn]:
    """A rolled-back transaction as lh_app, scoped to `tenant` (unset if None)."""
    tx = conn.transaction()
    await tx.start()
    try:
        await conn.execute("set local role lh_app")
        if tenant is not None:
            await conn.execute("select set_config('app.tenant_id', $1, true)", str(tenant))
        yield conn
    finally:
        await tx.rollback()


async def _seed(superuser: Conn) -> tuple[UUID, UUID, UUID, UUID]:
    tenant_a = await create_tenant(superuser, "Example Tenant A")
    tenant_b = await create_tenant(superuser, "Example Tenant B")
    alerts: list[UUID] = []
    for tenant, tokens in ((tenant_a, 111), (tenant_b, 222)):
        await superuser.execute(_INSERT_USAGE, tenant, tokens)
        alert = await create_alert(superuser, tenant)
        await superuser.execute(
            "update lh.alerts set evidence = $2::jsonb, reasoning = 'r', confidence = 0.5"
            " where id = $1",
            alert,
            '{"host_name": "secret-host"}',
        )
        alerts.append(alert)
    return tenant_a, tenant_b, alerts[0], alerts[1]


async def test_model_usage_reads_are_tenant_scoped(superuser: Conn, app_conn: Conn) -> None:
    tenant_a, tenant_b, _, _ = await _seed(superuser)
    async with as_app(app_conn, tenant_a) as conn:
        rows = await conn.fetch("select tenant_id, input_tokens from lh.model_usage")
    assert {r["tenant_id"] for r in rows} == {tenant_a}
    async with as_app(app_conn, tenant_b) as conn:
        rows = await conn.fetch("select tenant_id from lh.model_usage")
    assert {r["tenant_id"] for r in rows} == {tenant_b}


async def test_model_usage_without_tenant_shows_nothing_and_accepts_nothing(
    superuser: Conn, app_conn: Conn
) -> None:
    tenant_a, _, _, _ = await _seed(superuser)
    async with as_app(app_conn, None) as conn:
        assert await conn.fetchval("select count(*) from lh.model_usage") == 0
    async with as_app(app_conn, None) as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(_INSERT_USAGE, tenant_a, 1)


async def test_model_usage_cannot_be_filed_under_another_tenant(
    superuser: Conn, app_conn: Conn
) -> None:
    tenant_a, tenant_b, _, _ = await _seed(superuser)
    async with as_app(app_conn, tenant_a) as conn:
        await conn.execute(_INSERT_USAGE, tenant_a, 5)  # own tenant: allowed
    async with as_app(app_conn, tenant_a) as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(_INSERT_USAGE, tenant_b, 5)


@pytest.mark.parametrize(
    "statement",
    [
        "update lh.model_usage set input_tokens = 0",
        "delete from lh.model_usage",
        "truncate lh.model_usage",
    ],
)
async def test_model_usage_is_append_only_for_lh_app(
    superuser: Conn, app_conn: Conn, statement: str
) -> None:
    tenant_a, _, _, _ = await _seed(superuser)
    async with as_app(app_conn, tenant_a) as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(statement)


async def test_model_usage_update_is_blocked_even_for_the_owner(superuser: Conn) -> None:
    await _seed(superuser)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await superuser.execute("update lh.model_usage set input_tokens = 0")


async def test_new_alert_columns_are_tenant_scoped(superuser: Conn, app_conn: Conn) -> None:
    tenant_a, _, alert_a, alert_b = await _seed(superuser)
    async with as_app(app_conn, tenant_a) as conn:
        visible = await conn.fetch("select id, evidence, reasoning from lh.alerts")
        assert {r["id"] for r in visible} == {alert_a}
        # Another tenant's evidence cannot be read or overwritten by id either.
        assert await conn.fetchval("select evidence from lh.alerts where id = $1", alert_b) is None
        result = await conn.execute(
            "update lh.alerts set reasoning = 'x', review_reason = 'refusal',"
            " needs_human_review = true where id = $1",
            alert_b,
        )
        assert result == "UPDATE 0"


async def test_model_usage_has_forced_rls_and_lh_app_policies_only(superuser: Conn) -> None:
    row = await superuser.fetchrow(
        "select relrowsecurity, relforcerowsecurity from pg_class"
        " where oid = 'lh.model_usage'::regclass"
    )
    assert row is not None
    assert (row["relrowsecurity"], row["relforcerowsecurity"]) == (True, True)
    policies = await superuser.fetch(
        "select cmd, roles, qual, with_check from pg_policies"
        " where schemaname = 'lh' and tablename = 'model_usage'"
    )
    assert sorted(p["cmd"] for p in policies) == ["INSERT", "SELECT"]
    for policy in policies:
        assert list(policy["roles"]) == ["lh_app"]
        expression = policy["qual"] or policy["with_check"]
        assert "current_tenant_id()" in expression


async def test_supabase_api_roles_cannot_reach_model_usage(superuser: Conn) -> None:
    # The harness granted anon/authenticated default privileges before migrating.
    for role in ("anon", "authenticated"):
        for privilege in ("select", "insert", "update", "delete"):
            assert not await superuser.fetchval(
                "select has_table_privilege($1, 'lh.model_usage', $2)", role, privilege
            ), (role, privilege)
        assert not await superuser.fetchval(
            "select has_function_privilege($1, 'lh.model_usage_no_update()', 'execute')", role
        )


async def test_review_reason_constraint_matches_python_enum(superuser: Conn) -> None:
    definition = await superuser.fetchval(
        "select pg_get_constraintdef(oid) from pg_constraint"
        " where conname = 'alerts_review_reason_known'"
    )
    assert isinstance(definition, str)
    in_database = set(re.findall(r"'([a-z_]+)'::text", definition))
    assert in_database == {reason.value for reason in ReviewReason}


async def test_review_reason_requires_needs_review(superuser: Conn) -> None:
    tenant = await create_tenant(superuser)
    alert = await create_alert(superuser, tenant)
    with pytest.raises(asyncpg.CheckViolationError):
        await superuser.execute(
            "update lh.alerts set review_reason = 'refusal', needs_human_review = false"
            " where id = $1",
            alert,
        )
    with pytest.raises(asyncpg.CheckViolationError):
        await superuser.execute(
            "update lh.alerts set review_reason = 'made_up', needs_human_review = true"
            " where id = $1",
            alert,
        )


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("confidence", "1.5"),
        ("confidence", "-0.1"),
        ("content_hash", "'not-a-hash'"),
        ("evidence", "'[]'::jsonb"),
        ("evidence", "jsonb_build_object('blob', repeat('x', 70000))"),
        ("triage_claim", "gen_random_uuid()"),  # a claim without its timestamp
    ],
)
async def test_new_alert_columns_have_backstop_checks(
    superuser: Conn, column: str, value: str
) -> None:
    tenant = await create_tenant(superuser)
    alert = await create_alert(superuser, tenant)
    with pytest.raises(asyncpg.CheckViolationError):
        await superuser.execute(f"update lh.alerts set {column} = {value} where id = $1", alert)  # noqa: S608


async def test_identity_and_floor_rules_still_hold_with_new_columns(superuser: Conn) -> None:
    tenant = await create_tenant(superuser)
    alert = await create_alert(superuser, tenant, source_severity="high")
    with pytest.raises(asyncpg.CheckViolationError):
        await superuser.execute(
            "update lh.alerts set source_severity = 'low', severity = 'low',"
            " evidence = '{}'::jsonb where id = $1",
            alert,
        )
    with pytest.raises(asyncpg.CheckViolationError):
        await superuser.execute(
            "update lh.alerts set source_alert_id = 'other', category = 'c' where id = $1", alert
        )
