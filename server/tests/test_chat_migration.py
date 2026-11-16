"""The chat rate-limit migration, at the SQL level: tenant isolation of the counters as
`lh_app`, no reset of the current window, no access for the Supabase API roles or the
ingestion role. No application code in between, except the route's own statements.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import asyncpg
import pytest

from lighthouse.db import rls_safety_problems
from lighthouse.ingest.run import ingest_role_problems
from lighthouse.routes.chat import COUNT_REQUEST_SQL, PRUNE_RATE_WINDOWS_SQL
from tests.helpers import Conn, create_tenant

TABLE = "lh.chat_rate_limits"


@asynccontextmanager
async def as_app(conn: Conn, tenant: UUID | str | None) -> AsyncGenerator[Conn]:
    """A transaction as lh_app with `app.tenant_id` set (unset if None), rolled back."""
    tx = conn.transaction()
    await tx.start()
    try:
        await conn.execute("set local role lh_app")
        if tenant is not None:
            await conn.execute("select set_config('app.tenant_id', $1, true)", str(tenant))
        yield conn
    finally:
        await tx.rollback()


def _minute(offset: int = 0) -> datetime:
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    return now + timedelta(minutes=offset)


async def _seed(superuser: Conn, tenant: UUID, user: UUID, *, minutes_ago: int, count: int) -> None:
    await superuser.execute(
        f"insert into {TABLE} (tenant_id, user_id, window_start, request_count) "  # noqa: S608
        "values ($1, $2, $3, $4)",
        tenant,
        user,
        _minute(-minutes_ago),
        count,
    )


@pytest.fixture
async def pair(superuser: Conn) -> tuple[UUID, UUID, UUID]:
    tenant_a = await create_tenant(superuser, "Example Tenant A")
    tenant_b = await create_tenant(superuser, "Example Tenant B")
    user = uuid4()  # the same user id in both tenants: tenant must still separate them
    await _seed(superuser, tenant_a, user, minutes_ago=0, count=3)
    await _seed(superuser, tenant_b, user, minutes_ago=0, count=7)
    await _seed(superuser, tenant_b, user, minutes_ago=5, count=9)
    return tenant_a, tenant_b, user


async def test_lh_app_sees_only_its_tenants_counters(
    superuser: Conn, pair: tuple[UUID, UUID, UUID]
) -> None:
    tenant_a, tenant_b, _ = pair
    async with as_app(superuser, tenant_a) as conn:
        rows = await conn.fetch(f"select tenant_id, request_count from {TABLE}")  # noqa: S608
        assert [(r["tenant_id"], r["request_count"]) for r in rows] == [(tenant_a, 3)]
    async with as_app(superuser, tenant_b) as conn:
        counts = await conn.fetch(f"select request_count from {TABLE} order by 1")  # noqa: S608
        assert [r["request_count"] for r in counts] == [7, 9]


@pytest.mark.parametrize("tenant", [None, "", "not-a-uuid"])
async def test_without_tenant_nothing_is_visible_or_writable(
    superuser: Conn, pair: tuple[UUID, UUID, UUID], tenant: str | None
) -> None:
    _, _, user = pair
    async with as_app(superuser, tenant) as conn:
        assert await conn.fetchval(f"select count(*) from {TABLE}") == 0  # noqa: S608
    async with as_app(superuser, tenant) as conn:
        with pytest.raises(asyncpg.PostgresError):
            await conn.fetchval(COUNT_REQUEST_SQL, user)


async def test_route_counter_is_per_tenant_for_the_same_user(
    superuser: Conn, pair: tuple[UUID, UUID, UUID]
) -> None:
    tenant_a, tenant_b, user = pair
    async with as_app(superuser, tenant_a) as conn:
        # Increments tenant A's row (3 -> 4), never tenant B's (7).
        assert await conn.fetchval(COUNT_REQUEST_SQL, user) == 4
    async with as_app(superuser, tenant_b) as conn:
        assert await conn.fetchval(COUNT_REQUEST_SQL, user) == 8


async def test_cannot_insert_for_another_tenant(
    superuser: Conn, pair: tuple[UUID, UUID, UUID]
) -> None:
    tenant_a, tenant_b, _ = pair
    async with as_app(superuser, tenant_a) as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(
                f"insert into {TABLE} (tenant_id, user_id, window_start) "  # noqa: S608
                "values ($1, $2, $3)",
                tenant_b,
                uuid4(),
                _minute(),
            )


async def test_cannot_update_or_delete_another_tenants_counters(
    superuser: Conn, pair: tuple[UUID, UUID, UUID]
) -> None:
    tenant_a, tenant_b, _ = pair
    async with as_app(superuser, tenant_a) as conn:
        updated = await conn.execute(
            f"update {TABLE} set request_count = request_count + 100 "  # noqa: S608
            "where tenant_id = $1",
            tenant_b,
        )
        assert updated == "UPDATE 0"
        deleted = await conn.execute(
            f"delete from {TABLE} where tenant_id = $1",  # noqa: S608
            tenant_b,
        )
        assert deleted == "DELETE 0"
    assert (
        await superuser.fetchval(
            f"select sum(request_count) from {TABLE} where tenant_id = $1",  # noqa: S608
            tenant_b,
        )
        == 16
    )


async def test_cannot_move_a_counter_to_another_tenant(
    superuser: Conn, pair: tuple[UUID, UUID, UUID]
) -> None:
    tenant_a, tenant_b, _ = pair
    async with as_app(superuser, tenant_a) as conn:
        with pytest.raises(asyncpg.PostgresError):
            await conn.execute(f"update {TABLE} set tenant_id = $1", tenant_b)  # noqa: S608


async def test_current_window_cannot_be_deleted_but_expired_ones_are_pruned(
    superuser: Conn, pair: tuple[UUID, UUID, UUID]
) -> None:
    _, tenant_b, user = pair
    async with as_app(superuser, tenant_b) as conn:
        # A blanket delete reaches only the expired window: the policy hides the current
        # one from DELETE, so the limit cannot be reset from the request role.
        assert await conn.execute(f"delete from {TABLE}") == "DELETE 1"  # noqa: S608
        assert await conn.fetchval(f"select request_count from {TABLE}") == 7  # noqa: S608
    async with as_app(superuser, tenant_b) as conn:
        assert await conn.execute(PRUNE_RATE_WINDOWS_SQL, user) == "DELETE 1"


async def test_counts_cannot_be_lowered_even_by_the_owner(
    superuser: Conn, pair: tuple[UUID, UUID, UUID]
) -> None:
    tenant_a, _, _ = pair
    async with as_app(superuser, tenant_a) as conn:
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(f"update {TABLE} set request_count = 1")  # noqa: S608
    with pytest.raises(asyncpg.CheckViolationError):
        await superuser.execute(
            f"update {TABLE} set request_count = 1 where tenant_id = $1",  # noqa: S608
            tenant_a,
        )


@pytest.mark.parametrize(
    "assignment", ["user_id = gen_random_uuid()", "window_start = window_start - interval '1h'"]
)
async def test_identity_columns_are_immutable(
    superuser: Conn, pair: tuple[UUID, UUID, UUID], assignment: str
) -> None:
    tenant_a, _, _ = pair
    with pytest.raises(asyncpg.CheckViolationError):
        await superuser.execute(
            f"update {TABLE} set {assignment} where tenant_id = $1",  # noqa: S608
            tenant_a,
        )


async def test_count_must_be_positive(superuser: Conn) -> None:
    tenant = await create_tenant(superuser)
    with pytest.raises(asyncpg.CheckViolationError):
        await _seed(superuser, tenant, uuid4(), minutes_ago=0, count=0)


async def test_api_roles_and_ingest_role_have_no_access(superuser: Conn) -> None:
    for role in ("anon", "authenticated", "lh_ingest"):
        for privilege in ("select", "insert", "update", "delete"):
            assert not await superuser.fetchval(
                "select has_table_privilege($1, $2, $3)", role, TABLE, privilege
            ), (role, privilege)
    assert not await superuser.fetchval(
        "select has_function_privilege('authenticated', "
        "'lh.chat_rate_limits_before_update()', 'execute')"
    )
    assert await ingest_role_problems(superuser) == []


async def test_new_table_keeps_the_startup_rls_invariants(superuser: Conn) -> None:
    assert await rls_safety_problems(superuser) == []
    row = await superuser.fetchrow(
        "select relrowsecurity, relforcerowsecurity from pg_class "
        "where oid = 'lh.chat_rate_limits'::regclass"
    )
    assert row is not None
    assert row["relrowsecurity"] is True
    assert row["relforcerowsecurity"] is True
