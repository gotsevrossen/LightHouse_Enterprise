from __future__ import annotations

import json
import math
from uuid import uuid4

import asyncpg
import pytest

from lighthouse.audit import (
    MAX_DETAIL_BYTES,
    REDACTED,
    AuditError,
    prepare_detail,
    record_audit,
)
from lighthouse.db import Pool, tenant_transaction
from tests.helpers import Conn, create_tenant


async def test_record_audit_writes_in_the_callers_tenant(superuser: Conn, app_pool: Pool) -> None:
    tenant_a = await create_tenant(superuser, "Example Tenant A")
    tenant_b = await create_tenant(superuser, "Example Tenant B")
    action = f"test.{uuid4()}"
    async with tenant_transaction(app_pool, tenant_a) as conn:
        await record_audit(
            conn, actor="user:example", action=action, target="alert:1", detail={"n": 1}
        )
    rows = await superuser.fetch(
        "select tenant_id, actor, target, detail from lh.audit_log where action = $1", action
    )
    assert len(rows) == 1
    assert rows[0]["tenant_id"] == tenant_a
    assert rows[0]["tenant_id"] != tenant_b
    assert rows[0]["actor"] == "user:example"
    assert rows[0]["target"] == "alert:1"
    # The raw superuser connection has no jsonb codec, so the value arrives as text.
    assert json.loads(rows[0]["detail"]) == {"n": 1}


async def test_record_audit_rolls_back_with_the_callers_transaction(
    superuser: Conn, app_pool: Pool
) -> None:
    tenant = await create_tenant(superuser)
    action = f"test.{uuid4()}"
    with pytest.raises(RuntimeError, match="boom"):
        async with tenant_transaction(app_pool, tenant) as conn:
            await record_audit(conn, actor="user:example", action=action)
            msg = "boom"
            raise RuntimeError(msg)
    assert await superuser.fetchval("select count(*) from lh.audit_log where action = $1", action) == 0


async def test_record_audit_refuses_outside_a_transaction(app_conn: Conn) -> None:
    with pytest.raises(AuditError):
        await record_audit(app_conn, actor="user:example", action="x")


async def test_record_audit_fails_without_a_tenant(app_conn: Conn) -> None:
    tx = app_conn.transaction()
    await tx.start()
    try:
        await app_conn.execute("set local role lh_app")
        with pytest.raises(asyncpg.PostgresError):
            await record_audit(app_conn, actor="user:example", action="x")
    finally:
        await tx.rollback()


def test_sensitive_keys_are_redacted_recursively() -> None:
    detail = prepare_detail(
        {
            "Authorization": "Bearer abc",
            "nested": {"api_key": "k", "ok": "v", "items": [{"password": "p", "n": 2}]},
            "refresh_token": "t",
            "count": 3,
        }
    )
    assert detail == {
        "Authorization": REDACTED,
        "nested": {"api_key": REDACTED, "ok": "v", "items": [{"password": REDACTED, "n": 2}]},
        "refresh_token": REDACTED,
        "count": 3,
    }


def test_oversized_detail_is_replaced_by_its_size() -> None:
    detail = prepare_detail({"blob": "x" * (MAX_DETAIL_BYTES + 1)})
    assert detail["truncated"] is True
    assert isinstance(detail["original_bytes"], int)
    assert detail["original_bytes"] > MAX_DETAIL_BYTES


def test_non_json_numbers_are_refused() -> None:
    with pytest.raises(AuditError):
        prepare_detail({"value": math.nan})
