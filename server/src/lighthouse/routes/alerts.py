from __future__ import annotations

from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from lighthouse.auth import Principal, Role, require_role
from lighthouse.db import Pool, Record, get_pool, tenant_transaction
from lighthouse.models import AlertOut, AlertPage
from lighthouse.pagination import InvalidCursorError, bad_cursor, decode_cursor, encode_cursor

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

# These queries have no tenant predicate, on purpose. Tenant isolation is the database's
# job (RLS on lh.alerts for lh_app), and tests run these exact statements to prove that a
# query which forgets `WHERE tenant_id` still cannot see another tenant's rows. Adding an
# application-side filter here would hide a broken policy instead of exposing it.
LIST_ALERTS_SQL: Final = """
    select id, source, source_alert_id, title, source_severity, severity, status,
           summary, recommended_action, needs_human_review, created_at, updated_at
      from lh.alerts
     order by created_at desc, id desc
     limit $1
"""

LIST_ALERTS_AFTER_SQL: Final = """
    select id, source, source_alert_id, title, source_severity, severity, status,
           summary, recommended_action, needs_human_review, created_at, updated_at
      from lh.alerts
     where (created_at, id) < ($1, $2)
     order by created_at desc, id desc
     limit $3
"""

GET_ALERT_SQL: Final = """
    select id, source, source_alert_id, title, source_severity, severity, status,
           summary, recommended_action, needs_human_review, created_at, updated_at
      from lh.alerts
     where id = $1
"""


def _to_alert(row: Record) -> AlertOut:
    return AlertOut.model_validate(dict(row.items()))


@router.get("")
async def list_alerts(
    principal: Annotated[Principal, Depends(require_role(Role.VIEWER))],
    pool: Annotated[Pool, Depends(get_pool)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
) -> AlertPage:
    after: tuple[object, UUID] | None = None
    if cursor is not None:
        try:
            created_at, key = decode_cursor(cursor)
            after = (created_at, UUID(key))
        except (InvalidCursorError, ValueError):
            raise bad_cursor() from None

    async with tenant_transaction(pool, principal.tenant_id) as conn:
        # One extra row tells us whether there is a next page without a count query.
        if after is None:
            rows = await conn.fetch(LIST_ALERTS_SQL, limit + 1)
        else:
            rows = await conn.fetch(LIST_ALERTS_AFTER_SQL, after[0], after[1], limit + 1)

    items = [_to_alert(row) for row in rows[:limit]]
    next_cursor = (
        encode_cursor(items[-1].created_at, items[-1].id) if len(rows) > limit and items else None
    )
    return AlertPage(items=items, next_cursor=next_cursor)


@router.get("/{alert_id}")
async def get_alert(
    alert_id: UUID,
    principal: Annotated[Principal, Depends(require_role(Role.VIEWER))],
    pool: Annotated[Pool, Depends(get_pool)],
) -> AlertOut:
    async with tenant_transaction(pool, principal.tenant_id) as conn:
        row = await conn.fetchrow(GET_ALERT_SQL, alert_id)
    # 404, not 403, for another tenant's id: RLS makes it indistinguishable from an id that
    # does not exist, and the response must not confirm that it exists elsewhere.
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return _to_alert(row)
