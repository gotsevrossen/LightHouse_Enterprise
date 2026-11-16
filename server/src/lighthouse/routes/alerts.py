from __future__ import annotations

from typing import Annotated, Final, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from lighthouse.audit import record_audit
from lighthouse.auth import Principal, Role, require_role
from lighthouse.db import Pool, Record, get_pool, tenant_transaction
from lighthouse.models import AlertDetailOut, AlertOut, AlertPage, AlertStatusUpdate
from lighthouse.pagination import (
    MAX_PAGE_SIZE,
    InvalidCursorError,
    bad_cursor,
    decode_cursor,
    encode_cursor,
)

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

# These queries have no tenant predicate, on purpose. Tenant isolation is the database's
# job (RLS on lh.alerts for lh_app), and tests run these exact statements to prove that a
# query which forgets `WHERE tenant_id` still cannot see another tenant's rows. Adding an
# application-side filter here would hide a broken policy instead of exposing it.
LIST_ALERTS_SQL: Final = """
    select id, source, source_alert_id, title, source_severity, severity, status,
           summary, recommended_action, needs_human_review, created_at, updated_at,
           category, occurred_at, confidence, review_reason, triaged_at
      from lh.alerts
     order by created_at desc, id desc
     limit $1
"""

LIST_ALERTS_AFTER_SQL: Final = """
    select id, source, source_alert_id, title, source_severity, severity, status,
           summary, recommended_action, needs_human_review, created_at, updated_at,
           category, occurred_at, confidence, review_reason, triaged_at
      from lh.alerts
     where (created_at, id) < ($1, $2)
     order by created_at desc, id desc
     limit $3
"""

GET_ALERT_SQL: Final = """
    select id, source, source_alert_id, title, source_severity, severity, status,
           summary, recommended_action, needs_human_review, created_at, updated_at,
           category, occurred_at, confidence, review_reason, triaged_at
      from lh.alerts
     where id = $1
"""


# Analyst-only columns. A separate statement rather than fetching and dropping them, so a
# viewer's request never loads attacker-controlled evidence at all.
GET_ALERT_DETAIL_SQL: Final = """
    select id, source, source_alert_id, title, source_severity, severity, status,
           summary, recommended_action, needs_human_review, created_at, updated_at,
           category, occurred_at, confidence, review_reason, triaged_at,
           evidence, reasoning
      from lh.alerts
     where id = $1
"""

# Who may see raw evidence and the model's rationale (CLAUDE.md rule 10: server-side).
DETAIL_ROLE: Final = Role.ANALYST
# Who may change an alert's status. Viewers read; working the queue starts at analyst.
STATUS_ROLE: Final = Role.ANALYST

# The row lock serialises concurrent status changes, so each audit entry's "from" is the
# value that change really replaced. No tenant predicate, as above: RLS scopes the row.
LOCK_ALERT_STATUS_SQL: Final = """
    select status from lh.alerts where id = $1 for update
"""

# Only `status` is written. Severity, triage output and identity columns are not
# reachable from this statement whatever the request body says.
UPDATE_ALERT_STATUS_SQL: Final = """
    update lh.alerts set status = $2::lh.alert_status where id = $1
"""


def _to_alert(row: Record) -> AlertOut:
    return AlertOut.model_validate(dict(row.items()))


@router.get("")
async def list_alerts(
    principal: Annotated[Principal, Depends(require_role(Role.VIEWER))],
    pool: Annotated[Pool, Depends(get_pool)],
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
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


def _alert_response(row: Record, *, detailed: bool) -> AlertDetailOut | AlertOut:
    if detailed:
        return AlertDetailOut.model_validate(dict(row.items()))
    return _to_alert(row)


@router.get("/{alert_id}")
async def get_alert(
    alert_id: UUID,
    principal: Annotated[Principal, Depends(require_role(Role.VIEWER))],
    pool: Annotated[Pool, Depends(get_pool)],
) -> AlertDetailOut | AlertOut:
    detailed = principal.role.at_least(DETAIL_ROLE)
    async with tenant_transaction(pool, principal.tenant_id) as conn:
        row = await conn.fetchrow(GET_ALERT_DETAIL_SQL if detailed else GET_ALERT_SQL, alert_id)
    # 404, not 403, for another tenant's id: RLS makes it indistinguishable from an id that
    # does not exist, and the response must not confirm that it exists elsewhere.
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return _alert_response(row, detailed=detailed)


@router.patch("/{alert_id}")
async def update_alert_status(
    alert_id: UUID,
    body: AlertStatusUpdate,
    principal: Annotated[Principal, Depends(require_role(STATUS_ROLE))],
    pool: Annotated[Pool, Depends(get_pool)],
) -> AlertDetailOut | AlertOut:
    """Change an alert's status; returns what `GET /api/alerts/{id}` returns the caller."""
    detailed = principal.role.at_least(DETAIL_ROLE)
    async with tenant_transaction(pool, principal.tenant_id) as conn:
        current = await conn.fetchval(LOCK_ALERT_STATUS_SQL, alert_id)
        # 404 for another tenant's id, exactly as for GET: RLS hides the row.
        if current is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
        previous = cast("str", current)
        new = body.status.value
        # A no-op changes nothing, so it writes nothing and is not audited as a change.
        if previous != new:
            await conn.execute(UPDATE_ALERT_STATUS_SQL, alert_id, new)
            # The audited change and its audit row commit or roll back together.
            await record_audit(
                conn,
                actor=str(principal.user_id),
                action="alert.status_changed",
                target=f"alert:{alert_id}",
                detail={"from": previous, "to": new},
            )
        row = await conn.fetchrow(GET_ALERT_DETAIL_SQL if detailed else GET_ALERT_SQL, alert_id)
    if row is None:  # pragma: no cover - the row was locked in this transaction
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return _alert_response(row, detailed=detailed)
