from __future__ import annotations

from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query

from lighthouse.audit import record_audit
from lighthouse.auth import Principal, Role, require_role
from lighthouse.db import Pool, get_pool, tenant_transaction
from lighthouse.models import AuditEntryOut, AuditPage
from lighthouse.pagination import (
    MAX_PAGE_SIZE,
    InvalidCursorError,
    bad_cursor,
    decode_cursor,
    encode_cursor,
)

router = APIRouter(prefix="/api/audit", tags=["audit"])

# As with alerts, no tenant predicate: RLS on lh.audit_log scopes the rows.
LIST_AUDIT_SQL: Final = """
    select id, actor, action, target, detail, created_at
      from lh.audit_log
     order by created_at desc, id desc
     limit $1
"""

LIST_AUDIT_AFTER_SQL: Final = """
    select id, actor, action, target, detail, created_at
      from lh.audit_log
     where (created_at, id) < ($1, $2)
     order by created_at desc, id desc
     limit $3
"""


# Admin only: the audit trail shows who did what across the tenant, including other users'
# activity, which analysts and responders do not need.
@router.get("")
async def list_audit(
    principal: Annotated[Principal, Depends(require_role(Role.ADMIN))],
    pool: Annotated[Pool, Depends(get_pool)],
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
) -> AuditPage:
    after: tuple[object, int] | None = None
    if cursor is not None:
        try:
            created_at, key = decode_cursor(cursor)
            after = (created_at, int(key))
        except (InvalidCursorError, ValueError):
            raise bad_cursor() from None

    async with tenant_transaction(pool, principal.tenant_id) as conn:
        if after is None:
            rows = await conn.fetch(LIST_AUDIT_SQL, limit + 1)
        else:
            rows = await conn.fetch(LIST_AUDIT_AFTER_SQL, after[0], after[1], limit + 1)
        # Reading the audit trail is itself audited: it is the export path for tenant data.
        await record_audit(
            conn,
            actor=str(principal.user_id),
            action="audit.read",
            detail={"returned": min(len(rows), limit)},
        )

    items = [AuditEntryOut.model_validate(dict(row.items())) for row in rows[:limit]]
    next_cursor = (
        encode_cursor(items[-1].created_at, items[-1].id) if len(rows) > limit and items else None
    )
    return AuditPage(items=items, next_cursor=next_cursor)
