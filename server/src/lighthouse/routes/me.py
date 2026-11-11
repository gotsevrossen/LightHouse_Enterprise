from __future__ import annotations

from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, status

from lighthouse.auth import Principal, Role, require_role
from lighthouse.db import Pool, get_pool, tenant_transaction
from lighthouse.models import MeOut

router = APIRouter(prefix="/api", tags=["me"])


@router.get("/me")
async def me(
    principal: Annotated[Principal, Depends(require_role(Role.VIEWER))],
    pool: Annotated[Pool, Depends(get_pool)],
) -> MeOut:
    async with tenant_transaction(pool, principal.tenant_id) as conn:
        name = await conn.fetchval("select name from lh.tenants")
    # A correctly signed token naming a tenant that does not exist (deleted, or a claim set
    # by mistake) gets no access rather than an empty but working session.
    if name is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    return MeOut(
        user_id=principal.user_id,
        tenant_id=principal.tenant_id,
        tenant_name=cast("str", name),
        role=principal.role,
    )
