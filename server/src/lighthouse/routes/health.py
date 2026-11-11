from __future__ import annotations

from fastapi import APIRouter

from lighthouse.models import HealthOut

router = APIRouter(tags=["health"])


# Liveness only. Unauthenticated, so it says nothing about version, configuration or the
# database: anything here is visible to the whole internet.
@router.get("/healthz")
async def healthz() -> HealthOut:
    return HealthOut(status="ok")
