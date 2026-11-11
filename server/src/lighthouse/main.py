"""Application factory.

Run with `uvicorn --factory lighthouse.main:create_app`. Nothing reads configuration at
import time, so tests build apps with their own settings and no environment.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response

from lighthouse.auth import TokenVerifier, build_verifier
from lighthouse.config import Settings, load_settings
from lighthouse.db import create_pool
from lighthouse.routes import alerts, audit, health, me


def create_app(settings: Settings | None = None, verifier: TokenVerifier | None = None) -> FastAPI:
    resolved = settings if settings is not None else load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        # create_pool refuses to return if RLS could be bypassed; the app then fails to
        # start rather than serve requests without tenant isolation.
        pool = await create_pool(resolved)
        app.state.pool = pool
        try:
            yield
        finally:
            await pool.close()

    app = FastAPI(
        title="LightHouse Enterprise API",
        lifespan=lifespan,
        docs_url="/docs" if resolved.dev else None,
        redoc_url=None,
        openapi_url="/openapi.json" if resolved.dev else None,
    )
    app.state.verifier = verifier if verifier is not None else build_verifier(resolved)

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        # API responses carry tenant security data: keep them out of shared and browser
        # caches, and stop browsers from sniffing JSON into something executable.
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    app.include_router(health.router)
    app.include_router(me.router)
    app.include_router(alerts.router)
    app.include_router(audit.router)
    return app
