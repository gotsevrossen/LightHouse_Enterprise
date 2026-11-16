"""Application factory.

Run with `uvicorn --factory lighthouse.main:create_app`. Nothing reads configuration at
import time, so tests build apps with their own settings and no environment.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response

from lighthouse.ai.chat_model import build_chat_model
from lighthouse.auth import TokenVerifier, build_verifier
from lighthouse.chat import ChatModel
from lighthouse.config import Settings, load_settings
from lighthouse.db import create_pool
from lighthouse.routes import alerts, audit, chat, health, me


def create_app(
    settings: Settings | None = None,
    verifier: TokenVerifier | None = None,
    chat_model: ChatModel | None = None,
) -> FastAPI:
    resolved = settings if settings is not None else load_settings()
    # Built without I/O. Without an Anthropic credential (or with chat disabled) it reports
    # itself unavailable and the rest of the API serves normally.
    resolved_chat = chat_model if chat_model is not None else build_chat_model(resolved)

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
            await resolved_chat.aclose()

    app = FastAPI(
        title="LightHouse Enterprise API",
        lifespan=lifespan,
        docs_url="/docs" if resolved.dev else None,
        redoc_url=None,
        openapi_url="/openapi.json" if resolved.dev else None,
    )
    app.state.verifier = verifier if verifier is not None else build_verifier(resolved)
    app.state.settings = resolved
    app.state.chat_model = resolved_chat

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
    app.include_router(chat.router)
    return app
