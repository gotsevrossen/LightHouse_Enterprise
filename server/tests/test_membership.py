"""Every authenticated request is checked against lh.memberships (auth.get_principal).

Threats: a person removed from a tenant, or demoted, keeps using a still-valid token; a
token names a tenant the user is not (or no longer) a member of. The effective role is the
lower of the token's claim and the membership row, so neither a stale token nor a row
alone raises privilege. A failed lookup is a 503, never access.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncGenerator, Callable, Sequence
from contextlib import asynccontextmanager
from typing import Any, Final
from uuid import UUID, uuid4

import asyncpg
import httpx
import pytest
from fastapi import APIRouter, FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from starlette.routing import BaseRoute

from lighthouse import auth
from lighthouse.ai.chat_model import AnthropicChatModel
from lighthouse.auth import Role, effective_role, get_principal
from lighthouse.config import Settings
from lighthouse.db import create_pool
from lighthouse.main import create_app
from tests.ai_helpers import StubAnthropic
from tests.chat_helpers import api, respond_stream, stream_events
from tests.helpers import (
    Conn,
    MemberTokens,
    TokenFactory,
    bearer,
    create_alert,
    create_tenant,
    remove_membership,
    set_membership,
)

# Every route that needs a signed-in caller, with a body that would succeed for an admin.
# `test_every_authenticated_route_is_listed` fails if a route is added and not listed here.
ROUTES: Final[list[tuple[str, str, dict[str, Any] | None]]] = [
    ("GET", "/api/me", None),
    ("GET", "/api/alerts", None),
    ("GET", "/api/alerts/{alert_id}", None),
    ("PATCH", "/api/alerts/{alert_id}", {"status": "resolved"}),
    ("GET", "/api/audit", None),
    ("GET", "/api/chat/status", None),
    ("POST", "/api/chat/stream", {"question": "Why did this fire?"}),
]
ROUTE_IDS: Final = [f"{method} {path}" for method, path, _ in ROUTES]
UNAUTHENTICATED_PATHS: Final = frozenset({"/healthz"})
FORBIDDEN: Final = {"detail": "forbidden"}
UNAVAILABLE: Final = {"detail": "unavailable"}


async def call(
    http: httpx.AsyncClient,
    *,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    token: str,
    alert_id: UUID,
) -> httpx.Response:
    return await http.request(
        method, path.format(alert_id=alert_id), json=body, headers=bearer(token)
    )


async def side_effects(superuser: Conn, *tenants: UUID) -> dict[str, Any]:
    """Everything a request could have written for these tenants."""
    audit = await superuser.fetch(
        "select tenant_id, actor, action from lh.audit_log where tenant_id = any($1) order by id",
        list(tenants),
    )
    rate = await superuser.fetchval(
        "select count(*) from lh.chat_rate_limits where tenant_id = any($1)", list(tenants)
    )
    usage = await superuser.fetchval(
        "select count(*) from lh.model_usage where tenant_id = any($1)", list(tenants)
    )
    statuses = await superuser.fetch(
        "select id, status::text from lh.alerts where tenant_id = any($1) order by id",
        list(tenants),
    )
    return {
        "audit": [tuple(r) for r in audit],
        "rate": rate,
        "usage": usage,
        "statuses": [tuple(r) for r in statuses],
    }


@asynccontextmanager
async def serve(settings: Settings) -> AsyncGenerator[tuple[FastAPI, httpx.AsyncClient]]:
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as http,
    ):
        yield app, http


# The check cannot be bypassed ------------------------------------------------------------


def _dependency_paths(dependant: Dependant, parents: tuple[object, ...] = ()) -> list[Any]:
    """Every dependency in the tree, as the chain of callables leading to it."""
    paths: list[tuple[object, ...]] = []
    for sub in dependant.dependencies:
        chain = (*parents, sub.call)
        paths.append(chain)
        paths.extend(_dependency_paths(sub, chain))
    return paths


def _api_routes(app: FastAPI) -> list[APIRoute]:
    """Every APIRoute the app serves. Included routers are kept nested by FastAPI (0.16x
    wraps them), so this descends into anything that exposes `original_router`;
    `test_route_walk_sees_every_served_route` proves it misses nothing."""
    found: list[APIRoute] = []

    def walk(routes: Sequence[BaseRoute]) -> None:
        for route in routes:
            if isinstance(route, APIRoute):
                found.append(route)
            inner: object = getattr(route, "original_router", None)
            if isinstance(inner, APIRouter):
                walk(inner.routes)

    walk(app.routes)
    return found


def _served(app: FastAPI) -> set[tuple[str, str]]:
    # A route without methods would drop out here and fail the OpenAPI cross-check.
    return {(method, route.path) for route in _api_routes(app) for method in route.methods or ()}


def test_route_walk_sees_every_served_route(settings: Settings) -> None:
    """The OpenAPI document is built from the full route table, independently of the
    walk above; if a FastAPI change hid routes from the walk, this fails."""
    app = create_app(settings)
    documented = {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
    }
    assert _served(app) == documented


def test_every_authenticated_route_is_listed(settings: Settings) -> None:
    app = create_app(settings)
    served = {(m, p) for m, p in _served(app) if p not in UNAUTHENTICATED_PATHS}
    assert served == {(method, path) for method, path, _ in ROUTES}


def test_every_authenticated_route_goes_through_the_membership_check(
    settings: Settings,
) -> None:
    app = create_app(settings)
    routes = [r for r in _api_routes(app) if r.path not in UNAUTHENTICATED_PATHS]
    assert routes
    for route in routes:
        chains = _dependency_paths(route.dependant)
        calls = {chain[-1] for chain in chains}
        assert get_principal in calls, route.path
        # The token-only dependency is reached solely through get_principal: no route can
        # get a principal that skipped the membership lookup.
        token_only = [c for c in chains if getattr(c[-1], "__name__", "") == "_token_principal"]
        assert token_only, route.path
        assert all(len(c) >= 2 and c[-2] is get_principal for c in token_only), route.path


def test_healthz_stays_unauthenticated(settings: Settings) -> None:
    app = create_app(settings)
    (health,) = [r for r in _api_routes(app) if r.path == "/healthz"]
    assert get_principal not in {chain[-1] for chain in _dependency_paths(health.dependant)}


# Effective role --------------------------------------------------------------------------


@pytest.mark.parametrize("token_role", list(Role))
@pytest.mark.parametrize("member_role", list(Role))
def test_effective_role_is_the_lower_of_token_and_membership(
    token_role: Role, member_role: Role
) -> None:
    result = effective_role(token_role, member_role)
    assert result.rank == min(token_role.rank, member_role.rank)
    assert result in {token_role, member_role}


# Removed member --------------------------------------------------------------------------


@pytest.mark.parametrize(("method", "path", "body"), ROUTES, ids=ROUTE_IDS)
async def test_removed_member_is_refused_on_every_route(
    *,
    client: httpx.AsyncClient,
    members: MemberTokens,
    superuser: Conn,
    method: str,
    path: str,
    body: dict[str, Any] | None,
) -> None:
    tenant = await create_tenant(superuser)
    alert_id = await create_alert(superuser, tenant)
    user = uuid4()
    token = await members.token(tenant, role="admin", user_id=user)
    # The token is valid and was working a moment ago.
    assert (await client.get("/api/me", headers=bearer(token))).status_code == 200

    await remove_membership(superuser, tenant, user)
    before = await side_effects(superuser, tenant)
    response = await call(
        client, method=method, path=path, body=body, token=token, alert_id=alert_id
    )
    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert await side_effects(superuser, tenant) == before


async def test_removal_and_readmission_take_effect_on_the_next_request(
    client: httpx.AsyncClient, members: MemberTokens, superuser: Conn
) -> None:
    """No membership cache: each request sees the row as it is now, in both directions."""
    tenant = await create_tenant(superuser)
    user = uuid4()
    token = await members.token(tenant, role="analyst", user_id=user)
    first = await client.get("/api/me", headers=bearer(token))
    assert first.json()["role"] == "analyst"

    await remove_membership(superuser, tenant, user)
    assert (await client.get("/api/me", headers=bearer(token))).status_code == 403

    await set_membership(superuser, tenant, user, "viewer")
    again = await client.get("/api/me", headers=bearer(token))
    assert again.status_code == 200
    assert again.json()["role"] == "viewer"


# Demoted member --------------------------------------------------------------------------


async def test_demoted_member_gets_viewer_behaviour(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn
) -> None:
    tenant = await create_tenant(superuser)
    alert_id = await create_alert(superuser, tenant)
    await superuser.execute(
        "update lh.alerts set evidence = '{\"k\": \"v\"}'::jsonb, reasoning = 'r' where id = $1",
        alert_id,
    )
    user = uuid4()
    # The token still says admin; the database says the person was demoted to viewer.
    await set_membership(superuser, tenant, user, "viewer")
    token = tokens.token(tenant, role="admin", user_id=user)

    me = await client.get("/api/me", headers=bearer(token))
    assert me.status_code == 200
    assert me.json()["role"] == "viewer"

    before = await side_effects(superuser, tenant)
    patched = await client.patch(
        f"/api/alerts/{alert_id}", json={"status": "resolved"}, headers=bearer(token)
    )
    assert patched.status_code == 403
    assert patched.json() == FORBIDDEN
    audit = await client.get("/api/audit", headers=bearer(token))
    assert audit.status_code == 403
    assert await side_effects(superuser, tenant) == before

    # Viewer projection: no evidence or model reasoning.
    detail = await client.get(f"/api/alerts/{alert_id}", headers=bearer(token))
    assert detail.status_code == 200
    assert not {"evidence", "reasoning"} & set(detail.json())


async def test_lower_token_role_wins_over_a_higher_membership(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn
) -> None:
    """Promotion in the database alone does not raise privilege until the token is
    refreshed with the new claim."""
    tenant = await create_tenant(superuser)
    alert_id = await create_alert(superuser, tenant)
    user = uuid4()
    await set_membership(superuser, tenant, user, "admin")
    token = tokens.token(tenant, role="viewer", user_id=user)

    me = await client.get("/api/me", headers=bearer(token))
    assert me.json()["role"] == "viewer"
    patched = await client.patch(
        f"/api/alerts/{alert_id}", json={"status": "resolved"}, headers=bearer(token)
    )
    assert patched.status_code == 403
    assert (await client.get("/api/audit", headers=bearer(token))).status_code == 403

    # Once the refreshed token carries the new claim, both sources agree.
    refreshed = tokens.token(tenant, role="admin", user_id=user)
    assert (await client.get("/api/me", headers=bearer(refreshed))).json()["role"] == "admin"
    assert (await client.get("/api/audit", headers=bearer(refreshed))).status_code == 200


# A token naming another tenant -------------------------------------------------------------


@pytest.mark.parametrize(("method", "path", "body"), ROUTES, ids=ROUTE_IDS)
async def test_token_naming_a_tenant_the_user_does_not_belong_to_is_refused(
    *,
    client: httpx.AsyncClient,
    tokens: TokenFactory,
    superuser: Conn,
    method: str,
    path: str,
    body: dict[str, Any] | None,
) -> None:
    tenant_a = await create_tenant(superuser, "Example Tenant A")
    tenant_b = await create_tenant(superuser, "Example Tenant B")
    alert_a = await create_alert(superuser, tenant_a, title="Alert of tenant A")
    alert_b = await create_alert(superuser, tenant_b, title="Alert of tenant B")
    user = uuid4()
    await set_membership(superuser, tenant_a, user, "admin")
    # Correctly signed, but app_metadata names tenant B, where this user has no row.
    token_b = tokens.token(tenant_b, role="admin", user_id=user)
    # Same user and claims, naming a tenant that does not exist at all.
    token_none = tokens.token(uuid4(), role="admin", user_id=user)

    before = await side_effects(superuser, tenant_a, tenant_b)
    for alert_id in (alert_a, alert_b):
        response = await call(
            client, method=method, path=path, body=body, token=token_b, alert_id=alert_id
        )
        assert response.status_code == 403
        assert response.json() == FORBIDDEN
        for leak in ("Alert of tenant", "Example Tenant", str(alert_a), str(alert_b)):
            assert leak not in response.text
        # Indistinguishable from a tenant that does not exist.
        absent = await call(
            client, method=method, path=path, body=body, token=token_none, alert_id=alert_id
        )
        assert (absent.status_code, absent.json()) == (403, FORBIDDEN)
    assert await side_effects(superuser, tenant_a, tenant_b) == before


# Database failure ------------------------------------------------------------------------


class _FailingPool:
    """Stands in for the pool: every acquire fails the way a broken database does."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def acquire(self) -> Any:
        raise self._exc


FAILURES: Final[list[tuple[str, Callable[[], BaseException]]]] = [
    ("connection-lost", lambda: asyncpg.ConnectionDoesNotExistError("gone")),
    ("server-error", lambda: asyncpg.InsufficientPrivilegeError("denied")),
    ("pool-closed", lambda: asyncpg.InterfaceError("pool is closed")),
    ("refused", lambda: ConnectionRefusedError("refused")),
    ("timeout", TimeoutError),
]


@pytest.mark.parametrize("make_exc", [f for _, f in FAILURES], ids=[n for n, _ in FAILURES])
async def test_database_failure_during_lookup_is_503(
    settings: Settings,
    members: MemberTokens,
    superuser: Conn,
    caplog: pytest.LogCaptureFixture,
    make_exc: Callable[[], BaseException],
) -> None:
    caplog.set_level(logging.DEBUG)
    tenant = await create_tenant(superuser)
    token = await members.token(tenant, role="admin")
    async with serve(settings) as (app, http):
        real_pool = app.state.pool
        app.state.pool = _FailingPool(make_exc())
        try:
            response = await http.get("/api/me", headers=bearer(token))
        finally:
            app.state.pool = real_pool
    assert response.status_code == 503
    assert response.json() == UNAVAILABLE
    assert "membership lookup failed" in caplog.text
    assert token not in caplog.text


async def test_closed_pool_is_503(
    settings: Settings, members: MemberTokens, superuser: Conn
) -> None:
    tenant = await create_tenant(superuser)
    token = await members.token(tenant, role="admin")
    closed = await create_pool(settings)
    await closed.close()
    async with serve(settings) as (app, http):
        real_pool = app.state.pool
        app.state.pool = closed
        try:
            response = await http.get("/api/alerts", headers=bearer(token))
        finally:
            app.state.pool = real_pool
    assert (response.status_code, response.json()) == (503, UNAVAILABLE)


async def test_lookup_timing_out_on_a_real_database_is_503(
    settings: Settings,
    members: MemberTokens,
    superuser: Conn,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The lookup blocks on a lock until the command timeout fires: still no access."""
    tenant = await create_tenant(superuser)
    token = await members.token(tenant, role="admin")
    async with serve(settings.model_copy(update={"db_command_timeout_seconds": 0.5})) as (
        _,
        http,
    ):
        async with superuser.transaction():
            await superuser.execute("lock table lh.memberships in access exclusive mode")
            response = await http.get("/api/me", headers=bearer(token))
        assert (response.status_code, response.json()) == (503, UNAVAILABLE)
        # The pool recovers once the database does.
        assert (await http.get("/api/me", headers=bearer(token))).status_code == 200
    assert "membership lookup failed: TimeoutError" in caplog.text


async def test_unrecognised_membership_role_is_503(
    client: httpx.AsyncClient,
    members: MemberTokens,
    superuser: Conn,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A database role this code does not know (schema drift) grants nothing."""
    tenant = await create_tenant(superuser)
    token = await members.token(tenant, role="admin")
    monkeypatch.setattr(
        auth,
        "MEMBERSHIP_ROLE_SQL",
        "select 'owner'::text from lh.memberships where user_id = $1",
    )
    response = await client.get("/api/me", headers=bearer(token))
    assert (response.status_code, response.json()) == (503, UNAVAILABLE)


# Chat ------------------------------------------------------------------------------------


async def test_chat_stream_refuses_non_members_before_any_model_call_or_write(
    settings: Settings, tokens: TokenFactory, superuser: Conn
) -> None:
    tenant_a = await create_tenant(superuser, "Example Tenant A")
    tenant_b = await create_tenant(superuser, "Example Tenant B")
    alert_b = await create_alert(superuser, tenant_b)
    removed, outsider = uuid4(), uuid4()
    await set_membership(superuser, tenant_a, outsider, "admin")
    await set_membership(superuser, tenant_b, removed, "admin")
    await remove_membership(superuser, tenant_b, removed)
    refused = [
        tokens.token(tenant_b, role="admin", user_id=removed),  # removed from B
        tokens.token(tenant_b, role="admin", user_id=outsider),  # member of A only
        tokens.token(tenant_b, role="admin"),  # never a member
    ]
    stub = StubAnthropic(respond_stream(stream_events(["should never be sent"])))
    before = await side_effects(superuser, tenant_a, tenant_b)
    async with api(settings, AnthropicChatModel(stub.client(), settings)) as http:
        for token in refused:
            for body in ({"question": "Why?"}, {"question": "Why?", "alert_id": str(alert_b)}):
                response = await http.post("/api/chat/stream", json=body, headers=bearer(token))
                assert response.status_code == 403
                assert response.json() == FORBIDDEN
                assert response.headers["content-type"] == "application/json"
    assert stub.requests == []
    # No rate-limit row, no usage row, no audit entry, in either tenant.
    after = await side_effects(superuser, tenant_a, tenant_b)
    assert after == before
    assert after["rate"] == 0
    assert after["usage"] == 0


async def test_chat_stream_works_for_a_member_with_the_same_harness(
    settings: Settings, members: MemberTokens, superuser: Conn
) -> None:
    """Control for the test above: the same request from a member is answered."""
    tenant = await create_tenant(superuser)
    stub = StubAnthropic(respond_stream(stream_events(["Answer."])))
    async with api(settings, AnthropicChatModel(stub.client(), settings)) as http:
        response = await http.post(
            "/api/chat/stream",
            json={"question": "Why?"},
            headers=bearer(await members.token(tenant)),
        )
    assert response.status_code == 200
    assert json.loads(response.text.splitlines()[-1]) == {"type": "done"}
    assert len(stub.requests) == 1
