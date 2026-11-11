"""Phase 0 done-criterion: through the HTTP API, a signed-in user of tenant A cannot read
tenant B's rows, and it is the database (RLS), not a WHERE clause, that stops it.

The alert routes deliberately contain no tenant predicate (see routes/alerts.py).
`test_route_sql_alone_would_leak` runs those exact statements as a superuser, which
bypasses RLS, and shows they would return both tenants' rows; the API tests show that the
same statements return only the caller's rows when run as lh_app.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest

from lighthouse.config import Settings
from lighthouse.db import UnsafeDatabaseConfigError, create_pool
from lighthouse.main import create_app
from lighthouse.routes.alerts import GET_ALERT_SQL, LIST_ALERTS_SQL
from tests.helpers import Conn, TokenFactory, bearer, create_alert, create_tenant


@dataclass(frozen=True)
class TwoTenants:
    tenant_a: UUID
    tenant_b: UUID
    alerts_a: frozenset[UUID]
    alerts_b: frozenset[UUID]


@pytest.fixture
async def two_tenants(superuser: Conn) -> TwoTenants:
    tenant_a = await create_tenant(superuser, "Example Tenant A")
    tenant_b = await create_tenant(superuser, "Example Tenant B")
    alerts_a = {await create_alert(superuser, tenant_a, title=f"A{i}") for i in range(3)}
    alerts_b = {
        await create_alert(superuser, tenant_b, title=f"B{i}", source_severity="critical")
        for i in range(3)
    }
    return TwoTenants(tenant_a, tenant_b, frozenset(alerts_a), frozenset(alerts_b))


async def _list_all(client: httpx.AsyncClient, token: str) -> list[dict[str, Any]]:
    response = await client.get("/api/alerts", params={"limit": 200}, headers=bearer(token))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["next_cursor"] is None
    return body["items"]


# Health and surface --------------------------------------------------------------------


async def test_healthz_needs_no_auth_and_reveals_nothing(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
async def test_docs_are_not_exposed_by_default(client: httpx.AsyncClient, path: str) -> None:
    assert (await client.get(path)).status_code == 404


async def test_docs_are_exposed_in_dev(settings: Settings) -> None:
    app = create_app(settings.model_copy(update={"dev": True}))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        assert (await http.get("/openapi.json")).status_code == 200
        assert (await http.get("/docs")).status_code == 200


async def test_security_headers(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


# Authentication at the HTTP edge ----------------------------------------------------------


@pytest.mark.parametrize("path", ["/api/me", "/api/alerts", f"/api/alerts/{uuid4()}", "/api/audit"])
async def test_routes_require_a_token(client: httpx.AsyncClient, path: str) -> None:
    response = await client.get(path)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


async def test_non_bearer_scheme_is_rejected(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/me", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert response.status_code == 401


async def test_expired_token_is_401(
    client: httpx.AsyncClient, tokens: TokenFactory, two_tenants: TwoTenants
) -> None:
    claims = tokens.claims(tenant_id=two_tenants.tenant_a)
    claims["iat"] -= 7200
    claims["exp"] = claims["iat"] + 60
    response = await client.get("/api/alerts", headers=bearer(tokens.sign(claims)))
    assert response.status_code == 401
    assert response.json() == {"detail": "not authenticated"}


async def test_tenant_only_in_user_metadata_is_403(
    client: httpx.AsyncClient, tokens: TokenFactory, two_tenants: TwoTenants
) -> None:
    claims = tokens.claims(tenant_id=None, role="admin")
    claims["user_metadata"] = {"tenant_id": str(two_tenants.tenant_b), "role": "admin"}
    response = await client.get("/api/alerts", headers=bearer(tokens.sign(claims)))
    assert response.status_code == 403


async def test_token_signed_by_another_key_is_401(
    client: httpx.AsyncClient, two_tenants: TwoTenants
) -> None:
    attacker = TokenFactory.generate()
    response = await client.get(
        "/api/alerts", headers=bearer(attacker.token(two_tenants.tenant_b, role="admin"))
    )
    assert response.status_code == 401


# /api/me -------------------------------------------------------------------------------


async def test_me_returns_principal(
    client: httpx.AsyncClient, tokens: TokenFactory, two_tenants: TwoTenants
) -> None:
    user_id = uuid4()
    token = tokens.token(two_tenants.tenant_a, role="analyst", user_id=user_id)
    response = await client.get("/api/me", headers=bearer(token))
    assert response.status_code == 200
    assert response.json() == {
        "user_id": str(user_id),
        "tenant_id": str(two_tenants.tenant_a),
        "tenant_name": "Example Tenant A",
        "role": "analyst",
    }


async def test_me_for_unknown_tenant_is_403(
    client: httpx.AsyncClient, tokens: TokenFactory
) -> None:
    response = await client.get("/api/me", headers=bearer(tokens.token(uuid4())))
    assert response.status_code == 403


# Cross-tenant isolation through the API -------------------------------------------------


async def test_tenant_a_lists_only_its_alerts(
    client: httpx.AsyncClient, tokens: TokenFactory, two_tenants: TwoTenants
) -> None:
    items = await _list_all(client, tokens.token(two_tenants.tenant_a))
    assert {UUID(item["id"]) for item in items} == two_tenants.alerts_a

    items = await _list_all(client, tokens.token(two_tenants.tenant_b))
    assert {UUID(item["id"]) for item in items} == two_tenants.alerts_b


async def test_tenant_a_gets_404_for_tenant_b_alert(
    client: httpx.AsyncClient, tokens: TokenFactory, two_tenants: TwoTenants
) -> None:
    token_a = tokens.token(two_tenants.tenant_a, role="admin")
    for alert_b in two_tenants.alerts_b:
        response = await client.get(f"/api/alerts/{alert_b}", headers=bearer(token_a))
        assert response.status_code == 404
        # Same body as an id that exists nowhere: nothing confirms B's alert exists.
        assert response.json() == {"detail": "not found"}
    missing = await client.get(f"/api/alerts/{uuid4()}", headers=bearer(token_a))
    assert missing.status_code == 404
    assert missing.json() == {"detail": "not found"}

    own = next(iter(two_tenants.alerts_a))
    response = await client.get(f"/api/alerts/{own}", headers=bearer(token_a))
    assert response.status_code == 200
    assert response.json()["id"] == str(own)


async def test_route_sql_alone_would_leak(superuser: Conn, two_tenants: TwoTenants) -> None:
    """Control: the route's SQL has no tenant filter, so RLS is what isolates tenants."""
    rows = await superuser.fetch(LIST_ALERTS_SQL, 100_000)
    ids = {row["id"] for row in rows}
    assert two_tenants.alerts_a <= ids
    assert two_tenants.alerts_b <= ids
    alert_b = next(iter(two_tenants.alerts_b))
    assert await superuser.fetchrow(GET_ALERT_SQL, alert_b) is not None


async def test_invalid_alert_id_is_422(
    client: httpx.AsyncClient, tokens: TokenFactory, two_tenants: TwoTenants
) -> None:
    response = await client.get(
        "/api/alerts/not-a-uuid", headers=bearer(tokens.token(two_tenants.tenant_a))
    )
    assert response.status_code == 422


# Response shape (contract with web/src/api.ts) -------------------------------------------


async def test_alert_shape_matches_web_contract(
    client: httpx.AsyncClient, tokens: TokenFactory, two_tenants: TwoTenants
) -> None:
    items = await _list_all(client, tokens.token(two_tenants.tenant_b))
    item = items[0]
    expected = {
        "id",
        "source",
        "title",
        "severity",
        "source_severity",
        "status",
        "summary",
        "recommended_action",
        "needs_human_review",
        "created_at",
    }
    assert expected <= set(item)
    assert "tenant_id" not in item
    assert item["severity"] in {"info", "low", "medium", "high", "critical"}
    assert item["source_severity"] == "critical"
    assert item["status"] == "new"
    assert item["summary"] is None
    assert item["needs_human_review"] is True
    assert "T" in item["created_at"]


# Pagination ------------------------------------------------------------------------------


async def test_pagination_walks_every_alert_once(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn
) -> None:
    tenant = await create_tenant(superuser)
    created = {await create_alert(superuser, tenant, title=f"P{i}") for i in range(5)}
    token = tokens.token(tenant)

    seen: list[str] = []
    cursor: str | None = None
    pages = 0
    while True:
        params: dict[str, str | int] = {"limit": 2}
        if cursor is not None:
            params["cursor"] = cursor
        response = await client.get("/api/alerts", params=params, headers=bearer(token))
        assert response.status_code == 200, response.text
        body = response.json()
        pages += 1
        seen.extend(item["id"] for item in body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break
        assert isinstance(cursor, str)
        assert cursor
    assert pages == 3
    assert len(seen) == len(set(seen)) == 5
    assert {UUID(i) for i in seen} == created


@pytest.mark.parametrize("cursor", ["!!!", "bm90LWEtY3Vyc29y", "x" * 201])
async def test_bad_cursor_is_rejected(
    client: httpx.AsyncClient, tokens: TokenFactory, two_tenants: TwoTenants, cursor: str
) -> None:
    response = await client.get(
        "/api/alerts",
        params={"cursor": cursor},
        headers=bearer(tokens.token(two_tenants.tenant_a)),
    )
    assert response.status_code in {400, 422}


@pytest.mark.parametrize("limit", [0, -1, 201])
async def test_limit_is_bounded(
    client: httpx.AsyncClient, tokens: TokenFactory, two_tenants: TwoTenants, limit: int
) -> None:
    response = await client.get(
        "/api/alerts", params={"limit": limit}, headers=bearer(tokens.token(two_tenants.tenant_a))
    )
    assert response.status_code == 422


# Role enforcement ------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "analyst", "responder"])
async def test_audit_log_requires_admin(
    client: httpx.AsyncClient, tokens: TokenFactory, two_tenants: TwoTenants, role: str
) -> None:
    response = await client.get(
        "/api/audit", headers=bearer(tokens.token(two_tenants.tenant_a, role=role))
    )
    assert response.status_code == 403


async def test_admin_reads_only_own_audit_log_and_the_read_is_audited(
    client: httpx.AsyncClient, tokens: TokenFactory, two_tenants: TwoTenants, superuser: Conn
) -> None:
    for tenant, action in ((two_tenants.tenant_a, "seed.a"), (two_tenants.tenant_b, "seed.b")):
        await superuser.execute(
            "insert into lh.audit_log (tenant_id, actor, action) values ($1, 'seed', $2)",
            tenant,
            action,
        )
    admin_id = uuid4()
    token = tokens.token(two_tenants.tenant_a, role="admin", user_id=admin_id)
    response = await client.get("/api/audit", headers=bearer(token))
    assert response.status_code == 200
    actions = {item["action"] for item in response.json()["items"]}
    assert "seed.a" in actions
    assert "seed.b" not in actions

    reads = await superuser.fetch(
        "select tenant_id, actor from lh.audit_log where action = 'audit.read' and actor = $1",
        str(admin_id),
    )
    assert [(r["tenant_id"], r["actor"]) for r in reads] == [(two_tenants.tenant_a, str(admin_id))]


# Startup safety --------------------------------------------------------------------------


async def test_server_refuses_to_start_without_forced_rls(
    superuser: Conn, settings: Settings
) -> None:
    await superuser.execute("alter table lh.alerts no force row level security")
    try:
        with pytest.raises(UnsafeDatabaseConfigError, match=r"lh\.alerts"):
            await create_pool(settings)
    finally:
        await superuser.execute("alter table lh.alerts force row level security")
