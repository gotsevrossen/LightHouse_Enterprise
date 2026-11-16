"""`PATCH /api/alerts/{id}`: only `status` is writable, analyst and above only, tenant
isolation by RLS (another tenant's id is a 404), and every change audited with from/to.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest

from tests.helpers import Conn, TokenFactory, bearer, create_alert, create_tenant

ALL_STATUSES = ("new", "triaged", "investigating", "resolved", "dismissed")


async def patch(
    client: httpx.AsyncClient, token: str, alert_id: UUID | str, body: Any
) -> httpx.Response:
    return await client.patch(f"/api/alerts/{alert_id}", json=body, headers=bearer(token))


async def status_audit(superuser: Conn, tenant: UUID) -> list[dict[str, Any]]:
    rows = await superuser.fetch(
        "select actor, action, target, detail from lh.audit_log "
        "where tenant_id = $1 and action = 'alert.status_changed' order by id",
        tenant,
    )
    return [{**dict(r.items()), "detail": json.loads(r["detail"])} for r in rows]


async def stored(superuser: Conn, alert_id: UUID) -> dict[str, Any]:
    row = await superuser.fetchrow(
        "select status::text, severity::text, source_severity::text, title "
        "from lh.alerts where id = $1",
        alert_id,
    )
    assert row is not None
    return dict(row.items())


@pytest.mark.parametrize("role", ["analyst", "responder", "admin"])
async def test_analyst_and_above_can_change_status(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn, role: str
) -> None:
    tenant = await create_tenant(superuser)
    alert_id = await create_alert(superuser, tenant)
    user = uuid4()
    token = tokens.token(tenant, role=role, user_id=user)
    response = await patch(client, token, alert_id, {"status": "investigating"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == str(alert_id)
    assert body["status"] == "investigating"
    # Same body as GET /api/alerts/{id} for this caller (analyst+: the detail view).
    get = await client.get(f"/api/alerts/{alert_id}", headers=bearer(token))
    assert body == get.json()
    assert {"evidence", "reasoning"} <= set(body)
    assert (await stored(superuser, alert_id))["status"] == "investigating"
    assert await status_audit(superuser, tenant) == [
        {
            "actor": str(user),
            "action": "alert.status_changed",
            "target": f"alert:{alert_id}",
            "detail": {"from": "new", "to": "investigating"},
        }
    ]


async def test_viewer_cannot_change_status(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn
) -> None:
    tenant = await create_tenant(superuser)
    alert_id = await create_alert(superuser, tenant)
    response = await patch(
        client, tokens.token(tenant, role="viewer"), alert_id, {"status": "dismissed"}
    )
    assert response.status_code == 403
    assert (await stored(superuser, alert_id))["status"] == "new"
    assert await status_audit(superuser, tenant) == []


async def test_requires_authentication(client: httpx.AsyncClient, superuser: Conn) -> None:
    tenant = await create_tenant(superuser)
    alert_id = await create_alert(superuser, tenant)
    response = await client.patch(f"/api/alerts/{alert_id}", json={"status": "resolved"})
    assert response.status_code == 401


async def test_other_tenants_alert_is_404_and_unchanged(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn
) -> None:
    tenant_a = await create_tenant(superuser, "Example Tenant A")
    tenant_b = await create_tenant(superuser, "Example Tenant B")
    alert_b = await create_alert(superuser, tenant_b)
    token_a = tokens.token(tenant_a, role="admin")
    for alert_id in (alert_b, uuid4()):
        response = await patch(client, token_a, alert_id, {"status": "dismissed"})
        assert response.status_code == 404
        assert response.json() == {"detail": "not found"}
    assert (await stored(superuser, alert_b))["status"] == "new"
    assert await status_audit(superuser, tenant_a) == []
    assert await status_audit(superuser, tenant_b) == []


@pytest.mark.parametrize("new_status", ALL_STATUSES)
async def test_every_status_value_is_accepted(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn, new_status: str
) -> None:
    tenant = await create_tenant(superuser)
    alert_id = await create_alert(superuser, tenant)
    await superuser.execute("update lh.alerts set status = 'resolved' where id = $1", alert_id)
    response = await patch(
        client, tokens.token(tenant, role="analyst"), alert_id, {"status": new_status}
    )
    assert response.status_code == 200
    assert response.json()["status"] == new_status


async def test_unchanged_status_writes_and_audits_nothing(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn
) -> None:
    tenant = await create_tenant(superuser)
    alert_id = await create_alert(superuser, tenant)
    before = await superuser.fetchval("select updated_at from lh.alerts where id = $1", alert_id)
    token = tokens.token(tenant, role="analyst")
    response = await patch(client, token, alert_id, {"status": "new"})
    assert response.status_code == 200
    assert response.json()["status"] == "new"
    assert await superuser.fetchval("select updated_at from lh.alerts where id = $1", alert_id) == (
        before
    )
    assert await status_audit(superuser, tenant) == []


async def test_successive_changes_audit_each_transition(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn
) -> None:
    tenant = await create_tenant(superuser)
    alert_id = await create_alert(superuser, tenant)
    token = tokens.token(tenant, role="responder")
    for new_status in ("investigating", "resolved", "new"):
        assert (await patch(client, token, alert_id, {"status": new_status})).status_code == 200
    transitions = [r["detail"] for r in await status_audit(superuser, tenant)]
    assert transitions == [
        {"from": "new", "to": "investigating"},
        {"from": "investigating", "to": "resolved"},
        {"from": "resolved", "to": "new"},
    ]


INVALID: list[tuple[str, Any]] = [
    ("severity-alongside", {"status": "resolved", "severity": "info"}),
    ("severity-only", {"severity": "info"}),
    ("title", {"status": "resolved", "title": "renamed"}),
    ("tenant", {"status": "resolved", "tenant_id": str(uuid4())}),
    ("empty", {}),
    ("null-status", {"status": None}),
    ("unknown-status", {"status": "closed"}),
    ("wrong-case", {"status": "Resolved"}),
    ("not-object", ["resolved"]),
]


@pytest.mark.parametrize("body", [b for _, b in INVALID], ids=[n for n, _ in INVALID])
async def test_only_a_valid_status_is_accepted_and_nothing_else_changes(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn, body: Any
) -> None:
    tenant = await create_tenant(superuser)
    alert_id = await create_alert(superuser, tenant, source_severity="high")
    before = await stored(superuser, alert_id)
    response = await patch(client, tokens.token(tenant, role="admin"), alert_id, body)
    assert response.status_code == 422
    assert await stored(superuser, alert_id) == before
    assert await status_audit(superuser, tenant) == []


async def test_bad_alert_id_is_422(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn
) -> None:
    tenant = await create_tenant(superuser)
    response = await patch(
        client, tokens.token(tenant, role="admin"), "not-a-uuid", {"status": "resolved"}
    )
    assert response.status_code == 422


async def test_viewer_still_gets_plain_view_from_get_after_a_change(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn
) -> None:
    tenant = await create_tenant(superuser)
    alert_id = await create_alert(superuser, tenant)
    await patch(client, tokens.token(tenant, role="analyst"), alert_id, {"status": "resolved"})
    viewer = await client.get(
        f"/api/alerts/{alert_id}", headers=bearer(tokens.token(tenant, role="viewer"))
    )
    assert viewer.json()["status"] == "resolved"
    assert not {"evidence", "reasoning"} & set(viewer.json())
