"""Alerts API after Phase 1 triage: new fields, server-side gating of evidence and model
reasoning, and that the server starts and serves without an Anthropic key.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import pytest

from lighthouse.ai.triage_model import AnthropicTriageModel, build_triage_model
from lighthouse.config import Settings
from lighthouse.db import Pool
from lighthouse.ingest.pipeline import ingest_alert
from lighthouse.main import create_app
from lighthouse.severity import Severity
from lighthouse.triage import ReviewReason, TriageInput
from tests.ai_helpers import StubAnthropic, answer, normalized, respond_text, triage_settings
from tests.helpers import Conn, TokenFactory, bearer, create_tenant

TRIAGE_FIELDS = {"category", "occurred_at", "confidence", "review_reason", "triaged_at"}
ANALYST_ONLY = {"evidence", "reasoning"}
ANTHROPIC_ENV = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_PROFILE",
    "ANTHROPIC_FEDERATION_RULE_ID",
    "ANTHROPIC_IDENTITY_TOKEN",
    "ANTHROPIC_IDENTITY_TOKEN_FILE",
)


async def _triaged_alert(pool: Pool, tenant: UUID) -> UUID:
    stub = StubAnthropic(respond_text(answer(severity="high", rationale="Analyst rationale.")))
    alert = normalized(
        source_severity=Severity.MEDIUM,
        evidence={"command_line": "powershell -enc AAAA", "host_name": "host-7"},
    )
    outcome = await ingest_alert(pool, tenant, alert, stub.model())
    return outcome.alert_id


async def _get(client: httpx.AsyncClient, token: str, path: str) -> dict[str, Any]:
    response = await client.get(path, headers=bearer(token))
    assert response.status_code == 200, response.text
    return response.json()


async def test_list_exposes_triage_fields_but_never_evidence_or_reasoning(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn, app_pool: Pool
) -> None:
    tenant = await create_tenant(superuser)
    alert_id = await _triaged_alert(app_pool, tenant)
    body = await _get(client, tokens.token(tenant, role="admin"), "/api/alerts")
    (item,) = body["items"]
    assert item["id"] == str(alert_id)
    assert set(item) >= TRIAGE_FIELDS
    assert not ANALYST_ONLY & set(item)
    assert item["category"] == "InitialAccess"
    assert item["confidence"] == pytest.approx(0.8)
    assert item["review_reason"] is None
    assert item["severity"] == "high"
    assert item["needs_human_review"] is False
    assert "T" in item["triaged_at"]
    assert item["occurred_at"].startswith("2026-11-01T09:30:00")


@pytest.mark.parametrize("role", ["analyst", "responder", "admin"])
async def test_detail_includes_evidence_and_reasoning_for_analyst_and_above(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn, app_pool: Pool, role: str
) -> None:
    tenant = await create_tenant(superuser)
    alert_id = await _triaged_alert(app_pool, tenant)
    item = await _get(client, tokens.token(tenant, role=role), f"/api/alerts/{alert_id}")
    assert item["evidence"] == {"command_line": "powershell -enc AAAA", "host_name": "host-7"}
    assert item["reasoning"] == "Analyst rationale."
    assert set(item) >= TRIAGE_FIELDS


async def test_detail_for_viewer_has_plain_english_fields_only(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn, app_pool: Pool
) -> None:
    tenant = await create_tenant(superuser)
    alert_id = await _triaged_alert(app_pool, tenant)
    response = await client.get(
        f"/api/alerts/{alert_id}", headers=bearer(tokens.token(tenant, role="viewer"))
    )
    assert response.status_code == 200
    item = response.json()
    assert not ANALYST_ONLY & set(item)
    assert "powershell" not in response.text
    assert "Analyst rationale" not in response.text
    assert item["summary"]
    assert item["recommended_action"]
    assert set(item) >= TRIAGE_FIELDS


async def test_detail_is_still_tenant_scoped_for_analysts(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn, app_pool: Pool
) -> None:
    tenant_a = await create_tenant(superuser)
    tenant_b = await create_tenant(superuser)
    alert_a = await _triaged_alert(app_pool, tenant_a)
    response = await client.get(
        f"/api/alerts/{alert_a}", headers=bearer(tokens.token(tenant_b, role="admin"))
    )
    assert response.status_code == 404
    assert "powershell" not in response.text


async def test_needs_review_alert_shape(
    client: httpx.AsyncClient, tokens: TokenFactory, superuser: Conn, app_pool: Pool
) -> None:
    tenant = await create_tenant(superuser)
    outcome = await ingest_alert(
        app_pool, tenant, normalized(), AnthropicTriageModel(None, triage_settings())
    )
    item = await _get(
        client, tokens.token(tenant, role="analyst"), f"/api/alerts/{outcome.alert_id}"
    )
    assert item["needs_human_review"] is True
    assert item["review_reason"] == ReviewReason.MODEL_UNAVAILABLE.value
    assert item["triaged_at"] is None
    assert item["confidence"] is None
    assert item["reasoning"] is None


async def test_server_starts_and_serves_without_an_anthropic_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    settings: Settings,
    tokens: TokenFactory,
    superuser: Conn,
) -> None:
    for name in ANTHROPIC_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ANTHROPIC_CONFIG_DIR", str(tmp_path / "none"))
    monkeypatch.setenv("HOME", str(tmp_path))
    tenant = await create_tenant(superuser)
    token = tokens.token(tenant, role="analyst")

    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as http,
    ):
        assert (await http.get("/healthz")).status_code == 200
        assert (await http.get("/api/me", headers=bearer(token))).status_code == 200
        assert (await http.get("/api/alerts", headers=bearer(token))).status_code == 200

    # And triage degrades to "needs human review", no exception, no call.
    model = build_triage_model(settings)
    result = await model.triage(
        TriageInput(
            source="fixture",
            source_alert_id="fixture-1",
            title="Example",
            source_severity=Severity.LOW,
        )
    )
    assert result.review_reason is ReviewReason.MODEL_UNAVAILABLE
