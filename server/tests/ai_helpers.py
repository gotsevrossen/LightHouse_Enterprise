"""Helpers for tests of the Claude integration. No network, no real key.

The Anthropic SDK is exercised for real (request building, serialisation, response
parsing, error mapping); only its HTTP transport is replaced by `httpx2.MockTransport`
(the SDK is built on httpx2), so every request is answered locally and recorded.

The "API key" is random text without any provider's key prefix, generated per test run:
nothing here is key-shaped, so secret scanning has nothing to find and nothing to leak.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final
from uuid import uuid4

import anthropic
import httpx2
from pydantic import SecretStr

from lighthouse.ai.triage_model import AnthropicTriageModel
from lighthouse.config import Settings
from lighthouse.ingest.schema import NormalizedAlert
from lighthouse.severity import Severity
from lighthouse.triage import TriageInput, TriageResult

type Handler = Callable[[httpx2.Request], httpx2.Response]


def fake_api_key() -> str:
    return f"test-{secrets.token_hex(12)}"


def triage_settings(**overrides: Any) -> Settings:
    """Settings with placeholder database/JWT values; only the triage fields matter."""
    values: dict[str, Any] = {
        "database_url": SecretStr("postgresql://unused.example.invalid/unused"),
        "jwt_issuer": "https://auth.example.invalid/auth/v1",
        "jwt_jwks_url": "https://auth.example.invalid/auth/v1/jwks",
    }
    values.update(overrides)
    return Settings(**values)


def answer(
    *,
    severity: str = "medium",
    confidence: float = 0.8,
    summary: str = "A sign-in from an unusual location was blocked.",
    recommended_action: str = "Ask the user whether they attempted this sign-in.",
    rationale: str = "The sign-in came from a new country and was blocked by policy.",
    **extra: Any,
) -> str:
    """A structured-output answer as the model would return it."""
    return json.dumps(
        {
            "severity": severity,
            "confidence": confidence,
            "summary": summary,
            "recommended_action": recommended_action,
            "rationale": rationale,
            **extra,
        }
    )


def message_body(
    text: str | list[str] | None = None,
    *,
    stop_reason: str = "end_turn",
    model: str = "claude-opus-5-5",
    usage: dict[str, Any] | None = None,
    stop_details: dict[str, Any] | None = None,
    extra_blocks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """A Messages API response body. Thinking comes first, as on adaptive-thinking models."""
    texts = [answer()] if text is None else ([text] if isinstance(text, str) else text)
    content: list[dict[str, Any]] = [{"type": "thinking", "thinking": "", "signature": "sig"}]
    content += extra_blocks or []
    content += [{"type": "text", "text": t} for t in texts]
    return {
        "id": f"msg_{secrets.token_hex(8)}",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "stop_details": stop_details,
        "usage": usage
        or {
            "input_tokens": 120,
            "output_tokens": 340,
            "cache_read_input_tokens": 900,
            "cache_creation_input_tokens": 0,
        },
    }


# A classifier decline before any output: HTTP 200, empty content (model-migration.md).
REFUSAL_BODY: Final = message_body(
    [],
    stop_reason="refusal",
    stop_details={"type": "refusal", "category": "cyber", "explanation": None},
)


@dataclass
class StubAnthropic:
    """Answers every request with `handler` and records the parsed request bodies."""

    handler: Handler
    requests: list[httpx2.Request] = field(default_factory=list[httpx2.Request])
    api_key: str = field(default_factory=fake_api_key)

    def _handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return self.handler(request)

    @property
    def bodies(self) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.requests]

    def client(self, *, max_retries: int = 0) -> anthropic.AsyncAnthropic:
        return anthropic.AsyncAnthropic(
            api_key=self.api_key,
            max_retries=max_retries,
            http_client=anthropic.DefaultAsyncHttpxClient(
                transport=httpx2.MockTransport(self._handle)
            ),
        )

    def model(self, *, max_retries: int = 0, **settings: Any) -> AnthropicTriageModel:
        return AnthropicTriageModel(
            self.client(max_retries=max_retries), triage_settings(**settings)
        )


def respond(body: dict[str, Any], status: int = 200) -> Handler:
    def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        return httpx2.Response(status, json=body)

    return handler


def respond_text(text: str | list[str] | None = None, **kwargs: Any) -> Handler:
    return respond(message_body(text, **kwargs))


def error(status: int, error_type: str) -> Handler:
    body = {"type": "error", "error": {"type": error_type, "message": "stubbed error"}}
    return respond(body, status)


def triage_input(
    *,
    title: str = "Unusual sign-in activity",
    source_severity: Severity = Severity.MEDIUM,
    evidence: dict[str, Any] | None = None,
    category: str | None = "InitialAccess",
    source_alert_id: str = "fixture-alert-1",
    description: str = "",
) -> TriageInput:
    return TriageInput(
        source="fixture",
        source_alert_id=source_alert_id,
        title=title,
        source_severity=source_severity,
        category=category,
        description=description,
        evidence=evidence
        if evidence is not None
        else {"account_upn": "user@example.invalid", "country": "Example Country"},
    )


def user_text(body: dict[str, Any]) -> str:
    """The text of the single user turn of a recorded request."""
    messages = body["messages"]
    assert len(messages) == 1
    assert messages[0]["role"] == "user"
    blocks = messages[0]["content"]
    assert len(blocks) == 1
    assert blocks[0]["type"] == "text"
    return blocks[0]["text"]


def normalized(
    *,
    source_alert_id: str | None = None,
    title: str = "Unusual sign-in activity",
    source_severity: Severity = Severity.MEDIUM,
    evidence: dict[str, Any] | None = None,
    category: str | None = "InitialAccess",
) -> NormalizedAlert:
    """A connector's output. Ids are random placeholders, never a real tenant's."""
    return NormalizedAlert(
        source="fixture",
        source_alert_id=source_alert_id or f"fixture-{uuid4()}",
        title=title,
        source_severity=source_severity,
        occurred_at=datetime(2026, 11, 1, 9, 30, tzinfo=UTC),
        category=category,
        evidence=evidence if evidence is not None else {"account_upn": "user@example.invalid"},
    )


class GatedModel:
    """A TriageModel that waits for `release` before answering, and counts calls."""

    def __init__(
        self,
        result: TriageResult,
        *,
        on_call: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        self.result = result
        self.calls = 0
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self._on_call = on_call

    async def triage(self, alert: TriageInput) -> TriageResult:
        del alert
        self.calls += 1
        self.entered.set()
        if self._on_call is not None:
            await self._on_call()
        await self.release.wait()
        return self.result
