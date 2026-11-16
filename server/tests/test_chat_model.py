"""AnthropicChatModel: streamed text, and every abnormal ending becomes an outcome on the
meter, never an exception. The SDK's streaming helper runs for real; only the HTTP
transport is stubbed (tests/chat_helpers.py).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx2
import pytest
from pydantic import ValidationError

from lighthouse.ai.chat_model import AnthropicChatModel, build_chat_model
from lighthouse.ai.client import build_chat_client
from lighthouse.chat import ChatErrorCode, ChatMeter, ChatModel, ChatOutcome, ChatQuery
from lighthouse.config import load_settings
from lighthouse.triage import TriageUsage
from tests.ai_helpers import StubAnthropic, error
from tests.chat_helpers import (
    TickingClock,
    chat_model,
    chat_settings,
    respond_stream,
    respond_stream_then_fail,
    stream_events,
)
from tests.test_ai_triage_model import CREDENTIAL_ENV

QUERY = ChatQuery(question="What does a blocked sign-in from abroad mean?")


@pytest.fixture
def no_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in CREDENTIAL_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ANTHROPIC_CONFIG_DIR", str(tmp_path / "no-anthropic-config"))
    monkeypatch.setenv("HOME", str(tmp_path))


async def _run(model: ChatModel, query: ChatQuery = QUERY) -> tuple[list[str], ChatMeter]:
    meter = ChatMeter()
    texts = [text async for text in model.answer(query, meter)]
    return texts, meter


async def test_answer_streams_text_and_meters_usage() -> None:
    stub = StubAnthropic(respond_stream(stream_events(["The sign-in ", "was blocked."])))
    texts, meter = await _run(chat_model(stub))
    assert texts == ["The sign-in ", "was blocked."]
    assert meter.outcome is ChatOutcome.COMPLETED
    assert meter.outcome.error_code is None
    assert meter.model_called is True
    assert meter.model == "claude-opus-5-5"
    assert meter.usage == TriageUsage(
        input_tokens=210, output_tokens=77, cache_read_tokens=1500, cache_creation_tokens=40
    )
    assert len(stub.requests) == 1
    assert stub.bodies[0]["stream"] is True


async def test_refusal_mid_stream_keeps_sent_text_and_ends_declined() -> None:
    events = stream_events(
        ["Here is how the attack ", "works:"],
        stop_reason="refusal",
        stop_details={"type": "refusal", "category": "cyber", "explanation": None},
    )
    texts, meter = await _run(chat_model(StubAnthropic(respond_stream(events))))
    # Already-streamed text is not withdrawn (it cannot be); the outcome marks it partial.
    assert texts == ["Here is how the attack ", "works:"]
    assert meter.outcome is ChatOutcome.DECLINED
    assert meter.outcome.error_code is ChatErrorCode.DECLINED
    assert meter.usage is not None
    assert meter.usage.output_tokens == 77


async def test_refusal_before_output_ends_declined_with_no_text() -> None:
    events = stream_events([], stop_reason="refusal", stop_details=None)
    texts, meter = await _run(chat_model(StubAnthropic(respond_stream(events))))
    assert texts == []
    assert meter.outcome is ChatOutcome.DECLINED


async def test_fallback_rescue_is_a_normal_answer_metered_over_every_attempt() -> None:
    iterations = [
        {
            "type": "message",
            "model": "claude-opus-5-5",
            "input_tokens": 100,
            "output_tokens": 5,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
        },
        {
            "type": "fallback_message",
            "model": "claude-opus-4-8",
            "input_tokens": 120,
            "output_tokens": 50,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 900,
        },
    ]
    events = stream_events(
        ["Answer from the fallback."],
        blocks_before=[
            {
                "type": "fallback",
                "from": {"model": "claude-opus-5-5"},
                "to": {"model": "claude-opus-4-8"},
            }
        ],
        end_usage_extra={"iterations": iterations},
    )
    texts, meter = await _run(chat_model(StubAnthropic(respond_stream(events))))
    assert texts == ["Answer from the fallback."]
    assert meter.outcome is ChatOutcome.COMPLETED
    assert meter.model == "claude-opus-4-8"
    assert meter.usage == TriageUsage(
        input_tokens=220, output_tokens=55, cache_read_tokens=0, cache_creation_tokens=900
    )


@pytest.mark.parametrize(
    ("stop_reason", "outcome", "code"),
    [
        ("max_tokens", ChatOutcome.MAX_TOKENS, ChatErrorCode.TOO_LONG),
        ("model_context_window_exceeded", ChatOutcome.MAX_TOKENS, ChatErrorCode.TOO_LONG),
        ("pause_turn", ChatOutcome.UNEXPECTED_STOP, ChatErrorCode.INTERNAL),
        ("tool_use", ChatOutcome.UNEXPECTED_STOP, ChatErrorCode.INTERNAL),
        (None, ChatOutcome.UNEXPECTED_STOP, ChatErrorCode.INTERNAL),
    ],
)
async def test_other_stop_reasons(
    stop_reason: str | None, outcome: ChatOutcome, code: ChatErrorCode
) -> None:
    events = stream_events(["Partial"], stop_reason=stop_reason)
    texts, meter = await _run(chat_model(StubAnthropic(respond_stream(events))))
    assert texts == ["Partial"]
    assert meter.outcome is outcome
    assert outcome.error_code is code


def _raise(exc: Exception) -> Any:
    def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        raise exc

    return handler


PRE_STREAM_FAILURES: list[tuple[str, Any, ChatOutcome]] = [
    ("429", error(429, "rate_limit_error"), ChatOutcome.UPSTREAM_RATE_LIMITED),
    ("401", error(401, "authentication_error"), ChatOutcome.AUTH_ERROR),
    ("403", error(403, "permission_error"), ChatOutcome.AUTH_ERROR),
    ("400", error(400, "invalid_request_error"), ChatOutcome.INTERNAL_ERROR),
    ("404", error(404, "not_found_error"), ChatOutcome.API_ERROR),
    ("500", error(500, "api_error"), ChatOutcome.API_ERROR),
    ("529", error(529, "overloaded_error"), ChatOutcome.API_ERROR),
    ("timeout", _raise(httpx2.ReadTimeout("stubbed")), ChatOutcome.TIMEOUT),
    ("connect", _raise(httpx2.ConnectError("stubbed")), ChatOutcome.CONNECTION_ERROR),
]


@pytest.mark.parametrize(
    ("handler", "outcome"),
    [(h, o) for _, h, o in PRE_STREAM_FAILURES],
    ids=[name for name, _, _ in PRE_STREAM_FAILURES],
)
async def test_failures_before_the_stream(handler: Any, outcome: ChatOutcome) -> None:
    texts, meter = await _run(chat_model(StubAnthropic(handler)))
    assert texts == []
    assert meter.outcome is outcome
    assert outcome.error_code in {ChatErrorCode.UNAVAILABLE, ChatErrorCode.INTERNAL}
    # Attempted: a zero usage row records the call.
    assert meter.model_called is True
    assert meter.usage == TriageUsage()


async def test_error_event_mid_stream_is_unavailable_after_partial_text() -> None:
    events = stream_events(["Partial "], complete=False)
    events.append({"type": "error", "error": {"type": "overloaded_error", "message": "busy"}})
    texts, meter = await _run(chat_model(StubAnthropic(respond_stream(events))))
    assert texts == ["Partial "]
    assert meter.outcome is ChatOutcome.API_ERROR
    assert meter.outcome.error_code is ChatErrorCode.UNAVAILABLE
    # Usage seen before the failure is kept.
    assert meter.usage is not None
    assert meter.usage.input_tokens == 210


@pytest.mark.parametrize(
    ("exc", "outcome"),
    [
        (httpx2.ReadTimeout("stubbed"), ChatOutcome.TIMEOUT),
        (httpx2.RemoteProtocolError("stubbed"), ChatOutcome.CONNECTION_ERROR),
    ],
)
async def test_transport_failure_mid_stream(exc: Exception, outcome: ChatOutcome) -> None:
    handler = respond_stream_then_fail(stream_events(["Partial "], complete=False), exc)
    texts, meter = await _run(chat_model(StubAnthropic(handler)))
    assert texts == ["Partial "]
    assert meter.outcome is outcome


async def test_wall_clock_deadline_cuts_the_answer_off() -> None:
    events = stream_events([f"chunk {i} " for i in range(50)])
    stub = StubAnthropic(respond_stream(events))
    # Every clock read advances 1s against a 10s budget: the answer is cut after a few
    # events without any real waiting.
    model = chat_model(stub, chat_settings(chat_timeout_seconds=10), clock=TickingClock(1.0))
    texts, meter = await _run(model)
    assert 0 < len(texts) < 50
    assert meter.outcome is ChatOutcome.TIMEOUT
    assert meter.outcome.error_code is ChatErrorCode.UNAVAILABLE
    assert meter.usage is not None
    assert meter.usage.input_tokens == 210


async def test_disabled_makes_no_call() -> None:
    settings = chat_settings(chat_enabled=False)
    assert build_chat_client(settings) is None
    model = build_chat_model(settings)
    assert model.available is False
    texts, meter = await _run(model)
    assert texts == []
    assert meter.outcome is ChatOutcome.MODEL_DISABLED
    assert meter.model_called is False
    assert meter.usage is None


@pytest.mark.usefixtures("no_credentials")
async def test_missing_key_is_unavailable_without_a_call() -> None:
    model = build_chat_model(chat_settings())
    assert model.available is False
    texts, meter = await _run(model)
    assert texts == []
    assert meter.outcome is ChatOutcome.MODEL_UNAVAILABLE
    assert meter.outcome.error_code is ChatErrorCode.UNAVAILABLE
    assert meter.model_called is False
    await model.aclose()


async def test_aclose_without_client_is_harmless() -> None:
    await AnthropicChatModel(None, chat_settings()).aclose()


def test_every_outcome_has_a_wire_code_or_is_done() -> None:
    for outcome in ChatOutcome:
        code = outcome.error_code
        assert (code is None) == (outcome is ChatOutcome.COMPLETED), outcome


# Settings ---------------------------------------------------------------------------------


def test_chat_settings_parse_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in {
        "LH_DATABASE_URL": "postgresql://unused.example.invalid/unused",
        "LH_JWT_ISSUER": "https://auth.example.invalid/auth/v1",
        "LH_JWT_JWKS_URL": "https://auth.example.invalid/auth/v1/jwks",
        "LH_CHAT_ENABLED": "false",
        "LH_CHAT_MODEL": "claude-sonnet-5-5",
        "LH_CHAT_EFFORT": "medium",
        "LH_CHAT_MAX_TOKENS": "4096",
        "LH_CHAT_TIMEOUT_SECONDS": "30",
        "LH_CHAT_REQUESTS_PER_MINUTE_PER_USER": "5",
    }.items():
        monkeypatch.setenv(name, value)
    settings = load_settings()
    assert settings.chat_enabled is False
    assert settings.chat_model == "claude-sonnet-5-5"
    assert settings.chat_effort == "medium"
    assert settings.chat_max_tokens == 4096
    assert settings.chat_timeout_seconds == 30
    assert settings.chat_requests_per_minute_per_user == 5


def test_chat_defaults() -> None:
    settings = chat_settings()
    assert settings.chat_enabled is True
    assert settings.chat_model == "claude-opus-5-5"
    assert settings.chat_effort == "low"
    assert settings.chat_max_tokens == 8000
    assert settings.chat_requests_per_minute_per_user == 10


@pytest.mark.parametrize(
    "override",
    [
        {"chat_requests_per_minute_per_user": 0},
        {"chat_requests_per_minute_per_user": -1},
        {"chat_effort": "none"},
        {"chat_max_tokens": 0},
        {"chat_max_tokens": 1_000_000},
        {"chat_timeout_seconds": 0},
        {"chat_model": "model with spaces"},
    ],
)
def test_unsafe_chat_settings_are_rejected(override: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        chat_settings(**override)
