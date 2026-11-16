"""Helpers for chat tests. No network, no real key.

As for triage (tests/ai_helpers.py), the Anthropic SDK runs for real, streaming helper
included; only its HTTP transport is replaced, here by one that answers with a recorded
server-sent-event stream in the Messages API's streaming format.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import httpx2

from lighthouse.ai.chat_model import AnthropicChatModel
from lighthouse.config import Settings
from lighthouse.main import create_app
from tests.ai_helpers import Handler, StubAnthropic, triage_settings

DEFAULT_USAGE_START: dict[str, Any] = {
    "input_tokens": 210,
    "output_tokens": 1,
    "cache_read_input_tokens": 1500,
    "cache_creation_input_tokens": 40,
}


def stream_events(
    texts: list[str] | None = None,
    *,
    stop_reason: str | None = "end_turn",
    model: str = "claude-opus-5-5",
    output_tokens: int = 77,
    stop_details: dict[str, Any] | None = None,
    usage_start: dict[str, Any] | None = None,
    end_usage_extra: dict[str, Any] | None = None,
    blocks_before: list[dict[str, Any]] | None = None,
    complete: bool = True,
) -> list[dict[str, Any]]:
    """The SSE events of one streamed answer: a thinking block, then one text block.

    `complete=False` stops after the text deltas (no message_delta / message_stop), for
    streams that are cut off or interrupted by an error event the caller appends.
    """
    texts = ["Hello", ", world."] if texts is None else texts
    events: list[dict[str, Any]] = [
        {
            "type": "message_start",
            "message": {
                "id": f"msg_{secrets.token_hex(8)}",
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [],
                "stop_reason": None,
                "stop_sequence": None,
                "usage": usage_start or DEFAULT_USAGE_START,
            },
        },
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "thinking", "thinking": "", "signature": ""},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "signature_delta", "signature": "sig"},
        },
        {"type": "content_block_stop", "index": 0},
    ]
    index = 1
    for block in blocks_before or []:
        events += [
            {"type": "content_block_start", "index": index, "content_block": block},
            {"type": "content_block_stop", "index": index},
        ]
        index += 1
    events.append(
        {
            "type": "content_block_start",
            "index": index,
            "content_block": {"type": "text", "text": ""},
        }
    )
    events += [
        {
            "type": "content_block_delta",
            "index": index,
            "delta": {"type": "text_delta", "text": text},
        }
        for text in texts
    ]
    if not complete:
        return events
    events.append({"type": "content_block_stop", "index": index})
    events += [
        {
            "type": "message_delta",
            "delta": {
                "stop_reason": stop_reason,
                "stop_sequence": None,
                "stop_details": stop_details,
            },
            "usage": {"output_tokens": output_tokens, **(end_usage_extra or {})},
        },
        {"type": "message_stop"},
    ]
    return events


def sse(events: list[dict[str, Any]]) -> bytes:
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def respond_stream(events: list[dict[str, Any]]) -> Handler:
    body = sse(events)

    def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        return httpx2.Response(200, headers={"content-type": "text/event-stream"}, content=body)

    return handler


def respond_stream_then_fail(events: list[dict[str, Any]], exc: Exception) -> Handler:
    """Streams `events`, then the connection fails with `exc` mid-body."""
    body = sse(events)

    async def content() -> AsyncGenerator[bytes]:
        yield body
        raise exc

    def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        return httpx2.Response(
            200, headers={"content-type": "text/event-stream"}, content=content()
        )

    return handler


def chat_settings(**overrides: Any) -> Settings:
    return triage_settings(**overrides)


def chat_model(
    stub: StubAnthropic, settings: Settings | None = None, **kwargs: Any
) -> AnthropicChatModel:
    return AnthropicChatModel(stub.client(), settings or chat_settings(), **kwargs)


class TickingClock:
    """A monotonic clock that advances `step` seconds every time it is read."""

    def __init__(self, step: float) -> None:
        self.now = 0.0
        self.step = step

    def __call__(self) -> float:
        self.now += self.step
        return self.now


def ndjson(text: str) -> list[dict[str, Any]]:
    """Parse a response body, checking the framing: one JSON object per line."""
    assert text.endswith("\n")
    return [json.loads(line) for line in text.splitlines()]


@asynccontextmanager
async def api(
    settings: Settings, model: AnthropicChatModel | None
) -> AsyncGenerator[httpx.AsyncClient]:
    app = create_app(settings, chat_model=model)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as http,
    ):
        yield http
