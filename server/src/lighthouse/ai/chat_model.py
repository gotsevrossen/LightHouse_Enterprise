"""`ChatModel` implemented with Claude, streaming.

Security boundary: model output handling (CLAUDE.md rule 4) and the API key (rule 1).

- `stop_reason` is checked on the final message before the answer counts as complete; a
  refusal, a cut-off answer or any other stop ends with an error outcome, never "done".
- Every API or transport failure, before or during the stream, becomes an outcome on the
  meter instead of an exception, so the route always sends exactly one terminal event.
- Usage is read from the stream as it arrives (`message_start`, `message_delta`), so a
  call that is cut off part-way is still metered with what the provider reported so far.
- Nothing logged contains the question, the history, the alert, the answer, the API key
  or a request body: errors are logged by class, status code and stop reason only.

Streaming uses the SDK's documented helper, `client.beta.messages.stream(...)` as an
async context manager, iterating its events and reading `get_final_message()` at the end
(skill python/claude-api/streaming.md). The beta namespace is needed for server-side
refusal fallbacks (`fallbacks`, beta `server-side-fallback-2026-07-01`).
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator, Callable
from typing import Final

import anthropic
import httpx2
from anthropic.types.beta import BetaMessage

from lighthouse.ai.chat_prompt import build_chat_request
from lighthouse.ai.client import build_chat_client
from lighthouse.ai.fence import FenceIntegrityError
from lighthouse.ai.triage_model import model_name, usage_from
from lighthouse.chat import ChatMeter, ChatModel, ChatOutcome, ChatQuery
from lighthouse.config import Settings
from lighthouse.triage import TriageUsage

logger = logging.getLogger(__name__)

# Stop reasons that mean "the answer did not fit". Both read as `too_long` to the person.
_TOO_LONG_STOPS: Final = frozenset({"max_tokens", "model_context_window_exceeded"})


# Most specific first: APITimeoutError is a subclass of APIConnectionError, and the status
# errors are all subclasses of APIStatusError (shared/error-codes.md). Transport errors
# raised while the body streams are not wrapped by the SDK, hence the httpx2 classes.
_ERROR_OUTCOMES: Final[tuple[tuple[tuple[type[Exception], ...], ChatOutcome], ...]] = (
    ((anthropic.APITimeoutError, httpx2.TimeoutException), ChatOutcome.TIMEOUT),
    ((anthropic.APIConnectionError, httpx2.TransportError), ChatOutcome.CONNECTION_ERROR),
    ((anthropic.RateLimitError,), ChatOutcome.UPSTREAM_RATE_LIMITED),
    ((anthropic.AuthenticationError, anthropic.PermissionDeniedError), ChatOutcome.AUTH_ERROR),
    # Our request was malformed: a bug on our side, not provider trouble.
    (
        (anthropic.BadRequestError, anthropic.UnprocessableEntityError),
        ChatOutcome.INTERNAL_ERROR,
    ),
    ((anthropic.AnthropicError,), ChatOutcome.API_ERROR),
)


def _outcome_for_error(exc: Exception) -> ChatOutcome:
    for classes, outcome in _ERROR_OUTCOMES:
        if isinstance(exc, classes):
            return outcome
    return ChatOutcome.INTERNAL_ERROR


def _outcome_for_stop(message: BetaMessage) -> ChatOutcome:
    stop = message.stop_reason
    if stop == "end_turn":
        return ChatOutcome.COMPLETED
    if stop == "refusal":
        # Informational only; branch on stop_reason, never on stop_details.
        category = message.stop_details.category if message.stop_details else None
        logger.info("chat refused by model: category=%s", category)
        return ChatOutcome.DECLINED
    if stop in _TOO_LONG_STOPS:
        return ChatOutcome.MAX_TOKENS
    logger.warning("chat stopped unexpectedly: %s", stop)
    return ChatOutcome.UNEXPECTED_STOP


def _meter_from(meter: ChatMeter, message: BetaMessage, configured: str) -> None:
    meter.usage = usage_from(message)
    meter.model = model_name(message.model, configured)


class AnthropicChatModel:
    """Chat through the Anthropic Messages API, streamed."""

    def __init__(
        self,
        client: anthropic.AsyncAnthropic | None,
        settings: Settings,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._settings = settings
        # Injectable so tests can check the wall-clock deadline without sleeping.
        self._clock = clock

    @property
    def available(self) -> bool:
        return self._client is not None

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.close()

    async def answer(self, query: ChatQuery, meter: ChatMeter) -> AsyncIterator[str]:
        if self._client is None:
            meter.outcome = (
                ChatOutcome.MODEL_DISABLED
                if not self._settings.chat_enabled
                else ChatOutcome.MODEL_UNAVAILABLE
            )
            return
        try:
            request = build_chat_request(query, self._settings)
        except FenceIntegrityError:
            # Unreachable while escaping works; if it ever regresses, nothing is sent.
            logger.error("chat request refused: fence integrity check failed")  # noqa: TRY400
            meter.outcome = ChatOutcome.INTERNAL_ERROR
            return

        configured = self._settings.chat_model
        timeout = self._settings.chat_timeout_seconds
        deadline = self._clock() + timeout
        meter.model_called = True
        meter.model = configured
        # Attempted: a zero row records the call even if the provider reports nothing.
        meter.usage = TriageUsage()
        try:
            async with self._client.beta.messages.stream(
                model=request.model,
                max_tokens=request.max_tokens,
                system=request.system,
                messages=request.messages,
                thinking=request.thinking,
                output_config=request.output_config,
                betas=request.betas,
                fallbacks=request.fallbacks,
                timeout=timeout,
            ) as stream:
                async for event in stream:
                    if event.type in ("message_start", "message_delta"):
                        _meter_from(meter, stream.current_message_snapshot, configured)
                    elif event.type == "text":
                        # Only text-block deltas. Thinking (empty by default on this
                        # model), fallback markers and anything else are not forwarded.
                        yield event.text
                    if self._clock() > deadline:
                        # The SDK timeout bounds each read; this bounds the whole answer.
                        # Leaving the context manager closes the connection, which stops
                        # generation; usage is what the stream reported so far.
                        logger.warning("chat answer exceeded its deadline")
                        meter.outcome = ChatOutcome.TIMEOUT
                        return
                message = await stream.get_final_message()
        except Exception as exc:  # noqa: BLE001 - rule 4: any failure is an outcome, not a crash
            outcome = _outcome_for_error(exc)
            status = exc.status_code if isinstance(exc, anthropic.APIStatusError) else None
            logger.warning(
                "chat call failed: %s status=%s outcome=%s",
                type(exc).__name__,
                status,
                outcome.value,
            )
            meter.outcome = outcome
            return

        _meter_from(meter, message, configured)
        # stop_reason decides; content is not read here at all (the text was streamed).
        # A refusal mid-stream: the skill (shared/model-migration.md, "refusal stop
        # reason") says to discard partial output rather than treat it as complete. The
        # partial text has already been streamed to the person who asked and cannot be
        # unsent, so the route ends the stream with `declined`, which tells the console
        # the text above it is incomplete and not to be relied on; the server never
        # stores, logs or reuses it. A refusal that a server-side fallback model rescued
        # does not end here: the fallback's continuation streams on and ends `end_turn`.
        meter.outcome = _outcome_for_stop(message)


def build_chat_model(settings: Settings) -> ChatModel:
    """The production chat model. Never raises for a missing key: see `build_chat_client`."""
    return AnthropicChatModel(build_chat_client(settings), settings)
