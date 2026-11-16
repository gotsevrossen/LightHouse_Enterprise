"""`TriageModel` implemented with Claude.

Security boundary: triage validation (CLAUDE.md rules 4 and 5). Model output is untrusted:

- `stop_reason` is checked before any content is read; a refusal, a cut-off answer or any
  other unexpected stop is "needs human review", never a partial parse;
- the answer must be exactly one text block that validates against `TriageOutput`;
- every API or transport failure maps to a `ReviewReason` instead of raising, so one
  alert can never stop ingestion;
- the stored severity is never below the source's: applied here, again in `run_triage`,
  in the pipeline's SQL, and by the database constraint.

Nothing returned or logged contains the API key, request bodies, or alert text. Errors are
logged by class and status code only.
"""

from __future__ import annotations

import logging
from typing import Final

import anthropic
from anthropic.types.beta import BetaMessage
from pydantic import ValidationError

from lighthouse.ai.client import build_client
from lighthouse.ai.prompt import TriageOutput, build_request
from lighthouse.config import Settings
from lighthouse.severity import Severity
from lighthouse.triage import (
    MAX_MODEL_NAME_CHARS,
    MAX_TOKENS_PER_FIELD,
    ReviewReason,
    TriageInput,
    TriageModel,
    TriageResult,
    TriageUsage,
    apply_source_floor,
    needs_human_review_result,
)

logger = logging.getLogger(__name__)

# Iteration entry types that are sampling attempts we pay for. A declined attempt is a
# "message" entry; the attempt that served a fallback is "fallback_message".
_BILLED_ITERATIONS: Final = frozenset({"message", "fallback_message"})


def _bounded(value: int | None) -> int:
    if value is None or value < 0:
        return 0
    return min(value, MAX_TOKENS_PER_FIELD)


def usage_from(message: BetaMessage) -> TriageUsage:
    """Token usage of the whole call.

    With server-side fallbacks, top-level `usage` covers only the attempt that produced
    the returned message; `usage.iterations` is the per-attempt record. Sum the
    iterations when present so a declined-then-rescued call is metered in full.
    """
    usage = message.usage
    iterations = [i for i in (usage.iterations or []) if i.type in _BILLED_ITERATIONS]
    if iterations:
        return TriageUsage(
            input_tokens=_bounded(sum(getattr(i, "input_tokens", 0) for i in iterations)),
            output_tokens=_bounded(sum(getattr(i, "output_tokens", 0) for i in iterations)),
            cache_read_tokens=_bounded(
                sum(getattr(i, "cache_read_input_tokens", 0) for i in iterations)
            ),
            cache_creation_tokens=_bounded(
                sum(getattr(i, "cache_creation_input_tokens", 0) for i in iterations)
            ),
        )
    return TriageUsage(
        input_tokens=_bounded(usage.input_tokens),
        output_tokens=_bounded(usage.output_tokens),
        cache_read_tokens=_bounded(usage.cache_read_input_tokens),
        cache_creation_tokens=_bounded(usage.cache_creation_input_tokens),
    )


def model_name(value: str, fallback: str) -> str:
    # The served model id comes from the response; bound it before it is stored.
    if 1 <= len(value) <= MAX_MODEL_NAME_CHARS:
        return value
    return fallback


def _reason_for_error(exc: anthropic.AnthropicError) -> ReviewReason:
    # Most specific first: APITimeoutError is a subclass of APIConnectionError, and the
    # status errors are all subclasses of APIStatusError (shared/error-codes.md).
    if isinstance(exc, anthropic.APITimeoutError):
        return ReviewReason.TIMEOUT
    if isinstance(exc, anthropic.APIConnectionError):
        return ReviewReason.CONNECTION_ERROR
    if isinstance(exc, anthropic.RateLimitError):
        return ReviewReason.RATE_LIMITED
    if isinstance(exc, anthropic.AuthenticationError | anthropic.PermissionDeniedError):
        return ReviewReason.AUTH_ERROR
    return ReviewReason.API_ERROR


class AnthropicTriageModel:
    """Triage through the Anthropic Messages API, with structured output."""

    def __init__(self, client: anthropic.AsyncAnthropic | None, settings: Settings) -> None:
        self._client = client
        self._settings = settings

    async def triage(self, alert: TriageInput) -> TriageResult:
        source = alert.source_severity
        if self._client is None:
            reason = (
                ReviewReason.MODEL_DISABLED
                if not self._settings.triage_enabled
                else ReviewReason.MODEL_UNAVAILABLE
            )
            return needs_human_review_result(source, reason=reason)

        configured = self._settings.triage_model
        request = build_request(alert, self._settings)
        try:
            message = await self._client.beta.messages.create(
                model=request.model,
                max_tokens=request.max_tokens,
                system=request.system,
                messages=request.messages,
                thinking=request.thinking,
                output_config=request.output_config,
                betas=request.betas,
                fallbacks=request.fallbacks,
                timeout=self._settings.triage_timeout_seconds,
            )
        except anthropic.AnthropicError as exc:
            reason = _reason_for_error(exc)
            status = exc.status_code if isinstance(exc, anthropic.APIStatusError) else None
            logger.warning(
                "triage call failed: %s status=%s reason=%s",
                type(exc).__name__,
                status,
                reason.value,
            )
            # The request was sent (or attempted); tokens may have been spent that the
            # failure does not report. A zero row still records the call.
            return needs_human_review_result(
                source, reason=reason, usage=TriageUsage(), model=configured
            )

        # The SDK hands back the raw body when a 200 is not JSON. Anything that is not a
        # parsed message is an API fault, not an answer.
        if not isinstance(message, BetaMessage):  # pyright: ignore[reportUnnecessaryIsInstance]
            logger.warning("triage call returned an unparseable response")
            return needs_human_review_result(
                source, reason=ReviewReason.API_ERROR, usage=TriageUsage(), model=configured
            )
        usage = usage_from(message)
        served = model_name(message.model, configured)
        output = _read_output(message)
        if isinstance(output, ReviewReason):
            return needs_human_review_result(source, reason=output, usage=usage, model=served)
        return TriageResult(
            # The model may raise severity, never lower it below the source's.
            severity=apply_source_floor(source, Severity(output.severity)),
            summary=output.summary,
            recommended_action=output.recommended_action,
            confidence=output.confidence,
            reasoning=output.rationale,
            model=served,
            usage=usage,
        )


def _read_output(message: BetaMessage) -> TriageOutput | ReviewReason:
    """The validated answer, or why there is none. Reads content only after stop_reason."""
    # stop_reason before content, always (shared/model-migration.md, refusal section): a
    # refusal can carry an empty or partial content array.
    if message.stop_reason == "refusal":
        category = message.stop_details.category if message.stop_details else None
        logger.info("triage refused by model: category=%s", category)
        return ReviewReason.REFUSAL
    if message.stop_reason == "max_tokens":
        return ReviewReason.MAX_TOKENS
    if message.stop_reason != "end_turn":
        logger.warning("triage stopped unexpectedly: %s", message.stop_reason)
        return ReviewReason.UNEXPECTED_STOP

    # Structured output arrives as exactly one text block (thinking and fallback marker
    # blocks may sit around it). Anything else is not an answer we can trust.
    texts = [block.text for block in message.content if block.type == "text"]
    if len(texts) != 1:
        return ReviewReason.SCHEMA_INVALID
    try:
        return TriageOutput.model_validate_json(texts[0])
    except ValidationError:
        # The validation error can quote model text; log nothing but the fact.
        logger.warning("triage output failed schema validation")
        return ReviewReason.SCHEMA_INVALID


def build_triage_model(settings: Settings) -> TriageModel:
    """The production triage model. Never raises for a missing key: see `build_client`."""
    return AnthropicTriageModel(build_client(settings), settings)
