"""Provider-independent triage pieces.

Security boundary: triage validation. The rules this module carries (CLAUDE.md 4 and 5):

- model output is untrusted and is validated against `TriageResult` before use;
- any failure (exception, timeout, refusal, invalid output) becomes the same "needs human
  review" result, with a machine-readable `ReviewReason`, and ingestion carries on;
- stored severity is `max(source severity, model severity)`: prompt-injected alert text
  can make the model say "info", but cannot lower what is stored.

Nothing here talks to a model provider; `lighthouse.ai` is the only package that imports
the Anthropic SDK, behind the `TriageModel` interface.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from typing import Final, Protocol, Self, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lighthouse.ingest.schema import (
    MAX_CATEGORY_CHARS,
    MAX_EVIDENCE_KEY_CHARS,
    MAX_EVIDENCE_KEYS,
    MAX_EVIDENCE_TOTAL_BYTES,
    EvidenceValue,
)
from lighthouse.severity import Severity

logger = logging.getLogger(__name__)

DEFAULT_TRIAGE_TIMEOUT_SECONDS: Final = 60.0
NEEDS_REVIEW_SUMMARY: Final = "Automated triage was unavailable for this alert."
NEEDS_REVIEW_ACTION: Final = "Review this alert manually."

MAX_SUMMARY_CHARS: Final = 2000
MAX_ACTION_CHARS: Final = 1000
MAX_REASONING_CHARS: Final = 4000
MAX_MODEL_NAME_CHARS: Final = 128
# Far above any real single call; a bound so a corrupt usage report cannot overflow the
# budget arithmetic or the bigint columns.
MAX_TOKENS_PER_FIELD: Final = 100_000_000


class ReviewReason(Enum):
    """Why an alert went to a person instead of (or despite) the model.

    Values are stored in `lh.alerts.review_reason`, whose CHECK constraint lists the same
    set (a test compares them). Append only; never rename a stored value.
    """

    MODEL_DISABLED = "model_disabled"
    MODEL_UNAVAILABLE = "model_unavailable"
    BUDGET_EXCEEDED = "budget_exceeded"
    REFUSAL = "refusal"
    MAX_TOKENS = "max_tokens"
    SCHEMA_INVALID = "schema_invalid"
    UNEXPECTED_STOP = "unexpected_stop"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    AUTH_ERROR = "auth_error"
    CONNECTION_ERROR = "connection_error"
    API_ERROR = "api_error"
    INTERNAL_ERROR = "internal_error"

    @property
    def retry_on_next_ingestion(self) -> bool:
        """Whether a later ingestion of the same content should try the model again.

        Only outcomes that cost nothing or almost nothing are retried. Outcomes the alert
        content itself can provoke (refusal, overlong or invalid output, timeouts) are
        final for that content: otherwise one hostile alert re-polled every few minutes
        would buy a model call every time.
        """
        return self in _RETRYABLE


_RETRYABLE: Final = frozenset(
    {
        ReviewReason.MODEL_DISABLED,
        ReviewReason.MODEL_UNAVAILABLE,
        ReviewReason.BUDGET_EXCEEDED,
        ReviewReason.RATE_LIMITED,
        ReviewReason.AUTH_ERROR,
        ReviewReason.CONNECTION_ERROR,
        ReviewReason.API_ERROR,
    }
)


def _check_evidence(value: dict[str, EvidenceValue]) -> dict[str, EvidenceValue]:
    # Re-checked here, not trusted from the connector side: the prompt builder caps again,
    # but a TriageInput built by hand (tests, re-triage jobs) must not be unbounded either.
    if len(value) > MAX_EVIDENCE_KEYS + 1:  # +1: the connector's truncation marker
        msg = "too many evidence keys"
        raise ValueError(msg)
    if any(len(key) > MAX_EVIDENCE_KEY_CHARS for key in value):
        msg = "evidence key too long"
        raise ValueError(msg)
    try:
        encoded = json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        )
    except ValueError as exc:
        msg = "evidence is not finite JSON"
        raise ValueError(msg) from exc
    # Same canonical encoding and limit as lighthouse.ingest.schema.
    if len(encoded.encode("utf-8")) > MAX_EVIDENCE_TOTAL_BYTES:
        msg = "evidence too large"
        raise ValueError(msg)
    return value


class TriageInput(BaseModel):
    """What a triage model is given about an alert.

    Every free-text field is attacker-controlled. Fencing it as untrusted evidence is the
    prompt builder's job (`lighthouse.ai.prompt`); this model only bounds its size.
    `source_alert_id` is carried for logging and fixtures but is never sent to the model.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(min_length=1, max_length=64)
    source_alert_id: str = Field(min_length=1, max_length=512)
    title: str = Field(min_length=1, max_length=1000)
    source_severity: Severity
    description: str = Field(default="", max_length=8000)
    category: str | None = Field(default=None, min_length=1, max_length=MAX_CATEGORY_CHARS)
    occurred_at: datetime | None = None
    evidence: dict[str, EvidenceValue] = Field(default_factory=dict)

    @field_validator("evidence")
    @classmethod
    def _evidence_caps(cls, value: dict[str, EvidenceValue]) -> dict[str, EvidenceValue]:
        return _check_evidence(value)


class TriageUsage(BaseModel):
    """Token counts of one model call (all attempts, fallbacks included)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    input_tokens: int = Field(default=0, ge=0, le=MAX_TOKENS_PER_FIELD)
    output_tokens: int = Field(default=0, ge=0, le=MAX_TOKENS_PER_FIELD)
    cache_read_tokens: int = Field(default=0, ge=0, le=MAX_TOKENS_PER_FIELD)
    cache_creation_tokens: int = Field(default=0, ge=0, le=MAX_TOKENS_PER_FIELD)

    @property
    def total(self) -> int:
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_read_tokens
            + self.cache_creation_tokens
        )


class TriageResult(BaseModel):
    """The only shape of triage output the rest of the system accepts.

    `usage` is None when no model call was attempted (model disabled, no credentials,
    budget exhausted), and set (possibly all zeros, when the provider reported nothing)
    whenever one was. The pipeline writes a usage row exactly when it is set.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    severity: Severity
    summary: str = Field(min_length=1, max_length=MAX_SUMMARY_CHARS)
    recommended_action: str = Field(min_length=1, max_length=MAX_ACTION_CHARS)
    confidence: float = Field(ge=0.0, le=1.0)
    needs_human_review: bool = False
    review_reason: ReviewReason | None = None
    # A short justification for analysts. Model text: shown only to analyst and above.
    reasoning: str | None = Field(default=None, max_length=MAX_REASONING_CHARS)
    model: str | None = Field(default=None, min_length=1, max_length=MAX_MODEL_NAME_CHARS)
    usage: TriageUsage | None = None

    @model_validator(mode="after")
    def _review_state_is_consistent(self) -> Self:
        # One unambiguous state: "needs review" always says why, and a reason is never
        # attached to a result that claims to be fine.
        if self.needs_human_review != (self.review_reason is not None):
            msg = "needs_human_review must be set exactly when review_reason is"
            raise ValueError(msg)
        return self


class TriageModel(Protocol):
    async def triage(self, alert: TriageInput) -> TriageResult: ...


def apply_source_floor(source: Severity, model: Severity) -> Severity:
    return max(source, model)


def needs_human_review_result(
    source_severity: Severity,
    *,
    reason: ReviewReason,
    usage: TriageUsage | None = None,
    model: str | None = None,
) -> TriageResult:
    """The fallback for every abnormal outcome. Carries no model text at all."""
    return TriageResult(
        severity=source_severity,
        summary=NEEDS_REVIEW_SUMMARY,
        recommended_action=NEEDS_REVIEW_ACTION,
        confidence=0.0,
        needs_human_review=True,
        review_reason=reason,
        model=model,
        usage=usage,
    )


class FixtureModel:
    """Deterministic stand-in for Claude in tests and local development.

    Without an override it echoes the source severity. Overrides, keyed by
    `source_alert_id`, let tests make the "model" misbehave (for example, try to lower a
    severity) without a network call or a key.
    """

    def __init__(self, overrides: Mapping[str, TriageResult] | None = None) -> None:
        self._overrides = dict(overrides or {})

    async def triage(self, alert: TriageInput) -> TriageResult:
        override = self._overrides.get(alert.source_alert_id)
        if override is not None:
            return override
        # Attacker-controlled title/description are deliberately not echoed back.
        return TriageResult(
            severity=alert.source_severity,
            summary=f"Fixture triage of a {alert.source} alert.",
            recommended_action="Confirm whether the activity was expected.",
            confidence=0.5,
        )


async def run_triage(
    model: TriageModel,
    alert: TriageInput,
    *,
    timeout_seconds: float = DEFAULT_TRIAGE_TIMEOUT_SECONDS,
) -> TriageResult:
    """Triage one alert; never raises because of the model, always applies the floor."""
    try:
        # Typed as TriageResult, but treated as unknown: an adapter could return another
        # shape, or build a TriageResult with `model_construct` and skip validation.
        raw = cast("object", await asyncio.wait_for(model.triage(alert), timeout_seconds))
        result = TriageResult.model_validate(
            raw.model_dump() if isinstance(raw, BaseModel) else raw,
        )
    except TimeoutError:
        # The call was in flight, so it may have cost tokens the provider never reported.
        # A zero usage row still records that a call was made.
        logger.warning("triage fell back to human review: timeout")
        return needs_human_review_result(
            alert.source_severity, reason=ReviewReason.TIMEOUT, usage=TriageUsage()
        )
    # Validation failures, and errors an adapter failed to map itself, end the same way.
    # Cancellation is not caught: shutdown must still work.
    except Exception as exc:  # noqa: BLE001 - rule 4: any model failure means human review
        logger.warning("triage fell back to human review: %s", type(exc).__name__)
        return needs_human_review_result(
            alert.source_severity, reason=ReviewReason.INTERNAL_ERROR, usage=TriageUsage()
        )
    floored = apply_source_floor(alert.source_severity, result.severity)
    if floored is result.severity:
        return result
    return result.model_copy(update={"severity": floored})
