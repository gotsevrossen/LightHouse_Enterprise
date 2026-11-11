"""Provider-independent triage pieces (no model calls in Phase 0).

Security boundary: triage validation. The rules this module carries (CLAUDE.md 4 and 5):

- model output is untrusted and is validated against `TriageResult` before use;
- any failure (exception, timeout, invalid output) becomes the same "needs human review"
  result, and ingestion carries on;
- stored severity is `max(source severity, model severity)`: prompt-injected alert text
  can make the model say "informational", but cannot lower what is stored.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from typing import Final, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field

from lighthouse.severity import Severity

logger = logging.getLogger(__name__)

DEFAULT_TRIAGE_TIMEOUT_SECONDS: Final = 60.0
NEEDS_REVIEW_SUMMARY: Final = "Automated triage was unavailable for this alert."
NEEDS_REVIEW_ACTION: Final = "Review this alert manually."


class TriageInput(BaseModel):
    """What a triage model is given about an alert.

    Free-text fields are attacker-controlled. Fencing them as untrusted evidence is the
    prompt builder's job (Phase 1); this model only caps their size.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(min_length=1, max_length=64)
    source_alert_id: str = Field(min_length=1, max_length=512)
    title: str = Field(min_length=1, max_length=1000)
    source_severity: Severity
    description: str = Field(default="", max_length=8000)


class TriageResult(BaseModel):
    """The only shape of model output the rest of the system accepts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    severity: Severity
    summary: str = Field(min_length=1, max_length=2000)
    recommended_action: str = Field(min_length=1, max_length=1000)
    confidence: float = Field(ge=0.0, le=1.0)
    needs_human_review: bool = False


class TriageModel(Protocol):
    async def triage(self, alert: TriageInput) -> TriageResult: ...


def apply_source_floor(source: Severity, model: Severity) -> Severity:
    return max(source, model)


def needs_human_review_result(source_severity: Severity) -> TriageResult:
    return TriageResult(
        severity=source_severity,
        summary=NEEDS_REVIEW_SUMMARY,
        recommended_action=NEEDS_REVIEW_ACTION,
        confidence=0.0,
        needs_human_review=True,
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
    # Timeouts, validation failures, refusals surfaced as errors by an adapter, and API
    # errors all end the same way. Cancellation is not caught: shutdown must still work.
    except Exception as exc:  # noqa: BLE001 - rule 4: any model failure means human review
        logger.warning("triage fell back to human review: %s", type(exc).__name__)
        return needs_human_review_result(alert.source_severity)
    floored = apply_source_floor(alert.source_severity, result.severity)
    if floored is result.severity:
        return result
    return result.model_copy(update={"severity": floored})
