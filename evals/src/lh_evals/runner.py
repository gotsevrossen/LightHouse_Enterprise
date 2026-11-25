"""Runs eval cases through the server's real triage path.

Every case goes through `lighthouse.triage.run_triage`, the same call the ingest pipeline
makes, with the same deadline. For Claude, the model is the server's own
`AnthropicTriageModel` built from `Settings` by `lighthouse.ai`: same prompt, schema,
effort, fallbacks, stop_reason handling and error mapping. Nothing about the request or
the validation is re-implemented here.

The one thing the server does not expose is the model's severity *before* the floor:
`AnthropicTriageModel` floors it itself. To measure the model's judgement (and not the
floor's), `ClaudeSubject` wraps the client in a pass-through that keeps the response
object in memory for the duration of one case, and reads the severity from it only when
the server accepted that response. The response is never written anywhere, and request
arguments are passed through untouched and never stored.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol, cast

from lighthouse.ai.prompt import OUTPUT_SCHEMA, SYSTEM_PROMPT, TriageOutput, render_user_content
from lighthouse.ai.triage_model import AnthropicTriageModel
from lighthouse.config import Settings
from lighthouse.severity import Severity
from lighthouse.triage import (
    FixtureModel,
    TriageInput,
    TriageModel,
    TriageResult,
    run_triage,
)
from pydantic import ValidationError

from lh_evals.cases import EvalCase
from lh_evals.score import CaseOutcome, TokenCounts, canary_echoed

if TYPE_CHECKING:
    from anthropic import AsyncAnthropic

# Billed attempts per triage call assumed by the budget reservation: the first model,
# and one server-side fallback after a refusal. The post-call check catches the case
# where this ever turns out low.
MAX_BILLED_ATTEMPTS: Final = 2
# Room for message framing and the structured-output instructions the API adds around
# the schema. Deliberately generous; it only affects when the run stops launching cases.
REQUEST_OVERHEAD_TOKENS: Final = 4096


@dataclass(frozen=True, slots=True)
class Observation:
    result: TriageResult
    # The model's own severity before the floor, when it gave an accepted answer.
    model_severity: Severity | None


class Subject(Protocol):
    """Something that triages one alert the way the server would."""

    @property
    def name(self) -> str: ...

    @property
    def model_id(self) -> str | None: ...

    def reservation(self, alert: TriageInput) -> int:
        """An upper bound on the tokens one triage of `alert` can bill."""
        ...

    async def observe(self, alert: TriageInput) -> Observation: ...


class _RecordingModel:
    """Passes a TriageModel through and keeps what it returned, before run_triage."""

    def __init__(self, inner: TriageModel) -> None:
        self._inner = inner
        self.returned: TriageResult | None = None

    async def triage(self, alert: TriageInput) -> TriageResult:
        result = await self._inner.triage(alert)
        self.returned = result
        return result


class ModelSubject:
    """Any in-process TriageModel (the fixture by default). Spends no tokens.

    Correct for models that do not floor their own answer, like FixtureModel, where the
    returned severity is the model's own. Not for AnthropicTriageModel: use ClaudeSubject.
    """

    def __init__(self, model: TriageModel | None = None, *, name: str = "fixture") -> None:
        self._model = model if model is not None else FixtureModel()
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def model_id(self) -> str | None:
        return None

    def reservation(self, alert: TriageInput) -> int:
        del alert
        return 0

    async def observe(self, alert: TriageInput) -> Observation:
        recording = _RecordingModel(self._model)
        result = await run_triage(recording, alert)
        returned = recording.returned
        raw = None if returned is None or result.needs_human_review else returned.severity
        return Observation(result=result, model_severity=raw)


class _CapturingMessages:
    def __init__(self, create: Callable[..., Awaitable[object]]) -> None:
        self._create = create
        self.responses: list[object] = []

    async def create(self, **kwargs: object) -> object:
        # Arguments go straight through and are not kept: they hold the prompt.
        response = await self._create(**kwargs)
        self.responses.append(response)
        return response


class _CapturingBeta:
    def __init__(self, messages: _CapturingMessages) -> None:
        self.messages = messages


class _CapturingClient:
    """Exposes only `beta.messages.create`, the one call AnthropicTriageModel makes."""

    def __init__(self, client: AsyncAnthropic) -> None:
        self.messages = _CapturingMessages(client.beta.messages.create)
        self.beta = _CapturingBeta(self.messages)


def raw_model_severity(response: object) -> Severity | None:
    """The severity the model answered with, read from an accepted response.

    Called only after the server accepted the response (the result is not "needs human
    review"), so stop_reason and the single text block were already checked by the
    server; they are re-checked here only so this function is safe on its own. Uses the
    server's own TriageOutput schema.
    """
    if getattr(response, "stop_reason", None) != "end_turn":
        return None
    content: object = getattr(response, "content", None)
    if not isinstance(content, list):
        return None
    texts = [
        getattr(block, "text", None)
        for block in cast("list[object]", content)
        if getattr(block, "type", None) == "text"
    ]
    if len(texts) != 1 or not isinstance(texts[0], str):
        return None
    try:
        return Severity(TriageOutput.model_validate_json(texts[0]).severity)
    except ValidationError:
        return None


class ClaudeSubject:
    """The server's AnthropicTriageModel, built from Settings, one instance per case."""

    def __init__(self, settings: Settings, client: AsyncAnthropic) -> None:
        self._settings = settings
        self._client = client
        # Constant per run: the system prompt and schema are the cached prefix.
        self._fixed_bytes = len(SYSTEM_PROMPT.encode("utf-8")) + len(
            json.dumps(OUTPUT_SCHEMA).encode("utf-8")
        )

    @property
    def name(self) -> str:
        return "claude"

    @property
    def model_id(self) -> str:
        return self._settings.triage_model

    def reservation(self, alert: TriageInput) -> int:
        # UTF-8 bytes bound the token count of text from above (every token covers at
        # least one byte). Output, thinking included, is bounded by max_tokens.
        prompt_bytes = self._fixed_bytes + len(render_user_content(alert).encode("utf-8"))
        per_attempt = prompt_bytes + REQUEST_OVERHEAD_TOKENS + self._settings.triage_max_tokens
        return MAX_BILLED_ATTEMPTS * per_attempt

    async def observe(self, alert: TriageInput) -> Observation:
        capture = _CapturingClient(self._client)
        # The wrapper offers only what AnthropicTriageModel uses; the cast is the price of
        # not re-implementing the model.
        model = AnthropicTriageModel(cast("AsyncAnthropic", capture), self._settings)
        result = await run_triage(
            model, alert, timeout_seconds=self._settings.triage_deadline_seconds
        )
        raw: Severity | None = None
        if not result.needs_human_review and len(capture.messages.responses) == 1:
            raw = raw_model_severity(capture.messages.responses[0])
        capture.messages.responses.clear()
        return Observation(result=result, model_severity=raw)


class TokenBudget:
    """Hard stop on the tokens one run may bill.

    A case starts only if the tokens already spent, plus the reservations of cases in
    flight, plus its own reservation (an upper bound), fit in the budget. Once any case
    cannot be reserved, or actual spend reaches the limit, no further case starts. Cases
    are launched in file order, so a stopped run always covers a prefix of the case set.
    The event loop is single-threaded and no await separates a check from its update, so
    no lock is needed.
    """

    def __init__(self, limit: int | None) -> None:
        if limit is not None and limit <= 0:
            msg = "token budget must be positive"
            raise ValueError(msg)
        self.limit = limit
        self.spent = 0
        self.reserved = 0
        self.exhausted = False
        self.underestimates = 0

    def try_reserve(self, amount: int) -> bool:
        if self.exhausted:
            return False
        if self.limit is not None and self.spent + self.reserved + amount > self.limit:
            self.exhausted = True
            return False
        self.reserved += amount
        return True

    def settle(self, reserved: int, actual: int) -> None:
        self.reserved -= reserved
        self.spent += actual
        if actual > reserved:
            self.underestimates += 1
        if self.limit is not None and self.spent >= self.limit:
            self.exhausted = True


@dataclass(frozen=True, slots=True)
class RunResult:
    outcomes: list[CaseOutcome]
    not_run: list[str]
    budget_stopped: bool
    tokens_spent: int
    reservation_underestimates: int


def outcome_for(case: EvalCase, observation: Observation) -> CaseOutcome:
    result = observation.result
    echoed = (
        canary_echoed(case.canary, (result.summary, result.recommended_action, result.reasoning))
        if case.canary is not None
        else None
    )
    return CaseOutcome(
        case_id=case.id,
        tags=case.tags,
        injection=case.is_injection,
        source_severity=case.alert.source_severity,
        model_severity=observation.model_severity,
        stored_severity=result.severity,
        min_severity=case.expected.min_severity,
        max_severity=case.expected.max_severity,
        expect_review=case.expected.expect_review,
        expected_category=case.expected.expected_category,
        needs_human_review=result.needs_human_review,
        review_reason=result.review_reason.value if result.review_reason else None,
        canary_echoed=echoed,
        model=result.model,
        tokens=TokenCounts.from_usage(result.usage),
    )


async def run_cases(
    subject: Subject,
    cases: Sequence[EvalCase],
    *,
    concurrency: int,
    budget: TokenBudget,
) -> RunResult:
    if concurrency < 1:
        msg = "concurrency must be at least 1"
        raise ValueError(msg)
    semaphore = asyncio.Semaphore(concurrency)
    outcomes: dict[str, CaseOutcome] = {}

    async def one(case: EvalCase, reserved: int) -> None:
        try:
            observation = await subject.observe(case.alert)
            outcome = outcome_for(case, observation)
            outcomes[case.id] = outcome
            budget.settle(reserved, outcome.tokens.total)
        except BaseException:
            # run_triage never raises for a model failure, so this is a harness fault (or
            # cancellation). Keep the reservation counted as spent: tokens may have been.
            budget.settle(reserved, reserved)
            raise
        finally:
            semaphore.release()

    launched: list[str] = []
    async with asyncio.TaskGroup() as group:
        for case in cases:
            await semaphore.acquire()
            reserved = subject.reservation(case.alert)
            if not budget.try_reserve(reserved):
                semaphore.release()
                break
            launched.append(case.id)
            group.create_task(one(case, reserved))

    ordered = [outcomes[case_id] for case_id in launched]
    not_run = [case.id for case in cases if case.id not in outcomes]
    return RunResult(
        outcomes=ordered,
        not_run=not_run,
        budget_stopped=bool(not_run),
        tokens_spent=budget.spent,
        reservation_underestimates=budget.underestimates,
    )
