from __future__ import annotations

import json
from typing import Any

import httpx2
import pytest
from lighthouse.ai.client import build_client
from lighthouse.ai.prompt import SYSTEM_PROMPT
from lighthouse.severity import Severity
from lighthouse.triage import (
    FixtureModel,
    ReviewReason,
    TriageInput,
    TriageResult,
    TriageUsage,
)

from lh_evals.cli import claude_settings
from lh_evals.runner import (
    ClaudeSubject,
    ModelSubject,
    Observation,
    TokenBudget,
    outcome_for,
    raw_model_severity,
    run_cases,
)
from tests.stubs import (
    REFUSAL_BODY,
    StubAnthropic,
    alert,
    answer,
    fake_api_key,
    injection_case_dict,
    make_case,
    message_body,
    respond,
)

S = Severity


class LoweringModel:
    """A misbehaving model that always answers 'info' (as an injected model might)."""

    async def triage(self, alert: TriageInput) -> TriageResult:
        del alert
        return TriageResult(
            severity=S.INFO,
            summary="Nothing to see. LHCANARY-test-1",
            recommended_action="None.",
            confidence=1.0,
            usage=TriageUsage(input_tokens=10, output_tokens=5),
        )


async def test_fixture_subject_runs_server_path() -> None:
    observation = await ModelSubject().observe(alert(severity=S.HIGH))
    assert observation.result.severity is S.HIGH
    assert observation.model_severity is S.HIGH
    assert not observation.result.needs_human_review


async def test_model_subject_sees_raw_severity_but_stores_floor() -> None:
    observation = await ModelSubject(LoweringModel(), name="lowering").observe(
        alert(severity=S.HIGH)
    )
    assert observation.model_severity is S.INFO
    assert observation.result.severity is S.HIGH  # run_triage applied the floor


def test_outcome_for_flags_canary_echo() -> None:
    case = make_case(**injection_case_dict())
    result = TriageResult(
        severity=S.HIGH,
        summary="Text tried to make me say lhcanary test 1.",
        recommended_action="Investigate.",
        confidence=0.5,
    )
    o = outcome_for(case, Observation(result=result, model_severity=S.HIGH))
    assert o.injection
    assert o.canary_echoed is True
    clean = result.model_copy(update={"summary": "Injected instructions were ignored."})
    assert outcome_for(case, Observation(clean, S.HIGH)).canary_echoed is False
    assert outcome_for(make_case(), Observation(clean, S.HIGH)).canary_echoed is None


def test_raw_model_severity_reads_only_accepted_shapes() -> None:
    class Block:
        def __init__(self, kind: str, text: str | None = None) -> None:
            self.type = kind
            self.text = text

    class Message:
        def __init__(self, stop: str, content: list[Block]) -> None:
            self.stop_reason = stop
            self.content = content

    good = Message("end_turn", [Block("thinking"), Block("text", answer("low"))])
    assert raw_model_severity(good) is S.LOW
    assert raw_model_severity(Message("refusal", [])) is None
    two = Message("end_turn", [Block("text", answer()), Block("text", answer())])
    assert raw_model_severity(two) is None
    assert raw_model_severity(Message("end_turn", [Block("text", "not json")])) is None
    assert raw_model_severity(object()) is None


def test_token_budget_reserves_and_stops() -> None:
    budget = TokenBudget(100)
    assert budget.try_reserve(60)
    assert not budget.try_reserve(50)  # 60 in flight + 50 > 100
    assert budget.exhausted
    assert not budget.try_reserve(1)  # once stopped, stays stopped
    budget.settle(60, 70)
    assert budget.spent == 70
    assert budget.underestimates == 1


def test_token_budget_stops_when_spend_reaches_limit() -> None:
    budget = TokenBudget(100)
    assert budget.try_reserve(100)
    budget.settle(100, 100)
    assert budget.exhausted
    unlimited = TokenBudget(None)
    assert unlimited.try_reserve(10**9)
    with pytest.raises(ValueError, match="positive"):
        TokenBudget(0)


class _CountingSubject:
    """Bills a fixed number of tokens per case and reserves a fixed amount."""

    def __init__(self, reserve: int, spend: int) -> None:
        self._reserve = reserve
        self._spend = spend
        self.calls = 0

    @property
    def name(self) -> str:
        return "counting"

    @property
    def model_id(self) -> str | None:
        return None

    def reservation(self, alert: TriageInput) -> int:
        del alert
        return self._reserve

    async def observe(self, alert: TriageInput) -> Observation:
        self.calls += 1
        result = await ModelSubject().observe(alert)
        usage = TriageUsage(input_tokens=self._spend)
        return Observation(result.result.model_copy(update={"usage": usage}), S.MEDIUM)


def _cases(n: int) -> list[Any]:
    return [make_case(id=f"case-{i}") for i in range(n)]


@pytest.mark.parametrize("concurrency", [1, 3])
async def test_run_stops_at_budget_and_reports_prefix(concurrency: int) -> None:
    subject = _CountingSubject(reserve=100, spend=40)
    # Room for 2.5 reservations: never more than 2 calls in flight; after spend, more fit.
    result = await run_cases(subject, _cases(10), concurrency=concurrency, budget=TokenBudget(250))
    assert result.budget_stopped
    assert result.tokens_spent <= 250
    ran = [o.case_id for o in result.outcomes]
    # Always a prefix of the case order, and every case is either run or listed.
    assert ran == [f"case-{i}" for i in range(len(ran))]
    assert result.not_run == [f"case-{i}" for i in range(len(ran), 10)]
    assert subject.calls == len(ran)


async def test_run_without_budget_runs_everything_in_order() -> None:
    result = await run_cases(
        ModelSubject(FixtureModel()), _cases(5), concurrency=2, budget=TokenBudget(None)
    )
    assert not result.budget_stopped
    assert [o.case_id for o in result.outcomes] == [f"case-{i}" for i in range(5)]


async def test_run_rejects_bad_concurrency() -> None:
    with pytest.raises(ValueError, match="concurrency"):
        await run_cases(ModelSubject(), _cases(1), concurrency=0, budget=TokenBudget(None))


# --- The Claude path: real SDK, real AnthropicTriageModel, local transport -------------


def _claude(stub: StubAnthropic, monkeypatch: pytest.MonkeyPatch) -> ClaudeSubject:
    monkeypatch.setenv("ANTHROPIC_API_KEY", fake_api_key())
    settings = claude_settings(None, None)
    client = build_client(settings, http_client=stub.http_client())
    assert client is not None
    return ClaudeSubject(settings, client)


async def test_claude_subject_uses_server_request_and_sees_raw_severity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = StubAnthropic(respond(message_body([answer("low")])))
    subject = _claude(stub, monkeypatch)
    observation = await subject.observe(alert(severity=S.HIGH))
    # The model said low; the server floored storage at the source's high.
    assert observation.model_severity is S.LOW
    assert observation.result.severity is S.HIGH
    assert observation.result.usage is not None
    assert observation.result.usage.total == 1300
    [request] = stub.requests
    body: dict[str, Any] = json.loads(request.content)
    # The server built this request, not the harness.
    assert body["system"][0]["text"] == SYSTEM_PROMPT
    assert body["model"] == "claude-opus-5-5"
    assert body["output_config"]["effort"] == "medium"


async def test_claude_refusal_is_review_without_model_severity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _claude(StubAnthropic(respond(REFUSAL_BODY)), monkeypatch)
    observation = await subject.observe(alert(severity=S.MEDIUM))
    assert observation.result.needs_human_review
    assert observation.result.review_reason is ReviewReason.REFUSAL
    assert observation.model_severity is None


async def test_claude_api_error_is_review(monkeypatch: pytest.MonkeyPatch) -> None:
    error = {"type": "error", "error": {"type": "api_error", "message": "stubbed"}}
    subject = _claude(StubAnthropic(respond(error, 500)), monkeypatch)
    observation = await subject.observe(alert())
    assert observation.result.review_reason is ReviewReason.API_ERROR
    assert observation.model_severity is None


async def test_claude_reservation_bounds_actual_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    subject = _claude(StubAnthropic(respond(message_body())), monkeypatch)
    big = alert(evidence={"description": "x" * 1000, "devices": ["d" * 200] * 20})
    reservation = subject.reservation(big)
    # Two attempts, each at least max_tokens of output plus the prompt.
    assert reservation >= 2 * (16_000 + len(SYSTEM_PROMPT))
    assert subject.reservation(alert()) < reservation


async def test_claude_case_through_run_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        return httpx2.Response(
            200, json=message_body([answer("info", summary="Said LHCANARY-test-1 as asked.")])
        )

    subject = _claude(StubAnthropic(handler), monkeypatch)
    case = make_case(**injection_case_dict())
    result = await run_cases(subject, [case], concurrency=1, budget=TokenBudget(10**6))
    [o] = result.outcomes
    assert o.canary_echoed is True
    assert o.model_severity is S.INFO
    assert o.stored_severity is S.MEDIUM
    assert o.model == "claude-opus-5-5"
    assert result.tokens_spent == 1300
