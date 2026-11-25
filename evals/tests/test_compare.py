from __future__ import annotations

from datetime import UTC, datetime

from lighthouse.severity import Severity

from lh_evals.compare import compare_reports
from lh_evals.config import CompareThresholds
from lh_evals.report import Report, RunInfo, RunStatus, render_markdown
from lh_evals.score import CaseOutcome, compute_metrics
from tests.stubs import outcome

S = Severity
NOW = datetime(2026, 11, 1, tzinfo=UTC)


def _report(
    outcomes: list[CaseOutcome], *, digest: str = "d" * 64, complete: bool = True
) -> Report:
    return Report(
        run=RunInfo(
            subject="fixture",
            model_id=None,
            effort=None,
            max_tokens=None,
            concurrency=1,
            tags=[],
            limit=None,
            max_tokens_budget=None,
            case_file="cases/triage.jsonl",
            case_set_sha256=digest,
            case_ids=[o.case_id for o in outcomes],
            started_at=NOW,
            finished_at=NOW,
        ),
        status=RunStatus(
            complete=complete,
            not_run=[] if complete else ["later"],
            tokens_spent=0,
            reservation_underestimates=0,
        ),
        metrics=compute_metrics(outcomes, prices={}),
        outcomes=outcomes,
    )


def _good() -> list[CaseOutcome]:
    return [
        outcome("a", model=S.HIGH, lo=S.HIGH, hi=S.CRITICAL),
        outcome("b", model=S.MEDIUM),
        outcome("inj", injection=True, model=S.HIGH, lo=S.HIGH),
        outcome("inj2", injection=True, model=S.HIGH, lo=S.HIGH),
    ]


def test_identical_runs_pass() -> None:
    result = compare_reports(_report(_good()), _report(_good()), CompareThresholds())
    assert result.ok
    assert any(line.startswith("under-triage") for line in result.lines)


def test_under_triage_rise_fails_and_names_cases() -> None:
    worse = _good()
    worse[0] = outcome("a", source=S.MEDIUM, model=S.LOW, lo=S.HIGH, hi=S.CRITICAL)
    result = compare_reports(_report(worse), _report(_good()), CompareThresholds())
    assert not result.ok
    assert any("under-triage rose" in f and "a" in f for f in result.failures)


def test_threshold_allows_small_rise() -> None:
    worse = _good()
    worse[0] = outcome("a", source=S.MEDIUM, model=S.LOW, lo=S.HIGH, hi=S.CRITICAL)
    loose = CompareThresholds(max_under_triage_increase=0.25)  # one case in four
    assert compare_reports(_report(worse), _report(_good()), loose).ok


def test_improvement_passes() -> None:
    worse = _good()
    worse[0] = outcome("a", source=S.MEDIUM, model=S.LOW, lo=S.HIGH, hi=S.CRITICAL)
    assert compare_reports(_report(_good()), _report(worse), CompareThresholds()).ok


def test_injection_resistance_drop_fails() -> None:
    worse = _good()
    worse[2] = outcome("inj", injection=True, canary_echoed=True, model=S.HIGH, lo=S.HIGH)
    result = compare_reports(_report(worse), _report(_good()), CompareThresholds())
    assert any("injection resistance fell" in f for f in result.failures)
    loose = CompareThresholds(max_injection_resistance_drop=0.5)
    assert compare_reports(_report(worse), _report(_good()), loose).ok


def test_floor_violation_always_fails() -> None:
    bad = _good()
    bad[1] = outcome("b", source=S.HIGH, model=S.LOW, stored=S.LOW, lo=S.LOW)
    loose = CompareThresholds(max_under_triage_increase=1.0, max_injection_resistance_drop=1.0)
    result = compare_reports(_report(bad), _report(_good()), loose)
    assert any("severity floor violated" in f for f in result.failures)


def test_different_case_set_fails() -> None:
    result = compare_reports(
        _report(_good(), digest="a" * 64), _report(_good()), CompareThresholds()
    )
    assert any("case set differs" in f for f in result.failures)


def test_incomplete_runs_fail() -> None:
    result = compare_reports(
        _report(_good(), complete=False), _report(_good()), CompareThresholds()
    )
    assert any("current run is incomplete" in f for f in result.failures)
    result = compare_reports(
        _report(_good()), _report(_good(), complete=False), CompareThresholds()
    )
    assert any("baseline run is incomplete" in f for f in result.failures)


def test_markdown_flags_floor_and_incomplete_runs() -> None:
    bad = [outcome("b", source=S.HIGH, model=S.LOW, stored=S.LOW, lo=S.LOW)]
    text = render_markdown(_report(bad, complete=False))
    assert "SEVERITY FLOOR VIOLATED" in text
    assert "INCOMPLETE" in text
    assert "Under-triage rate (headline" in text
    clean = render_markdown(_report(_good()))
    assert "SEVERITY FLOOR" not in clean
    assert "Cost: $0.0000" in clean
