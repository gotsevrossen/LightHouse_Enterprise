"""The eval report: a JSON file (the record, and what `--compare` reads) and a short
Markdown summary for people.

Neither contains model text, prompts, request bodies or credentials: only case ids,
labels, severities, flags, token counts and the run's settings.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from lh_evals.score import CaseOutcome, Metrics

REPORT_FORMAT: Final = 1


class RunInfo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: Literal["fixture", "claude"]
    # The configured model id (Claude runs); the served model per case is in outcomes.
    model_id: str | None
    effort: str | None
    max_tokens: int | None
    concurrency: int
    tags: list[str]
    limit: int | None
    max_tokens_budget: int | None
    case_file: str
    case_set_sha256: str
    case_ids: list[str]
    started_at: datetime
    finished_at: datetime


class RunStatus(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    complete: bool
    # Cases never started because the token budget would have been exceeded.
    not_run: list[str]
    tokens_spent: int
    # Cases whose actual usage exceeded the budget reservation. Should stay 0; if not,
    # the reservation formula in runner.py is too low.
    reservation_underestimates: int


class Report(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    format: int = Field(default=REPORT_FORMAT)
    run: RunInfo
    status: RunStatus
    metrics: Metrics
    outcomes: list[CaseOutcome]


def load_report(path: Path) -> Report:
    return Report.model_validate_json(path.read_text(encoding="utf-8"))


def write_report(report: Report, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _ids(ids: list[str]) -> str:
    return ", ".join(ids) if ids else "none"


def render_markdown(report: Report) -> str:
    m = report.metrics
    run = report.run
    subject = run.subject if run.model_id is None else f"{run.subject} ({run.model_id})"
    lines = [
        f"# Triage eval: {subject}",
        "",
        (
            f"- Cases: {m.cases} of {len(run.case_ids)} selected"
            f" (case set {run.case_set_sha256[:12]}), answered by the model: {m.answered}"
        ),
        f"- Effort: {run.effort or 'n/a'}, max tokens: {run.max_tokens or 'n/a'}",
        f"- Started {run.started_at.isoformat()}, finished {run.finished_at.isoformat()}",
    ]
    if not report.status.complete:
        lines += [
            "",
            (
                f"**INCOMPLETE: token budget reached; {len(report.status.not_run)} cases not"
                " run. Do not compare this run with a complete one.**"
            ),
        ]
    if not m.floor_ok:
        lines += [
            "",
            (
                "**SEVERITY FLOOR VIOLATED: stored severity below source severity on "
                f"{_ids(m.floor_violation_cases)}. This is a bug, not a model score.**"
            ),
        ]
    lines += [
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Under-triage rate (headline, lower is better) | {_pct(m.under_triage_rate)} |",
        f"| Severity in range | {_pct(m.severity_in_range_rate)} |",
        f"| Over-triage rate | {_pct(m.over_triage_rate)} |",
        f"| Stored under-triage (after floor) | {_pct(m.stored_under_triage_rate)} |",
        f"| Severity floor held | {'yes' if m.floor_ok else 'NO'} |",
        (
            f"| Injection resistance ({m.injection_cases} cases) "
            f"| {_pct(m.injection_resistance_rate)} |"
        ),
        f"| Review agreement | {_pct(m.review_agreement_rate)} |",
        f"| Needs-human-review rate | {_pct(m.needs_review_rate)} |",
        f"| Category accuracy | {_pct(m.category_accuracy)} |",
        (
            f"| Composite (weights {m.composite_weights}) | "
            f"{'n/a' if m.composite is None else f'{m.composite:.3f}'} |"
        ),
        "",
        f"- Under-triaged: {_ids(m.under_triage_cases)}",
        f"- Over-triaged: {_ids(m.over_triage_cases)}",
        f"- Canary echoed: {_ids(m.canary_echo_cases)}",
        f"- Injection cases under-triaged: {_ids(m.injection_under_triage_cases)}",
        f"- Review missed: {_ids(m.review_missed_cases)}",
        f"- Review noise: {_ids(m.review_noise_cases)}",
        f"- Review reasons: {m.review_reasons or 'none'}",
        "",
        (
            f"Tokens: input {m.tokens.input}, output {m.tokens.output}, cache read "
            f"{m.tokens.cache_read}, cache write {m.tokens.cache_write}, total {m.tokens.total}"
            f" ({'n/a' if m.tokens_per_case is None else f'{m.tokens_per_case:.0f}'} per case)."
        ),
    ]
    if m.cost_usd is None:
        lines.append(
            f"Cost: not computed; no price configured for {_ids(m.unpriced_models)}"
            " (eval-config.toml)."
        )
    else:
        per_case = "n/a" if m.cost_per_case_usd is None else f"${m.cost_per_case_usd:.6f}"
        lines.append(f"Cost: ${m.cost_usd:.4f} ({per_case} per case).")
    if m.category_accuracy is None and m.category_labelled_cases:
        lines.append(
            f"Category: {m.category_labelled_cases} cases are labelled, but the triage output"
            " has no category field, so accuracy cannot be measured yet."
        )
    return "\n".join(lines) + "\n"
