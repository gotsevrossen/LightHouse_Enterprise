"""Compare a run with a baseline report and decide whether it regressed.

Gates (any one fails the comparison):

- the two reports must cover the same case set (same digest): a score on different cases
  is not a regression or an improvement, just a different number;
- both runs must be complete (a budget-stopped run covers only a prefix);
- the current run's severity floor must hold (always; no threshold);
- the under-triage rate may not rise by more than the configured threshold;
- injection resistance may not fall by more than the configured threshold.

Everything else (over-triage, review agreement, tokens, cost, composite) is printed as a
delta for the reader and never gates: those are trade-offs the owner weighs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from lh_evals.config import CompareThresholds
from lh_evals.report import Report

# Rates are ratios of small integers; allow for float noise when comparing them.
_EPSILON: Final = 1e-9


@dataclass
class Comparison:
    lines: list[str] = field(default_factory=list[str])
    failures: list[str] = field(default_factory=list[str])

    @property
    def ok(self) -> bool:
        return not self.failures


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _delta(name: str, current: float | None, baseline: float | None) -> str:
    if current is None or baseline is None:
        return f"{name}: {_fmt(current)} (baseline {_fmt(baseline)})"
    change = (current - baseline) * 100
    return f"{name}: {_fmt(current)} (baseline {_fmt(baseline)}, {change:+.1f} points)"


def compare_reports(current: Report, baseline: Report, thresholds: CompareThresholds) -> Comparison:
    out = Comparison()
    cm, bm = current.metrics, baseline.metrics

    if current.run.case_set_sha256 != baseline.run.case_set_sha256:
        out.failures.append(
            "case set differs from the baseline (cases, labels, --tags or --limit changed);"
            " regenerate the baseline or run on the same cases"
        )
    if not current.status.complete:
        out.failures.append("current run is incomplete (token budget reached)")
    if not baseline.status.complete:
        out.failures.append("baseline run is incomplete")
    if not cm.floor_ok:
        out.failures.append(
            f"severity floor violated on {', '.join(cm.floor_violation_cases)} (a bug)"
        )

    out.lines.append(_delta("under-triage", cm.under_triage_rate, bm.under_triage_rate))
    if cm.under_triage_rate is not None and bm.under_triage_rate is not None:
        rise = cm.under_triage_rate - bm.under_triage_rate
        if rise > thresholds.max_under_triage_increase + _EPSILON:
            newly = sorted(set(cm.under_triage_cases) - set(bm.under_triage_cases))
            out.failures.append(
                f"under-triage rose by {rise * 100:.1f} points"
                f" (allowed {thresholds.max_under_triage_increase * 100:.1f});"
                f" newly under-triaged: {', '.join(newly) or 'none'}"
            )

    out.lines.append(
        _delta("injection resistance", cm.injection_resistance_rate, bm.injection_resistance_rate)
    )
    if cm.injection_resistance_rate is not None and bm.injection_resistance_rate is not None:
        drop = bm.injection_resistance_rate - cm.injection_resistance_rate
        if drop > thresholds.max_injection_resistance_drop + _EPSILON:
            out.failures.append(
                f"injection resistance fell by {drop * 100:.1f} points"
                f" (allowed {thresholds.max_injection_resistance_drop * 100:.1f})"
            )

    out.lines += [
        _delta("severity in range", cm.severity_in_range_rate, bm.severity_in_range_rate),
        _delta("over-triage", cm.over_triage_rate, bm.over_triage_rate),
        _delta("review agreement", cm.review_agreement_rate, bm.review_agreement_rate),
        _delta("needs-human-review", cm.needs_review_rate, bm.needs_review_rate),
        f"composite: {cm.composite} (baseline {bm.composite})",
        f"tokens: {cm.tokens.total} (baseline {bm.tokens.total})",
        f"cost (USD): {cm.cost_usd} (baseline {bm.cost_usd})",
    ]
    return out
