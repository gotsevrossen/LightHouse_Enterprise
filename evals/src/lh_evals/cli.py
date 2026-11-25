"""`lh-eval`: run the triage eval and write a report.

Exit codes: 0 ok; 1 regression against `--compare`; 2 usage or configuration error
(including a refused Claude run); 3 severity floor violated (a bug, always fatal);
4 run incomplete because the token budget was reached.

Key handling (CLAUDE.md "Secrets"): this program never reads, prints, logs or stores the
Anthropic API key. It checks only whether ANTHROPIC_API_KEY is set, then lets the
server's own `lighthouse.ai.client.build_client` build the client, exactly as the server
does, so the SDK reads the key from the environment itself.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, get_args

from lighthouse.ai.client import build_client
from lighthouse.config import Effort, Settings
from pydantic import SecretStr, ValidationError

from lh_evals.cases import (
    CaseFileError,
    EvalCase,
    case_set_digest,
    load_cases,
    select_cases,
)
from lh_evals.compare import compare_reports
from lh_evals.config import ConfigError, load_config
from lh_evals.report import Report, RunInfo, RunStatus, load_report, render_markdown, write_report
from lh_evals.runner import ClaudeSubject, ModelSubject, Subject, TokenBudget, run_cases
from lh_evals.score import compute_metrics

EXIT_OK: Final = 0
EXIT_REGRESSION: Final = 1
EXIT_USAGE: Final = 2
EXIT_FLOOR: Final = 3
EXIT_INCOMPLETE: Final = 4

MAX_CONCURRENCY: Final = 16
API_KEY_ENV: Final = "ANTHROPIC_API_KEY"

# Settings requires database and sign-in fields the eval never uses. Inert placeholders
# (reserved .invalid names, no credentials) passed explicitly, so a developer's real
# LH_DATABASE_URL is never needed or read for an eval run.
_PLACEHOLDER_SETTINGS: Final[dict[str, object]] = {
    "database_url": SecretStr("postgresql://unused.example.invalid/unused"),
    "jwt_issuer": "https://auth.example.invalid/auth/v1",
    "jwt_jwks_url": "https://auth.example.invalid/auth/v1/jwks",
    "jwt_public_key": None,
}


class UsageError(Exception):
    pass


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        msg = f"not an integer: {text!r}"
        raise argparse.ArgumentTypeError(msg) from exc
    if value < 1:
        msg = "must be at least 1"
        raise argparse.ArgumentTypeError(msg)
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lh-eval", description="Run the LightHouse triage eval through the server code."
    )
    parser.add_argument("--model", choices=("fixture", "claude"), default="fixture")
    parser.add_argument(
        "--model-id", help="Claude model id (default: LH_TRIAGE_MODEL or the server default)"
    )
    parser.add_argument(
        "--effort",
        choices=get_args(Effort.__value__),
        help="effort (default: LH_TRIAGE_EFFORT or the server default)",
    )
    parser.add_argument("--concurrency", type=_positive_int, default=2)
    parser.add_argument("--limit", type=_positive_int, help="run at most this many cases")
    parser.add_argument(
        "--tags",
        action="append",
        default=[],
        help="only cases with any of these tags (comma-separated, repeatable)",
    )
    parser.add_argument(
        "--max-tokens-budget",
        type=_positive_int,
        help="hard limit on tokens billed by the run (required with --model claude)",
    )
    parser.add_argument("--cases", type=Path, default=Path("cases/triage.jsonl"))
    parser.add_argument("--config", type=Path, default=Path("eval-config.toml"))
    parser.add_argument("--out-dir", type=Path, default=Path("results"))
    parser.add_argument("--json-out", type=Path, help="report path (default: in --out-dir)")
    parser.add_argument("--compare", type=Path, help="baseline report to compare against")
    return parser


def _split_tags(values: Sequence[str]) -> list[str]:
    return sorted({t.strip() for v in values for t in v.split(",") if t.strip()})


def claude_settings(model_id: str | None, effort: str | None) -> Settings:
    overrides: dict[str, object] = dict(_PLACEHOLDER_SETTINGS)
    if model_id is not None:
        overrides["triage_model"] = model_id
    if effort is not None:
        overrides["triage_effort"] = effort
    try:
        return Settings(**overrides)  # pyright: ignore[reportArgumentType]
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
            for e in exc.errors(include_url=False, include_input=False)
        )
        msg = f"invalid triage settings: {details}"
        raise UsageError(msg) from exc


def build_subject(args: argparse.Namespace) -> tuple[Subject, Settings | None]:
    if args.model == "fixture":
        if args.model_id is not None or args.effort is not None:
            msg = "--model-id and --effort apply only to --model claude"
            raise UsageError(msg)
        return ModelSubject(), None
    # A Claude run spends real money: no budget, no run.
    if args.max_tokens_budget is None:
        msg = "--model claude needs --max-tokens-budget"
        raise UsageError(msg)
    # Presence only; the value is never read into this program.
    if not os.environ.get(API_KEY_ENV):
        msg = (
            f"{API_KEY_ENV} is not set. Run this where the key is a runtime secret of the"
            " environment; never paste it into a chat, a file or a command line."
        )
        raise UsageError(msg)
    settings = claude_settings(args.model_id, args.effort)
    client = build_client(settings)
    if client is None:
        msg = "the server could not build a Claude client (triage disabled or no credential)"
        raise UsageError(msg)
    return ClaudeSubject(settings, client), settings


def _default_report_path(out_dir: Path, subject: Subject, started: datetime) -> Path:
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    name = subject.name if subject.model_id is None else f"{subject.name}-{subject.model_id}"
    return out_dir / f"{stamp}-{name.replace(':', '_')}.json"


def _selected_cases(path: Path, tags: Sequence[str], limit: int | None) -> list[EvalCase]:
    cases = select_cases(load_cases(path), tags=tags, limit=limit)
    if not cases:
        msg = "no cases match --tags/--limit"
        raise UsageError(msg)
    return cases


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        tags = _split_tags(args.tags)
        cases = _selected_cases(args.cases, tags, args.limit)
        concurrency = min(args.concurrency, MAX_CONCURRENCY)
        subject, settings = build_subject(args)
        baseline = load_report(args.compare) if args.compare is not None else None
    except (UsageError, CaseFileError, ConfigError, OSError, ValidationError) as exc:
        sys.stderr.write(f"lh-eval: {exc}\n")
        return EXIT_USAGE

    started = datetime.now(UTC)
    budget = TokenBudget(args.max_tokens_budget)
    result = asyncio.run(run_cases(subject, cases, concurrency=concurrency, budget=budget))
    finished = datetime.now(UTC)

    metrics = compute_metrics(result.outcomes, prices=config.prices, default_model=subject.model_id)
    report = Report(
        run=RunInfo(
            subject="claude" if settings is not None else "fixture",
            model_id=subject.model_id,
            effort=settings.triage_effort if settings is not None else None,
            max_tokens=settings.triage_max_tokens if settings is not None else None,
            concurrency=concurrency,
            tags=tags,
            limit=args.limit,
            max_tokens_budget=args.max_tokens_budget,
            case_file=args.cases.as_posix(),
            case_set_sha256=case_set_digest(cases),
            case_ids=[c.id for c in cases],
            started_at=started,
            finished_at=finished,
        ),
        status=RunStatus(
            complete=not result.not_run,
            not_run=result.not_run,
            tokens_spent=result.tokens_spent,
            reservation_underestimates=result.reservation_underestimates,
        ),
        metrics=metrics,
        outcomes=result.outcomes,
    )
    json_path = args.json_out or _default_report_path(args.out_dir, subject, started)
    write_report(report, json_path)
    markdown = render_markdown(report)
    md_path = args.out_dir / (json_path.stem + ".md")
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(markdown, encoding="utf-8")
    sys.stdout.write(markdown)
    sys.stdout.write(f"\nReport: {json_path}\nSummary: {md_path}\n")

    regression = False
    if baseline is not None:
        comparison = compare_reports(report, baseline, config.compare)
        sys.stdout.write(f"\nCompared with {args.compare}:\n")
        sys.stdout.writelines(f"  {line}\n" for line in comparison.lines)
        for failure in comparison.failures:
            sys.stdout.write(f"  REGRESSION: {failure}\n")
        sys.stdout.write("  Result: " + ("ok\n" if comparison.ok else "FAILED\n"))
        regression = not comparison.ok

    if not metrics.floor_ok:
        sys.stderr.write("lh-eval: SEVERITY FLOOR VIOLATED; this is a bug, see the report\n")
        return EXIT_FLOOR
    if result.not_run:
        sys.stderr.write(
            f"lh-eval: token budget reached; {len(result.not_run)} cases were not run\n"
        )
        return EXIT_INCOMPLETE
    return EXIT_REGRESSION if regression else EXIT_OK


def main() -> None:
    # WARNING keeps the server's per-case warnings visible without ever enabling the
    # SDK's DEBUG request logging (which lighthouse.ai.client also pins off).
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    sys.exit(run())
