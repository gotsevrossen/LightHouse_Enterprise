from __future__ import annotations

import json
import shutil
import tomllib
from pathlib import Path
from typing import Any

import anthropic
import pytest
from lighthouse.ai.client import build_client
from lighthouse.config import Settings
from lighthouse.severity import Severity

from lh_evals import cli
from lh_evals.cases import case_set_digest, load_cases
from lh_evals.config import ConfigError, EvalConfig, load_config
from lh_evals.report import load_report
from lh_evals.runner import RunResult
from tests.stubs import StubAnthropic, answer, fake_api_key, message_body, outcome, respond

EVALS_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A copy of the committed inputs, so a run writes nothing into the repository."""
    shutil.copytree(EVALS_ROOT / "cases", tmp_path / "cases")
    shutil.copytree(EVALS_ROOT / "baselines", tmp_path / "baselines")
    shutil.copy(EVALS_ROOT / "eval-config.toml", tmp_path / "eval-config.toml")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return tmp_path


def test_fixture_run_writes_report_and_matches_baseline(
    workdir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = cli.run(["--compare", "baselines/fixture.json", "--json-out", "results/run.json"])
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK, out
    report = load_report(workdir / "results" / "run.json")
    assert report.status.complete
    assert report.metrics.floor_ok
    assert report.metrics.cases == len(load_cases(workdir / "cases" / "triage.jsonl"))
    assert (workdir / "results" / "run.md").read_text(encoding="utf-8").startswith("# Triage eval")
    assert "Result: ok" in out


def test_committed_baseline_matches_committed_cases() -> None:
    # If this fails, the cases changed: regenerate the baseline (see README.md).
    baseline = load_report(EVALS_ROOT / "baselines" / "fixture.json")
    cases = load_cases(EVALS_ROOT / "cases" / "triage.jsonl")
    assert baseline.run.case_set_sha256 == case_set_digest(cases)
    assert baseline.run.subject == "fixture"


def test_fixture_rejects_claude_only_options(workdir: Path) -> None:
    del workdir
    assert cli.run(["--model-id", "claude-opus-5-5"]) == cli.EXIT_USAGE
    assert cli.run(["--effort", "low"]) == cli.EXIT_USAGE


def test_bad_inputs_are_usage_errors(workdir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (workdir / "cases" / "bad.jsonl").write_text("{not json\n", encoding="utf-8")
    assert cli.run(["--cases", "cases/bad.jsonl"]) == cli.EXIT_USAGE
    assert "line 1" in capsys.readouterr().err
    assert cli.run(["--tags", "no_such_tag"]) == cli.EXIT_USAGE
    assert cli.run(["--compare", "baselines/missing.json"]) == cli.EXIT_USAGE
    assert cli.run(["--config", "missing.toml"]) == cli.EXIT_USAGE


def test_compare_fails_on_different_case_set(
    workdir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    del workdir
    code = cli.run(["--tags", "malware", "--compare", "baselines/fixture.json"])
    assert code == cli.EXIT_REGRESSION
    assert "case set differs" in capsys.readouterr().out


def test_claude_needs_a_budget(workdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    del workdir
    monkeypatch.setenv("ANTHROPIC_API_KEY", fake_api_key())
    assert cli.run(["--model", "claude"]) == cli.EXIT_USAGE


def test_claude_needs_the_key_and_never_asks_for_it_to_be_pasted(
    workdir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    del workdir
    assert cli.run(["--model", "claude", "--max-tokens-budget", "1000"]) == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert "ANTHROPIC_API_KEY is not set" in err
    assert "never paste it" in err


def test_claude_invalid_model_id_is_usage_error(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del workdir
    monkeypatch.setenv("ANTHROPIC_API_KEY", fake_api_key())
    args = ["--model", "claude", "--max-tokens-budget", "1000", "--model-id", "bad id!"]
    assert cli.run(args) == cli.EXIT_USAGE


def _stub_claude(monkeypatch: pytest.MonkeyPatch, stub: StubAnthropic) -> str:
    key = fake_api_key()
    monkeypatch.setenv("ANTHROPIC_API_KEY", key)

    def build(settings: Settings) -> anthropic.AsyncAnthropic | None:
        return build_client(settings, http_client=stub.http_client())

    monkeypatch.setattr(cli, "build_client", build)
    return key


def test_claude_run_end_to_end_never_writes_the_key(
    workdir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stub = StubAnthropic(respond(message_body([answer("critical")])))
    key = _stub_claude(monkeypatch, stub)
    args = [
        "--model",
        "claude",
        "--max-tokens-budget",
        "10000000",
        "--tags",
        "ransomware",
        "--effort",
        "low",
        "--json-out",
        "results/claude.json",
    ]
    code = cli.run(args)
    captured = capsys.readouterr()
    assert code == cli.EXIT_OK, captured.out + captured.err
    report = load_report(workdir / "results" / "claude.json")
    assert report.run.subject == "claude"
    assert report.run.model_id == "claude-opus-5-5"
    assert report.run.effort == "low"
    assert report.status.complete
    assert report.metrics.tokens.total == 1300 * report.metrics.cases
    # Cost: no prices configured -> tokens only.
    assert report.metrics.cost_usd is None
    assert report.metrics.unpriced_models == ["claude-opus-5-5"]
    assert all(json.loads(r.content)["output_config"]["effort"] == "low" for r in stub.requests)
    for path in (workdir / "results").iterdir():
        assert key not in path.read_text(encoding="utf-8")
    assert key not in captured.out
    assert key not in captured.err


def test_claude_run_stops_at_budget(
    workdir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    del workdir
    stub = StubAnthropic(respond(message_body()))
    _stub_claude(monkeypatch, stub)
    # Smaller than one reservation: nothing may start, and nothing is sent.
    code = cli.run(["--model", "claude", "--max-tokens-budget", "1000"])
    assert code == cli.EXIT_INCOMPLETE
    assert stub.requests == []
    assert "token budget reached" in capsys.readouterr().err


def test_floor_violation_exit_code(workdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    del workdir

    # Simulates a server regression that stores below the source severity.
    async def broken(*_: Any, **__: Any) -> RunResult:
        bad = outcome("mal-001", source=Severity.HIGH, model=Severity.LOW, stored=Severity.LOW)
        return RunResult(
            [bad], [], budget_stopped=False, tokens_spent=0, reservation_underestimates=0
        )

    monkeypatch.setattr(cli, "run_cases", broken)
    assert cli.run(["--limit", "1"]) == cli.EXIT_FLOOR


def test_committed_config_loads_with_no_prices() -> None:
    config = load_config(EVALS_ROOT / "eval-config.toml")
    # Prices are the owner's to fill in; none are committed from memory.
    assert config.prices == {}
    assert config.compare.max_under_triage_increase == 0.0


def test_config_validation(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    path.write_text('[prices."m"]\ninput = 1.0\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="output"):
        load_config(path)
    path.write_text("[compare]\nmax_under_triage_increase = 2\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="max_under_triage_increase"):
        load_config(path)
    path.write_text("not = [toml", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(path)
    path.write_text(
        '[prices."m"]\ninput = 1\noutput = 2\ncache_read = 0.1\ncache_write = 1.25\n',
        encoding="utf-8",
    )
    assert isinstance(load_config(path), EvalConfig)


def _locked_versions(path: Path) -> dict[str, str]:
    with path.open("rb") as handle:
        lock = tomllib.load(handle)
    return {
        p["name"]: p["version"]
        for p in lock["package"]
        if "version" in p and p.get("source", {}).get("registry")
    }


def test_eval_lock_pins_the_same_versions_as_the_server() -> None:
    # The eval must measure the SDK and libraries the server ships, not newer ones.
    server = _locked_versions(EVALS_ROOT.parent / "server" / "uv.lock")
    evals = _locked_versions(EVALS_ROOT / "uv.lock")
    shared = sorted(set(server) & set(evals))
    assert "anthropic" in shared
    assert "pydantic" in shared
    mismatched = {
        name: (server[name], evals[name]) for name in shared if server[name] != evals[name]
    }
    assert mismatched == {}, "re-seed evals/uv.lock from server/uv.lock (see README.md)"
