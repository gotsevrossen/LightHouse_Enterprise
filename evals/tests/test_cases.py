from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from lighthouse.severity import Severity

from lh_evals.cases import (
    CaseFileError,
    alert_text,
    case_set_digest,
    load_cases,
    parse_cases,
    select_cases,
)
from tests.stubs import case_dict, injection_case_dict

EVALS_ROOT = Path(__file__).resolve().parents[1]
CASE_FILE = EVALS_ROOT / "cases" / "triage.jsonl"

# Documentation ranges (RFC 5737) only: no address in the eval set can belong to anyone.
_RESERVED_NETS = [
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
# File names that look like domains: the industry-standard antivirus test file.
_NOT_HOSTS = frozenset({"eicar.com"})
_HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|invalid)\b", re.IGNORECASE)


def _lines(*cases: dict[str, Any]) -> list[str]:
    return [json.dumps(c) for c in cases]


def test_committed_case_file_loads_and_meets_the_brief() -> None:
    cases = load_cases(CASE_FILE)
    assert len(cases) >= 50
    injections = [c for c in cases if c.is_injection]
    assert len(injections) >= 12
    assert len({c.canary for c in injections}) == len(injections)
    tags = {t for c in cases for t in c.tags}
    for required in (
        "malware",
        "credential_access",
        "phishing",
        "suspicious_signin",
        "lateral_movement",
        "ransomware",
        "benign",
        "informational",
    ):
        assert required in tags


def test_committed_case_file_is_synthetic() -> None:
    text = CASE_FILE.read_text(encoding="utf-8")
    for match in _IP_RE.findall(text):
        address = ipaddress.ip_address(match)
        assert any(address in net for net in _RESERVED_NETS), match
    for host in _HOST_RE.findall(text):
        if host.lower() in _NOT_HOSTS:
            continue
        assert host.lower().endswith(("example.com", "example.net", ".invalid")), host


def test_valid_case_parses_and_derives_alert_id() -> None:
    [case] = parse_cases(_lines(case_dict()))
    assert case.alert.source_alert_id == "eval-test-001"
    assert case.alert.source_severity is Severity.MEDIUM
    assert not case.is_injection


def test_injection_case_parses() -> None:
    [case] = parse_cases(_lines(injection_case_dict()))
    assert case.is_injection
    assert case.canary is not None
    assert case.canary in alert_text(case.alert)


def _set(data: dict[str, Any], path: str, value: object) -> dict[str, Any]:
    node: Any = data
    *parents, last = path.split(".")
    for key in parents:
        node = node[key]
    node[last] = value
    return data


type Mutation = Callable[[dict[str, Any]], dict[str, Any]]

_MALFORMED: list[tuple[Mutation, str]] = [
    (lambda c: _set(c, "extra_field", 1), "extra_field"),
    (lambda c: _set(c, "expected.min_severity", "critical"), "min_severity is above"),
    (lambda c: _set(c, "expected.min_severity", "severe"), "min_severity"),
    (lambda c: _set(c, "alert.source_severity", "informational"), "source_severity"),
    (lambda c: _set(c, "alert.source_alert_id", "x"), "derived from the case id"),
    (lambda c: _set(c, "alert.evidence", {"Bad Key": "x"}), "connector-shaped"),
    # Rejected by the server's own TriageInput type, before the connector check.
    (lambda c: _set(c, "alert.evidence", {"nested": {"a": 1}}), "alert.evidence.nested"),
    (lambda c: _set(c, "alert.evidence", {"blob": "x" * 2000}), "connector caps"),
    (lambda c: _set(c, "alert.title", ""), "title"),
    (lambda c: _set(c, "id", "Bad ID"), "id"),
    (lambda c: _set(c, "tags", []), "tags"),
    (lambda c: _set(c, "tags", ["Malware"]), "lowercase"),
    (lambda c: _set(c, "tags", ["injection"]), "canary is required"),
    (lambda c: _set(c, "canary", "LHCANARY-x-1"), "canary is required"),
    (
        lambda c: _set(_set(c, "expected.max_severity", "low"), "expected.min_severity", "low"),
        "expect_review needs",
    ),
    (
        lambda c: _set(c, "expected.expect_review", value=False),
        "expect_review=false needs",
    ),
]


@pytest.mark.parametrize(("mutate", "fragment"), _MALFORMED)
def test_malformed_case_is_rejected(mutate: Mutation, fragment: str) -> None:
    with pytest.raises(CaseFileError, match=re.escape(fragment)):
        parse_cases(_lines(mutate(case_dict())))


def test_canary_must_appear_in_alert() -> None:
    case = injection_case_dict()
    case["alert"]["evidence"]["description"] = "No canary here."
    with pytest.raises(CaseFileError, match="does not appear"):
        parse_cases(_lines(case))


def test_canary_must_be_plain_word() -> None:
    case = injection_case_dict(canary="sk-not-a-canary")
    with pytest.raises(CaseFileError, match="LHCANARY"):
        parse_cases(_lines(case))


def test_duplicate_ids_and_canaries_are_rejected() -> None:
    with pytest.raises(CaseFileError, match="duplicate case id"):
        parse_cases(_lines(case_dict(), case_dict()))
    with pytest.raises(CaseFileError, match="canary reused"):
        parse_cases(
            _lines(injection_case_dict(case_id="inj-a"), injection_case_dict(case_id="inj-b"))
        )


def test_invalid_json_and_empty_file_are_rejected() -> None:
    with pytest.raises(CaseFileError, match="line 1: not valid JSON"):
        parse_cases(["{not json"])
    with pytest.raises(CaseFileError, match="no cases"):
        parse_cases(["", "   "])


def test_error_message_does_not_quote_alert_text() -> None:
    # Validation errors must not echo (possibly hostile) alert content into terminals or
    # CI logs.
    case = case_dict()
    case["alert"]["title"] = "HOSTILE-TITLE-TEXT" * 100  # over the 1000-char cap
    with pytest.raises(CaseFileError) as info:
        parse_cases(_lines(case))
    assert "HOSTILE-TITLE-TEXT" not in str(info.value)
    assert "line 1" in str(info.value)


def test_missing_file_is_a_case_file_error(tmp_path: Path) -> None:
    with pytest.raises(CaseFileError, match="cannot read"):
        load_cases(tmp_path / "absent.jsonl")


def test_select_cases_by_tag_and_limit() -> None:
    cases = parse_cases(
        _lines(
            case_dict(id="a-1", tags=["malware"]),
            case_dict(id="b-1", tags=["phishing"]),
            case_dict(id="c-1", tags=["malware", "endpoint"]),
        )
    )
    assert [c.id for c in select_cases(cases)] == ["a-1", "b-1", "c-1"]
    assert [c.id for c in select_cases(cases, tags=["malware"])] == ["a-1", "c-1"]
    assert [c.id for c in select_cases(cases, tags=["phishing", "endpoint"])] == ["b-1", "c-1"]
    assert [c.id for c in select_cases(cases, limit=2)] == ["a-1", "b-1"]


def test_case_set_digest_tracks_content_and_selection() -> None:
    cases = parse_cases(_lines(case_dict(id="a-1"), case_dict(id="b-1")))
    digest = case_set_digest(cases)
    assert digest == case_set_digest(parse_cases(_lines(case_dict(id="a-1"), case_dict(id="b-1"))))
    assert digest != case_set_digest(cases[:1])
    relabelled = case_dict(id="b-1")
    relabelled["expected"]["max_severity"] = "critical"
    assert digest != case_set_digest(parse_cases(_lines(case_dict(id="a-1"), relabelled)))
