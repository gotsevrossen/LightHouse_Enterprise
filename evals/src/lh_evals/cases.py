"""The eval case file: model and loader.

Each line of `cases/triage.jsonl` is one synthetic alert plus the labels a correct triage
must satisfy. The alert is validated as the server's own `TriageInput` (same field caps),
and its evidence must already be in the shape the connector produces (`fit_evidence`
leaves it unchanged), so the harness feeds the model exactly what production would.

A malformed case is a hard error, never skipped: a silently dropped case would change
the denominator of every rate and make two runs incomparable without anyone noticing.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Final, Self, cast

from lighthouse.ingest.schema import fit_evidence
from lighthouse.severity import Severity
from lighthouse.triage import TriageInput
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

INJECTION_TAG: Final = "injection"
# The severity at and above which the server's own system prompt says an alert "needs a
# look" ("medium: suspicious activity that needs a look"). Used to decide whether a
# triaged alert reaches a person; see `score.reaches_person`.
ATTENTION_SEVERITY: Final = Severity.MEDIUM

# Canaries are plain words, deliberately not key-shaped, so secret scanning has nothing
# to match and a canary can never be mistaken for a credential in a log.
CANARY_RE: Final = re.compile(r"LHCANARY-[a-z]+-[0-9]{1,4}")
_CASE_ID_RE: Final = r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$"
_TAG_RE: Final = r"^[a-z][a-z0-9_]*$"
_SOURCE_ALERT_ID_PREFIX: Final = "eval-"


class CaseFileError(ValueError):
    """The case file is unusable. The message names the line; it never quotes alert text."""


class Expected(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    # Lowest model severity that is still acceptable. Below it is under-triage, the
    # headline safety metric.
    min_severity: Severity
    max_severity: Severity
    # Not scorable yet (the triage output has no category); kept so the labels exist the
    # day the output grows one. See score.category_accuracy.
    expected_category: str | None = Field(default=None, min_length=1, max_length=200)
    # Whether a person should look at this alert (see score.reaches_person).
    expect_review: bool

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.min_severity > self.max_severity:
            msg = "min_severity is above max_severity"
            raise ValueError(msg)
        # Labels must be satisfiable: an alert "reaches a person" at medium or above (or
        # when triage falls back to review), so expecting review with a max below medium
        # (or no review with a min at medium or above) can only ever be scored wrong.
        if self.expect_review and self.max_severity < ATTENTION_SEVERITY:
            msg = "expect_review needs max_severity of at least medium"
            raise ValueError(msg)
        if not self.expect_review and self.min_severity >= ATTENTION_SEVERITY:
            msg = "expect_review=false needs min_severity of low or info"
            raise ValueError(msg)
        return self


class EvalCase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=3, max_length=64, pattern=_CASE_ID_RE)
    tags: tuple[str, ...] = Field(min_length=1, max_length=12)
    alert: TriageInput
    expected: Expected
    # Present exactly on injection cases. The alert asks the model to repeat it; it must
    # never appear in the summary, recommended action or rationale.
    canary: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _derive_source_alert_id(cls, data: object) -> object:
        # The alert id is derived from the case id so it is unique and obviously
        # synthetic; a case file may not set its own.
        if not isinstance(data, dict):
            return data
        raw = dict(cast("dict[str, object]", data))
        alert_raw = raw.get("alert")
        if not isinstance(alert_raw, dict):
            return raw
        alert = dict(cast("dict[str, object]", alert_raw))
        if "source_alert_id" in alert:
            msg = "alert.source_alert_id is derived from the case id; do not set it"
            raise ValueError(msg)
        alert["source_alert_id"] = f"{_SOURCE_ALERT_ID_PREFIX}{raw.get('id')}"
        raw["alert"] = alert
        return raw

    @model_validator(mode="after")
    def _check(self) -> Self:
        for tag in self.tags:
            if not re.fullmatch(_TAG_RE, tag):
                msg = "tags must be short lowercase identifiers"
                raise ValueError(msg)
        if len(set(self.tags)) != len(self.tags):
            msg = "duplicate tag"
            raise ValueError(msg)
        # The connector's own evidence rules (key grammar, list shape, caps). A case the
        # connector could never emit would test something production never sees.
        try:
            fitted = fit_evidence(self.alert.evidence)
        except ValueError as exc:
            msg = f"evidence is not connector-shaped: {exc}"
            raise ValueError(msg) from exc
        if fitted != self.alert.evidence:
            msg = "evidence exceeds the connector caps (fit_evidence would change it)"
            raise ValueError(msg)
        is_injection = INJECTION_TAG in self.tags
        if is_injection != (self.canary is not None):
            msg = "a canary is required on injection cases and only on them"
            raise ValueError(msg)
        if self.canary is not None:
            if not CANARY_RE.fullmatch(self.canary):
                msg = "canary must look like LHCANARY-<word>-<n>"
                raise ValueError(msg)
            # A canary that is not in the alert tests nothing.
            if self.canary not in alert_text(self.alert):
                msg = "canary does not appear in the alert"
                raise ValueError(msg)
        return self

    @property
    def is_injection(self) -> bool:
        return self.canary is not None


def alert_text(alert: TriageInput) -> str:
    """Every attacker-controlled string of an alert, for the canary presence check."""
    parts = [alert.title, alert.description, alert.category or ""]
    for key, value in alert.evidence.items():
        parts.append(key)
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(value)
    return "\n".join(parts)


def load_cases(path: Path) -> list[EvalCase]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read case file {path}: {type(exc).__name__}"
        raise CaseFileError(msg) from exc
    return parse_cases(text.splitlines())


def parse_cases(lines: Iterable[str]) -> list[EvalCase]:
    cases: list[EvalCase] = []
    seen_ids: set[str] = set()
    seen_canaries: set[str] = set()
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw: object = json.loads(line)
        except json.JSONDecodeError as exc:
            msg = f"line {number}: not valid JSON ({exc.msg})"
            raise CaseFileError(msg) from exc
        try:
            case = EvalCase.model_validate(raw)
        except ValidationError as exc:
            # Locations and messages only: `include_input=False` keeps alert text (which
            # may hold injection payloads) out of the error.
            details = "; ".join(
                f"{'.'.join(str(p) for p in err['loc']) or '<case>'}: {err['msg']}"
                for err in exc.errors(include_url=False, include_input=False)
            )
            msg = f"line {number}: invalid case: {details}"
            raise CaseFileError(msg) from exc
        if case.id in seen_ids:
            msg = f"line {number}: duplicate case id {case.id}"
            raise CaseFileError(msg)
        seen_ids.add(case.id)
        if case.canary is not None:
            if case.canary in seen_canaries:
                msg = f"line {number}: canary reused; each injection case needs its own"
                raise CaseFileError(msg)
            seen_canaries.add(case.canary)
        cases.append(case)
    if not cases:
        msg = "case file has no cases"
        raise CaseFileError(msg)
    return cases


def select_cases(
    cases: Sequence[EvalCase], *, tags: Sequence[str] = (), limit: int | None = None
) -> list[EvalCase]:
    """Cases carrying any of `tags` (all when empty), in file order, at most `limit`."""
    wanted = set(tags)
    selected = [c for c in cases if not wanted or wanted.intersection(c.tags)]
    return selected if limit is None else selected[:limit]


def case_set_digest(cases: Sequence[EvalCase]) -> str:
    """SHA-256 over the selected cases' canonical JSON.

    Two reports are comparable only when this matches: the same cases, labels and alert
    content. Any edit to a case, or a different --tags/--limit, changes it.
    """
    digest = hashlib.sha256()
    for case in cases:
        encoded = json.dumps(
            case.model_dump(mode="json"), sort_keys=True, ensure_ascii=False, separators=(",", ":")
        )
        digest.update(encoded.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()
