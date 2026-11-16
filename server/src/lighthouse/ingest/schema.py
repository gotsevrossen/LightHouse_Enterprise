"""The normalised alert: the only shape a connector hands to the ingest pipeline.

Security boundary (CLAUDE.md rule 3). Everything in a `NormalizedAlert` except `source`
is attacker-controlled text from a customer system: anyone who can make a customer's EDR
raise an alert chooses the file name, the command line, often the title. This model is
the choke point that bounds what reaches the database and, later, the prompt:

- every string is length-capped, and attacker-sized text is *truncated*, never rejected,
  so an attacker cannot make an alert disappear by making it big;
- evidence is flat (scalars or a short list of strings), with a fixed key grammar, a cap
  on keys, list length and total serialised size, so nothing downstream receives a deeply
  nested or oversized payload;
- NUL characters and lone surrogates are removed, because PostgreSQL rejects both in
  `text` and `jsonb`; left in, one hostile alert would fail its insert on every run;
- text that looks like markup (for example a closing `</untrusted_evidence>` tag) is kept
  verbatim as data. Neutralising fence-breaking text is the prompt builder's job, which
  has to escape it anyway; doing it here as well would hide what the source really said.

Identity fields (`source`, `source_alert_id`) are rejected rather than truncated when out
of bounds: a truncated id could collide with another alert and overwrite it.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Annotated, Final, cast

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from lighthouse.severity import Severity

EvidenceValue = str | int | float | bool | None | list[str]

MAX_TITLE_CHARS: Final = 1000
MAX_CATEGORY_CHARS: Final = 200
MAX_SOURCE_ALERT_ID_CHARS: Final = 512

# Evidence caps. The total budget is what one alert may contribute to a prompt; the
# per-value caps keep a single field from eating the whole budget.
MAX_EVIDENCE_KEYS: Final = 32
MAX_EVIDENCE_KEY_CHARS: Final = 64
MAX_EVIDENCE_STRING_CHARS: Final = 1024
MAX_EVIDENCE_LIST_ITEMS: Final = 20
MAX_EVIDENCE_LIST_ITEM_CHARS: Final = 256
MAX_EVIDENCE_TOTAL_BYTES: Final = 16 * 1024

# Set when anything in the evidence was cut, so a reviewer (and the model) knows the
# projection is incomplete. Reserved: a connector may not set it itself.
EVIDENCE_TRUNCATED_KEY: Final = "evidence_truncated"

TRUNCATION_MARK: Final = "…"

# Evidence keys are chosen by connector code from an allow-list, never copied from the
# source record, so a narrow grammar costs nothing and keeps key names from carrying text.
_KEY_RE: Final = re.compile(r"[a-z][a-z0-9_]*")
_SOURCE_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,63}")
# PostgreSQL bigint range: anything wider is not a count or an id we would use, and very
# long ints are expensive to print (Python caps int->str at 4300 digits and raises).
_INT_MIN: Final = -(2**63)
_INT_MAX: Final = 2**63 - 1


def clean_text(value: str) -> str:
    """Make attacker text storable: drop NUL, replace lone surrogates.

    PostgreSQL `text` and `jsonb` cannot hold U+0000, and a lone surrogate cannot be
    encoded as UTF-8. Both arrive easily from JSON (`"\\u0000"`, `"\\ud800"`).
    """
    if "\x00" in value:
        value = value.replace("\x00", "")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        value = value.encode("utf-8", "replace").decode("utf-8")
    return value


def cap_text(value: str, limit: int) -> str:
    """Clean and truncate to at most `limit` characters, marking the cut."""
    value = clean_text(value)
    if len(value) <= limit:
        return value
    return value[: limit - len(TRUNCATION_MARK)] + TRUNCATION_MARK


def _is_storable_identity(value: str) -> bool:
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):  # noqa: PLR2004 - C0 range
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _entry_bytes(key: str, value: EvidenceValue) -> int:
    # Size of `"key": value, ` in the canonical encoding; an upper bound on what the entry
    # adds to the serialised object.
    return len(_canonical_json({key: value}).encode("utf-8"))


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _fit_value(raw: object) -> tuple[EvidenceValue, bool]:
    """Coerce one evidence value into the allowed shape; returns (value, was_cut)."""
    if raw is None or isinstance(raw, bool):
        return raw, False
    if isinstance(raw, int | float):
        # Out-of-range ints and NaN/infinity are not something we would use, and jsonb
        # rejects non-finite numbers, so they are dropped to null and the cut is marked.
        in_range = _INT_MIN <= raw <= _INT_MAX if isinstance(raw, int) else math.isfinite(raw)
        return (raw, False) if in_range else (None, True)
    if isinstance(raw, str):
        capped = cap_text(raw, MAX_EVIDENCE_STRING_CHARS)
        return capped, capped != raw
    if isinstance(raw, list | tuple):
        items = cast("list[object] | tuple[object, ...]", raw)
        cut = len(items) > MAX_EVIDENCE_LIST_ITEMS
        out: list[str] = []
        for item in items[:MAX_EVIDENCE_LIST_ITEMS]:
            if not isinstance(item, str):
                # A list is a list of strings; anything else is a connector bug.
                msg = "evidence list items must be strings"
                raise TypeError(msg)
            capped = cap_text(item, MAX_EVIDENCE_LIST_ITEM_CHARS)
            cut = cut or capped != item
            out.append(capped)
        return out, cut
    # Dicts and other objects are refused: evidence is flat by design, and silently
    # stringifying an object would copy raw source structure into the projection.
    msg = "evidence values must be a string, number, boolean, null or list of strings"
    raise TypeError(msg)


def fit_evidence(raw: Mapping[str, object]) -> dict[str, EvidenceValue]:
    """Apply every evidence cap, truncating attacker-sized content instead of rejecting.

    Keys are kept in the order given, so a connector lists its most useful fields first:
    when the total budget runs out, later keys are dropped and the result is marked.
    """
    if len(raw) > MAX_EVIDENCE_KEYS:
        msg = f"evidence has more than {MAX_EVIDENCE_KEYS} keys"
        raise ValueError(msg)
    marker_bytes = _entry_bytes(EVIDENCE_TRUNCATED_KEY, True)  # noqa: FBT003 - a value
    budget = MAX_EVIDENCE_TOTAL_BYTES - 2 - marker_bytes  # braces, room for the marker
    out: dict[str, EvidenceValue] = {}
    truncated = False
    for key, value in raw.items():
        if key == EVIDENCE_TRUNCATED_KEY:
            msg = f"evidence key {EVIDENCE_TRUNCATED_KEY!r} is reserved"
            raise ValueError(msg)
        if len(key) > MAX_EVIDENCE_KEY_CHARS or not _KEY_RE.fullmatch(key):
            msg = "evidence keys must be short lowercase identifiers"
            raise ValueError(msg)
        fitted, cut = _fit_value(value)
        truncated = truncated or cut
        size = _entry_bytes(key, fitted) + 1  # the comma separating entries
        if size > budget:
            truncated = True
            continue
        budget -= size
        out[key] = fitted
    if truncated:
        out[EVIDENCE_TRUNCATED_KEY] = True
    return out


def _list_over_caps(value: list[str]) -> bool:
    return len(value) > MAX_EVIDENCE_LIST_ITEMS or any(
        len(item) > MAX_EVIDENCE_LIST_ITEM_CHARS for item in value
    )


def _check_evidence(evidence: dict[str, EvidenceValue]) -> dict[str, EvidenceValue]:
    """Hard caps, re-checked after fitting so the invariant does not rest on one function."""
    if len(evidence) > MAX_EVIDENCE_KEYS + 1:
        msg = "too many evidence keys"
        raise ValueError(msg)
    for key, value in evidence.items():
        if len(key) > MAX_EVIDENCE_KEY_CHARS or not _KEY_RE.fullmatch(key):
            msg = "invalid evidence key"
            raise ValueError(msg)
        if isinstance(value, str) and len(value) > MAX_EVIDENCE_STRING_CHARS:
            msg = "evidence string too long"
            raise ValueError(msg)
        if isinstance(value, list) and _list_over_caps(value):
            msg = "evidence list too long"
            raise ValueError(msg)
    if len(_canonical_json(evidence).encode("utf-8")) > MAX_EVIDENCE_TOTAL_BYTES:
        msg = "evidence too large"
        raise ValueError(msg)
    return evidence


class NormalizedAlert(BaseModel):
    """One alert from a source system, reduced to the fields LightHouse uses."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: Annotated[str, Field(min_length=1, max_length=64)]
    source_alert_id: Annotated[str, Field(min_length=1, max_length=MAX_SOURCE_ALERT_ID_CHARS)]
    title: Annotated[str, Field(min_length=1, max_length=MAX_TITLE_CHARS)]
    source_severity: Severity
    occurred_at: AwareDatetime
    category: Annotated[str, Field(min_length=1, max_length=MAX_CATEGORY_CHARS)] | None
    evidence: dict[str, EvidenceValue]

    @field_validator("source")
    @classmethod
    def _source_is_identifier(cls, value: str) -> str:
        # `source` is ours (a connector constant), so it is held to an identifier grammar.
        if not _SOURCE_RE.fullmatch(value):
            msg = "source must be a lowercase identifier"
            raise ValueError(msg)
        return value

    @field_validator("source_alert_id")
    @classmethod
    def _id_is_storable(cls, value: str) -> str:
        if not _is_storable_identity(value):
            msg = "source_alert_id contains control characters or invalid unicode"
            raise ValueError(msg)
        return value

    @field_validator("title", mode="before")
    @classmethod
    def _cap_title(cls, value: object) -> object:
        if isinstance(value, str):
            return cap_text(value, MAX_TITLE_CHARS).strip()
        return value

    @field_validator("category", mode="before")
    @classmethod
    def _cap_category(cls, value: object) -> object:
        if isinstance(value, str):
            capped = cap_text(value, MAX_CATEGORY_CHARS).strip()
            return capped or None
        return value

    @field_validator("occurred_at")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        # One instant, one representation: keeps `content_hash` stable across sources
        # that report the same time with different offsets.
        return value.astimezone(UTC)

    @field_validator("evidence", mode="before")
    @classmethod
    def _fit_evidence(cls, value: object) -> object:
        if isinstance(value, Mapping):
            return fit_evidence(cast("Mapping[str, object]", value))
        return value

    @field_validator("evidence")
    @classmethod
    def _evidence_caps(cls, value: dict[str, EvidenceValue]) -> dict[str, EvidenceValue]:
        return _check_evidence(value)

    def content_hash(self) -> str:
        """SHA-256 hex over a canonical JSON of every field.

        Used to skip re-triage of an alert whose content has not changed. Canonical means
        sorted keys, no whitespace, UTF-8, UTC timestamps, so the same alert always hashes
        the same regardless of the order a source listed its fields in.
        """
        payload = self.model_dump(mode="json")
        return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
