"""Provider-independent pieces of "Ask LightHouse" chat.

Security boundary: prompt construction (what may reach the model) and model output
handling. The rules this module carries:

- Everything a chat request contains is untrusted: the question and the history come from
  a console session that may be stolen or used by a malicious insider, and the alert
  fields come from customer systems (written by attackers) or from the model. The types
  here only bound sizes; fencing is the prompt builder's job (`lighthouse.ai`).
- What a role may show the model is decided by construction, not by a flag a caller can
  forget: a viewer's `AlertContext` has no `analyst` part, so evidence and reasoning
  cannot reach the model for a viewer.
- The answer is model output: it is streamed to the person who asked and nowhere else. It
  is never stored, logged, audited or used to change an alert.

Nothing here talks to a model provider; `lighthouse.ai` is the only package that imports
the Anthropic SDK, behind the `ChatModel` interface.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from enum import Enum
from typing import Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from lighthouse.severity import Severity
from lighthouse.triage import TriageUsage

MAX_QUESTION_CHARS: Final = 2000
MAX_HISTORY_ITEMS: Final = 10
MAX_HISTORY_ITEM_CHARS: Final = 4000

# The same counters as triage; one name so the meter does not read as triage-specific.
type ModelUsage = TriageUsage


class ChatErrorCode(Enum):
    """The `code` of the terminal `{"type": "error"}` stream event (API contract)."""

    BUDGET_EXCEEDED = "budget_exceeded"
    RATE_LIMITED = "rate_limited"
    DECLINED = "declined"
    UNAVAILABLE = "unavailable"
    TOO_LONG = "too_long"
    INTERNAL = "internal"


class ChatOutcome(Enum):
    """How one chat request ended. Finer than the wire codes: this is what the audit
    entry and the usage row record, for operators. Values match the `outcome` format of
    `lh.model_usage`; append only.
    """

    COMPLETED = "completed"
    DECLINED = "declined"
    MAX_TOKENS = "max_tokens"
    RATE_LIMITED = "rate_limited"  # this user's per-minute limit (ours)
    BUDGET_EXCEEDED = "budget_exceeded"  # the tenant's daily token budget
    MODEL_DISABLED = "model_disabled"
    MODEL_UNAVAILABLE = "model_unavailable"
    TIMEOUT = "timeout"
    UPSTREAM_RATE_LIMITED = "upstream_rate_limited"  # the provider's 429, not the user's
    AUTH_ERROR = "auth_error"
    CONNECTION_ERROR = "connection_error"
    API_ERROR = "api_error"
    UNEXPECTED_STOP = "unexpected_stop"
    INTERNAL_ERROR = "internal_error"
    CLIENT_DISCONNECTED = "client_disconnected"

    @property
    def error_code(self) -> ChatErrorCode | None:
        """The wire code for the terminal event; None means `{"type": "done"}`."""
        return _ERROR_CODES.get(self)


# Provider trouble the person can do nothing about reads as "unavailable", including the
# provider's own 429: "rate_limited" tells a person *they* asked too often, which would be
# wrong. Our own faults read as "internal".
_ERROR_CODES: Final[dict[ChatOutcome, ChatErrorCode]] = {
    ChatOutcome.DECLINED: ChatErrorCode.DECLINED,
    ChatOutcome.MAX_TOKENS: ChatErrorCode.TOO_LONG,
    ChatOutcome.RATE_LIMITED: ChatErrorCode.RATE_LIMITED,
    ChatOutcome.BUDGET_EXCEEDED: ChatErrorCode.BUDGET_EXCEEDED,
    ChatOutcome.MODEL_DISABLED: ChatErrorCode.UNAVAILABLE,
    ChatOutcome.MODEL_UNAVAILABLE: ChatErrorCode.UNAVAILABLE,
    ChatOutcome.TIMEOUT: ChatErrorCode.UNAVAILABLE,
    ChatOutcome.UPSTREAM_RATE_LIMITED: ChatErrorCode.UNAVAILABLE,
    ChatOutcome.AUTH_ERROR: ChatErrorCode.UNAVAILABLE,
    ChatOutcome.CONNECTION_ERROR: ChatErrorCode.UNAVAILABLE,
    ChatOutcome.API_ERROR: ChatErrorCode.UNAVAILABLE,
    ChatOutcome.UNEXPECTED_STOP: ChatErrorCode.INTERNAL,
    ChatOutcome.INTERNAL_ERROR: ChatErrorCode.INTERNAL,
    # Nobody is listening any more; listed so every outcome has a defined code.
    ChatOutcome.CLIENT_DISCONNECTED: ChatErrorCode.INTERNAL,
}


class ChatTurn(BaseModel):
    """One client-supplied history item. Both roles are untrusted text (see the prompt
    builder): an "assistant" item is only what the console claims the model said."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    role: Literal["user", "assistant"]
    content: str = Field(max_length=MAX_HISTORY_ITEM_CHARS)


class AnalystDetail(BaseModel):
    """Alert fields only analyst and above may put in front of the model."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence: dict[str, JsonValue]
    reasoning: str | None


class AlertContext(BaseModel):
    """The one alert a question is about, as the asking user's role may see it.

    Deliberately no id, no tenant, no source ids and no user identity: the model needs
    none of them to explain an alert, and what it is not given it cannot repeat.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    title: str
    severity: Severity
    status: str
    category: str | None
    summary: str | None
    recommended_action: str | None
    analyst: AnalystDetail | None = None


class ChatQuery(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    question: str = Field(min_length=1, max_length=MAX_QUESTION_CHARS)
    history: tuple[ChatTurn, ...] = Field(default=(), max_length=MAX_HISTORY_ITEMS)
    alert: AlertContext | None = None


@dataclass(slots=True)
class ChatMeter:
    """What one model call cost and how it ended, filled in by the model as it streams.

    A mutable record rather than a return value so the caller can still meter and audit
    a call that was cut off part-way (client disconnect, cancellation): whatever usage the
    stream had reported by then is here.
    """

    model_called: bool = False
    model: str | None = None
    usage: ModelUsage | None = None
    outcome: ChatOutcome | None = None


class ChatModel(Protocol):
    @property
    def available(self) -> bool:
        """Whether a model call can be attempted at all (enabled and a credential)."""
        ...

    def answer(self, query: ChatQuery, meter: ChatMeter) -> AsyncIterator[str]:
        """Stream the answer's text. Never raises because of the model: every failure
        ends the iteration with `meter.outcome` set. Cancellation still propagates."""
        ...

    async def aclose(self) -> None: ...
