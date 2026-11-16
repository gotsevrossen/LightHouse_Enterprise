"""Ask LightHouse chat: `GET /api/chat/status` and `POST /api/chat/stream`.

Security boundary: tenant scoping, prompt construction (via `lighthouse.ai`) and cost
control. Threats and controls:

- Spending the key: every request is counted against a per-user, per-minute limit kept
  in Postgres (works across replicas), and the tenant's daily token budget (shared with
  triage) is checked, both before any model call. `max_tokens` caps each answer.
- Cross-tenant data: the alert is read through `tenant_transaction`, so RLS decides; an
  alert of another tenant is a 404, exactly like one that does not exist.
- Role leakage: viewers' context is read with a statement that does not select evidence
  or reasoning at all; analyst and above get them (CLAUDE.md rule 10, server-side).
- Text in logs or audit: the question, history and answer are never logged, stored or
  audited. `chat.asked` records the alert id, the model, token counts and the outcome.
- Long transactions: no transaction or pooled connection is held while the answer
  streams. One short transaction does the checks before; one records usage and the audit
  entry after, shielded from cancellation so a client that disconnects mid-answer is
  still metered and audited.

Wire format (`application/x-ndjson`, one JSON object per line): `{"type":"start"}`, then
zero or more `{"type":"delta","text":...}`, then exactly one terminal event,
`{"type":"done"}` or `{"type":"error","code":...}`. Validation failures and an unknown
alert are ordinary 4xx JSON responses, sent before the stream starts.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Annotated, Final, cast
from uuid import UUID

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from lighthouse.audit import JsonValue, record_audit
from lighthouse.auth import Principal, Role, require_role
from lighthouse.chat import (
    AlertContext,
    AnalystDetail,
    ChatMeter,
    ChatModel,
    ChatOutcome,
    ChatQuery,
)
from lighthouse.config import Settings
from lighthouse.db import Connection, Pool, get_pool, tenant_transaction
from lighthouse.ingest.pipeline import INSERT_USAGE_SQL, SPENT_TODAY_SQL, UNKNOWN_MODEL
from lighthouse.ingest.schema import clean_text
from lighthouse.models import ChatStatusOut, ChatStreamIn
from lighthouse.severity import Severity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/chat", tags=["chat"])

MEDIA_TYPE: Final = "application/x-ndjson"
AUDIT_ACTION: Final = "chat.asked"
USAGE_PURPOSE: Final = "chat"
# Who may put evidence and the triage reasoning in front of the model. Same line as for
# reading them through GET /api/alerts/{id}.
ANALYST_CONTEXT_ROLE: Final = Role.ANALYST

# Expired windows of the asking user only; the delete policy refuses the current window.
PRUNE_RATE_WINDOWS_SQL: Final = """
    delete from lh.chat_rate_limits
     where user_id = $1
       and window_start < pg_catalog.date_trunc('minute', pg_catalog.now(), 'UTC')
"""

# Atomic across replicas: concurrent requests for the same user serialise on the row, so
# each one sees a distinct count. Rejected requests are counted too, so hammering does not
# reopen the window.
COUNT_REQUEST_SQL: Final = """
    insert into lh.chat_rate_limits as r (tenant_id, user_id, window_start)
    values (lh.current_tenant_id(), $1, pg_catalog.date_trunc('minute', pg_catalog.now(), 'UTC'))
    on conflict (tenant_id, user_id, window_start)
    do update set request_count = r.request_count + 1
    returning request_count
"""

# No tenant predicate, as in routes/alerts.py: RLS scopes the row. Two statements so a
# viewer's request never loads attacker-controlled evidence or model reasoning at all.
CHAT_ALERT_SQL: Final = """
    select title, severity, status, category, summary, recommended_action
      from lh.alerts
     where id = $1
"""

CHAT_ALERT_DETAIL_SQL: Final = """
    select title, severity, status, category, summary, recommended_action,
           evidence, reasoning
      from lh.alerts
     where id = $1
"""


def get_chat_model(request: Request) -> ChatModel:
    return cast("ChatModel", request.app.state.chat_model)


def get_settings(request: Request) -> Settings:
    return cast("Settings", request.app.state.settings)


@router.get("/status")
async def chat_status(
    principal: Annotated[Principal, Depends(require_role(Role.VIEWER))],
    model: Annotated[ChatModel, Depends(get_chat_model)],
) -> ChatStatusOut:
    del principal  # authentication and role are the point; nothing tenant-specific here
    return ChatStatusOut(available=model.available)


def _alert_context(row: dict[str, object], *, analyst: bool) -> AlertContext:
    detail: AnalystDetail | None = None
    if analyst:
        evidence = row.get("evidence")
        detail = AnalystDetail(
            evidence=cast("dict[str, object]", evidence) if isinstance(evidence, dict) else {},  # pyright: ignore[reportArgumentType]
            reasoning=cast("str | None", row.get("reasoning")),
        )
    return AlertContext(
        title=cast("str", row["title"]),
        severity=Severity(cast("str", row["severity"])),
        status=cast("str", row["status"]),
        category=cast("str | None", row["category"]),
        summary=cast("str | None", row["summary"]),
        recommended_action=cast("str | None", row["recommended_action"]),
        analyst=detail,
    )


@dataclass(frozen=True, slots=True)
class _Admission:
    """Result of the checks made before streaming."""

    rejected: ChatOutcome | None
    alert: AlertContext | None
    found: bool


async def _admit(
    conn: Connection,
    principal: Principal,
    body: ChatStreamIn,
    model: ChatModel,
    settings: Settings,
) -> _Admission:
    limit = settings.chat_requests_per_minute_per_user
    await conn.execute(PRUNE_RATE_WINDOWS_SQL, principal.user_id)
    count = cast("int", await conn.fetchval(COUNT_REQUEST_SQL, principal.user_id))
    if count > limit:
        # Audited once per user and minute (the first rejection), not per request: an
        # abusive client must not be able to flood the append-only trail. The counter row
        # itself records how many were refused.
        if count == limit + 1:
            await _audit(
                conn, principal, body.alert_id, ChatMeter(outcome=ChatOutcome.RATE_LIMITED)
            )
        return _Admission(rejected=ChatOutcome.RATE_LIMITED, alert=None, found=True)

    alert: AlertContext | None = None
    if body.alert_id is not None:
        analyst = principal.role.at_least(ANALYST_CONTEXT_ROLE)
        row = await conn.fetchrow(
            CHAT_ALERT_DETAIL_SQL if analyst else CHAT_ALERT_SQL, body.alert_id
        )
        if row is None:
            return _Admission(rejected=None, alert=None, found=False)
        alert = _alert_context(dict(row.items()), analyst=analyst)

    # Checked before the call, against everything the tenant spent today (triage and
    # chat). It can overshoot by at most the calls already in flight, each capped by
    # max_tokens. Skipped when no call can be made anyway.
    if model.available:
        spent = cast("int", await conn.fetchval(SPENT_TODAY_SQL))
        if spent >= settings.triage_daily_token_budget_per_tenant:
            return _Admission(rejected=ChatOutcome.BUDGET_EXCEEDED, alert=alert, found=True)
    return _Admission(rejected=None, alert=alert, found=True)


async def _audit(
    conn: Connection, principal: Principal, alert_id: UUID | None, meter: ChatMeter
) -> None:
    outcome = meter.outcome or ChatOutcome.INTERNAL_ERROR
    detail: dict[str, JsonValue] = {
        "alert_id": str(alert_id) if alert_id is not None else None,
        "outcome": outcome.value,
        "model": meter.model,
    }
    if meter.usage is not None:
        # Key names avoid the substring "token": lighthouse.audit redacts any key matching
        # it (credential protection), which would replace these counts with "[redacted]".
        detail |= {
            "usage_input": meter.usage.input_tokens,
            "usage_output": meter.usage.output_tokens,
            "usage_cache_read": meter.usage.cache_read_tokens,
            "usage_cache_write": meter.usage.cache_creation_tokens,
        }
    await record_audit(
        conn,
        actor=str(principal.user_id),
        action=AUDIT_ACTION,
        target=f"alert:{alert_id}" if alert_id is not None else None,
        detail=detail,
    )


async def _record(
    pool: Pool, principal: Principal, alert_id: UUID | None, meter: ChatMeter
) -> None:
    """Meter and audit one request. Shielded: it must land even if the request is being
    cancelled (client disconnect), or a disconnect would be a way to chat unmetered."""
    with anyio.CancelScope(shield=True):
        async with tenant_transaction(pool, principal.tenant_id) as conn:
            outcome = meter.outcome or ChatOutcome.INTERNAL_ERROR
            if meter.model_called and meter.usage is not None:
                usage = meter.usage
                await conn.execute(
                    INSERT_USAGE_SQL,
                    USAGE_PURPOSE,
                    clean_text(meter.model or UNKNOWN_MODEL) or UNKNOWN_MODEL,
                    usage.input_tokens,
                    usage.output_tokens,
                    usage.cache_read_tokens,
                    usage.cache_creation_tokens,
                    outcome.value,
                )
            await _audit(conn, principal, alert_id, meter)


def _line(event: dict[str, str]) -> bytes:
    # ensure_ascii (the default): every line is pure ASCII, so model text can never
    # contain a raw newline that would split an event across lines.
    return (json.dumps(event, separators=(",", ":")) + "\n").encode("ascii")


START: Final = _line({"type": "start"})
DONE: Final = _line({"type": "done"})


def _terminal(outcome: ChatOutcome) -> bytes:
    code = outcome.error_code
    if code is None:
        return DONE
    # Error events carry the code only: no provider message, no exception text.
    return _line({"type": "error", "code": code.value})


@dataclass(frozen=True, slots=True)
class ChatJob:
    """Everything the response body needs once the handler has returned."""

    pool: Pool
    principal: Principal
    model: ChatModel
    query: ChatQuery
    alert_id: UUID | None
    rejected: ChatOutcome | None


async def chat_events(job: ChatJob) -> AsyncGenerator[bytes]:
    """The response body. Exactly one terminal event, always last.

    Runs after the request handler has returned, with no transaction open.
    """
    pool, principal, alert_id, rejected = job.pool, job.principal, job.alert_id, job.rejected
    yield START
    if rejected is ChatOutcome.RATE_LIMITED:
        # Already audited (once per minute) in the admission transaction.
        yield _terminal(rejected)
        return

    meter = ChatMeter(outcome=rejected)
    recorded = False
    try:
        if rejected is None:
            try:
                async for text in job.model.answer(job.query, meter):
                    yield _line({"type": "delta", "text": text})
            except Exception as exc:  # noqa: BLE001 - rule 4: never a broken stream
                # The model maps its own failures; this is a bug on our side. Class only.
                logger.warning("chat stream failed: %s", type(exc).__name__)
                meter.outcome = ChatOutcome.INTERNAL_ERROR
        outcome = meter.outcome or ChatOutcome.INTERNAL_ERROR
        meter.outcome = outcome
        try:
            await _record(pool, principal, alert_id, meter)
        except Exception as exc:  # noqa: BLE001 - the person still gets a terminal event
            # An unaudited answer must not look like a clean one (rule 11).
            logger.error("chat usage/audit write failed: %s", type(exc).__name__)  # noqa: TRY400
            outcome = ChatOutcome.INTERNAL_ERROR
        recorded = True
        yield _terminal(outcome)
    finally:
        if not recorded:
            # Cancelled or closed part-way (the client went away): meter and audit what
            # was spent. Never re-raised from here; the cancellation continues as is.
            if meter.outcome is None:
                meter.outcome = ChatOutcome.CLIENT_DISCONNECTED
            try:
                await _record(pool, principal, alert_id, meter)
            except Exception as exc:  # noqa: BLE001
                logger.error("chat usage/audit write failed: %s", type(exc).__name__)  # noqa: TRY400


@router.post("/stream")
async def chat_stream(
    body: ChatStreamIn,
    principal: Annotated[Principal, Depends(require_role(Role.VIEWER))],
    pool: Annotated[Pool, Depends(get_pool)],
    model: Annotated[ChatModel, Depends(get_chat_model)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> StreamingResponse:
    async with tenant_transaction(pool, principal.tenant_id) as conn:
        admission = await _admit(conn, principal, body, model, settings)
    # After the commit, so the request still counts against the rate limit: probing for
    # alert ids is not free.
    if not admission.found:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    query = ChatQuery(question=body.question, history=tuple(body.history), alert=admission.alert)
    return StreamingResponse(
        chat_events(
            ChatJob(
                pool=pool,
                principal=principal,
                model=model,
                query=query,
                alert_id=body.alert_id,
                rejected=admission.rejected,
            )
        ),
        media_type=MEDIA_TYPE,
        # Reverse proxies must pass events through as they come, not buffer the answer.
        headers={"X-Accel-Buffering": "no"},
    )
