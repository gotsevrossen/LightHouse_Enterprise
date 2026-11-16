"""Store one normalised alert and triage it.

Security boundary: tenant scoping and triage validation. Threats and controls:

- Tenant isolation: every statement runs in `db.tenant_transaction` as `lh_app`, with bind
  parameters only; rows are written with `lh.current_tenant_id()`, never a tenant id from
  the caller's data, and no statement filters by tenant itself (RLS does).
- Severity floor: `source_severity` only ever rises on re-ingestion (`greatest()`, so the
  database trigger that forbids lowering it is never tripped), and the stored severity is
  `greatest(stored, source, model)`. A model, injected or not, can raise severity but
  never lower it; the table constraint is the backstop.
- Cost: an unchanged alert that was already triaged costs nothing (content hash dedupe),
  a per-tenant daily token budget is checked before every call, and outcomes the alert
  content can provoke (refusal, timeout, invalid output) are not retried for that content.
- Long transactions: the model call can take minutes, so no transaction or pooled
  connection is held across it. A first transaction stores the alert and takes a
  short-lived claim; the call runs outside any transaction; a second transaction writes
  the result only if the claim is still ours. A newer version of the alert clears the
  claim, so a slow, stale result is discarded instead of overwriting newer content.
- Audit and metering: every model call writes a `model_usage` row and an audit entry with
  ids, model, token counts and the review reason. Never alert text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final, cast
from uuid import UUID, uuid4

from lighthouse.audit import JsonValue, record_audit
from lighthouse.config import Settings
from lighthouse.db import Connection, Pool, tenant_transaction
from lighthouse.ingest.schema import NormalizedAlert, clean_text
from lighthouse.severity import Severity
from lighthouse.triage import (
    ReviewReason,
    TriageInput,
    TriageModel,
    TriageResult,
    run_triage,
)

AUDIT_ACTOR: Final = "lighthouse:triage"
USAGE_PURPOSE: Final = "triage"
UNKNOWN_MODEL: Final = "unknown"

# Defaults mirror lighthouse.config.Settings, for callers that pass no policy.
_DEFAULT_TIMEOUT_SECONDS: Final = 120.0
_DEFAULT_RETRIES: Final = 2
_DEFAULT_DEADLINE_SECONDS: Final = _DEFAULT_TIMEOUT_SECONDS * (_DEFAULT_RETRIES + 1) + 15.0
_DEFAULT_DAILY_BUDGET: Final = 2_000_000


@dataclass(frozen=True, slots=True)
class TriagePolicy:
    """Limits the pipeline enforces around a model call."""

    daily_token_budget: int = _DEFAULT_DAILY_BUDGET
    deadline_seconds: float = _DEFAULT_DEADLINE_SECONDS
    claim_lease_seconds: float = _DEFAULT_DEADLINE_SECONDS + 60.0

    def __post_init__(self) -> None:
        # A zero or negative deadline/lease would make every claim instantly stale (two
        # workers calling the model for the same alert); refuse rather than misbehave.
        if self.daily_token_budget < 0:
            msg = "daily_token_budget must be >= 0"
            raise ValueError(msg)
        if self.deadline_seconds <= 0 or self.claim_lease_seconds <= self.deadline_seconds:
            msg = "need 0 < deadline_seconds < claim_lease_seconds"
            raise ValueError(msg)

    @classmethod
    def from_settings(cls, settings: Settings) -> TriagePolicy:
        return cls(
            daily_token_budget=settings.triage_daily_token_budget_per_tenant,
            deadline_seconds=settings.triage_deadline_seconds,
            claim_lease_seconds=settings.triage_claim_lease_seconds,
        )


class IngestStatus(Enum):
    TRIAGED = "triaged"  # model answered; result stored
    NEEDS_REVIEW = "needs_review"  # stored as needing a person (see review_reason)
    UNCHANGED = "unchanged"  # same content, already triaged: nothing done, no call
    IN_PROGRESS = "in_progress"  # another worker holds the triage claim: no call
    SUPERSEDED = "superseded"  # newer content arrived during the call: result discarded


@dataclass(frozen=True, slots=True)
class IngestOutcome:
    alert_id: UUID
    status: IngestStatus
    inserted: bool
    model_called: bool
    review_reason: ReviewReason | None = None


# Insert, or update only when the content changed. On a change, the previous triage no
# longer describes the alert, so its output and any claim are cleared; severities only go
# up. Returns no row when the content is unchanged.
UPSERT_ALERT_SQL: Final = """
    insert into lh.alerts as a (
        tenant_id, source, source_alert_id, title, source_severity, severity,
        category, occurred_at, evidence, content_hash
    )
    values (
        lh.current_tenant_id(), $1, $2, $3, $4::lh.severity, $4::lh.severity,
        $5, $6, $7, $8
    )
    on conflict (tenant_id, source, source_alert_id) do update set
        title = excluded.title,
        category = excluded.category,
        occurred_at = excluded.occurred_at,
        evidence = excluded.evidence,
        content_hash = excluded.content_hash,
        source_severity = greatest(a.source_severity, excluded.source_severity),
        severity = greatest(a.severity, excluded.source_severity),
        summary = null,
        recommended_action = null,
        confidence = null,
        reasoning = null,
        review_reason = null,
        triage_model = null,
        triaged_at = null,
        needs_human_review = true,
        status = case when a.status = 'triaged' then 'new'::lh.alert_status else a.status end,
        triage_claim = null,
        triage_claimed_at = null
    where a.content_hash is distinct from excluded.content_hash
    returning id, (xmax = 0) as inserted
"""

ALERT_STATE_SQL: Final = """
    select id, triaged_at, review_reason
      from lh.alerts
     where source = $1 and source_alert_id = $2
"""

CLAIM_SQL: Final = """
    update lh.alerts
       set triage_claim = $2, triage_claimed_at = now()
     where id = $1
       and triaged_at is null
       and (triage_claim is null
            or triage_claimed_at < now() - make_interval(secs => $3))
    returning id
"""

# Tokens spent by the current tenant (RLS) since the start of the UTC day. All four
# counters count: the budget is a ceiling, so it errs towards stopping early.
SPENT_TODAY_SQL: Final = """
    select coalesce(sum(input_tokens + output_tokens + cache_read_tokens
                        + cache_creation_tokens), 0)::bigint
      from lh.model_usage
     where created_at >= date_trunc('day', now(), 'UTC')
"""

DEFER_SQL: Final = """
    update lh.alerts
       set needs_human_review = true,
           review_reason = $2,
           triage_claim = null,
           triage_claimed_at = null
     where id = $1 and triage_claim = $3
"""

APPLY_RESULT_SQL: Final = """
    update lh.alerts
       set severity = greatest(severity, source_severity, $3::lh.severity),
           summary = $4,
           recommended_action = $5,
           confidence = $6,
           reasoning = $7,
           needs_human_review = $8,
           review_reason = $9,
           triage_model = $10,
           triaged_at = case when $11::boolean then now() else null end,
           status = case when status = 'new' and not $8::boolean
                         then 'triaged'::lh.alert_status else status end,
           triage_claim = null,
           triage_claimed_at = null
     where id = $1 and triage_claim = $2
    returning id
"""

INSERT_USAGE_SQL: Final = """
    insert into lh.model_usage (
        tenant_id, purpose, model, input_tokens, output_tokens,
        cache_read_tokens, cache_creation_tokens, outcome
    )
    values (lh.current_tenant_id(), $1, $2, $3, $4, $5, $6, $7)
"""


def triage_input(alert: NormalizedAlert) -> TriageInput:
    return TriageInput(
        source=alert.source,
        source_alert_id=alert.source_alert_id,
        title=alert.title,
        source_severity=alert.source_severity,
        category=alert.category,
        occurred_at=alert.occurred_at,
        evidence=alert.evidence,
    )


def _storable(text: str | None) -> str | None:
    # Model text may contain NUL or lone surrogates (valid JSON escapes), which Postgres
    # text rejects. Left in, the result write would fail and the alert stay claimed.
    return None if text is None else clean_text(text)


async def _audit(
    conn: Connection,
    *,
    alert_id: UUID,
    result: TriageResult | None,
    reason: ReviewReason | None,
    applied: bool,
) -> None:
    usage = result.usage if result is not None else None
    detail: dict[str, JsonValue] = {
        "alert_id": str(alert_id),
        "model": result.model if result is not None else None,
        "review_reason": reason.value if reason is not None else None,
        "applied": applied,
    }
    if usage is not None:
        # Key names avoid the substring "token": lighthouse.audit redacts any key matching
        # it (credential protection), which would replace these counts with "[redacted]".
        detail |= {
            "usage_input": usage.input_tokens,
            "usage_output": usage.output_tokens,
            "usage_cache_read": usage.cache_read_tokens,
            "usage_cache_write": usage.cache_creation_tokens,
        }
    await record_audit(
        conn,
        actor=AUDIT_ACTOR,
        action="triage.needs_review" if reason is not None else "triage.completed",
        target=f"alert:{alert_id}",
        detail=detail,
    )


@dataclass(frozen=True, slots=True)
class _Claim:
    alert_id: UUID
    inserted: bool
    prior_reason: str | None


async def _store_and_claim(
    conn: Connection, alert: NormalizedAlert, token: UUID, limits: TriagePolicy
) -> _Claim | IngestOutcome:
    """Transaction 1: upsert, dedupe, claim, budget. Returns a claim, or the final outcome."""
    row = await conn.fetchrow(
        UPSERT_ALERT_SQL,
        alert.source,
        alert.source_alert_id,
        alert.title,
        alert.source_severity.value,
        alert.category,
        alert.occurred_at,
        alert.evidence,
        alert.content_hash(),
    )
    if row is not None:
        claim = _Claim(
            alert_id=cast("UUID", row["id"]), inserted=bool(row["inserted"]), prior_reason=None
        )
    else:
        state = await conn.fetchrow(ALERT_STATE_SQL, alert.source, alert.source_alert_id)
        if state is None:  # pragma: no cover - the upsert just saw the row
            msg = "alert vanished during upsert"
            raise RuntimeError(msg)
        claim = _Claim(
            alert_id=cast("UUID", state["id"]),
            inserted=False,
            prior_reason=cast("str | None", state["review_reason"]),
        )
        if state["triaged_at"] is not None:
            return IngestOutcome(
                claim.alert_id, IngestStatus.UNCHANGED, inserted=False, model_called=False
            )

    if await conn.fetchval(CLAIM_SQL, claim.alert_id, token, limits.claim_lease_seconds) is None:
        return IngestOutcome(
            claim.alert_id, IngestStatus.IN_PROGRESS, inserted=claim.inserted, model_called=False
        )

    spent = cast("int", await conn.fetchval(SPENT_TODAY_SQL))
    if spent >= limits.daily_token_budget:
        reason = ReviewReason.BUDGET_EXCEEDED
        await conn.execute(DEFER_SQL, claim.alert_id, reason.value, token)
        # Audited when the state changes, not on every re-poll of an over-budget tenant,
        # which would flood the trail with identical entries.
        if claim.prior_reason != reason.value:
            await _audit(conn, alert_id=claim.alert_id, result=None, reason=reason, applied=True)
        return IngestOutcome(
            claim.alert_id,
            IngestStatus.NEEDS_REVIEW,
            inserted=claim.inserted,
            model_called=False,
            review_reason=reason,
        )
    return claim


async def _record_result(
    conn: Connection,
    claim: _Claim,
    token: UUID,
    source_severity: Severity,
    result: TriageResult,
) -> bool:
    """Transaction 2: write the result if the claim is still ours; meter and audit."""
    reason = result.review_reason
    # Final for this content unless the failure is one a later attempt can fix cheaply.
    final = reason is None or not reason.retry_on_next_ingestion
    applied_id = await conn.fetchval(
        APPLY_RESULT_SQL,
        claim.alert_id,
        token,
        max(source_severity, result.severity).value,
        _storable(result.summary),
        _storable(result.recommended_action),
        None if result.needs_human_review else result.confidence,
        None if result.needs_human_review else _storable(result.reasoning),
        result.needs_human_review,
        reason.value if reason is not None else None,
        _storable(result.model),
        final,
    )
    applied = applied_id is not None
    if result.usage is not None:
        usage = result.usage
        await conn.execute(
            INSERT_USAGE_SQL,
            USAGE_PURPOSE,
            _storable(result.model) or UNKNOWN_MODEL,
            usage.input_tokens,
            usage.output_tokens,
            usage.cache_read_tokens,
            usage.cache_creation_tokens,
            reason.value if reason is not None else "completed",
        )
    # Every model call is audited. A no-call outcome (model disabled, no key) is audited
    # only when it changes the stored state, for the same reason as the budget case.
    reason_changed = (reason.value if reason is not None else None) != claim.prior_reason
    if result.usage is not None or (applied and reason_changed):
        await _audit(conn, alert_id=claim.alert_id, result=result, reason=reason, applied=applied)
    return applied


async def ingest_alert(
    pool: Pool,
    tenant_id: UUID,
    alert: NormalizedAlert,
    model: TriageModel,
    *,
    policy: TriagePolicy | None = None,
) -> IngestOutcome:
    """Upsert one alert for `tenant_id` and triage it if its content needs triage.

    Never raises because of the model (rule 4). Database errors do propagate: they are not
    the model misbehaving, and the caller decides whether to continue with the next alert.
    """
    limits = policy or TriagePolicy()
    token = uuid4()

    async with tenant_transaction(pool, tenant_id) as conn:
        claim = await _store_and_claim(conn, alert, token, limits)
    if isinstance(claim, IngestOutcome):
        return claim

    # The model call: outside any transaction, with no pooled connection held.
    result = await run_triage(model, triage_input(alert), timeout_seconds=limits.deadline_seconds)

    async with tenant_transaction(pool, tenant_id) as conn:
        applied = await _record_result(conn, claim, token, alert.source_severity, result)

    if not applied:
        status = IngestStatus.SUPERSEDED
    elif result.review_reason is None:
        status = IngestStatus.TRIAGED
    else:
        status = IngestStatus.NEEDS_REVIEW
    return IngestOutcome(
        claim.alert_id,
        status,
        inserted=claim.inserted,
        model_called=result.usage is not None,
        review_reason=result.review_reason,
    )


__all__ = [
    "IngestOutcome",
    "IngestStatus",
    "TriagePolicy",
    "ingest_alert",
    "triage_input",
]
