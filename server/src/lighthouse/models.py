"""Response models for the HTTP API.

Responses list their fields explicitly so a column added to a table later is not exposed
by accident. `tenant_id` is not returned on tenant-scoped resources: the caller's tenant is
implied by their token.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, JsonValue

from lighthouse.auth import Role
from lighthouse.severity import Severity
from lighthouse.triage import ReviewReason


class AlertStatus(Enum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class _Out(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")


class HealthOut(_Out):
    status: str


class MeOut(_Out):
    user_id: UUID
    tenant_id: UUID
    tenant_name: str
    role: Role


class AlertOut(_Out):
    id: UUID
    source: str
    source_alert_id: str
    title: str
    source_severity: Severity
    severity: Severity
    status: AlertStatus
    summary: str | None
    recommended_action: str | None
    needs_human_review: bool
    created_at: datetime
    updated_at: datetime
    # Phase 1 triage fields. All nullable: an alert may not have been triaged yet.
    category: str | None
    occurred_at: datetime | None
    confidence: float | None
    review_reason: ReviewReason | None
    triaged_at: datetime | None


class AlertDetailOut(AlertOut):
    """`GET /api/alerts/{id}` for analyst and above.

    `evidence` is attacker-controlled text from the customer's systems, and `reasoning`
    is model text about it; both are for people trained to read them as such. Viewers get
    `AlertOut`, the plain-English fields only. Enforced in the route, not the console.
    """

    evidence: dict[str, JsonValue]
    reasoning: str | None


class AlertPage(_Out):
    items: list[AlertOut]
    next_cursor: str | None


class AuditEntryOut(_Out):
    id: int
    actor: str
    action: str
    target: str | None
    detail: dict[str, JsonValue]
    created_at: datetime


class AuditPage(_Out):
    items: list[AuditEntryOut]
    next_cursor: str | None
