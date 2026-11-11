"""Append-only audit trail (CLAUDE.md rule 11).

Entries are written inside the caller's tenant transaction, so an audited change and its
audit row commit or roll back together, and RLS pins the row to the caller's tenant.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Final

from lighthouse.db import Connection

type JsonValue = str | int | float | bool | list[JsonValue] | dict[str, JsonValue] | None

MAX_DETAIL_BYTES: Final = 16_384
REDACTED: Final = "[redacted]"

# Audit rows are exported to customers and kept for a long time. Values under keys that
# look like credentials are dropped, so a careless caller cannot persist a token.
_SENSITIVE_KEY = re.compile(
    r"authorization|token|secret|password|passwd|api[_-]?key|cookie|credential|private[_-]?key",
    re.IGNORECASE,
)


class AuditError(RuntimeError):
    pass


def _redact_object(obj: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        key: (REDACTED if _SENSITIVE_KEY.search(key) else redact(item)) for key, item in obj.items()
    }


def redact(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return _redact_object(value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def prepare_detail(detail: Mapping[str, JsonValue] | None) -> dict[str, JsonValue]:
    cleaned = _redact_object(detail or {})
    try:
        encoded = json.dumps(cleaned, separators=(",", ":"), allow_nan=False)
    except ValueError as exc:  # NaN/Infinity: not valid JSON, and jsonb rejects them
        msg = "audit detail is not valid JSON"
        raise AuditError(msg) from exc
    size = len(encoded.encode())
    if size > MAX_DETAIL_BYTES:
        # Keep the fact and the size, not the payload: an oversized detail is more likely a
        # bug or abuse than evidence, and must not bloat an append-only table.
        return {"truncated": True, "original_bytes": size}
    return cleaned


async def record_audit(
    conn: Connection,
    *,
    actor: str,
    action: str,
    target: str | None = None,
    detail: Mapping[str, JsonValue] | None = None,
) -> None:
    """Append one audit entry for the tenant of the current transaction.

    The tenant comes from the transaction (`lh.current_tenant_id()`), not from a parameter,
    so a caller cannot file an entry under another tenant; outside a tenant transaction the
    insert fails.
    """
    if not conn.is_in_transaction():
        msg = "record_audit must run inside the caller's tenant transaction"
        raise AuditError(msg)
    await conn.execute(
        """
        insert into lh.audit_log (tenant_id, actor, action, target, detail)
        values (lh.current_tenant_id(), $1, $2, $3, $4)
        """,
        actor,
        action,
        target,
        prepare_detail(detail),
    )
