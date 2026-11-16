"""Microsoft Defender XDR incidents and alerts, read through the Microsoft Graph security API.

Read-only: `GET /v1.0/security/incidents?$expand=alerts`, application permissions
`SecurityIncident.Read.All` (least privileged for this call per Microsoft's permissions
table) and `SecurityAlert.Read.All` for the expanded alerts. Nothing here writes to the
customer's tenant.

Security boundaries this module holds (CLAUDE.md rules 3 and 9):

- The bearer token is sent only to `https://graph.microsoft.com/v1.0/security/incidents...`.
  `@odata.nextLink` comes from the response body, so it is validated before it is
  followed: https, host exactly `graph.microsoft.com`, the same API path. A link anywhere
  else is refused, because following it would hand the token to whoever chose the URL.
- Every value in an incident or alert is attacker-controlled (titles, command lines, file
  and host names are chosen by whoever triggered the detection). Each alert becomes a
  `NormalizedAlert` holding an allow-listed, length-capped projection, never the record.
- Bounded work: request timeouts, a byte cap per page, a page cap and an alert cap per
  run. Throttling is surfaced as an error carrying `Retry-After`; nothing here sleeps.
- One malformed alert is skipped and counted; it never stops the run.

Incremental fetching. Microsoft documents `$filter` on `lastUpdateDateTime` for incidents
but no `$orderby`, and lists "most recent first", so we cannot rely on order to advance a
cursor. Instead each run reads one closed time window `[since, until)` of incidents by
`lastUpdateDateTime`, and the cursor moves to `until` only when every page of that window
was read. If a cap stops the run early, the cursor keeps `since` and halves the window,
so the next run reads a smaller slice instead of skipping what it could not reach.
`until` trails the clock by a settle lag so late-indexed updates are not jumped over.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, Literal, Protocol, cast
from urllib.parse import quote, urlsplit
from uuid import UUID

import httpx
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from lighthouse.connectors._http import (
    HTTP_FORBIDDEN,
    HTTP_OK,
    HTTP_REQUEST_TIMEOUT,
    HTTP_SERVER_ERROR,
    HTTP_UNAUTHORIZED,
    THROTTLING_STATUSES,
    retry_after_seconds,
    send_capped,
)
from lighthouse.connectors.base import (
    ConnectorAuthError,
    ConnectorCredential,
    ConnectorPermanentError,
    ConnectorThrottledError,
    ConnectorTransientError,
    FetchResult,
)
from lighthouse.connectors.msgraph_auth import AccessToken
from lighthouse.ingest.schema import (
    EVIDENCE_TRUNCATED_KEY,
    TRUNCATION_MARK,
    EvidenceValue,
    NormalizedAlert,
    cap_text,
)
from lighthouse.severity import Severity

logger = logging.getLogger(__name__)

SOURCE: Final = "defender_xdr"
GRAPH_HOST: Final = "graph.microsoft.com"
INCIDENTS_PATH: Final = "/v1.0/security/incidents"
INCIDENTS_URL: Final = f"https://{GRAPH_HOST}{INCIDENTS_PATH}"
UNTITLED: Final = "Untitled Defender XDR alert"
DEFAULT_MAX_EVIDENCE_ITEMS: Final = 200

_MAX_LINK_CHARS: Final = 8192
_MAX_ID_CHARS: Final = 512
_MAX_TIMESTAMP_CHARS: Final = 40
_SHORT: Final = 64
_NAME: Final = 200
_ENTITY: Final = 256
_DESCRIPTION: Final = 1000
_MAX_ENTITIES: Final = 8
_MAX_COMMAND_LINES: Final = 4
_MITRE_RE: Final = re.compile(r"T\d{4}(?:\.\d{3})?")
_SHA256_RE: Final = re.compile(r"[0-9a-fA-F]{64}")
_EVIDENCE_TYPE_PREFIX: Final = "#microsoft.graph.security."

# Graph's alertSeverity: unknown, informational, low, medium, high, unknownFutureValue.
_SEVERITY: Final[dict[str, Severity]] = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
}


def map_severity(raw: object) -> Severity:
    """Map a Graph alert severity onto ours.

    The source severity is the floor the model can never lower (CLAUDE.md rule 5), so a
    value we cannot read must not quietly become a low floor:

    - `unknown`, missing or null mean the source has not rated the alert. MEDIUM: low
      enough not to flood the queue, high enough that it is never filed as noise, and
      triage may still raise it.
    - any other value (including `unknownFutureValue`, which Graph sends in place of an
      enum member added after our client was written) may be a new level above `high`.
      HIGH, so an unrecognised rating fails towards attention; a person can lower it.
    """
    if raw is None:
        return Severity.MEDIUM
    if isinstance(raw, str):
        value = raw.strip().lower()
        known = _SEVERITY.get(value)
        if known is not None:
            return known
        if value in {"", "unknown"}:
            return Severity.MEDIUM
    return Severity.HIGH


@dataclass(frozen=True, slots=True)
class DefenderLimits:
    """Per-run bounds. Validated, because 0 or a negative value must never mean
    "unbounded" or silently disable fetching."""

    page_size: int = 50
    max_pages: int = 20
    max_alerts: int = 2000
    max_alerts_per_incident: int = 500
    max_evidence_items: int = DEFAULT_MAX_EVIDENCE_ITEMS
    max_page_bytes: int = 8 * 1024 * 1024
    request_timeout_seconds: float = 30.0
    initial_lookback: timedelta = timedelta(days=7)
    max_window: timedelta = timedelta(days=1)
    min_window: timedelta = timedelta(minutes=1)
    settle_lag: timedelta = timedelta(minutes=2)

    def __post_init__(self) -> None:
        positive_ints = (
            self.page_size,
            self.max_pages,
            self.max_alerts,
            self.max_alerts_per_incident,
            self.max_evidence_items,
            self.max_page_bytes,
        )
        if any(value <= 0 for value in positive_ints) or self.request_timeout_seconds <= 0:
            msg = "Defender limits must be positive"
            raise ValueError(msg)
        if self.page_size > 100:  # noqa: PLR2004 - well above Graph's usual page size
            msg = "page_size must be at most 100"
            raise ValueError(msg)
        zero = timedelta(0)
        if (
            self.initial_lookback <= zero
            or self.min_window < timedelta(seconds=1)
            or self.max_window < self.min_window
            or self.settle_lag < zero
        ):
            msg = "Defender time windows are inconsistent"
            raise ValueError(msg)


class TokenSource(Protocol):
    async def get_token(self, credential: ConnectorCredential) -> AccessToken: ...

    def invalidate(self, credential: ConnectorCredential) -> None: ...


# Cursor ---------------------------------------------------------------------------------


class _CursorState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    v: Literal[1] = 1
    since: AwareDatetime
    window_s: int = Field(ge=1, le=366 * 86400)


def _format_ts(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _floor_seconds(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(microsecond=0)


def encode_cursor(since: datetime, window: timedelta) -> str:
    return json.dumps(
        {"v": 1, "since": _format_ts(since), "window_s": int(window.total_seconds())},
        separators=(",", ":"),
    )


def decode_cursor(cursor: str) -> tuple[datetime, timedelta] | None:
    """Parse a stored cursor; None if it is not one of ours (it is then restarted)."""
    try:
        state = _CursorState.model_validate_json(cursor)
    except ValidationError:
        return None
    return _floor_seconds(state.since), timedelta(seconds=state.window_s)


# Paging links ---------------------------------------------------------------------------


def validate_next_link(link: object) -> str:
    """Accept `@odata.nextLink` only if it points back at the incidents API on Graph.

    The token is attached to whatever URL we follow. A link to another host (or to
    `graph.microsoft.com@other.example`, or over http) would leak it, and a link to a
    different Graph path would make this read-only connector read something else.
    """
    refused = ConnectorPermanentError("refused a paging link outside the Graph incidents API")
    if not isinstance(link, str) or not link or len(link) > _MAX_LINK_CHARS:
        raise refused
    # Whitespace, control characters and backslashes are where URL parsers disagree.
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F or ch == "\\" for ch in link):  # noqa: PLR2004
        raise refused
    try:
        parts = urlsplit(link)
        port = parts.port
    except ValueError:
        raise refused from None
    if (
        parts.scheme != "https"
        or parts.netloc.lower() not in {GRAPH_HOST, f"{GRAPH_HOST}:443"}
        or parts.hostname != GRAPH_HOST
        or port not in {None, 443}
        or parts.fragment
        or parts.path != INCIDENTS_PATH
    ):
        raise refused
    return link


def first_page_url(since: datetime, until: datetime, page_size: int) -> str:
    # `$` is kept literal in the parameter names; values are percent-encoded.
    # Half-open window: `ge since and lt until`, so consecutive windows neither overlap
    # nor leave a gap.
    window = (
        f"lastUpdateDateTime ge {_format_ts(since)} and lastUpdateDateTime lt {_format_ts(until)}"
    )
    query = {
        "$filter": window,
        "$expand": "alerts",
        "$top": str(page_size),
    }
    encoded = "&".join(f"{key}={quote(value, safe='')}" for key, value in query.items())
    return f"{INCIDENTS_URL}?{encoded}"


# Normalisation --------------------------------------------------------------------------


class MalformedAlertError(ValueError):
    """An alert record we cannot use. Counted and skipped; never fatal to the run."""


def _str(record: Mapping[str, object], key: str, limit: int) -> str | None:
    value = record.get(key)
    if not isinstance(value, str):
        return None
    capped = cap_text(value, limit).strip()
    return capped or None


def _mapping(value: object) -> Mapping[str, object] | None:
    return cast("Mapping[str, object]", value) if isinstance(value, dict) else None


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value or len(value) > _MAX_TIMESTAMP_CHARS:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    # Graph DateTimeOffset values carry an offset; a bare one is read as UTC.
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _string_list(value: object, limit: int, max_items: int) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in cast("list[object]", value)[: max_items * 4]:
        if isinstance(item, str):
            capped = cap_text(item, limit).strip()
            if capped and capped not in out:
                out.append(capped)
        if len(out) >= max_items:
            break
    return out


class _Entities:
    """Collects a few capped, de-duplicated entity names per kind."""

    def __init__(self) -> None:
        self.lists: dict[str, list[str]] = {
            "devices": [],
            "users": [],
            "ip_addresses": [],
            "file_names": [],
            "file_sha256": [],
            "urls": [],
            "process_command_lines": [],
        }
        # Set when an entity was left out because its list was full, so the projection
        # can say it is incomplete.
        self.cut = False

    def add(self, kind: str, value: object, limit: int = _ENTITY) -> None:
        if not isinstance(value, str):
            return
        cap = _MAX_COMMAND_LINES if kind == "process_command_lines" else _MAX_ENTITIES
        bucket = self.lists[kind]
        cleaned = cap_text(value, limit).strip()
        if not cleaned or cleaned in bucket:
            return
        if len(bucket) >= cap:
            self.cut = True
            return
        bucket.append(cleaned)

    def add_ip(self, value: object) -> None:
        if not isinstance(value, str) or len(value) > _SHORT:
            return
        try:
            self.add("ip_addresses", str(ipaddress.ip_address(value.strip())))
        except ValueError:
            return

    def add_sha256(self, value: object) -> None:
        if isinstance(value, str) and _SHA256_RE.fullmatch(value):
            self.add("file_sha256", value.lower())

    def add_user(self, account: object) -> None:
        user = _mapping(account)
        if user is None:
            return
        upn = _str(user, "userPrincipalName", _ENTITY)
        if upn is not None:
            self.add("users", upn)
            return
        name = _str(user, "accountName", _NAME)
        domain = _str(user, "domainName", _NAME)
        if name is not None:
            self.add("users", f"{domain}\\{name}" if domain else name)

    def add_file(self, details: object) -> None:
        file = _mapping(details)
        if file is None:
            return
        self.add("file_names", file.get("fileName"))
        self.add_sha256(file.get("sha256"))


def _device(entities: _Entities, item: Mapping[str, object]) -> None:
    entities.add("devices", item.get("deviceDnsName") or item.get("hostName"))


def _process(entities: _Entities, item: Mapping[str, object]) -> None:
    entities.add("process_command_lines", item.get("processCommandLine"))
    entities.add_file(item.get("imageFile"))
    entities.add_user(item.get("userAccount"))


# Only these evidence types are read, and only the fields named here. Every other type
# (mailbox, cloud app, registry, ...) contributes to `evidence_count` and nothing else.
_EVIDENCE_READERS: Final[dict[str, Callable[[_Entities, Mapping[str, object]], None]]] = {
    "deviceEvidence": _device,
    "userEvidence": lambda e, item: e.add_user(item.get("userAccount")),
    "ipEvidence": lambda e, item: e.add_ip(item.get("ipAddress")),
    "processEvidence": _process,
    "fileEvidence": lambda e, item: e.add_file(item.get("fileDetails")),
    "urlEvidence": lambda e, item: e.add("urls", item.get("url")),
}


def _collect_entities(evidence: object, max_items: int) -> tuple[int, _Entities]:
    entities = _Entities()
    if not isinstance(evidence, list):
        return 0, entities
    items = cast("list[object]", evidence)
    for raw in items[:max_items]:
        item = _mapping(raw)
        odata_type = item.get("@odata.type") if item is not None else None
        if item is None or not isinstance(odata_type, str):
            continue
        reader = _EVIDENCE_READERS.get(odata_type.removeprefix(_EVIDENCE_TYPE_PREFIX))
        if reader is not None and odata_type.startswith(_EVIDENCE_TYPE_PREFIX):
            reader(entities, item)
    if len(items) > max_items:
        entities.cut = True
    return len(items), entities


def _value_was_cut(value: EvidenceValue) -> bool:
    # cap_text marks every cut with TRUNCATION_MARK at the end of the value.
    if isinstance(value, str):
        return value.endswith(TRUNCATION_MARK)
    if isinstance(value, list):
        return any(item.endswith(TRUNCATION_MARK) for item in value)
    return False


def project_evidence(
    alert: Mapping[str, object],
    incident: Mapping[str, object],
    *,
    max_evidence_items: int,
) -> dict[str, EvidenceValue]:
    """The allow-listed fields an analyst (and the model) get. Most useful first: if the
    evidence budget runs out, `fit_evidence` drops keys from the end."""
    evidence_count, entities = _collect_entities(alert.get("evidence"), max_evidence_items)
    first = _parse_timestamp(alert.get("firstActivityDateTime"))
    last = _parse_timestamp(alert.get("lastActivityDateTime"))
    projected: dict[str, EvidenceValue] = {
        "incident_id": _str(alert, "incidentId", _SHORT) or _str(incident, "id", _SHORT),
        "service_source": _str(alert, "serviceSource", _SHORT),
        "detection_source": _str(alert, "detectionSource", _SHORT),
        "product_name": _str(alert, "productName", _NAME),
        "status": _str(alert, "status", _SHORT),
        "classification": _str(alert, "classification", _SHORT),
        "determination": _str(alert, "determination", _SHORT),
        "mitre_techniques": [
            t for t in _string_list(alert.get("mitreTechniques"), 16, 20) if _MITRE_RE.fullmatch(t)
        ],
        "categories": _string_list(alert.get("categories"), _SHORT, 8),
        "threat_family_name": _str(alert, "threatFamilyName", _NAME),
        "threat_display_name": _str(alert, "threatDisplayName", _NAME),
        "actor_display_name": _str(alert, "actorDisplayName", _NAME),
        "first_activity_at": first.astimezone(UTC).isoformat() if first else None,
        "last_activity_at": last.astimezone(UTC).isoformat() if last else None,
        "evidence_count": evidence_count,
        **entities.lists,
        "description": _str(alert, "description", _DESCRIPTION),
    }
    # Drop empties: absent is clearer than null, and saves the evidence budget.
    kept = {key: value for key, value in projected.items() if value not in (None, [], "")}
    if entities.cut or any(_value_was_cut(value) for value in kept.values()):
        kept[EVIDENCE_TRUNCATED_KEY] = True
    return kept


def normalize_alert(
    raw: object,
    *,
    incident: Mapping[str, object],
    expected_tenant: UUID,
    max_evidence_items: int = DEFAULT_MAX_EVIDENCE_ITEMS,
) -> NormalizedAlert:
    """One Graph security alert to a NormalizedAlert, or MalformedAlertError."""
    alert = _mapping(raw)
    if alert is None:
        msg = "alert is not an object"
        raise MalformedAlertError(msg)
    alert_id = alert.get("id")
    if not isinstance(alert_id, str) or not alert_id or len(alert_id) > _MAX_ID_CHARS:
        msg = "alert has no usable id"
        raise MalformedAlertError(msg)
    # Defence in depth: the token is for one directory, so Graph should never return
    # another's alerts; if it ever does, they must not land in this tenant's queue.
    reported_tenant = alert.get("tenantId")
    if isinstance(reported_tenant, str) and reported_tenant.strip().lower() != str(expected_tenant):
        msg = "alert belongs to a different directory"
        raise MalformedAlertError(msg)
    occurred = _parse_timestamp(alert.get("createdDateTime")) or _parse_timestamp(
        alert.get("firstActivityDateTime")
    )
    if occurred is None:
        msg = "alert has no usable timestamp"
        raise MalformedAlertError(msg)
    title = _str(alert, "title", 4 * _DESCRIPTION) or UNTITLED
    categories = _string_list(alert.get("categories"), _NAME, 1)
    category = categories[0] if categories else _str(alert, "category", _NAME)
    try:
        return NormalizedAlert(
            source=SOURCE,
            source_alert_id=alert_id,
            title=title,
            source_severity=map_severity(alert.get("severity")),
            occurred_at=occurred,
            category=category,
            evidence=project_evidence(alert, incident, max_evidence_items=max_evidence_items),
        )
    except (ValidationError, TypeError, ValueError):
        # The validation message can quote the offending value; it is not propagated.
        msg = "alert failed validation"
        raise MalformedAlertError(msg) from None


# Connector ------------------------------------------------------------------------------


@dataclass(slots=True)
class _Collected:
    alerts: dict[str, NormalizedAlert]
    skipped: int = 0
    pages: int = 0
    complete: bool = False


def _utcnow() -> datetime:
    return datetime.now(UTC)


class DefenderXdrConnector:
    """Fetches one customer directory's Defender XDR alerts, incrementally."""

    def __init__(  # noqa: PLR0913 - keyword-only dependencies, injected for tests
        self,
        *,
        http: httpx.AsyncClient,
        tokens: TokenSource,
        credential: ConnectorCredential,
        external_tenant_id: UUID,
        limits: DefenderLimits | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        # The connection row says which customer directory this tenant consented from;
        # the credential must be for that same directory. A mismatch would read one
        # customer's alerts into another tenant's queue, so it is refused outright.
        if credential.entra_tenant_id != external_tenant_id:
            msg = "credential does not belong to this connection's directory"
            raise ConnectorPermanentError(msg)
        self._http = http
        self._tokens = tokens
        self._credential = credential
        self._tenant = external_tenant_id
        self._limits = limits or DefenderLimits()
        self._clock = clock

    async def fetch(self, cursor: str | None) -> FetchResult:
        limits = self._limits
        now = _floor_seconds(self._clock())
        decoded = decode_cursor(cursor) if cursor is not None else None
        if cursor is not None and decoded is None:
            # Re-reading the lookback is safe (ingestion is an idempotent upsert keyed on
            # the alert id, and unchanged alerts are not re-triaged); refusing would stall
            # the connection on a value only our own code writes.
            logger.warning("defender cursor unreadable; restarting from the lookback")
        since, window = decoded or (now - limits.initial_lookback, limits.max_window)
        window = min(max(window, limits.min_window), limits.max_window)
        until = min(now - limits.settle_lag, since + window)
        if until <= since:
            return FetchResult(alerts=[], next_cursor=encode_cursor(since, window))

        collected = await self._collect(since, until)
        if collected.complete:
            next_cursor = encode_cursor(until, min(window * 2, limits.max_window))
        else:
            # Keep `since`: the alerts returned are handed on, the rest of the window is
            # read again, in a smaller slice, next time.
            next_cursor = encode_cursor(since, max(window / 2, limits.min_window))
        return FetchResult(
            alerts=list(collected.alerts.values()),
            next_cursor=next_cursor,
            skipped=collected.skipped,
            truncated=not collected.complete,
            pages=collected.pages,
        )

    async def _collect(self, since: datetime, until: datetime) -> _Collected:
        limits = self._limits
        collected = _Collected(alerts={})
        url = first_page_url(since, until, limits.page_size)
        while True:
            if collected.pages >= limits.max_pages:
                return collected
            incidents, next_link = await self._get_page(url)
            collected.pages += 1
            for incident in incidents:
                if not self._take_incident(incident, collected):
                    return collected
            if next_link is None:
                collected.complete = True
                return collected
            url = validate_next_link(next_link)

    def _take_incident(self, raw: object, collected: _Collected) -> bool:
        """Normalise one incident's alerts; False when the per-run alert cap is reached."""
        limits = self._limits
        incident = _mapping(raw)
        if incident is None:
            collected.skipped += 1
            return True
        alerts = incident.get("alerts")
        if alerts is None:
            return True
        if not isinstance(alerts, list):
            collected.skipped += 1
            return True
        items = cast("list[object]", alerts)
        # Alerts beyond the per-incident cap would never fit however small the window,
        # so they are counted as skipped rather than making the run look truncated.
        collected.skipped += max(0, len(items) - limits.max_alerts_per_incident)
        for raw_alert in items[: limits.max_alerts_per_incident]:
            if len(collected.alerts) >= limits.max_alerts:
                return False
            try:
                alert = normalize_alert(
                    raw_alert,
                    incident=incident,
                    expected_tenant=self._tenant,
                    max_evidence_items=limits.max_evidence_items,
                )
            except MalformedAlertError:
                collected.skipped += 1
                continue
            collected.alerts[alert.source_alert_id] = alert
        return True

    async def _get_page(self, url: str) -> tuple[list[object], object]:
        # Re-validated even for the URL we built: the token goes nowhere else.
        validate_next_link(url)
        for attempt in range(2):
            token = await self._tokens.get_token(self._credential)
            response = await send_capped(
                self._http,
                "GET",
                url,
                headers={
                    "Authorization": f"Bearer {token.reveal()}",
                    "Accept": "application/json",
                },
                max_bytes=self._limits.max_page_bytes,
                timeout_seconds=self._limits.request_timeout_seconds,
            )
            status = response.status_code
            if status == HTTP_OK:
                return _parse_page(response.body)
            if status == HTTP_UNAUTHORIZED and attempt == 0:
                # A cached token can be revoked before it expires: retry once, fresh.
                self._tokens.invalidate(self._credential)
                continue
            _raise_for_status(status, response.headers)
        msg = "Microsoft Graph rejected the access token"
        raise ConnectorAuthError(msg)


def _parse_page(body: bytes) -> tuple[list[object], object]:
    """The page's incidents and its `@odata.nextLink` (None when it is the last page)."""
    try:
        parsed = cast("object", json.loads(body))
    except (ValueError, RecursionError):
        msg = "unparseable response from Microsoft Graph"
        raise ConnectorTransientError(msg) from None
    page = _mapping(parsed)
    incidents = page.get("value") if page is not None else None
    if page is None or not isinstance(incidents, list):
        msg = "unexpected response shape from Microsoft Graph"
        raise ConnectorTransientError(msg)
    return cast("list[object]", incidents), page.get("@odata.nextLink")


def _raise_for_status(status: int, headers: httpx.Headers) -> None:
    if status == HTTP_UNAUTHORIZED:
        msg = "Microsoft Graph rejected the access token"
        raise ConnectorAuthError(msg)
    if status == HTTP_FORBIDDEN:
        msg = "missing application permission or admin consent for the Graph security API"
        raise ConnectorAuthError(msg)
    if status in THROTTLING_STATUSES:
        raise ConnectorThrottledError(retry_after_seconds(headers))
    if status >= HTTP_SERVER_ERROR or status == HTTP_REQUEST_TIMEOUT:
        msg = f"Microsoft Graph error (HTTP {status})"
        raise ConnectorTransientError(msg)
    msg = f"Microsoft Graph refused the request (HTTP {status})"
    raise ConnectorPermanentError(msg)
