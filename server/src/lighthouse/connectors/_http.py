"""Small HTTP helpers shared by connectors: bounded reads and `Retry-After` parsing."""

from __future__ import annotations

import email.utils
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

import httpx

from lighthouse.connectors.base import ConnectorTransientError

DEFAULT_RETRY_AFTER_SECONDS: Final = 60
MAX_RETRY_AFTER_SECONDS: Final = 3600

# Plain ints: comparing a status code against these reads the same everywhere and type
# checks cleanly (pyright mis-types `httpx.codes` members in comparisons).
HTTP_OK: Final = 200
HTTP_BAD_REQUEST: Final = 400
HTTP_UNAUTHORIZED: Final = 401
HTTP_FORBIDDEN: Final = 403
HTTP_REQUEST_TIMEOUT: Final = 408
HTTP_TOO_MANY_REQUESTS: Final = 429
HTTP_SERVER_ERROR: Final = 500
HTTP_SERVICE_UNAVAILABLE: Final = 503
THROTTLING_STATUSES: Final = frozenset({HTTP_TOO_MANY_REQUESTS, HTTP_SERVICE_UNAVAILABLE})


@dataclass(frozen=True, slots=True)
class CappedResponse:
    status_code: int
    headers: httpx.Headers
    body: bytes


async def send_capped(  # noqa: PLR0913 - keyword-only options of one request
    http: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_bytes: int,
    timeout_seconds: float,
    headers: Mapping[str, str] | None = None,
    data: Mapping[str, str] | None = None,
) -> CappedResponse:
    """Send one request and read at most `max_bytes` of the body.

    The body is streamed and the read stops at the cap, so a huge or never-ending
    response cannot exhaust the worker's memory. Redirects are never followed: the
    bearer token goes only to the URL we validated. Transport errors and timeouts become
    `ConnectorTransientError` with a fixed message (httpx messages can include the URL).
    """
    request = http.build_request(
        method,
        url,
        headers=dict(headers or {}),
        data=dict(data) if data is not None else None,
        # Applies to connect, each read, each write and pool wait: a server trickling
        # bytes cannot hold the request open past this between chunks. The runner's
        # per-connection budget bounds the total.
        timeout=httpx.Timeout(timeout_seconds),
    )
    try:
        response = await http.send(request, stream=True, follow_redirects=False)
        try:
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > max_bytes:
                    msg = "response exceeded the size limit"
                    raise ConnectorTransientError(msg)
                chunks.append(chunk)
        finally:
            await response.aclose()
    except httpx.TimeoutException:
        msg = "request timed out"
        raise ConnectorTransientError(msg) from None
    except httpx.HTTPError:
        msg = "network error"
        raise ConnectorTransientError(msg) from None
    return CappedResponse(response.status_code, response.headers, b"".join(chunks))


def retry_after_seconds(headers: httpx.Headers, *, now: datetime | None = None) -> int:
    """Seconds to wait according to `Retry-After` (delta-seconds or HTTP-date).

    Clamped to [1, 3600] so a hostile or broken value cannot park a connection forever
    or make the runner spin; a missing or unparseable value gets a fixed default.
    """
    raw = headers.get("retry-after")
    if raw is None:
        return DEFAULT_RETRY_AFTER_SECONDS
    raw = raw.strip()
    seconds: float | None = None
    if raw.isdigit() and len(raw) <= 10:  # noqa: PLR2004 - bounds int() on hostile input
        seconds = int(raw)
    else:
        try:
            when = email.utils.parsedate_to_datetime(raw)
        except (TypeError, ValueError, IndexError):
            when = None
        if when is not None:
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
            seconds = (when - (now or datetime.now(UTC))).total_seconds()
    if seconds is None or not math.isfinite(seconds):
        return DEFAULT_RETRY_AFTER_SECONDS
    return int(min(max(math.ceil(seconds), 1), MAX_RETRY_AFTER_SECONDS))
