"""App-only access tokens for Microsoft Graph, with a certificate credential.

Security boundary: connector credential handling (CLAUDE.md rules 1, 9 and "Secrets").

OAuth 2.0 client credentials grant against the Microsoft identity platform, where the
client authenticates with a signed JWT assertion (`private_key_jwt`) instead of a client
secret. The assertion format follows Microsoft's "certificate credentials" reference:
header `alg=PS256`, `typ=JWT`, `x5t#S256` = base64url SHA-256 thumbprint of the
certificate; claims `aud` (the token endpoint), `iss` = `sub` = client id, `jti`, `nbf`,
`iat`, and a short `exp`.

What this module guarantees:
- the customer's directory id must be a canonical UUID before it is placed in the token
  endpoint URL, so a crafted value cannot redirect the request (and our signed assertion)
  to another path or host;
- tokens, assertions and keys never appear in logs, exception messages or `repr`s; a
  rejected request surfaces only the AADSTS code and a fixed message;
- tokens are cached in memory per (directory, client) until shortly before they expire,
  so one run does not mint a token per page, and nothing is written to disk.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from collections.abc import Callable
from typing import Final, cast
from uuid import UUID

import httpx
import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from lighthouse.connectors._http import retry_after_seconds, send_capped
from lighthouse.connectors.base import (
    ConnectorAuthError,
    ConnectorCredential,
    ConnectorPermanentError,
    ConnectorThrottledError,
    ConnectorTransientError,
)

LOGIN_HOST: Final = "login.microsoftonline.com"
GRAPH_SCOPE: Final = "https://graph.microsoft.com/.default"
CLIENT_ASSERTION_TYPE: Final = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
ASSERTION_ALGORITHM: Final = "PS256"
# Microsoft advises 5-10 minutes at most; the assertion is single-use in practice.
ASSERTION_LIFETIME_SECONDS: Final = 300
# Refresh this long before expiry, so a token never expires half-way through a run.
REFRESH_MARGIN_SECONDS: Final = 300
MIN_RSA_KEY_BITS: Final = 2048
TOKEN_REQUEST_TIMEOUT_SECONDS: Final = 15.0
MAX_TOKEN_RESPONSE_BYTES: Final = 64 * 1024
# Bounds on what we accept as `expires_in`; outside them the response is treated as broken.
_MIN_EXPIRES_IN: Final = 60
_MAX_EXPIRES_IN: Final = 24 * 3600

# Canonical lowercase/uppercase hex 8-4-4-4-12 only. `uuid.UUID()` alone also accepts
# braces, a `urn:uuid:` prefix and missing hyphens, none of which belong in a URL path.
_UUID_RE: Final = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

# Fixed, human-readable explanations for the AADSTS codes an operator is most likely to
# see. Anything else gets the generic message plus its code.
_AADSTS_MESSAGES: Final[dict[int, str]] = {
    65001: "admin consent has not been granted for the application",
    700016: "the application is not present in the customer directory (consent missing)",
    700027: "the client assertion was rejected (certificate not registered or expired)",
    7000112: "the application is disabled",
    90002: "the customer directory was not found",
    90023: "the token request was malformed",
}
_GENERIC_REJECTION: Final = "the identity platform rejected the token request"


class AccessToken:
    """A bearer token with an expiry. Its `repr` and `str` never show the value."""

    __slots__ = ("_value", "expires_at")

    def __init__(self, value: str, expires_at: float) -> None:
        self._value = value
        self.expires_at = expires_at

    def reveal(self) -> str:
        """The token value, for the Authorization header and nothing else."""
        return self._value

    def __repr__(self) -> str:
        return f"AccessToken(<redacted>, expires_at={self.expires_at:.0f})"

    __str__ = __repr__


def entra_tenant_uuid(value: UUID | str) -> UUID:
    """Return the directory id as a UUID, refusing anything that is not a canonical one."""
    if isinstance(value, UUID):
        return value
    if not _UUID_RE.fullmatch(value):
        msg = "Entra tenant id must be a UUID"
        raise ConnectorPermanentError(msg)
    return UUID(value)


def token_url(entra_tenant_id: UUID | str) -> str:
    # str(UUID) is always the canonical lowercase form: nothing else reaches the path.
    tenant = entra_tenant_uuid(entra_tenant_id)
    return f"https://{LOGIN_HOST}/{tenant}/oauth2/v2.0/token"


def _load_rsa_key(credential: ConnectorCredential) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(
            credential.private_key_pem.get_secret_value().encode(),
            password=None,
        )
    # `from None`: the original exception is not needed, and anything derived from key
    # material should not travel onwards in an exception chain.
    except (ValueError, TypeError, UnsupportedAlgorithm):
        msg = "connector private key could not be loaded"
        raise ConnectorPermanentError(msg) from None
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < MIN_RSA_KEY_BITS:
        # PS256 needs RSA; Entra certificate credentials are RSA.
        msg = "connector private key must be RSA with at least 2048 bits"
        raise ConnectorPermanentError(msg)
    return key


def build_client_assertion(credential: ConnectorCredential, *, now: float) -> str:
    """The signed `client_assertion` for one token request."""
    key = _load_rsa_key(credential)
    issued = int(now)
    claims = {
        "aud": token_url(credential.entra_tenant_id),
        "iss": str(credential.client_id),
        "sub": str(credential.client_id),
        "jti": str(uuid.uuid4()),
        "nbf": issued,
        "iat": issued,
        "exp": issued + ASSERTION_LIFETIME_SECONDS,
    }
    return jwt.encode(
        claims,
        key,
        algorithm=ASSERTION_ALGORITHM,
        headers={"typ": "JWT", "x5t#S256": credential.certificate_thumbprint_sha256},
    )


def _aadsts_code(body: bytes) -> int | None:
    """The first AADSTS code from an error response, or None. The body is never kept."""
    try:
        parsed = cast("object", json.loads(body))
    except (ValueError, RecursionError):
        return None
    if not isinstance(parsed, dict):
        return None
    codes = cast("dict[str, object]", parsed).get("error_codes")
    if not isinstance(codes, list) or not codes:
        return None
    first = cast("list[object]", codes)[0]
    if isinstance(first, int) and not isinstance(first, bool) and 0 < first < 10**8:
        return first
    return None


def _parse_token_response(body: bytes, *, now: float) -> AccessToken:
    malformed = ConnectorTransientError("malformed token response")
    try:
        parsed = cast("object", json.loads(body))
    except (ValueError, RecursionError):
        raise malformed from None
    if not isinstance(parsed, dict):
        raise malformed
    data = cast("dict[str, object]", parsed)
    token = data.get("access_token")
    token_type = data.get("token_type")
    expires_in = data.get("expires_in")
    if isinstance(expires_in, str) and expires_in.isdigit() and len(expires_in) <= 6:  # noqa: PLR2004
        expires_in = int(expires_in)
    if (
        not isinstance(token, str)
        or not token
        or not isinstance(token_type, str)
        or token_type.lower() != "bearer"
        or not isinstance(expires_in, int)
        or isinstance(expires_in, bool)
        or not _MIN_EXPIRES_IN <= expires_in <= _MAX_EXPIRES_IN
    ):
        raise malformed
    return AccessToken(token, now + expires_in)


class GraphTokenProvider:
    """Mints and caches app-only Graph tokens. One instance per worker process."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        *,
        clock: Callable[[], float] = time.time,
        timeout_seconds: float = TOKEN_REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        if timeout_seconds <= 0:
            msg = "timeout_seconds must be positive"
            raise ValueError(msg)
        self._http = http
        self._clock = clock
        self._timeout = timeout_seconds
        self._cache: dict[tuple[UUID, UUID], AccessToken] = {}
        self._locks: dict[tuple[UUID, UUID], asyncio.Lock] = {}

    @staticmethod
    def _key(credential: ConnectorCredential) -> tuple[UUID, UUID]:
        return (credential.entra_tenant_id, credential.client_id)

    def invalidate(self, credential: ConnectorCredential) -> None:
        """Drop a cached token, e.g. after Graph answered 401 to it."""
        self._cache.pop(self._key(credential), None)

    async def get_token(self, credential: ConnectorCredential) -> AccessToken:
        key = self._key(credential)
        cached = self._cache.get(key)
        if cached is not None and cached.expires_at - REFRESH_MARGIN_SECONDS > self._clock():
            return cached
        # One request per (directory, client) at a time: concurrent pages or runs for the
        # same connection wait for the first token instead of each minting their own.
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            cached = self._cache.get(key)
            if cached is not None and cached.expires_at - REFRESH_MARGIN_SECONDS > self._clock():
                return cached
            token = await self._request_token(credential)
            self._cache[key] = token
            return token

    async def _request_token(self, credential: ConnectorCredential) -> AccessToken:
        url = token_url(credential.entra_tenant_id)
        now = self._clock()
        form = {
            "client_id": str(credential.client_id),
            "scope": GRAPH_SCOPE,
            "grant_type": "client_credentials",
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": build_client_assertion(credential, now=now),
        }
        response = await send_capped(
            self._http,
            "POST",
            url,
            data=form,
            headers={"Accept": "application/json"},
            max_bytes=MAX_TOKEN_RESPONSE_BYTES,
            timeout=self._timeout,
        )
        status = response.status_code
        if status == httpx.codes.OK:
            return _parse_token_response(response.body, now=now)
        if status in {httpx.codes.TOO_MANY_REQUESTS, httpx.codes.SERVICE_UNAVAILABLE}:
            raise ConnectorThrottledError(retry_after_seconds(response.headers))
        if status >= httpx.codes.INTERNAL_SERVER_ERROR:
            msg = f"identity platform error (HTTP {status})"
            raise ConnectorTransientError(msg)
        if status in {httpx.codes.BAD_REQUEST, httpx.codes.UNAUTHORIZED, httpx.codes.FORBIDDEN}:
            code = _aadsts_code(response.body)
            message = _AADSTS_MESSAGES.get(code, _GENERIC_REJECTION) if code else _GENERIC_REJECTION
            raise ConnectorAuthError(message, aadsts_code=code)
        msg = f"unexpected token endpoint response (HTTP {status})"
        raise ConnectorPermanentError(msg)

    def __repr__(self) -> str:
        return f"GraphTokenProvider(<{len(self._cache)} cached tokens>)"
