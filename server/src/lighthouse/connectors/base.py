"""What every connector provides, the errors it may raise, and where credentials come from.

Security boundary: connector credential handling. A connector credential is a customer's
certificate private key for our multi-tenant Entra application. It is held in memory only
for as long as a run needs it, it has no readable `repr`, and it never reaches a log, an
error message, the database or a prompt (CLAUDE.md, "Secrets").
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from lighthouse.ingest.schema import NormalizedAlert

# Mirrors the CHECK constraint on lh.connections.credential_ref: a reference, never a secret.
CREDENTIAL_REF_RE: Final = re.compile(r"vault:[a-z0-9][a-z0-9_-]{0,63}")
# The x5t#S256 thumbprint is unpadded base64url of a 32-byte digest: 43 characters.
_THUMBPRINT_RE: Final = re.compile(r"[A-Za-z0-9_-]{43}")


# Errors ---------------------------------------------------------------------------------
#
# Messages are fixed strings chosen by our code, plus at most a status code, an AADSTS
# code or a number of seconds. They are written to `lh.connections.last_error`, which a
# tenant admin can read, and to logs, so they must never carry a response body, a token,
# a URL with a token, or text from the customer's system.


class ConnectorError(Exception):
    """Base class. `kind` is a stable label for logs, audit detail and metrics."""

    kind: str = "error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ConnectorAuthError(ConnectorError):
    """The source rejected our identity or permissions (bad credential, consent revoked,
    missing application permission). Retrying will not help until a person acts."""

    kind = "auth"

    def __init__(self, message: str, *, aadsts_code: int | None = None) -> None:
        if aadsts_code is not None:
            message = f"{message} (AADSTS{aadsts_code})"
        super().__init__(message)
        self.aadsts_code = aadsts_code


class ConnectorThrottledError(ConnectorError):
    """The source asked us to slow down. The runner decides when to try again."""

    kind = "throttled"

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(f"throttled by the source; retry after {retry_after_seconds}s")
        self.retry_after_seconds = retry_after_seconds


class ConnectorTransientError(ConnectorError):
    """Network failure, timeout, 5xx, or an unexpected response: worth retrying later."""

    kind = "transient"


class ConnectorPermanentError(ConnectorError):
    """A request the source will keep refusing (4xx other than auth/throttling), or a
    configuration problem on our side. Needs a person or a code change."""

    kind = "permanent"


# Results --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FetchResult:
    """One fetch: the alerts, and the cursor to store once all of them were handed on.

    `next_cursor` is only ever stored by the runner after every alert in `alerts` was
    ingested successfully, so a connector may move it past exactly the data it returns.
    `truncated` means a per-run cap was hit and the connector chose a cursor that does
    not skip the data it could not return. `skipped` counts records that could not be
    normalised (malformed or hostile); they are dropped, never retried forever.
    """

    alerts: Sequence[NormalizedAlert]
    next_cursor: str | None
    skipped: int = 0
    truncated: bool = False
    pages: int = 0
    counters: Mapping[str, int] = field(default_factory=dict[str, int])


class Connector(Protocol):
    async def fetch(self, cursor: str | None) -> FetchResult: ...


# Credentials ----------------------------------------------------------------------------


class ConnectorCredential(BaseModel):
    """Our application's identity in one customer directory.

    `private_key_pem` is the private key of the certificate registered on the Entra
    application; `certificate_thumbprint_sha256` is the base64url SHA-256 thumbprint of
    that certificate (the `x5t#S256` assertion header). Certificates, not client secrets:
    the key never leaves our side, and what Entra holds is only the public certificate.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    client_id: UUID
    entra_tenant_id: UUID
    private_key_pem: SecretStr = Field(repr=False)
    certificate_thumbprint_sha256: str

    @field_validator("certificate_thumbprint_sha256")
    @classmethod
    def _thumbprint_shape(cls, value: str) -> str:
        if not _THUMBPRINT_RE.fullmatch(value):
            msg = "certificate thumbprint must be an unpadded base64url SHA-256 digest"
            raise ValueError(msg)
        return value


class CredentialNotFoundError(ConnectorPermanentError):
    def __init__(self) -> None:
        super().__init__("connector credential not found")


class CredentialProvider(Protocol):
    async def get(self, credential_ref: str) -> ConnectorCredential: ...


def check_credential_ref(credential_ref: str) -> str:
    if not CREDENTIAL_REF_RE.fullmatch(credential_ref):
        # The value is not echoed: if it fails the grammar it may be a pasted secret.
        msg = "credential_ref is not a valid reference"
        raise ConnectorPermanentError(msg)
    return credential_ref


class InMemoryCredentialProvider:
    """For tests and local development only.

    The production implementation reads the secret from Supabase Vault, scoped to the one
    tenant whose connector job is running. It is the next step once a Supabase project
    exists to build and test it against; it is deliberately not faked here, because a
    Vault reader that has never touched Vault would look finished and not be.
    """

    def __init__(self, credentials: Mapping[str, ConnectorCredential]) -> None:
        for ref in credentials:
            check_credential_ref(ref)
        self._credentials = dict(credentials)

    async def get(self, credential_ref: str) -> ConnectorCredential:
        check_credential_ref(credential_ref)
        credential = self._credentials.get(credential_ref)
        if credential is None:
            raise CredentialNotFoundError
        return credential

    def __repr__(self) -> str:
        return f"InMemoryCredentialProvider(<{len(self._credentials)} credentials>)"
