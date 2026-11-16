"""Helpers for connector and runner tests.

Every key and certificate is generated at run time; nothing here is a real secret, a real
tenant or real customer data. Directory ids are random UUIDs, names use example.com and
.invalid, addresses come from the documentation ranges (192.0.2.0/24, 2001:db8::/32).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote, urlsplit, urlunsplit
from uuid import UUID, uuid4

import asyncpg
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import SecretStr

from lighthouse.connectors.base import ConnectorCredential
from lighthouse.connectors.msgraph_auth import AccessToken

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "defender"
WORKER_LOGIN_ROLE = "lh_ingest_worker_test"

type Conn = asyncpg.Connection[asyncpg.Record]


def load_fixture(name: str) -> dict[str, Any]:
    data: Any = json.loads((FIXTURES / name).read_text())
    assert isinstance(data, dict)
    return cast("dict[str, Any]", data)


def set_alert_tenant(page: dict[str, Any], directory: UUID) -> dict[str, Any]:
    """Fixtures carry a placeholder directory id; tests substitute a random one."""
    incidents: list[Any] = page.get("value", [])
    for incident in incidents:
        if not isinstance(incident, dict):
            continue
        alerts: Any = cast("dict[str, Any]", incident).get("alerts")
        if not isinstance(alerts, list):
            continue
        for alert in cast("list[Any]", alerts):
            if isinstance(alert, dict):
                record = cast("dict[str, Any]", alert)
                if record.get("tenantId") == "{directory}":
                    record["tenantId"] = str(directory)
    return page


# Keys and credentials ------------------------------------------------------------------


@dataclass(frozen=True)
class TestCertificate:
    __test__ = False  # not a pytest test class

    key: rsa.RSAPrivateKey
    certificate: x509.Certificate

    @property
    def private_pem(self) -> str:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    @property
    def thumbprint_sha256(self) -> str:
        der = self.certificate.public_bytes(serialization.Encoding.DER)
        return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode().rstrip("=")


def make_certificate(key_size: int = 2048) -> TestCertificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lighthouse-test.invalid")])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return TestCertificate(key=key, certificate=certificate)


def make_credential(
    cert: TestCertificate,
    *,
    directory: UUID | None = None,
    client_id: UUID | None = None,
) -> ConnectorCredential:
    return ConnectorCredential(
        client_id=client_id or uuid4(),
        entra_tenant_id=directory or uuid4(),
        private_key_pem=SecretStr(cert.private_pem),
        certificate_thumbprint_sha256=cert.thumbprint_sha256,
    )


def random_token_value() -> str:
    """An opaque stand-in for an access token, built at run time (never JWT-shaped)."""
    return "test-access-" + secrets.token_hex(16)


class StaticTokens:
    """A TokenSource that hands out fixed tokens and counts invalidations."""

    def __init__(self) -> None:
        self.values = [random_token_value(), random_token_value()]
        self.issued = 0
        self.invalidated = 0

    async def get_token(self, credential: ConnectorCredential) -> AccessToken:
        del credential
        value = self.values[min(self.invalidated, len(self.values) - 1)]
        self.issued += 1
        return AccessToken(value, expires_at=4102444800.0)

    def invalidate(self, credential: ConnectorCredential) -> None:
        del credential
        self.invalidated += 1


# HTTP ----------------------------------------------------------------------------------


@dataclass
class RecordingTransport:
    """An httpx MockTransport that records requests and answers from a handler."""

    handler: Callable[[httpx.Request], httpx.Response]
    requests: list[httpx.Request] = field(default_factory=list[httpx.Request])

    def client(self) -> httpx.AsyncClient:
        def handle(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return self.handler(request)

        return httpx.AsyncClient(transport=httpx.MockTransport(handle))

    @property
    def hosts(self) -> list[str]:
        return [request.url.host for request in self.requests]


def json_response(
    status: int, body: object, headers: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(status, json=body, headers=headers)


# Database ------------------------------------------------------------------------------


def with_login(dsn: str, user: str, password: str) -> str:
    """The same DSN, logged in as another role."""
    parts = urlsplit(dsn)
    host = parts.netloc.rsplit("@", 1)[-1]
    netloc = f"{quote(user, safe='')}:{quote(password, safe='')}@{host}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


async def ensure_worker_role(superuser_dsn: str) -> str:
    """Create (or reset) the worker's login role; return its password.

    The worker's production shape: a NOINHERIT login role that may only SET ROLE to
    `lh_app` (per-tenant work) and `lh_ingest` (scheduling), and holds nothing itself.
    """
    password = secrets.token_hex(24)
    conn = await asyncpg.connect(superuser_dsn)
    try:
        exists = await conn.fetchval("select 1 from pg_roles where rolname = $1", WORKER_LOGIN_ROLE)
        if exists:
            await conn.execute(f"alter role {WORKER_LOGIN_ROLE} login password '{password}'")
        else:
            await conn.execute(
                f"create role {WORKER_LOGIN_ROLE} login nosuperuser nobypassrls noinherit "
                f"password '{password}'"
            )
        database = await conn.fetchval("select current_database()")
        await conn.execute(f'grant connect on database "{database}" to {WORKER_LOGIN_ROLE}')
        await conn.execute(f"grant lh_app, lh_ingest to {WORKER_LOGIN_ROLE}")
    finally:
        await conn.close()
    return password


async def create_connection(
    conn: Conn,
    tenant_id: UUID,
    *,
    directory: UUID | None = None,
    status: str = "active",
    credential_ref: str | None = None,
) -> UUID:
    connection_id = await conn.fetchval(
        """
        insert into lh.connections (tenant_id, kind, external_tenant_id, status, credential_ref)
        values ($1, 'defender_xdr', $2, $3, $4)
        returning id
        """,
        tenant_id,
        directory or uuid4(),
        status,
        f"vault:{uuid4()}" if credential_ref is None else credential_ref,
    )
    assert isinstance(connection_id, UUID)
    return connection_id
