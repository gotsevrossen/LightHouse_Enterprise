"""Shared test helpers. Keys are generated per run; nothing here is a real secret or a
real tenant: every identifier is random and every name is an obvious placeholder."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

TEST_ISSUER = "https://auth.example.invalid/auth/v1"
TEST_AUDIENCE = "authenticated"

type Conn = asyncpg.Connection[asyncpg.Record]


def public_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unsigned_token(claims: dict[str, Any], alg: str = "none") -> str:
    """A token with the given header `alg` and an empty signature."""
    header = _b64url(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(claims).encode())
    return f"{header}.{payload}."


def hmac_token(claims: dict[str, Any], secret: bytes) -> str:
    """HS256 token, built by hand because PyJWT refuses PEM keys as HMAC secrets, which is
    exactly the algorithm-confusion attack the verifier must reject."""
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    signature = _b64url(hmac.new(secret, signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


@dataclass(frozen=True)
class TokenFactory:
    private_key: ec.EllipticCurvePrivateKey
    public_pem: str
    kid: str

    @classmethod
    def generate(cls) -> TokenFactory:
        key = ec.generate_private_key(ec.SECP256R1())
        return cls(private_key=key, public_pem=public_pem(key), kid=secrets.token_hex(8))

    def claims(
        self,
        *,
        tenant_id: UUID | None,
        role: str = "viewer",
        user_id: UUID | None = None,
        lifetime: int = 300,
    ) -> dict[str, Any]:
        now = int(time.time())
        app_metadata: dict[str, Any] = {"provider": "email", "role": role}
        if tenant_id is not None:
            app_metadata["tenant_id"] = str(tenant_id)
        return {
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "sub": str(user_id or uuid4()),
            "iat": now,
            "exp": now + lifetime,
            "role": "authenticated",
            "app_metadata": app_metadata,
            "user_metadata": {},
        }

    def sign(
        self,
        claims: dict[str, Any],
        *,
        key: ec.EllipticCurvePrivateKey | None = None,
        kid: str | None = None,
    ) -> str:
        return jwt.encode(
            claims,
            key or self.private_key,
            algorithm="ES256",
            headers={"kid": kid or self.kid},
        )

    def token(self, tenant_id: UUID, role: str = "viewer", user_id: UUID | None = None) -> str:
        return self.sign(self.claims(tenant_id=tenant_id, role=role, user_id=user_id))


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def create_tenant(conn: Conn, name: str = "Example Tenant") -> UUID:
    tenant_id = uuid4()
    await conn.execute("insert into lh.tenants (id, name) values ($1, $2)", tenant_id, name)
    return tenant_id


async def create_alert(
    conn: Conn,
    tenant_id: UUID,
    *,
    title: str = "Example alert",
    source: str = "fixture",
    source_severity: str = "medium",
    severity: str | None = None,
) -> UUID:
    alert_id = await conn.fetchval(
        """
        insert into lh.alerts (tenant_id, source, source_alert_id, title, source_severity, severity)
        values ($1, $2, $3, $4, $5, $6)
        returning id
        """,
        tenant_id,
        source,
        f"fixture-{uuid4()}",
        title,
        source_severity,
        severity or source_severity,
    )
    assert isinstance(alert_id, UUID)
    return alert_id
