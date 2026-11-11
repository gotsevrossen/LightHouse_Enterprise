"""Bearer-token authentication and server-side role checks.

Security boundary. Threats this module holds against:

- forged tokens (bad signature, `alg: none`, HS256 signed with our public key as the
  HMAC secret, i.e. algorithm confusion);
- replayed or misdirected tokens (expired, wrong audience, wrong issuer);
- a signed-in user choosing their own tenant or role. Supabase lets users edit
  `user_metadata`, so tenant and role are read only from `app_metadata`, which only the
  service can set. A missing or malformed claim is rejected; there is no default tenant.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Annotated, Any, Final, Protocol, cast
from uuid import UUID

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from lighthouse.config import Settings

logger = logging.getLogger(__name__)

# Only asymmetric algorithms. HS* is never accepted: our verifier would need the shared
# secret, and anything holding that secret could mint tokens for any tenant.
ALLOWED_ALGORITHMS: Final = frozenset({"ES256", "RS256"})

# Real Supabase access tokens are a few KB at most. Refusing very large input bounds the
# work an unauthenticated caller can make us do.
MAX_TOKEN_LENGTH: Final = 8192

TENANT_CLAIM: Final = "tenant_id"
ROLE_CLAIM: Final = "role"
MIN_RSA_KEY_BITS: Final = 2048

type PublicKey = ec.EllipticCurvePublicKey | rsa.RSAPublicKey


class Role(Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    RESPONDER = "responder"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return _ROLE_RANK[self]

    def at_least(self, minimum: Role) -> bool:
        return self.rank >= minimum.rank


_ROLE_RANK: Final[dict[Role, int]] = {member: index for index, member in enumerate(Role)}


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: UUID
    tenant_id: UUID
    role: Role


class AuthenticationError(Exception):
    """The token is not a valid token from our identity provider (HTTP 401)."""


class AuthorizationError(Exception):
    """The token is valid but does not grant access to a tenant (HTTP 403)."""


class TokenVerifier(Protocol):
    def verify(self, token: str) -> Principal: ...


class SigningKeyResolver(Protocol):
    def resolve(self, token: str) -> tuple[PublicKey, str]:
        """Return the verification key and the single algorithm it may be used with."""
        ...


def _algorithm_for_key(key: object) -> str:
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
        return "ES256"
    if isinstance(key, rsa.RSAPublicKey) and key.key_size >= MIN_RSA_KEY_BITS:
        return "RS256"
    msg = "unsupported public key: need an EC P-256 or an RSA >= 2048-bit key"
    raise ValueError(msg)


def _header_algorithm(token: str) -> str:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise AuthenticationError from exc
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in ALLOWED_ALGORITHMS:
        raise AuthenticationError
    return alg


class StaticKeyResolver:
    """One configured public key. The algorithm is pinned to the key's type so a token
    cannot pick a different algorithm for the same key material."""

    def __init__(self, pem: str) -> None:
        key = load_pem_public_key(pem.encode())
        self._algorithm = _algorithm_for_key(key)
        self._key = cast("PublicKey", key)

    def resolve(self, token: str) -> tuple[PublicKey, str]:
        if _header_algorithm(token) != self._algorithm:
            raise AuthenticationError
        return self._key, self._algorithm


class JwksKeyResolver:
    """Keys from the identity provider's JWKS endpoint, selected by `kid`.

    `PyJWKClient` caches the key set and fetches it with blocking I/O, so verification
    must run off the event loop (FastAPI runs the sync `get_principal` in a threadpool).
    """

    def __init__(self, url: str, client: jwt.PyJWKClient | None = None) -> None:
        self._client = client or jwt.PyJWKClient(url, cache_keys=True, lifespan=300, timeout=5)

    def resolve(self, token: str) -> tuple[PublicKey, str]:
        alg = _header_algorithm(token)
        try:
            signing_key = self._client.get_signing_key_from_jwt(token)
        except jwt.PyJWTError as exc:
            raise AuthenticationError from exc
        key: object = signing_key.key
        # The key's own type decides the algorithm; a JWKS that also carried a symmetric
        # ("oct") key, or a token whose header disagrees with the key, is refused.
        try:
            key_alg = _algorithm_for_key(key)
        except ValueError as exc:
            raise AuthenticationError from exc
        if key_alg != alg:
            raise AuthenticationError
        return cast("PublicKey", key), alg


class JwtTokenVerifier:
    def __init__(
        self,
        resolver: SigningKeyResolver,
        *,
        issuer: str,
        audience: str,
        leeway_seconds: int = 30,
    ) -> None:
        self._resolver = resolver
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway_seconds

    def verify(self, token: str) -> Principal:
        if not token or len(token) > MAX_TOKEN_LENGTH:
            raise AuthenticationError
        key, alg = self._resolver.resolve(token)
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=[alg],
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            # The reason is logged for operators; the client only learns "invalid token".
            # The token itself is never logged.
            logger.info("token rejected: %s", type(exc).__name__)
            raise AuthenticationError from exc
        return principal_from_claims(claims)


def _parse_uuid(value: object) -> UUID | None:
    if not isinstance(value, str):
        return None
    try:
        return UUID(value)
    except ValueError:
        return None


def principal_from_claims(claims: Mapping[str, Any]) -> Principal:
    user_id = _parse_uuid(claims.get("sub"))
    if user_id is None:
        raise AuthenticationError
    # Supabase anonymous sign-ins carry a valid token with no verified identity behind it.
    if claims.get("is_anonymous") is True:
        raise AuthorizationError
    # `user_metadata` is deliberately never read: users can edit it themselves.
    app_metadata = claims.get("app_metadata")
    if not isinstance(app_metadata, dict):
        raise AuthorizationError
    metadata = cast("dict[str, object]", app_metadata)
    tenant_id = _parse_uuid(metadata.get(TENANT_CLAIM))
    if tenant_id is None:
        raise AuthorizationError
    raw_role = metadata.get(ROLE_CLAIM)
    if not isinstance(raw_role, str):
        raise AuthorizationError
    try:
        role = Role(raw_role)
    except ValueError as exc:
        raise AuthorizationError from exc
    return Principal(user_id=user_id, tenant_id=tenant_id, role=role)


def build_verifier(settings: Settings) -> TokenVerifier:
    resolver: SigningKeyResolver
    if settings.jwt_public_key is not None:
        resolver = StaticKeyResolver(settings.jwt_public_key)
    elif settings.jwt_jwks_url is not None:
        resolver = JwksKeyResolver(settings.jwt_jwks_url)
    else:  # pragma: no cover - Settings validation guarantees one is set
        msg = "no JWT key source configured"
        raise ValueError(msg)
    return JwtTokenVerifier(
        resolver,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        leeway_seconds=settings.jwt_leeway_seconds,
    )


# FastAPI dependencies ---------------------------------------------------------------------

_bearer = HTTPBearer(auto_error=False)

_UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_verifier(request: Request) -> TokenVerifier:
    return cast("TokenVerifier", request.app.state.verifier)


# Sync on purpose: JWKS fetches block, and FastAPI runs sync dependencies in a threadpool.
def get_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    verifier: Annotated[TokenVerifier, Depends(get_verifier)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _UNAUTHENTICATED
    try:
        return verifier.verify(credentials.credentials)
    except AuthenticationError:
        raise _UNAUTHENTICATED from None
    except AuthorizationError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden") from None


def require_role(minimum: Role) -> Callable[[Principal], Principal]:
    """Dependency factory: the caller must hold `minimum` or a higher role.

    Enforced here on the server; hiding a control in the console is not access control.
    """

    def dependency(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
        if not principal.role.at_least(minimum):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
        return principal

    return dependency
