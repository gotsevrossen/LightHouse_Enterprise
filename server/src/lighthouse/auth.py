"""Bearer-token authentication and server-side role checks.

Security boundary. Threats this module holds against:

- forged tokens (bad signature, `alg: none`, HS256 signed with our public key as the
  HMAC secret, i.e. algorithm confusion);
- replayed or misdirected tokens (expired, wrong audience, wrong issuer);
- a signed-in user choosing their own tenant or role. Supabase lets users edit
  `user_metadata`, so tenant and role are read only from `app_metadata`, which only the
  service can set. A missing or malformed claim is rejected; there is no default tenant;
- a person removed from a tenant, or demoted, who keeps using a still-valid token
  (access tokens live up to an hour, refresh tokens longer), and a token whose claims name
  a tenant the user is not a member of. Every request is checked against `lh.memberships`
  after the token is verified (`get_principal`); the token alone never grants access.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Annotated, Any, Final, Protocol, cast
from uuid import UUID

import asyncpg
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from lighthouse.config import Settings
from lighthouse.db import Pool, get_pool, tenant_transaction

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
    must run off the event loop (FastAPI runs the sync `_token_principal` in a threadpool).
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


def _forbidden() -> HTTPException:
    # One body for every refusal of a valid token: no tenant, no membership, too low a role.
    # It must not reveal whether the named tenant exists or whether the user belongs to it.
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")


def _unavailable() -> HTTPException:
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="unavailable")


def get_verifier(request: Request) -> TokenVerifier:
    return cast("TokenVerifier", request.app.state.verifier)


# Sync on purpose: JWKS fetches block, and FastAPI runs sync dependencies in a threadpool.
# Private: it checks the token only. Routes depend on `get_principal` or `require_role`,
# which add the membership check; depending on this directly would skip it.
def _token_principal(
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
        raise _forbidden() from None


# Membership ------------------------------------------------------------------------------

# No tenant predicate, as in routes/alerts.py: the lookup runs in `tenant_transaction` for
# the token's tenant, and RLS on lh.memberships returns that tenant's rows only. A token
# naming tenant B for a member of tenant A therefore finds no row. (tenant_id, user_id) is
# the primary key, so there is at most one row.
MEMBERSHIP_ROLE_SQL: Final = """
    select role::text from lh.memberships where user_id = $1
"""

# What a failed lookup can raise: a server-side error (including a lost connection), a
# client-side protocol or pool error, a refused socket, or a command timeout. Any of them
# means "membership unknown", which is answered with 503, never with access. Anything not
# listed here propagates as a 500, which is also no access.
_DATABASE_ERRORS: Final = (
    asyncpg.PostgresError,
    asyncpg.InterfaceError,
    asyncpg.InternalClientError,
    OSError,
    TimeoutError,
)


def effective_role(token_role: Role, member_role: Role) -> Role:
    """The lower of the two roles.

    Demotion and removal take effect on the next request, because the database row is
    read every time. Promotion takes effect only once the person's token is refreshed
    with the new claim. So neither a stale token nor a database row alone can raise
    privilege: raising it needs both the identity provider and the database to agree.
    """
    return token_role if token_role.rank <= member_role.rank else member_role


async def get_principal(
    token_principal: Annotated[Principal, Depends(_token_principal)],
    pool: Annotated[Pool, Depends(get_pool)],
) -> Principal:
    """The verified caller, confirmed against `lh.memberships` on every request.

    One query per request, and deliberately no cache of memberships in process memory:
    a cache would bring back the window in which a removed or demoted person keeps their
    access, which is the threat this check exists to close. The route's own queries run
    in a later transaction, so a removal that commits between the two is seen from the
    next request on.
    """
    try:
        async with tenant_transaction(pool, token_principal.tenant_id) as conn:
            raw = await conn.fetchval(MEMBERSHIP_ROLE_SQL, token_principal.user_id)
    except _DATABASE_ERRORS as exc:
        # Fail closed. Class name only: never the token, the query or its parameters.
        logger.warning("membership lookup failed: %s", type(exc).__name__)
        raise _unavailable() from None
    if raw is None:
        raise _forbidden()
    try:
        member_role = Role(cast("str", raw))
    except ValueError:
        # The database enum gained a value this code does not know. A server fault, so
        # the same answer as an unreachable database: no access, and visible to operators.
        logger.error("membership has an unrecognised role")  # noqa: TRY400
        raise _unavailable() from None
    return Principal(
        user_id=token_principal.user_id,
        tenant_id=token_principal.tenant_id,
        role=effective_role(token_principal.role, member_role),
    )


def require_role(minimum: Role) -> Callable[[Principal], Principal]:
    """Dependency factory: the caller must hold `minimum` or a higher role.

    Enforced here on the server; hiding a control in the console is not access control.
    The role compared is the effective one from `get_principal` (membership-checked), not
    the token's claim.
    """

    def dependency(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
        if not principal.role.at_least(minimum):
            raise _forbidden()
        return principal

    return dependency
