"""JWT verification. No network and no real keys: keys are generated per run."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import SecretStr, ValidationError

from lighthouse.auth import (
    AuthenticationError,
    AuthorizationError,
    JwksKeyResolver,
    JwtTokenVerifier,
    Role,
    StaticKeyResolver,
    build_verifier,
)
from lighthouse.config import Settings, load_settings
from tests.helpers import (
    TEST_AUDIENCE,
    TEST_ISSUER,
    TokenFactory,
    hmac_token,
    public_pem,
    unsigned_token,
)


@pytest.fixture
def factory() -> TokenFactory:
    return TokenFactory.generate()


@pytest.fixture
def verifier(factory: TokenFactory) -> JwtTokenVerifier:
    return JwtTokenVerifier(
        StaticKeyResolver(factory.public_pem),
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
        leeway_seconds=5,
    )


def test_valid_token_yields_principal_from_app_metadata(
    factory: TokenFactory, verifier: JwtTokenVerifier
) -> None:
    tenant_id, user_id = uuid4(), uuid4()
    principal = verifier.verify(factory.token(tenant_id, role="responder", user_id=user_id))
    assert principal.tenant_id == tenant_id
    assert principal.user_id == user_id
    assert principal.role is Role.RESPONDER


def test_expired_token_is_rejected(factory: TokenFactory, verifier: JwtTokenVerifier) -> None:
    claims = factory.claims(tenant_id=uuid4())
    claims["iat"] -= 3600
    claims["exp"] = claims["iat"] + 60
    with pytest.raises(AuthenticationError):
        verifier.verify(factory.sign(claims))


@pytest.mark.parametrize("claim", ["exp", "iat", "sub", "aud", "iss"])
def test_missing_registered_claim_is_rejected(
    factory: TokenFactory, verifier: JwtTokenVerifier, claim: str
) -> None:
    claims = factory.claims(tenant_id=uuid4())
    del claims[claim]
    with pytest.raises(AuthenticationError):
        verifier.verify(factory.sign(claims))


def test_wrong_audience_is_rejected(factory: TokenFactory, verifier: JwtTokenVerifier) -> None:
    claims = factory.claims(tenant_id=uuid4())
    claims["aud"] = "some-other-service"
    with pytest.raises(AuthenticationError):
        verifier.verify(factory.sign(claims))


def test_wrong_issuer_is_rejected(factory: TokenFactory, verifier: JwtTokenVerifier) -> None:
    claims = factory.claims(tenant_id=uuid4())
    claims["iss"] = "https://attacker.example.invalid/auth/v1"
    with pytest.raises(AuthenticationError):
        verifier.verify(factory.sign(claims))


def test_bad_signature_is_rejected(factory: TokenFactory, verifier: JwtTokenVerifier) -> None:
    other_key = ec.generate_private_key(ec.SECP256R1())
    token = factory.sign(factory.claims(tenant_id=uuid4()), key=other_key)
    with pytest.raises(AuthenticationError):
        verifier.verify(token)


def test_tampered_payload_is_rejected(factory: TokenFactory, verifier: JwtTokenVerifier) -> None:
    token = factory.token(uuid4(), role="viewer")
    header, _, signature = token.split(".")
    forged_claims = factory.claims(tenant_id=uuid4(), role="admin")
    forged_payload = unsigned_token(forged_claims).split(".")[1]
    with pytest.raises(AuthenticationError):
        verifier.verify(f"{header}.{forged_payload}.{signature}")


@pytest.mark.parametrize("alg", ["none", "None", "NONE", ""])
def test_alg_none_is_rejected(factory: TokenFactory, verifier: JwtTokenVerifier, alg: str) -> None:
    with pytest.raises(AuthenticationError):
        verifier.verify(unsigned_token(factory.claims(tenant_id=uuid4()), alg=alg))


def test_hs256_signed_with_public_key_is_rejected(
    factory: TokenFactory, verifier: JwtTokenVerifier
) -> None:
    # Classic algorithm confusion: use the published public key as an HMAC secret.
    token = hmac_token(factory.claims(tenant_id=uuid4()), factory.public_pem.encode())
    with pytest.raises(AuthenticationError):
        verifier.verify(token)


def test_static_key_pins_algorithm(factory: TokenFactory) -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rs_token = jwt.encode(factory.claims(tenant_id=uuid4()), rsa_key, algorithm="RS256")
    resolver = StaticKeyResolver(factory.public_pem)  # an EC key: ES256 only
    with pytest.raises(AuthenticationError):
        resolver.resolve(rs_token)


def test_rs256_with_rsa_key_is_accepted(factory: TokenFactory) -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = (
        rsa_key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    verifier = JwtTokenVerifier(
        StaticKeyResolver(pem), issuer=TEST_ISSUER, audience=TEST_AUDIENCE
    )
    tenant_id = uuid4()
    token = jwt.encode(factory.claims(tenant_id=tenant_id), rsa_key, algorithm="RS256")
    assert verifier.verify(token).tenant_id == tenant_id


def test_weak_or_unsupported_static_keys_are_refused() -> None:
    small_rsa = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    pem = (
        small_rsa.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    with pytest.raises(ValueError, match="unsupported public key"):
        StaticKeyResolver(pem)
    p384 = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(ValueError, match="unsupported public key"):
        StaticKeyResolver(public_pem(p384))


def test_missing_tenant_in_app_metadata_is_rejected(
    factory: TokenFactory, verifier: JwtTokenVerifier
) -> None:
    with pytest.raises(AuthorizationError):
        verifier.verify(factory.sign(factory.claims(tenant_id=None)))


def test_tenant_only_in_user_metadata_is_rejected(
    factory: TokenFactory, verifier: JwtTokenVerifier
) -> None:
    claims = factory.claims(tenant_id=None, role="admin")
    claims["user_metadata"] = {"tenant_id": str(uuid4()), "role": "admin"}
    with pytest.raises(AuthorizationError):
        verifier.verify(factory.sign(claims))


def test_user_metadata_cannot_override_app_metadata(
    factory: TokenFactory, verifier: JwtTokenVerifier
) -> None:
    tenant_id = uuid4()
    claims = factory.claims(tenant_id=tenant_id, role="viewer")
    claims["user_metadata"] = {"tenant_id": str(uuid4()), "role": "admin"}
    principal = verifier.verify(factory.sign(claims))
    assert principal.tenant_id == tenant_id
    assert principal.role is Role.VIEWER


@pytest.mark.parametrize(
    "app_metadata",
    [
        None,
        "tenant",
        {"tenant_id": "not-a-uuid", "role": "viewer"},
        {"tenant_id": 12345, "role": "viewer"},
        {"tenant_id": "TENANT", "role": "viewer"},
        {"role": "viewer"},
        {"tenant_id": "00000000-0000-4000-8000-000000000001"},
        {"tenant_id": "00000000-0000-4000-8000-000000000001", "role": "superadmin"},
        {"tenant_id": "00000000-0000-4000-8000-000000000001", "role": ["admin"]},
    ],
)
def test_malformed_app_metadata_is_rejected(
    factory: TokenFactory, verifier: JwtTokenVerifier, app_metadata: Any
) -> None:
    claims = factory.claims(tenant_id=uuid4())
    claims["app_metadata"] = app_metadata
    with pytest.raises(AuthorizationError):
        verifier.verify(factory.sign(claims))


@pytest.mark.parametrize("sub", ["", "not-a-uuid", 42])
def test_invalid_subject_is_rejected(
    factory: TokenFactory, verifier: JwtTokenVerifier, sub: object
) -> None:
    claims = factory.claims(tenant_id=uuid4())
    claims["sub"] = sub
    with pytest.raises(AuthenticationError):
        verifier.verify(factory.sign(claims))


def test_anonymous_user_is_rejected(factory: TokenFactory, verifier: JwtTokenVerifier) -> None:
    claims = factory.claims(tenant_id=uuid4())
    claims["is_anonymous"] = True
    with pytest.raises(AuthorizationError):
        verifier.verify(factory.sign(claims))


@pytest.mark.parametrize("token", ["", "garbage", "a.b.c", "x" * 9000])
def test_garbage_tokens_are_rejected(verifier: JwtTokenVerifier, token: str) -> None:
    with pytest.raises(AuthenticationError):
        verifier.verify(token)


def test_role_ordering() -> None:
    assert Role.ADMIN.at_least(Role.RESPONDER)
    assert Role.RESPONDER.at_least(Role.ANALYST)
    assert Role.ANALYST.at_least(Role.VIEWER)
    assert Role.VIEWER.at_least(Role.VIEWER)
    assert not Role.VIEWER.at_least(Role.ANALYST)
    assert not Role.RESPONDER.at_least(Role.ADMIN)


# JWKS ------------------------------------------------------------------------------------


class _OfflineJwksClient(jwt.PyJWKClient):
    """PyJWKClient with the HTTP fetch replaced by a fixed key set."""

    def __init__(self, jwks: dict[str, Any]) -> None:
        super().__init__("https://auth.example.invalid/auth/v1/.well-known/jwks.json")
        self._jwks = jwks

    def fetch_data(self) -> Any:
        return self._jwks


def _jwk(factory: TokenFactory) -> dict[str, Any]:
    jwk: dict[str, Any] = json.loads(
        jwt.algorithms.ECAlgorithm.to_jwk(factory.private_key.public_key())
    )
    jwk.update({"kid": factory.kid, "alg": "ES256", "use": "sig"})
    return jwk


def _jwks_verifier(jwks: dict[str, Any]) -> JwtTokenVerifier:
    resolver = JwksKeyResolver("unused", client=_OfflineJwksClient(jwks))
    return JwtTokenVerifier(resolver, issuer=TEST_ISSUER, audience=TEST_AUDIENCE)


def test_jwks_resolves_key_by_kid(factory: TokenFactory) -> None:
    verifier = _jwks_verifier({"keys": [_jwk(factory)]})
    tenant_id = uuid4()
    assert verifier.verify(factory.token(tenant_id)).tenant_id == tenant_id


def test_jwks_unknown_kid_is_rejected(factory: TokenFactory) -> None:
    verifier = _jwks_verifier({"keys": [_jwk(factory)]})
    token = factory.sign(factory.claims(tenant_id=uuid4()), kid="unknown-kid")
    with pytest.raises(AuthenticationError):
        verifier.verify(token)


def test_jwks_symmetric_key_cannot_be_used(factory: TokenFactory) -> None:
    secret = b"example-shared-secret-for-tests-only-0123456789"
    oct_jwk = json.loads(jwt.algorithms.HMACAlgorithm.to_jwk(secret))
    oct_jwk.update({"kid": "oct-key", "alg": "HS256"})
    verifier = _jwks_verifier({"keys": [_jwk(factory), oct_jwk]})
    claims = factory.claims(tenant_id=uuid4())
    token = jwt.encode(claims, secret, algorithm="HS256", headers={"kid": "oct-key"})
    with pytest.raises(AuthenticationError):
        verifier.verify(token)
    # Same, but the header claims an allowed algorithm: the key's own type must still
    # disqualify it.
    _, payload, signature = token.split(".")
    es_header_with_kid = jwt.utils.base64url_encode(
        json.dumps({"alg": "ES256", "typ": "JWT", "kid": "oct-key"}).encode()
    ).decode()
    with pytest.raises(AuthenticationError):
        verifier.verify(f"{es_header_with_kid}.{payload}.{signature}")


def test_jwks_header_algorithm_must_match_key(factory: TokenFactory) -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = _jwks_verifier({"keys": [_jwk(factory)]})
    # Claims an RSA algorithm but points at the EC key.
    token = jwt.encode(
        factory.claims(tenant_id=uuid4()), rsa_key, algorithm="RS256", headers={"kid": factory.kid}
    )
    with pytest.raises(AuthenticationError):
        verifier.verify(token)


# Settings --------------------------------------------------------------------------------


def _settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "database_url": SecretStr("postgresql://example.invalid/db"),
        "jwt_issuer": TEST_ISSUER,
    }
    values.update(overrides)
    return Settings.model_validate(values)


def test_settings_require_exactly_one_key_source(factory: TokenFactory) -> None:
    with pytest.raises(ValidationError):
        _settings()
    with pytest.raises(ValidationError):
        _settings(
            jwt_public_key=factory.public_pem,
            jwt_jwks_url="https://auth.example.invalid/jwks.json",
        )


def test_settings_require_https_jwks() -> None:
    with pytest.raises(ValidationError):
        _settings(jwt_jwks_url="http://auth.example.invalid/jwks.json")


def test_build_verifier_from_settings(factory: TokenFactory) -> None:
    verifier = build_verifier(_settings(jwt_public_key=factory.public_pem))
    tenant_id = uuid4()
    assert verifier.verify(factory.token(tenant_id)).tenant_id == tenant_id
    jwks_verifier = build_verifier(_settings(jwt_jwks_url="https://auth.example.invalid/jwks.json"))
    assert isinstance(jwks_verifier, JwtTokenVerifier)


def test_settings_read_from_lh_environment(
    monkeypatch: pytest.MonkeyPatch, factory: TokenFactory
) -> None:
    monkeypatch.setenv("LH_DATABASE_URL", "postgresql://user:placeholder-pw@db.invalid/db")
    monkeypatch.setenv("LH_JWT_ISSUER", TEST_ISSUER)
    monkeypatch.setenv("LH_JWT_PUBLIC_KEY", factory.public_pem)
    monkeypatch.setenv("LH_DEV", "1")
    settings = load_settings()
    assert settings.dev is True
    assert settings.database_url.get_secret_value().endswith("@db.invalid/db")
    # The URL carries the database password; it must not appear in reprs or logs.
    assert "placeholder-pw" not in repr(settings)
