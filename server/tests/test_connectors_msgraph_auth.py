"""Certificate-based client credentials for Microsoft Graph. No network: every response
comes from an httpx MockTransport, and every key is generated for this run."""

from __future__ import annotations

import asyncio
import base64
import hashlib
from typing import Any
from urllib.parse import parse_qs
from uuid import UUID, uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pydantic import SecretStr, ValidationError

from lighthouse.connectors.base import (
    ConnectorAuthError,
    ConnectorCredential,
    ConnectorPermanentError,
    ConnectorThrottledError,
    ConnectorTransientError,
    InMemoryCredentialProvider,
)
from lighthouse.connectors.msgraph_auth import (
    ASSERTION_LIFETIME_SECONDS,
    CLIENT_ASSERTION_TYPE,
    GRAPH_SCOPE,
    REFRESH_MARGIN_SECONDS,
    AccessToken,
    GraphTokenProvider,
    build_client_assertion,
    entra_tenant_uuid,
    token_url,
)
from tests.connector_helpers import (
    RecordingTransport,
    TestCertificate,
    json_response,
    make_certificate,
    make_credential,
    random_token_value,
)

LEAK_MARKER = "do-not-leak-" + "x" * 8


@pytest.fixture(scope="module")
def cert() -> TestCertificate:
    return make_certificate()


class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _form(request: httpx.Request) -> dict[str, str]:
    parsed = parse_qs(request.content.decode(), strict_parsing=True)
    return {key: values[0] for key, values in parsed.items()}


def _token_ok(lifetime: int = 3599) -> tuple[RecordingTransport, list[str]]:
    issued: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        value = random_token_value()
        issued.append(value)
        return json_response(
            200, {"token_type": "Bearer", "expires_in": lifetime, "access_token": value}
        )

    return RecordingTransport(handler), issued


# Tenant id validation --------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "evil.example/x",
        "common",
        "organizations",
        "../../other/oauth2/v2.0/token?x=",
        "{6f1b7b0e-0000-4000-8000-000000000001}",
        "urn:uuid:6f1b7b0e-0000-4000-8000-000000000001",
        "6f1b7b0e000040008000000000000001",
        "6f1b7b0e-0000-4000-8000-000000000001/../x",
        "6f1b7b0e-0000-4000-8000-000000000001\n",
        "",
    ],
)
def test_tenant_id_injection_rejected(value: str) -> None:
    with pytest.raises(ConnectorPermanentError):
        token_url(value)
    with pytest.raises(ConnectorPermanentError):
        entra_tenant_uuid(value)


def test_token_url_uses_canonical_uuid() -> None:
    directory = UUID("6F1B7B0E-0000-4000-8000-000000000001")
    assert token_url(directory) == (
        "https://login.microsoftonline.com/6f1b7b0e-0000-4000-8000-000000000001/oauth2/v2.0/token"
    )
    assert token_url(str(directory).upper()) == token_url(directory)


def test_credential_refuses_non_uuid_directory(cert: TestCertificate) -> None:
    with pytest.raises(ValidationError):
        ConnectorCredential(
            client_id=uuid4(),
            entra_tenant_id="evil.example/x",  # pyright: ignore[reportArgumentType]
            private_key_pem=SecretStr(cert.private_pem),
            certificate_thumbprint_sha256=cert.thumbprint_sha256,
        )


@pytest.mark.parametrize("thumbprint", ["", "abc", "A" * 44, "+" * 43, "A" * 42 + "="])
def test_credential_refuses_malformed_thumbprint(cert: TestCertificate, thumbprint: str) -> None:
    with pytest.raises(ValidationError):
        ConnectorCredential(
            client_id=uuid4(),
            entra_tenant_id=uuid4(),
            private_key_pem=SecretStr(cert.private_pem),
            certificate_thumbprint_sha256=thumbprint,
        )


# Assertion -------------------------------------------------------------------------------


def test_assertion_headers_claims_and_signature(cert: TestCertificate) -> None:
    credential = make_credential(cert)
    now = 1_800_000_000.0
    assertion = build_client_assertion(credential, now=now)

    header = jwt.get_unverified_header(assertion)
    assert header["alg"] == "PS256"
    assert header["typ"] == "JWT"
    der = cert.certificate.public_bytes(serialization.Encoding.DER)
    expected = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode().rstrip("=")
    assert header["x5t#S256"] == expected
    assert "x5t" not in header  # the SHA-1 thumbprint is not what Entra asks for

    audience = token_url(credential.entra_tenant_id)
    claims: dict[str, Any] = jwt.decode(
        assertion,
        cert.key.public_key(),
        algorithms=["PS256"],
        audience=audience,
        options={"verify_exp": False, "verify_nbf": False, "verify_iat": False},
    )
    assert claims["iss"] == claims["sub"] == str(credential.client_id)
    assert claims["aud"] == audience
    assert claims["nbf"] == claims["iat"] == int(now)
    assert claims["exp"] - claims["nbf"] == ASSERTION_LIFETIME_SECONDS
    UUID(claims["jti"])
    assert build_client_assertion(credential, now=now) != assertion  # fresh jti


def test_assertion_does_not_verify_with_another_key(cert: TestCertificate) -> None:
    credential = make_credential(cert)
    assertion = build_client_assertion(credential, now=1_800_000_000.0)
    other = make_certificate()
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(
            assertion,
            other.key.public_key(),
            algorithms=["PS256"],
            options={"verify_aud": False, "verify_exp": False, "verify_nbf": False},
        )


def test_non_rsa_or_short_key_refused(cert: TestCertificate) -> None:
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    for pem in (ec_pem, make_certificate(key_size=1024).private_pem, "not a key"):
        credential = make_credential(cert).model_copy(update={"private_key_pem": SecretStr(pem)})
        with pytest.raises(ConnectorPermanentError) as caught:
            build_client_assertion(credential, now=0)
        assert "PRIVATE KEY" not in str(caught.value)
        assert caught.value.__cause__ is None


def test_secrets_do_not_appear_in_reprs(cert: TestCertificate) -> None:
    credential = make_credential(cert)
    assert "PRIVATE KEY" not in repr(credential)
    assert "PRIVATE KEY" not in str(credential)
    value = random_token_value()
    token = AccessToken(value, expires_at=0)
    assert value not in repr(token)
    assert value not in str(token)
    assert value not in f"{token}"
    provider = InMemoryCredentialProvider({"vault:test-ref": credential})
    assert "PRIVATE KEY" not in repr(provider)


# Token requests --------------------------------------------------------------------------


async def test_token_request_shape(cert: TestCertificate) -> None:
    credential = make_credential(cert)
    transport, issued = _token_ok()
    async with transport.client() as http:
        token = await GraphTokenProvider(http).get_token(credential)
    assert token.reveal() == issued[0]
    (request,) = transport.requests
    assert request.method == "POST"
    assert str(request.url) == token_url(credential.entra_tenant_id)
    form = _form(request)
    assert form["grant_type"] == "client_credentials"
    assert form["scope"] == GRAPH_SCOPE
    assert form["client_id"] == str(credential.client_id)
    assert form["client_assertion_type"] == CLIENT_ASSERTION_TYPE
    assert "client_secret" not in form
    header = jwt.get_unverified_header(form["client_assertion"])
    assert header["x5t#S256"] == cert.thumbprint_sha256
    assert "authorization" not in request.headers


async def test_token_cached_until_refresh_margin(cert: TestCertificate) -> None:
    credential = make_credential(cert)
    transport, issued = _token_ok(lifetime=3600)
    clock = Clock()
    async with transport.client() as http:
        provider = GraphTokenProvider(http, clock=clock)
        first = await provider.get_token(credential)
        clock.now += 3600 - REFRESH_MARGIN_SECONDS - 1
        assert (await provider.get_token(credential)).reveal() == first.reveal()
        assert len(transport.requests) == 1
        clock.now += 2  # now inside the refresh margin
        second = await provider.get_token(credential)
    assert second.reveal() == issued[1] != first.reveal()
    assert len(transport.requests) == 2


async def test_cache_is_per_directory_and_client(cert: TestCertificate) -> None:
    one = make_credential(cert)
    other_directory = make_credential(cert, client_id=one.client_id)
    other_client = make_credential(cert, directory=one.entra_tenant_id)
    transport, _ = _token_ok()
    async with transport.client() as http:
        provider = GraphTokenProvider(http)
        tokens = {
            (await provider.get_token(credential)).reveal()
            for credential in (one, other_directory, other_client, one)
        }
    assert len(tokens) == 3
    assert len(transport.requests) == 3


async def test_concurrent_requests_share_one_token(cert: TestCertificate) -> None:
    credential = make_credential(cert)
    transport, _ = _token_ok()
    async with transport.client() as http:
        provider = GraphTokenProvider(http)
        tokens = await asyncio.gather(*(provider.get_token(credential) for _ in range(10)))
    assert len({token.reveal() for token in tokens}) == 1
    assert len(transport.requests) == 1


async def test_invalidate_forces_new_token(cert: TestCertificate) -> None:
    credential = make_credential(cert)
    transport, _ = _token_ok()
    async with transport.client() as http:
        provider = GraphTokenProvider(http)
        first = await provider.get_token(credential)
        provider.invalidate(credential)
        second = await provider.get_token(credential)
    assert first.reveal() != second.reveal()


@pytest.mark.parametrize(
    ("code", "fragment"),
    [
        (700016, "not present in the customer directory"),
        (700027, "client assertion was rejected"),
        (65001, "admin consent"),
        (9999999, "rejected the token request"),
    ],
)
async def test_aadsts_error_mapped_without_body(
    cert: TestCertificate, code: int, fragment: str
) -> None:
    credential = make_credential(cert)
    body = {
        "error": "invalid_client",
        "error_description": f"AADSTS{code}: {LEAK_MARKER} Trace ID: {uuid4()}",
        "error_codes": [code],
        "trace_id": str(uuid4()),
        "correlation_id": LEAK_MARKER,
    }
    transport = RecordingTransport(lambda _: json_response(400, body))
    async with transport.client() as http:
        with pytest.raises(ConnectorAuthError) as caught:
            await GraphTokenProvider(http).get_token(credential)
    error = caught.value
    assert error.aadsts_code == code
    assert f"AADSTS{code}" in str(error)
    assert fragment in str(error)
    assert LEAK_MARKER not in str(error)
    assert LEAK_MARKER not in repr(error)
    assert "invalid_client" not in str(error)


@pytest.mark.parametrize(
    "body",
    [b"<html>not json</html>", b"[]", b'{"error_codes": "x"}', b'{"error_codes": [true]}'],
)
async def test_unparseable_error_body_still_auth_error(cert: TestCertificate, body: bytes) -> None:
    transport = RecordingTransport(lambda _: httpx.Response(401, content=body))
    async with transport.client() as http:
        with pytest.raises(ConnectorAuthError) as caught:
            await GraphTokenProvider(http).get_token(make_credential(cert))
    assert caught.value.aadsts_code is None


async def test_token_endpoint_throttling(cert: TestCertificate) -> None:
    transport = RecordingTransport(
        lambda _: httpx.Response(429, headers={"Retry-After": "17"}, content=b"slow down")
    )
    async with transport.client() as http:
        with pytest.raises(ConnectorThrottledError) as caught:
            await GraphTokenProvider(http).get_token(make_credential(cert))
    assert caught.value.retry_after_seconds == 17


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, content=b"oops"),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3599}),
        httpx.Response(200, json={"token_type": "mac", "expires_in": 3599, "access_token": "x"}),
        httpx.Response(200, json={"token_type": "Bearer", "expires_in": 5, "access_token": "x"}),
        httpx.Response(200, json={"token_type": "Bearer", "expires_in": 10**9, "access_token": "x"}),
    ],
    ids=["5xx", "not-json", "no-token", "wrong-type", "too-short", "too-long"],
)
async def test_broken_token_responses_are_transient(
    cert: TestCertificate, response: httpx.Response
) -> None:
    transport = RecordingTransport(lambda _: response)
    async with transport.client() as http:
        with pytest.raises(ConnectorTransientError):
            await GraphTokenProvider(http).get_token(make_credential(cert))


async def test_redirect_is_not_followed(cert: TestCertificate) -> None:
    transport = RecordingTransport(
        lambda _: httpx.Response(302, headers={"Location": "https://login.example.invalid/x"})
    )
    async with transport.client() as http:
        with pytest.raises(ConnectorPermanentError):
            await GraphTokenProvider(http).get_token(make_credential(cert))
    assert transport.hosts == ["login.microsoftonline.com"]


async def test_network_error_is_transient_with_fixed_message(cert: TestCertificate) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        msg = f"connection refused to {request.url}"
        raise httpx.ConnectError(msg, request=request)

    async with RecordingTransport(handler).client() as http:
        with pytest.raises(ConnectorTransientError) as caught:
            await GraphTokenProvider(http).get_token(make_credential(cert))
    assert str(caught.value) == "network error"


def test_in_memory_provider_refuses_bad_refs(cert: TestCertificate) -> None:
    with pytest.raises(ConnectorPermanentError):
        InMemoryCredentialProvider({"-----BEGIN PRIVATE KEY-----": make_credential(cert)})


async def test_in_memory_provider_lookup(cert: TestCertificate) -> None:
    credential = make_credential(cert)
    provider = InMemoryCredentialProvider({"vault:known": credential})
    assert await provider.get("vault:known") is credential
    with pytest.raises(ConnectorPermanentError):
        await provider.get("vault:unknown")
    with pytest.raises(ConnectorPermanentError):
        await provider.get("Vault:Known")
