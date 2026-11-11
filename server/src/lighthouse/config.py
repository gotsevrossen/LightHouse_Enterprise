from __future__ import annotations

from typing import Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from `LH_*` environment variables.

    Secrets (the database URL carries the password) arrive only as runtime environment
    variables of the container; no `.env` file is read, so a stray file in the image or
    working directory cannot inject configuration.
    """

    model_config = SettingsConfigDict(env_prefix="LH_", extra="ignore", frozen=True)

    # Enables the OpenAPI schema and interactive docs. Off in production: the schema is a
    # free map of the attack surface.
    dev: bool = False

    database_url: SecretStr
    db_pool_min_size: int = Field(default=1, ge=0, le=100)
    db_pool_max_size: int = Field(default=10, ge=1, le=100)
    # Set to 0 when connecting through a transaction-mode pooler (Supavisor port 6543),
    # which cannot keep prepared statements across transactions.
    db_statement_cache_size: int = Field(default=100, ge=0)
    db_command_timeout_seconds: float = Field(default=30.0, gt=0)

    jwt_issuer: str = Field(min_length=1)
    jwt_audience: str = Field(default="authenticated", min_length=1)
    # Exactly one of these. Only asymmetric keys are accepted: with a shared HS256 secret,
    # anyone holding it (every service that verifies tokens) could mint tokens.
    jwt_jwks_url: str | None = None
    jwt_public_key: str | None = None
    jwt_leeway_seconds: int = Field(default=30, ge=0, le=300)

    @model_validator(mode="after")
    def _check_key_source(self) -> Self:
        if (self.jwt_jwks_url is None) == (self.jwt_public_key is None):
            msg = "set exactly one of LH_JWT_JWKS_URL and LH_JWT_PUBLIC_KEY"
            raise ValueError(msg)
        # Fetching signing keys over plain HTTP would let anyone on the path swap them.
        if self.jwt_jwks_url is not None and not self.jwt_jwks_url.startswith("https://"):
            msg = "LH_JWT_JWKS_URL must use https"
            raise ValueError(msg)
        if self.db_pool_min_size > self.db_pool_max_size:
            msg = "LH_DB_POOL_MIN_SIZE must not exceed LH_DB_POOL_MAX_SIZE"
            raise ValueError(msg)
        return self


def load_settings() -> Settings:
    # Required fields come from the environment, which pyright cannot see.
    return Settings()  # pyright: ignore[reportCallIssue]
