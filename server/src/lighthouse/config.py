from __future__ import annotations

from typing import Final, Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# SDK retries for 408/409/429/5xx and connection errors, with backoff. Fixed rather than
# configurable: it multiplies worst-case latency and spend, so changing it is a code review.
TRIAGE_MAX_RETRIES: Final = 2
# Chat is interactive: a person is waiting, so one quick retry of a failed connection or a
# 429/5xx before the answer starts is worth it, two with backoff is not.
CHAT_MAX_RETRIES: Final = 1

type Effort = Literal["low", "medium", "high", "xhigh", "max"]


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

    # --- Triage with Claude (CLAUDE.md "Using the Claude API") ---------------------------
    # The Anthropic API key is NOT a setting here: the SDK reads ANTHROPIC_API_KEY from the
    # container's runtime secrets itself, so the key never passes through this object, its
    # repr, or a validation error. Without a key the server still starts and serves;
    # triage then stores alerts as needing human review (reason `model_unavailable`).
    triage_enabled: bool = True
    # Model IDs come from configuration. Moving to a cheaper model is the owner's decision,
    # taken on eval results (docs/PLAN.md 2.6).
    triage_model: str = Field(
        default="claude-opus-5-5", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][\w.:-]*$"
    )
    # Explicit, because the default differs by model (Opus 5.5 defaults to "medium",
    # others to "high") and a silent change of model must not silently change spend.
    # "medium": triage is a high-volume classification-and-explanation route, where the
    # skill guidance puts medium as the step-down that holds quality; the severity floor
    # bounds the downside of a weaker judgement. Raising it needs an eval result.
    triage_effort: Effort = "medium"
    # Thinking counts against max_tokens. 16k keeps a non-streaming request well inside
    # SDK HTTP timeouts while leaving room for thinking plus a short structured answer.
    triage_max_tokens: int = Field(default=16_000, ge=1_024, le=32_000)
    # Per HTTP attempt. The SDK retries 429/5xx/connection errors TRIAGE_MAX_RETRIES times,
    # so one triage can take up to `triage_deadline_seconds` of wall clock.
    triage_timeout_seconds: float = Field(default=120.0, gt=0, le=600)
    # Tokens (input + output + cache read + cache write) one tenant may spend per UTC day,
    # triage and chat together (every lh.model_usage row counts). 0 means "no model calls",
    # never "unlimited": there is no unlimited setting.
    triage_daily_token_budget_per_tenant: int = Field(default=2_000_000, ge=0, le=10**12)

    # --- "Ask LightHouse" chat (Phase 2) -----------------------------------------------
    # Same key handling as triage: no key setting here; without a credential chat reports
    # itself unavailable and the rest of the server works.
    chat_enabled: bool = True
    chat_model: str = Field(
        default="claude-opus-5-5", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][\w.:-]*$"
    )
    # "low": chat is interactive, so time to first token matters, and the skill guidance
    # puts chat among the routes that do well at low effort (on Opus 5.5, effort is the only
    # thinking control and low keeps thinking short). Chat explains; it decides nothing:
    # it cannot change an alert, its severity or its status. Raising it needs an eval
    # result, like the triage effort. Explicit because model defaults differ.
    chat_effort: Effort = "low"
    # Per answer, thinking included. A cost ceiling (a stolen session should not be able to
    # buy long essays) rather than a timeout guard: chat always streams.
    chat_max_tokens: int = Field(default=8_000, ge=1_024, le=32_000)
    # Wall-clock limit for one answer, from the request to the last streamed event, and
    # the SDK's per-read timeout. An answer still running at the deadline is cut off.
    chat_timeout_seconds: float = Field(default=90.0, gt=0, le=600)
    # Per signed-in user, counted in Postgres so the limit holds across server replicas.
    # At least 1: turning chat off is `chat_enabled=false`, never a zero that could be
    # read as "no limit".
    chat_requests_per_minute_per_user: int = Field(default=10, ge=1, le=600)

    @property
    def triage_deadline_seconds(self) -> float:
        """Upper bound on one triage call, SDK retries included, plus a small margin."""
        return self.triage_timeout_seconds * (TRIAGE_MAX_RETRIES + 1) + 15.0

    @property
    def triage_claim_lease_seconds(self) -> float:
        """How long an alert's triage claim blocks other workers before it is abandoned."""
        return self.triage_deadline_seconds + 60.0

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
