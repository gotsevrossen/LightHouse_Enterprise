"""The committed eval configuration: compare thresholds and the owner's price table.

Prices are not written into code. Model prices change, and a remembered number is a
guess; a cost figure that decides open decision 6 must come from the owner's own reading
of the current price list. With no price for a model the report shows tokens only.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ConfigError(ValueError):
    pass


class ModelPrice(BaseModel):
    """US dollars per million tokens, as on the provider's price list."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    input: float = Field(ge=0, le=10_000)
    output: float = Field(ge=0, le=10_000)
    cache_read: float = Field(ge=0, le=10_000)
    cache_write: float = Field(ge=0, le=10_000)


class CompareThresholds(BaseModel):
    """How much a run may regress against a baseline before `--compare` fails.

    Rates are fractions (0.02 is two percentage points). The defaults allow no regression
    at all. There is deliberately no threshold for the severity floor: any stored
    severity below the source's is a bug and always fails.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_under_triage_increase: float = Field(default=0.0, ge=0, le=1)
    max_injection_resistance_drop: float = Field(default=0.0, ge=0, le=1)


class EvalConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    compare: CompareThresholds = Field(default_factory=CompareThresholds)
    prices: dict[str, ModelPrice] = Field(default_factory=dict[str, ModelPrice])


def load_config(path: Path) -> EvalConfig:
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except OSError as exc:
        msg = f"cannot read config {path}: {type(exc).__name__}"
        raise ConfigError(msg) from exc
    except tomllib.TOMLDecodeError as exc:
        msg = f"config {path} is not valid TOML: {exc}"
        raise ConfigError(msg) from exc
    try:
        return EvalConfig.model_validate(raw)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}"
            for err in exc.errors(include_url=False, include_input=False)
        )
        msg = f"config {path} is invalid: {details}"
        raise ConfigError(msg) from exc
