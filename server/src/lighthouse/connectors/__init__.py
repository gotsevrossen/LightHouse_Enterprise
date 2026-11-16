"""Connectors: read alerts from customers' security services and normalise them.

Each connector implements `base.Connector`. Connectors only read; they never write to a
customer's tenant (write actions are a separate, opt-in consent in a later phase).
"""

from __future__ import annotations

from lighthouse.connectors.base import (
    Connector,
    ConnectorAuthError,
    ConnectorCredential,
    ConnectorError,
    ConnectorPermanentError,
    ConnectorThrottledError,
    ConnectorTransientError,
    CredentialProvider,
    FetchResult,
    InMemoryCredentialProvider,
)

__all__ = [
    "Connector",
    "ConnectorAuthError",
    "ConnectorCredential",
    "ConnectorError",
    "ConnectorPermanentError",
    "ConnectorThrottledError",
    "ConnectorTransientError",
    "CredentialProvider",
    "FetchResult",
    "InMemoryCredentialProvider",
]
