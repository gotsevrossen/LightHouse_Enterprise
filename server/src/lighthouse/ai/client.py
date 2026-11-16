"""The one place that builds the Anthropic client.

Security boundary: the Anthropic API key (CLAUDE.md rule 1 and "Secrets").

- The key is resolved by the SDK's normal credential chain (ANTHROPIC_API_KEY in the
  container's runtime secrets). It is never read, copied, logged or stored by our code:
  this module only asks whether *some* credential was found.
- A missing credential is a normal state, not an error: the server starts and serves,
  and triage returns "needs human review" with reason `model_unavailable`.
- Nothing outside `lighthouse.ai` imports `anthropic`; the rest of the server sees only
  the `TriageModel` interface, so a provider change (Claude on Microsoft Foundry) is a
  change here, not across the codebase.
"""

from __future__ import annotations

import logging

import anthropic

from lighthouse.config import TRIAGE_MAX_RETRIES, Settings

logger = logging.getLogger(__name__)


def build_client(
    settings: Settings, *, http_client: anthropic.DefaultAsyncHttpxClient | None = None
) -> anthropic.AsyncAnthropic | None:
    """Return a client, or None when triage is disabled or no credential is available.

    `http_client` exists for tests, which inject a transport that answers locally; it
    must never be used to point production traffic elsewhere.
    """
    if not settings.triage_enabled:
        return None
    try:
        client = anthropic.AsyncAnthropic(
            timeout=settings.triage_timeout_seconds,
            max_retries=TRIAGE_MAX_RETRIES,
            http_client=http_client,
        )
    except anthropic.AnthropicError as exc:
        # The message could describe the credential source; only the class is logged.
        logger.warning("anthropic client unavailable: %s", type(exc).__name__)
        return None
    # The constructor succeeds without credentials and fails on the first request
    # instead. Check up front so "no key" is a clean, cheap `model_unavailable`.
    if client.api_key is None and client.auth_token is None and client.credentials is None:
        logger.warning("anthropic client unavailable: no credentials configured")
        return None
    return client
