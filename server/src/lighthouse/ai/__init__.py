"""Model-provider code. The only package that imports the Anthropic SDK (CLAUDE.md
"Using the Claude API"): everything else depends on `lighthouse.triage.TriageModel`.
"""

from __future__ import annotations

from lighthouse.ai.triage_model import AnthropicTriageModel, build_triage_model

__all__ = ["AnthropicTriageModel", "build_triage_model"]
