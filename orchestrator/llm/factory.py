"""Select and instantiate an LLMClient based on env / config.

Selection order:
  1. explicit `provider=` argument
  2. SAST_PROVIDER env var ("anthropic" | "openai")
  3. fallback: anthropic if ANTHROPIC_API_KEY set, else openai
"""

from __future__ import annotations

import os

from .base import LLMClient


def get_default_provider() -> str:
    p = os.environ.get("SAST_PROVIDER")
    if p:
        return p.lower()
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    # default to anthropic — a missing key will raise clearly at call time
    return "anthropic"


def build_client(
    provider: str | None = None,
    *,
    model: str | None = None,
) -> LLMClient:
    prov = (provider or get_default_provider()).lower()

    if prov == "anthropic":
        from .anthropic_client import AnthropicClient
        return AnthropicClient(model=model)
    if prov in ("openai", "openai-compatible", "deepseek", "moonshot", "ollama"):
        from .openai_client import OpenAIClient
        return OpenAIClient(model=model)

    raise ValueError(f"Unknown provider: {prov!r}. Use 'anthropic' or 'openai'.")
