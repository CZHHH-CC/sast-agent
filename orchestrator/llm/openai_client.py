"""OpenAI-compatible provider adapter.

Works against:
  - OpenAI (default base_url)
  - Azure OpenAI (set SAST_OPENAI_BASE_URL)
  - Any OpenAI-compatible endpoint: DeepSeek, Moonshot, Together, Ollama's
    /v1, vLLM, etc.
"""

from __future__ import annotations

import json
import os
from typing import Any

from openai import AsyncOpenAI

from .base import (
    LLMClient,
    LLMResponse,
    Message,
    StopReason,
    ToolCall,
    ToolDef,
)


_STOP_MAP = {
    "stop": StopReason.END_TURN,
    "tool_calls": StopReason.TOOL_USE,
    "length": StopReason.MAX_TOKENS,
    "content_filter": StopReason.ERROR,
}


class OpenAIClient(LLMClient):
    provider = "openai"

    def __init__(
        self,
        *,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self.model = model or os.environ.get("SAST_OPENAI_MODEL", "gpt-4o")
        self._configured_base_url = base_url or os.environ.get("SAST_OPENAI_BASE_URL")
        self.client = AsyncOpenAI(
            api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            base_url=self._configured_base_url,
        )

    def _base_url_looks_official(self) -> bool:
        """Whitelist of base_urls that are known to accept OpenAI's prompt_cache_key
        field. Third-party proxies may 400 on unknown params."""
        url = self._configured_base_url
        if not url:
            return True  # default → api.openai.com
        lowered = url.lower()
        return "api.openai.com" in lowered or "azure.com" in lowered

    def _tools_to_openai(self, tools: list[ToolDef]) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema,
                },
            }
            for t in tools
        ]

    def _messages_to_openai(
        self, system: str, messages: list[Message]
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for m in messages:
            if m.role == "system":
                continue
            if m.role == "user":
                # a user message CAN also carry tool results (from our tool loop)
                if m.tool_results:
                    for tr in m.tool_results:
                        out.append({
                            "role": "tool",
                            "tool_call_id": tr.tool_call_id,
                            "content": tr.content,
                        })
                    if m.text:
                        out.append({"role": "user", "content": m.text})
                else:
                    out.append({"role": "user", "content": m.text or ""})
            elif m.role == "assistant":
                entry: dict[str, Any] = {"role": "assistant"}
                if m.text:
                    entry["content"] = m.text
                else:
                    entry["content"] = None
                if m.tool_calls:
                    entry["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": json.dumps(tc.arguments, ensure_ascii=False),
                            },
                        }
                        for tc in m.tool_calls
                    ]
                out.append(entry)
            elif m.role == "tool":
                for tr in m.tool_results:
                    out.append({
                        "role": "tool",
                        "tool_call_id": tr.tool_call_id,
                        "content": tr.content,
                    })
        return out

    async def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        tools: list[ToolDef],
        max_tokens: int = 4096,
        cache_key: str | None = None,
    ) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": self._messages_to_openai(system, messages),
            "max_tokens": max_tokens,
        }
        if tools:
            kwargs["tools"] = self._tools_to_openai(tools)
            kwargs["tool_choice"] = "auto"

        # --- Prompt caching hint --------------------------------------------
        # OpenAI Automatic Prompt Caching (≥1024 token prefix) is free and
        # transparent; `prompt_cache_key` is a routing hint that dramatically
        # improves hit rate when the same role is called many times in a run.
        # Third-party OpenAI-compatible endpoints may not recognize the field,
        # so it is opt-out via SAST_DISABLE_PROMPT_CACHE=1. We also skip it
        # when a non-official base_url is configured unless explicitly enabled
        # via SAST_OPENAI_PROMPT_CACHE_KEY=1, to avoid 400s from strict proxies.
        cache_disabled = os.environ.get("SAST_DISABLE_PROMPT_CACHE") == "1"
        force_cache_key = os.environ.get("SAST_OPENAI_PROMPT_CACHE_KEY") == "1"
        is_official = self._base_url_looks_official()
        if cache_key and not cache_disabled and (is_official or force_cache_key):
            # `extra_body` sends the field as-is; unknown fields on official
            # OpenAI get silently ignored, so it's safe to always include there.
            kwargs["extra_body"] = {"prompt_cache_key": cache_key}

        resp = await self.client.chat.completions.create(**kwargs)
        choice = resp.choices[0]
        raw_msg = choice.message

        tool_calls: list[ToolCall] = []
        for tc in (raw_msg.tool_calls or []):
            args_raw = tc.function.arguments
            try:
                args = json.loads(args_raw) if args_raw else {}
            except json.JSONDecodeError:
                args = {"__raw__": args_raw}
            tool_calls.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args))

        msg = Message(
            role="assistant",
            text=raw_msg.content or None,
            tool_calls=tool_calls,
        )
        stop = _STOP_MAP.get(choice.finish_reason or "stop", StopReason.END_TURN)
        usage_obj = getattr(resp, "usage", None)
        cached = 0
        if usage_obj is not None:
            details = getattr(usage_obj, "prompt_tokens_details", None)
            if details is not None:
                cached = getattr(details, "cached_tokens", 0) or 0
        usage = {
            "input_tokens": getattr(usage_obj, "prompt_tokens", 0) if usage_obj else 0,
            "output_tokens": getattr(usage_obj, "completion_tokens", 0) if usage_obj else 0,
            "cache_read_input_tokens": cached,
            "cache_creation_input_tokens": 0,
        }
        return LLMResponse(message=msg, stop_reason=stop, usage=usage)
