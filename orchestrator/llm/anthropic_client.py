"""Anthropic provider adapter."""

from __future__ import annotations

import asyncio
import os
from typing import Any

from anthropic import AsyncAnthropic

from .base import (
    LLMClient,
    LLMResponse,
    Message,
    StopReason,
    ToolCall,
    ToolDef,
)


_STOP_MAP = {
    "end_turn": StopReason.END_TURN,
    "tool_use": StopReason.TOOL_USE,
    "max_tokens": StopReason.MAX_TOKENS,
    "stop_sequence": StopReason.STOP_SEQUENCE,
}


async def _call_with_retry(fn, *, timeout_s: float):
    """Bound a request with a timeout + single transient-error retry. B4."""
    try:
        return await asyncio.wait_for(fn(), timeout=timeout_s)
    except asyncio.TimeoutError:
        await asyncio.sleep(2.0)
        return await asyncio.wait_for(fn(), timeout=timeout_s)
    except Exception as e:
        name = type(e).__name__
        transient = ("APIConnectionError", "APITimeoutError", "InternalServerError",
                     "RateLimitError", "ServiceUnavailableError", "OverloadedError")
        if name in transient:
            await asyncio.sleep(2.0)
            return await asyncio.wait_for(fn(), timeout=timeout_s)
        raise


class AnthropicClient(LLMClient):
    provider = "anthropic"

    def __init__(
        self,
        *,
        model: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.model = model or os.environ.get("SAST_ANTHROPIC_MODEL", "claude-sonnet-4-5")
        self.client = AsyncAnthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))

    def _tools_to_anthropic(self, tools: list[ToolDef]) -> list[dict[str, Any]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in tools
        ]

    def _messages_to_anthropic(self, messages: list[Message]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for m in messages:
            if m.role == "system":
                # Anthropic takes `system` as a separate top-level param
                continue
            if m.role == "assistant":
                blocks: list[dict[str, Any]] = []
                if m.text:
                    blocks.append({"type": "text", "text": m.text})
                for tc in m.tool_calls:
                    blocks.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.arguments,
                    })
                out.append({"role": "assistant", "content": blocks})
            elif m.role == "user":
                blocks = []
                if m.text:
                    blocks.append({"type": "text", "text": m.text})
                for tr in m.tool_results:
                    blocks.append({
                        "type": "tool_result",
                        "tool_use_id": tr.tool_call_id,
                        "content": tr.content,
                        "is_error": tr.is_error,
                    })
                out.append({"role": "user", "content": blocks})
            elif m.role == "tool":
                # normalize into user role for Anthropic
                out.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tr.tool_call_id,
                            "content": tr.content,
                            "is_error": tr.is_error,
                        }
                        for tr in m.tool_results
                    ],
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
        # --- Prompt caching -------------------------------------------------
        # System prompt is the largest stable chunk (role instructions + skill
        # refs, ~10–30K tokens). Mark it as an ephemeral cache breakpoint so
        # subsequent calls within ~5 min reuse it instead of re-billing full
        # input. Tools are also stable across a run — cache the last tool
        # entry, which implicitly caches the entire tools block.
        cache_enabled = os.environ.get("SAST_DISABLE_PROMPT_CACHE") != "1"

        if cache_enabled and system:
            system_param: Any = [{
                "type": "text",
                "text": system,
                "cache_control": {"type": "ephemeral"},
            }]
        else:
            system_param = system

        anth_tools = self._tools_to_anthropic(tools) if tools else []
        if cache_enabled and anth_tools:
            # Mark the last tool as a cache breakpoint → everything up to and
            # including tools is cached.
            anth_tools[-1] = {**anth_tools[-1], "cache_control": {"type": "ephemeral"}}

        # cache_key is advisory for Anthropic (no native param); it is consumed
        # by OpenAI-compatible endpoints. Accept silently here.
        _ = cache_key

        timeout_s = float(os.environ.get("SAST_LLM_TIMEOUT_S", "120"))
        resp = await _call_with_retry(
            lambda: self.client.messages.create(
                model=self.model,
                system=system_param,
                max_tokens=max_tokens,
                messages=self._messages_to_anthropic(messages),
                tools=anth_tools,
            ),
            timeout_s=timeout_s,
        )

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in resp.content:
            btype = getattr(block, "type", None)
            if btype == "text":
                text_parts.append(getattr(block, "text", ""))
            elif btype == "tool_use":
                tool_calls.append(ToolCall(
                    id=getattr(block, "id"),
                    name=getattr(block, "name"),
                    arguments=dict(getattr(block, "input", {}) or {}),
                ))

        msg = Message(
            role="assistant",
            text="\n".join(text_parts) if text_parts else None,
            tool_calls=tool_calls,
        )
        stop = _STOP_MAP.get(resp.stop_reason, StopReason.END_TURN)
        usage = {
            "input_tokens": getattr(resp.usage, "input_tokens", 0),
            "output_tokens": getattr(resp.usage, "output_tokens", 0),
            # Expose cache stats so users can verify hit rate.
            "cache_creation_input_tokens": getattr(
                resp.usage, "cache_creation_input_tokens", 0
            ) or 0,
            "cache_read_input_tokens": getattr(
                resp.usage, "cache_read_input_tokens", 0
            ) or 0,
        }
        return LLMResponse(message=msg, stop_reason=stop, usage=usage)
