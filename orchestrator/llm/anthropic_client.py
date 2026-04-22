"""Anthropic provider adapter."""

from __future__ import annotations

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
    ) -> LLMResponse:
        resp = await self.client.messages.create(
            model=self.model,
            system=system,
            max_tokens=max_tokens,
            messages=self._messages_to_anthropic(messages),
            tools=self._tools_to_anthropic(tools) if tools else [],
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
        }
        return LLMResponse(message=msg, stop_reason=stop, usage=usage)
